// SoftEther VPN Client - DHCPv6 Client (RFC 8415)
// Provides IPv6 address configuration for the tunnel interface.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// DHCPv6 message types (RFC 8415 §7.3)
pub const Dhcpv6MessageType = enum(u8) {
    solicit = 1,
    advertise = 2,
    request = 3,
    confirm = 4,
    renew = 5,
    rebind = 6,
    reply = 7,
    release = 8,
    decline = 9,
    reconfigure = 10,
    information_request = 11,
    relay_forw = 12,
    relay_repl = 13,
};

/// DHCPv6 option codes (RFC 8415 §21.1)
pub const Dhcpv6Option = enum(u16) {
    client_id = 1,
    server_id = 2,
    ia_na = 3, // Identity Association for Non-temporary Addresses
    ia_ta = 4, // Identity Association for Temporary Addresses
    ia_addr = 5,
    oro = 6, // Option Request Option
    preference = 7,
    elapsed_time = 8,
    relay_msg = 9,
    authentication = 11,
    server_unicast = 12,
    status_code = 13,
    rapid_commit = 14,
    user_class = 15,
    vendor_class = 16,
    vendor_opts = 17,
    interface_id = 18,
    relay_agent_option = 19,
    dns_recursive_name_server = 23,
    domain_search_list = 24,
    ia_pd = 25, // Identity Association for Prefix Delegation
    ip_address = 29,
    option_lifetime = 32,
    dhcpv6_relay_msg = 33,
};

/// DHCPv6 client state
pub const Dhcpv6State = enum {
    init,
    solicit_sent,
    request_sent,
    configured,
    failed,

    pub fn isConfigured(self: Dhcpv6State) bool {
        return self == .configured;
    }
};

/// DHCPv6 address configuration received from server
pub const Dhcpv6Config = struct {
    /// Assigned IPv6 address (16 bytes, network byte order)
    address: [16]u8 = [_]u8{0} ** 16,
    /// Prefix length (typically 128 for IA_NA, 64 for IA_PD)
    prefix_len: u8 = 128,
    /// Preferred lifetime in seconds
    preferred_lifetime: u32 = 0,
    /// Valid lifetime in seconds
    valid_lifetime: u32 = 0,
    /// DNS servers (up to 4, each 16 bytes)
    dns_servers: [4][16]u8 = [_][16]u8{[_]u8{0} ** 16} ** 4,
    dns_count: u8 = 0,
    /// DNS search list (concatenated labels)
    search_list: [256]u8 = [_]u8{0} ** 256,
    search_list_len: usize = 0,

    pub fn isValid(self: *const Dhcpv6Config) bool {
        // Check if address is non-zero (not all zeros)
        for (self.address) |b| {
            if (b != 0) return true;
        }
        return false;
    }
};

/// DHCPv6 client for obtaining IPv6 addresses via IA_NA
pub const Dhcpv6Client = struct {
    state: Dhcpv6State = .init,
    duid: [14]u8, // DHCPv6 Unique Identifier (type 2, link-layer address)
    iaid: u32 = 0, // Identity Association ID
    transaction_id: u32 = 0,
    config: Dhcpv6Config = .{},
    retry_count: u32 = 0,
    last_send_time: i64 = 0,
    allocator: std.mem.Allocator,

    const MAX_RETRIES: u32 = 5;
    const RETRY_INTERVAL_MS: i64 = 3000;

    pub fn init(allocator: std.mem.Allocator, mac: [6]u8) Dhcpv6Client {
        var xid: u32 = 0;
        std.crypto.random.bytes(std.mem.asBytes(&xid));

        // Build DUID-LLT (type 2): 2-byte type + 2-byte hw type + 4-byte time + 6-byte MAC
        var duid: [14]u8 = undefined;
        duid[0] = 0x00; // type high
        duid[1] = 0x02; // DUID-LLT
        duid[2] = 0x00; // hw type high (Ethernet = 1)
        duid[3] = 0x01; // hw type low
        // Timestamp (4 bytes, seconds since 2000-01-01)
        const now_secs: u32 = @intCast(@divTrunc(std.time.milliTimestamp(), 1000));
        const epoch_diff: u32 = 946684800; // seconds between 1970 and 2000
        const hw_time = now_secs -| epoch_diff;
        duid[4] = @intCast((hw_time >> 24) & 0xFF);
        duid[5] = @intCast((hw_time >> 16) & 0xFF);
        duid[6] = @intCast((hw_time >> 8) & 0xFF);
        duid[7] = @intCast(hw_time & 0xFF);
        @memcpy(duid[8..14], &mac);

        return .{
            .allocator = allocator,
            .duid = duid,
            .transaction_id = xid,
        };
    }

    /// Build a DHCPv6 Solicit message
    /// Returns the message payload (no UDP/IP headers — caller wraps)
    pub fn buildSolicit(self: *Dhcpv6Client, buffer: []u8) !usize {
        if (buffer.len < 100) return error.BufferTooSmall;

        var pos: usize = 0;

        // Message type: Solicit (1)
        buffer[pos] = @intFromEnum(Dhcpv6MessageType.solicit);
        pos += 1;

        // Transaction ID (3 bytes, big-endian)
        buffer[pos] = @intCast((self.transaction_id >> 16) & 0xFF);
        buffer[pos + 1] = @intCast((self.transaction_id >> 8) & 0xFF);
        buffer[pos + 2] = @intCast(self.transaction_id & 0xFF);
        pos += 3;

        // Option: Rapid Commit (option 14, length 0)
        buffer[pos] = 0x00;
        buffer[pos + 1] = 14;
        buffer[pos + 2] = 0x00;
        buffer[pos + 3] = 0x00;
        pos += 4;

        // Option: Client Identifier (option 1)
        pos = writeOptionHeader(buffer, pos, 1, @intCast(self.duid.len));
        @memcpy(buffer[pos..][0..self.duid.len], &self.duid);
        pos += self.duid.len;

        // Option: IA_NA (option 3)
        // IA_NA: 4 bytes IAID + 4 bytes T1 + 4 bytes T2 + IAADDR sub-options
        const ia_na_start = pos;
        pos += 4; // option header
        const ia_na_data_start = pos;
        // IAID (4 bytes)
        buffer[pos] = @intCast((self.iaid >> 24) & 0xFF);
        buffer[pos + 1] = @intCast((self.iaid >> 16) & 0xFF);
        buffer[pos + 2] = @intCast((self.iaid >> 8) & 0xFF);
        buffer[pos + 3] = @intCast(self.iaid & 0xFF);
        pos += 4;
        // T1 = 0 (let server decide)
        buffer[pos] = 0;
        buffer[pos + 1] = 0;
        buffer[pos + 2] = 0;
        buffer[pos + 3] = 0;
        pos += 4;
        // T2 = 0 (let server decide)
        buffer[pos] = 0;
        buffer[pos + 1] = 0;
        buffer[pos + 2] = 0;
        buffer[pos + 3] = 0;
        pos += 4;
        // No IAADDR sub-options in Solicit (we're requesting an address)
        // Write IA_NA option header
        writeOptionHeaderAt(buffer, ia_na_start, 3, @intCast(pos - ia_na_data_start));

        // Option: Option Request Option (option 6)
        // Request: DNSRecursiveNameServer (23), DomainSearchList (24), SIP (21)
        pos = writeOptionHeader(buffer, pos, 6, 6);
        buffer[pos] = 0x00;
        buffer[pos + 1] = 23; // DNS
        buffer[pos + 2] = 0x00;
        buffer[pos + 3] = 24; // Domain search
        buffer[pos + 4] = 0x00;
        buffer[pos + 5] = 21; // SIP
        pos += 6;

        return pos;
    }

    /// Build a DHCPv6 Request message (after receiving Advertise)
    pub fn buildRequest(self: *Dhcpv6Client, buffer: []u8, server_duid: []const u8, offered_addr: [16]u8) !usize {
        if (buffer.len < 150) return error.BufferTooSmall;

        var pos: usize = 0;

        // Message type: Request (3)
        buffer[pos] = @intFromEnum(Dhcpv6MessageType.request);
        pos += 1;

        // Transaction ID (3 bytes)
        buffer[pos] = @intCast((self.transaction_id >> 16) & 0xFF);
        buffer[pos + 1] = @intCast((self.transaction_id >> 8) & 0xFF);
        buffer[pos + 2] = @intCast(self.transaction_id & 0xFF);
        pos += 3;

        // Option: Server Identifier (option 2)
        pos = writeOptionHeader(buffer, pos, 2, @intCast(server_duid.len));
        @memcpy(buffer[pos..][0..server_duid.len], server_duid);
        pos += server_duid.len;

        // Option: Client Identifier (option 1)
        pos = writeOptionHeader(buffer, pos, 1, @intCast(self.duid.len));
        @memcpy(buffer[pos..][0..self.duid.len], &self.duid);
        pos += self.duid.len;

        // Option: IA_NA (option 3) with IAADDR sub-option
        const ia_na_start = pos;
        pos += 4; // option header
        const ia_na_data_start = pos;
        // IAID
        buffer[pos] = @intCast((self.iaid >> 24) & 0xFF);
        buffer[pos + 1] = @intCast((self.iaid >> 16) & 0xFF);
        buffer[pos + 2] = @intCast((self.iaid >> 8) & 0xFF);
        buffer[pos + 3] = @intCast(self.iaid & 0xFF);
        pos += 4;
        // T1
        @memset(buffer[pos..][0..4], 0);
        pos += 4;
        // T2
        @memset(buffer[pos..][0..4], 0);
        pos += 4;
        // IAADDR sub-option (option 5)
        pos = writeOptionHeader(buffer, pos, 5, 24);
        @memcpy(buffer[pos..][0..16], &offered_addr);
        pos += 16;
        // Preferred lifetime (4 bytes)
        @memset(buffer[pos..][0..4], 0);
        pos += 4;
        // Valid lifetime (4 bytes)
        @memset(buffer[pos..][0..4], 0);
        pos += 4;
        // Update IA_NA header
        writeOptionHeaderAt(buffer, ia_na_start, 3, @intCast(pos - ia_na_data_start));

        // Option: Option Request Option
        pos = writeOptionHeader(buffer, pos, 6, 6);
        buffer[pos] = 0x00;
        buffer[pos + 1] = 23;
        buffer[pos + 2] = 0x00;
        buffer[pos + 3] = 24;
        buffer[pos + 4] = 0x00;
        buffer[pos + 5] = 21;
        pos += 6;

        return pos;
    }

    /// Parse a DHCPv6 Advertise or Reply message
    pub fn parseResponse(self: *Dhcpv6Client, data: []const u8) !?struct { msg_type: Dhcpv6MessageType, server_duid: ?[]const u8 } {
        if (data.len < 4) return null;

        const msg_type: Dhcpv6MessageType = @enumFromInt(data[0]);

        // Verify transaction ID
        const xid = (@as(u32, data[1]) << 16) |
            (@as(u32, data[2]) << 8) |
            data[3];
        if (xid != self.transaction_id) return null;

        var server_duid: ?[]const u8 = null;

        // Parse options
        var pos: usize = 4;
        while (pos + 4 <= data.len) {
            const opt_code = (@as(u16, data[pos]) << 8) | data[pos + 1];
            const opt_len = (@as(u16, data[pos + 2]) << 8) | data[pos + 3];
            pos += 4;

            if (pos + @as(usize, opt_len) > data.len) break;
            const opt_data = data[pos..][0..opt_len];

            switch (opt_code) {
                2 => { // Server Identifier
                    server_duid = opt_data;
                },
                3 => { // IA_NA
                    try self.parseIaNa(opt_data);
                },
                23 => { // DNS Recursive Name Server
                    self.parseDnsServers(opt_data);
                },
                24 => { // Domain Search List
                    self.parseSearchList(opt_data);
                },
                else => {},
            }

            pos += opt_len;
        }

        return .{ .msg_type = msg_type, .server_duid = server_duid };
    }

    fn parseIaNa(self: *Dhcpv6Client, data: []const u8) !void {
        if (data.len < 12) return; // IAID(4) + T1(4) + T2(4) + sub-options
        // Skip IAID, T1, T2
        var pos: usize = 12;

        // Parse IAADDR sub-options
        while (pos + 4 <= data.len) {
            const sub_code = (@as(u16, data[pos]) << 8) | data[pos + 1];
            const sub_len = (@as(u16, data[pos + 2]) << 8) | data[pos + 3];
            pos += 4;

            if (pos + @as(usize, sub_len) > data.len) break;

            if (sub_code == 5 and sub_len >= 24) {
                // IAADDR: address(16) + preferred(4) + valid(4) + options(4+)
                @memcpy(&self.config.address, data[pos..][0..16]);
                self.config.preferred_lifetime = (@as(u32, data[pos + 16]) << 24) |
                    (@as(u32, data[pos + 17]) << 16) |
                    (@as(u32, data[pos + 18]) << 8) |
                    data[pos + 19];
                self.config.valid_lifetime = (@as(u32, data[pos + 20]) << 24) |
                    (@as(u32, data[pos + 21]) << 16) |
                    (@as(u32, data[pos + 22]) << 8) |
                    data[pos + 23];
                self.config.prefix_len = 128;
            }

            pos += sub_len;
        }
    }

    fn parseDnsServers(self: *Dhcpv6Client, data: []const u8) void {
        var pos: usize = 0;
        self.config.dns_count = 0;
        while (pos + 16 <= data.len and self.config.dns_count < 4) {
            @memcpy(&self.config.dns_servers[self.config.dns_count], data[pos..][0..16]);
            self.config.dns_count += 1;
            pos += 16;
        }
    }

    fn parseSearchList(self: *Dhcpv6Client, data: []const u8) void {
        const copy_len = @min(data.len, 256);
        @memcpy(self.config.search_list[0..copy_len], data[0..copy_len]);
        self.config.search_list_len = copy_len;
    }

    /// Format the assigned IPv6 address as a string (e.g. "2001:db8::1")
    pub fn formatAddress(self: *const Dhcpv6Client, buffer: []u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "{}", .{
            std.net.fmt_ipv6(self.config.address),
        });
    }
};

/// Write an option header at the given position, return position after header.
fn writeOptionHeader(buffer: []u8, pos: usize, code: u16, length: u16) usize {
    buffer[pos] = @intCast((code >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(code & 0xFF);
    buffer[pos + 2] = @intCast((length >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(length & 0xFF);
    return pos + 4;
}

/// Overwrite an option header at a specific position (for backfilling length).
fn writeOptionHeaderAt(buffer: []u8, pos: usize, code: u16, length: u16) void {
    buffer[pos] = @intCast((code >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(code & 0xFF);
    buffer[pos + 2] = @intCast((length >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(length & 0xFF);
}

// ============================================================================
// Tests
// ============================================================================

test "Dhcpv6MessageType values" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Dhcpv6MessageType.solicit));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Dhcpv6MessageType.advertise));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(Dhcpv6MessageType.request));
    try std.testing.expectEqual(@as(u8, 7), @intFromEnum(Dhcpv6MessageType.reply));
}

test "Dhcpv6Client init" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const client = Dhcpv6Client.init(std.testing.allocator, mac);

    // DUID should be DUID-LLT (type 2)
    try std.testing.expectEqual(@as(u8, 0x00), client.duid[0]);
    try std.testing.expectEqual(@as(u8, 0x02), client.duid[1]);
    // HW type Ethernet (1)
    try std.testing.expectEqual(@as(u8, 0x00), client.duid[2]);
    try std.testing.expectEqual(@as(u8, 0x01), client.duid[3]);
    // MAC should be at offset 8
    try std.testing.expectEqual(@as(u8, 0x02), client.duid[8]);
    try std.testing.expectEqual(@as(u8, 0x33), client.duid[13]);
}

test "Build DHCPv6 Solicit" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    var client = Dhcpv6Client.init(std.testing.allocator, mac);

    var buffer: [256]u8 = undefined;
    const len = try client.buildSolicit(&buffer);

    // Message type should be Solicit (1)
    try std.testing.expectEqual(@as(u8, 1), buffer[0]);
    // Transaction ID should match
    try std.testing.expectEqual(@as(u8, (client.transaction_id >> 16) & 0xFF), buffer[1]);
    // Should have at least: msg_type(1) + xid(3) + rapid_commit(4) + client_id + ia_na + oro
    try std.testing.expect(len > 40);
}

test "Dhcpv6Config validity" {
    var config = Dhcpv6Config{};
    try std.testing.expect(!config.isValid());

    config.address[0] = 0x20;
    config.address[1] = 0x01;
    try std.testing.expect(config.isValid());
}

test "Write option header" {
    var buffer: [16]u8 = [_]u8{0} ** 16;
    const pos = writeOptionHeader(&buffer, 0, 23, 16);
    try std.testing.expectEqual(@as(usize, 4), pos);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[0]);
    try std.testing.expectEqual(@as(u8, 23), buffer[1]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[2]);
    try std.testing.expectEqual(@as(u8, 16), buffer[3]);
}
