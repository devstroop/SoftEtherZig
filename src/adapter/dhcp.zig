// SoftEther VPN Client - DHCP Protocol Implementation
// DHCP packet building and parsing

const std = @import("std");

/// DHCP message types
pub const DhcpMessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

/// DHCP option codes
pub const DhcpOption = enum(u8) {
    pad = 0,
    subnet_mask = 1,
    router = 3,
    dns_server = 6,
    hostname = 12,
    domain_name = 15,
    requested_ip = 50,
    lease_time = 51,
    message_type = 53,
    server_identifier = 54,
    parameter_request = 55,
    renewal_time = 58,
    rebinding_time = 59,
    end_option = 255,
};

/// DHCP magic cookie
pub const DHCP_MAGIC: u32 = 0x63825363;

/// DHCP ports
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

/// Minimum DHCP packet size (excluding options)
pub const DHCP_HEADER_SIZE: usize = 236;

/// DHCP configuration result
pub const DhcpConfig = struct {
    ip_address: u32 = 0,
    subnet_mask: u32 = 0,
    gateway: u32 = 0,
    dns1: u32 = 0,
    dns2: u32 = 0,
    server_id: u32 = 0,
    lease_time: u32 = 0,
    domain_name: [64]u8 = [_]u8{0} ** 64,
    domain_name_len: usize = 0,

    pub fn isValid(self: *const DhcpConfig) bool {
        return self.ip_address != 0;
    }
};

/// Build DHCP DISCOVER packet
/// Returns Ethernet frame with IP/UDP headers
pub fn buildDhcpDiscover(
    mac: [6]u8,
    xid: u32,
    buffer: []u8,
) !usize {
    if (buffer.len < 300) return error.BufferTooSmall;

    var pos: usize = 0;

    // === Ethernet Header (14 bytes) ===
    // Destination: broadcast
    @memset(buffer[pos..][0..6], 0xFF);
    pos += 6;
    // Source: our MAC
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;
    // EtherType: IPv4 (0x0800)
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x00;
    pos += 2;

    const ip_header_start = pos;

    // === IPv4 Header (20 bytes) ===
    buffer[pos] = 0x45; // Version 4, IHL 5
    buffer[pos + 1] = 0x00; // DSCP/ECN
    pos += 2;

    // Total length placeholder (will update)
    const ip_len_pos = pos;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    // ID, flags, fragment
    @memset(buffer[pos..][0..4], 0);
    pos += 4;

    buffer[pos] = 64; // TTL
    buffer[pos + 1] = 17; // Protocol: UDP
    pos += 2;

    // Checksum placeholder
    const ip_checksum_pos = pos;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    // Source IP: 0.0.0.0
    @memset(buffer[pos..][0..4], 0);
    pos += 4;

    // Dest IP: 255.255.255.255
    @memset(buffer[pos..][0..4], 0xFF);
    pos += 4;

    const udp_header_start = pos;

    // === UDP Header (8 bytes) ===
    buffer[pos] = 0x00;
    buffer[pos + 1] = DHCP_CLIENT_PORT; // Source: 68
    pos += 2;
    buffer[pos] = 0x00;
    buffer[pos + 1] = DHCP_SERVER_PORT; // Dest: 67
    pos += 2;

    // UDP length placeholder
    const udp_len_pos = pos;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    // UDP checksum (optional for IPv4)
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    // === DHCP Packet ===
    buffer[pos] = 0x01; // op: BOOTREQUEST
    buffer[pos + 1] = 0x01; // htype: Ethernet
    buffer[pos + 2] = 0x06; // hlen: 6
    buffer[pos + 3] = 0x00; // hops: 0
    pos += 4;

    // Transaction ID
    buffer[pos] = @intCast((xid >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((xid >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((xid >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(xid & 0xFF);
    pos += 4;

    // secs: 0, flags: broadcast (0x8000)
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    buffer[pos + 2] = 0x80;
    buffer[pos + 3] = 0x00;
    pos += 4;

    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    @memset(buffer[pos..][0..16], 0);
    pos += 16;

    // chaddr (client MAC + padding)
    @memcpy(buffer[pos..][0..6], &mac);
    @memset(buffer[pos + 6 ..][0..10], 0);
    pos += 16;

    // sname, file (zeros)
    @memset(buffer[pos..][0..192], 0);
    pos += 192;

    // DHCP magic cookie
    buffer[pos] = 0x63;
    buffer[pos + 1] = 0x82;
    buffer[pos + 2] = 0x53;
    buffer[pos + 3] = 0x63;
    pos += 4;

    // === DHCP Options ===
    // Option 53: Message Type = DISCOVER
    buffer[pos] = @intFromEnum(DhcpOption.message_type);
    buffer[pos + 1] = 1;
    buffer[pos + 2] = @intFromEnum(DhcpMessageType.discover);
    pos += 3;

    // Option 55: Parameter Request List
    buffer[pos] = @intFromEnum(DhcpOption.parameter_request);
    buffer[pos + 1] = 4;
    buffer[pos + 2] = @intFromEnum(DhcpOption.subnet_mask);
    buffer[pos + 3] = @intFromEnum(DhcpOption.router);
    buffer[pos + 4] = @intFromEnum(DhcpOption.dns_server);
    buffer[pos + 5] = @intFromEnum(DhcpOption.domain_name);
    pos += 6;

    // Option 255: End
    buffer[pos] = @intFromEnum(DhcpOption.end_option);
    pos += 1;

    // Update lengths
    const ip_total_len: u16 = @intCast(pos - ip_header_start);
    buffer[ip_len_pos] = @intCast((ip_total_len >> 8) & 0xFF);
    buffer[ip_len_pos + 1] = @intCast(ip_total_len & 0xFF);

    const udp_len: u16 = @intCast(pos - udp_header_start);
    buffer[udp_len_pos] = @intCast((udp_len >> 8) & 0xFF);
    buffer[udp_len_pos + 1] = @intCast(udp_len & 0xFF);

    // Calculate IP checksum
    const checksum = computeIpChecksum(buffer[ip_header_start..][0..20]);
    buffer[ip_checksum_pos] = @intCast((checksum >> 8) & 0xFF);
    buffer[ip_checksum_pos + 1] = @intCast(checksum & 0xFF);

    return pos;
}

/// Build DHCP REQUEST packet
pub fn buildDhcpRequest(
    mac: [6]u8,
    xid: u32,
    requested_ip: u32,
    server_ip: u32,
    buffer: []u8,
) !usize {
    if (buffer.len < 320) return error.BufferTooSmall;

    var pos: usize = 0;

    // Ethernet header
    @memset(buffer[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x00;
    pos += 2;

    const ip_header_start = pos;

    // IPv4 header
    buffer[pos] = 0x45;
    buffer[pos + 1] = 0x00;
    pos += 2;

    const ip_len_pos = pos;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    @memset(buffer[pos..][0..4], 0);
    pos += 4;

    buffer[pos] = 64;
    buffer[pos + 1] = 17;
    pos += 2;

    const ip_checksum_pos = pos;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    @memset(buffer[pos..][0..4], 0);
    pos += 4;
    @memset(buffer[pos..][0..4], 0xFF);
    pos += 4;

    const udp_header_start = pos;

    // UDP header
    buffer[pos] = 0x00;
    buffer[pos + 1] = DHCP_CLIENT_PORT;
    pos += 2;
    buffer[pos] = 0x00;
    buffer[pos + 1] = DHCP_SERVER_PORT;
    pos += 2;

    const udp_len_pos = pos;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    // DHCP packet
    buffer[pos] = 0x01;
    buffer[pos + 1] = 0x01;
    buffer[pos + 2] = 0x06;
    buffer[pos + 3] = 0x00;
    pos += 4;

    buffer[pos] = @intCast((xid >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((xid >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((xid >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(xid & 0xFF);
    pos += 4;

    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    buffer[pos + 2] = 0x80;
    buffer[pos + 3] = 0x00;
    pos += 4;

    @memset(buffer[pos..][0..16], 0);
    pos += 16;

    @memcpy(buffer[pos..][0..6], &mac);
    @memset(buffer[pos + 6 ..][0..10], 0);
    pos += 16;

    @memset(buffer[pos..][0..192], 0);
    pos += 192;

    buffer[pos] = 0x63;
    buffer[pos + 1] = 0x82;
    buffer[pos + 2] = 0x53;
    buffer[pos + 3] = 0x63;
    pos += 4;

    // Options
    // Message Type = REQUEST
    buffer[pos] = @intFromEnum(DhcpOption.message_type);
    buffer[pos + 1] = 1;
    buffer[pos + 2] = @intFromEnum(DhcpMessageType.request);
    pos += 3;

    // Requested IP Address
    buffer[pos] = @intFromEnum(DhcpOption.requested_ip);
    buffer[pos + 1] = 4;
    buffer[pos + 2] = @intCast((requested_ip >> 24) & 0xFF);
    buffer[pos + 3] = @intCast((requested_ip >> 16) & 0xFF);
    buffer[pos + 4] = @intCast((requested_ip >> 8) & 0xFF);
    buffer[pos + 5] = @intCast(requested_ip & 0xFF);
    pos += 6;

    // Server Identifier
    buffer[pos] = @intFromEnum(DhcpOption.server_identifier);
    buffer[pos + 1] = 4;
    buffer[pos + 2] = @intCast((server_ip >> 24) & 0xFF);
    buffer[pos + 3] = @intCast((server_ip >> 16) & 0xFF);
    buffer[pos + 4] = @intCast((server_ip >> 8) & 0xFF);
    buffer[pos + 5] = @intCast(server_ip & 0xFF);
    pos += 6;

    // Parameter Request List
    buffer[pos] = @intFromEnum(DhcpOption.parameter_request);
    buffer[pos + 1] = 4;
    buffer[pos + 2] = @intFromEnum(DhcpOption.subnet_mask);
    buffer[pos + 3] = @intFromEnum(DhcpOption.router);
    buffer[pos + 4] = @intFromEnum(DhcpOption.dns_server);
    buffer[pos + 5] = @intFromEnum(DhcpOption.domain_name);
    pos += 6;

    // End
    buffer[pos] = @intFromEnum(DhcpOption.end_option);
    pos += 1;

    // Update lengths
    const ip_total_len: u16 = @intCast(pos - ip_header_start);
    buffer[ip_len_pos] = @intCast((ip_total_len >> 8) & 0xFF);
    buffer[ip_len_pos + 1] = @intCast(ip_total_len & 0xFF);

    const udp_len: u16 = @intCast(pos - udp_header_start);
    buffer[udp_len_pos] = @intCast((udp_len >> 8) & 0xFF);
    buffer[udp_len_pos + 1] = @intCast(udp_len & 0xFF);

    const checksum = computeIpChecksum(buffer[ip_header_start..][0..20]);
    buffer[ip_checksum_pos] = @intCast((checksum >> 8) & 0xFF);
    buffer[ip_checksum_pos + 1] = @intCast(checksum & 0xFF);

    return pos;
}

/// Parse DHCP OFFER or ACK packet
/// Returns configuration if valid, null otherwise
pub fn parseDhcpResponse(
    data: []const u8,
    expected_xid: u32,
) !?struct { config: DhcpConfig, msg_type: DhcpMessageType } {
    // Skip Ethernet header
    if (data.len < 14) return null;

    // Check EtherType (IPv4)
    if (data[12] != 0x08 or data[13] != 0x00) return null;

    var pos: usize = 14;

    // Check IPv4 header
    if (data.len < pos + 20) return null;
    const protocol = data[pos + 9];
    if (protocol != 17) return null; // Not UDP

    const ihl: usize = @as(usize, data[pos] & 0x0F) * 4;
    pos += ihl;

    // Check UDP ports
    if (data.len < pos + 8) return null;
    const src_port = (@as(u16, data[pos]) << 8) | data[pos + 1];
    const dst_port = (@as(u16, data[pos + 2]) << 8) | data[pos + 3];
    if (src_port != DHCP_SERVER_PORT or dst_port != DHCP_CLIENT_PORT) return null;

    pos += 8; // Skip UDP header

    // Parse DHCP
    if (data.len < pos + DHCP_HEADER_SIZE + 4) return null;

    // Check BOOTREPLY
    if (data[pos] != 2) return null;

    // Check XID
    const xid = (@as(u32, data[pos + 4]) << 24) |
        (@as(u32, data[pos + 5]) << 16) |
        (@as(u32, data[pos + 6]) << 8) |
        data[pos + 7];
    if (xid != expected_xid) return null;

    // Extract yiaddr (offered IP)
    const yiaddr = (@as(u32, data[pos + 16]) << 24) |
        (@as(u32, data[pos + 17]) << 16) |
        (@as(u32, data[pos + 18]) << 8) |
        data[pos + 19];

    // Check magic cookie
    const magic_pos = pos + 236;
    if (data.len < magic_pos + 4) return null;
    const magic = (@as(u32, data[magic_pos]) << 24) |
        (@as(u32, data[magic_pos + 1]) << 16) |
        (@as(u32, data[magic_pos + 2]) << 8) |
        data[magic_pos + 3];
    if (magic != DHCP_MAGIC) return null;

    // Parse options
    var config = DhcpConfig{};
    config.ip_address = yiaddr;

    var msg_type: ?DhcpMessageType = null;
    var opt_pos = magic_pos + 4;

    while (opt_pos < data.len) {
        const opt_type = data[opt_pos];

        if (opt_type == @intFromEnum(DhcpOption.end_option)) break;
        if (opt_type == @intFromEnum(DhcpOption.pad)) {
            opt_pos += 1;
            continue;
        }

        if (opt_pos + 1 >= data.len) break;
        const opt_len = data[opt_pos + 1];

        if (opt_pos + 2 + opt_len > data.len) break;

        const opt_data = data[opt_pos + 2 ..][0..opt_len];

        if (opt_type == @intFromEnum(DhcpOption.message_type) and opt_len >= 1) {
            msg_type = @enumFromInt(opt_data[0]);
        } else if (opt_type == @intFromEnum(DhcpOption.subnet_mask) and opt_len >= 4) {
            config.subnet_mask = (@as(u32, opt_data[0]) << 24) |
                (@as(u32, opt_data[1]) << 16) |
                (@as(u32, opt_data[2]) << 8) |
                opt_data[3];
        } else if (opt_type == @intFromEnum(DhcpOption.router) and opt_len >= 4) {
            config.gateway = (@as(u32, opt_data[0]) << 24) |
                (@as(u32, opt_data[1]) << 16) |
                (@as(u32, opt_data[2]) << 8) |
                opt_data[3];
        } else if (opt_type == @intFromEnum(DhcpOption.dns_server)) {
            if (opt_len >= 4) {
                config.dns1 = (@as(u32, opt_data[0]) << 24) |
                    (@as(u32, opt_data[1]) << 16) |
                    (@as(u32, opt_data[2]) << 8) |
                    opt_data[3];
            }
            if (opt_len >= 8) {
                config.dns2 = (@as(u32, opt_data[4]) << 24) |
                    (@as(u32, opt_data[5]) << 16) |
                    (@as(u32, opt_data[6]) << 8) |
                    opt_data[7];
            }
        } else if (opt_type == @intFromEnum(DhcpOption.server_identifier) and opt_len >= 4) {
            config.server_id = (@as(u32, opt_data[0]) << 24) |
                (@as(u32, opt_data[1]) << 16) |
                (@as(u32, opt_data[2]) << 8) |
                opt_data[3];
        } else if (opt_type == @intFromEnum(DhcpOption.lease_time) and opt_len >= 4) {
            config.lease_time = (@as(u32, opt_data[0]) << 24) |
                (@as(u32, opt_data[1]) << 16) |
                (@as(u32, opt_data[2]) << 8) |
                opt_data[3];
        } else if (opt_type == @intFromEnum(DhcpOption.domain_name)) {
            const copy_len = @min(opt_len, 64);
            @memcpy(config.domain_name[0..copy_len], opt_data[0..copy_len]);
            config.domain_name_len = copy_len;
        }

        opt_pos += 2 + opt_len;
    }

    if (msg_type) |mt| {
        if (mt == .offer or mt == .ack) {
            return .{ .config = config, .msg_type = mt };
        }
    }

    return null;
}

/// Check if packet is an ARP request for our IP
pub fn parseArpRequest(data: []const u8, our_ip: u32) ?struct { sender_mac: [6]u8, sender_ip: u32 } {
    // Check Ethernet frame
    if (data.len < 42) return null;

    // Check EtherType (ARP)
    if (data[12] != 0x08 or data[13] != 0x06) return null;

    // Check hardware type (Ethernet) and protocol type (IPv4)
    if (data[14] != 0x00 or data[15] != 0x01) return null;
    if (data[16] != 0x08 or data[17] != 0x00) return null;

    // Check opcode (Request = 1)
    if (data[20] != 0x00 or data[21] != 0x01) return null;

    // Get target IP
    const target_ip = (@as(u32, data[38]) << 24) |
        (@as(u32, data[39]) << 16) |
        (@as(u32, data[40]) << 8) |
        data[41];

    // Check if target is our IP
    if (target_ip != our_ip) return null;

    // Extract sender info
    var sender_mac: [6]u8 = undefined;
    @memcpy(&sender_mac, data[22..28]);

    const sender_ip = (@as(u32, data[28]) << 24) |
        (@as(u32, data[29]) << 16) |
        (@as(u32, data[30]) << 8) |
        data[31];

    return .{ .sender_mac = sender_mac, .sender_ip = sender_ip };
}

/// Check if packet is an ARP reply and extract gateway MAC
pub fn parseArpReply(data: []const u8, expected_ip: u32) ?[6]u8 {
    if (data.len < 42) return null;

    // Check EtherType (ARP)
    if (data[12] != 0x08 or data[13] != 0x06) return null;

    // Check opcode (Reply = 2)
    if (data[20] != 0x00 or data[21] != 0x02) return null;

    // Get sender IP
    const sender_ip = (@as(u32, data[28]) << 24) |
        (@as(u32, data[29]) << 16) |
        (@as(u32, data[30]) << 8) |
        data[31];

    if (sender_ip != expected_ip) return null;

    var sender_mac: [6]u8 = undefined;
    @memcpy(&sender_mac, data[22..28]);

    return sender_mac;
}

/// Compute IP header checksum
fn computeIpChecksum(header: []const u8) u16 {
    var sum: u32 = 0;

    var i: usize = 0;
    while (i < header.len) : (i += 2) {
        const word = (@as(u32, header[i]) << 8) | header[i + 1];
        sum += word;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @intCast(~sum & 0xFFFF);
}

// ============================================
// Tests
// ============================================

test "DHCP message types" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(DhcpMessageType.discover));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(DhcpMessageType.offer));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(DhcpMessageType.request));
    try std.testing.expectEqual(@as(u8, 5), @intFromEnum(DhcpMessageType.ack));
}

test "DHCP option codes" {
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(DhcpOption.subnet_mask));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(DhcpOption.router));
    try std.testing.expectEqual(@as(u8, 6), @intFromEnum(DhcpOption.dns_server));
    try std.testing.expectEqual(@as(u8, 53), @intFromEnum(DhcpOption.message_type));
    try std.testing.expectEqual(@as(u8, 255), @intFromEnum(DhcpOption.end_option));
}

test "Build DHCP DISCOVER" {
    var buffer: [512]u8 = undefined;
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const xid: u32 = 0x12345678;

    const size = try buildDhcpDiscover(mac, xid, &buffer);

    // Should be at least: Ethernet(14) + IP(20) + UDP(8) + DHCP(240) + Options(~10)
    try std.testing.expect(size >= 290);

    // Check broadcast destination
    try std.testing.expectEqual(@as(u8, 0xFF), buffer[0]);

    // Check source MAC
    try std.testing.expectEqual(@as(u8, 0x02), buffer[6]);

    // Check EtherType (IPv4)
    try std.testing.expectEqual(@as(u8, 0x08), buffer[12]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[13]);

    // Check UDP ports (at offset 34-37 in standard header)
    // Source: 68, Dest: 67
}

test "Build DHCP REQUEST" {
    var buffer: [512]u8 = undefined;
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const xid: u32 = 0x12345678;
    const requested_ip: u32 = 0xC0A80101; // 192.168.1.1
    const server_ip: u32 = 0xC0A80FE; // 192.168.1.254

    const size = try buildDhcpRequest(mac, xid, requested_ip, server_ip, &buffer);

    try std.testing.expect(size >= 300);
}

test "IP checksum computation" {
    // Test with known values
    const header = [_]u8{
        0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Total Length
        0x1c, 0x46, 0x40, 0x00, // ID, Flags, Fragment
        0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum (0 for calculation)
        0xac, 0x10, 0x0a, 0x63, // Source IP
        0xac, 0x10, 0x0a, 0x0c, // Dest IP
    };

    const checksum = computeIpChecksum(&header);
    // Checksum should be non-zero
    try std.testing.expect(checksum != 0);
}

test "DhcpConfig validity" {
    var config = DhcpConfig{};
    try std.testing.expect(!config.isValid());

    config.ip_address = 0xC0A80101;
    try std.testing.expect(config.isValid());
}

test "DHCP magic cookie constant" {
    try std.testing.expectEqual(@as(u32, 0x63825363), DHCP_MAGIC);
}

test "DHCP port constants" {
    try std.testing.expectEqual(@as(u16, 68), DHCP_CLIENT_PORT);
    try std.testing.expectEqual(@as(u16, 67), DHCP_SERVER_PORT);
}

test "Parse ARP request - not an ARP" {
    var data: [64]u8 = [_]u8{0} ** 64;
    // Not ARP EtherType
    data[12] = 0x08;
    data[13] = 0x00;

    const result = parseArpRequest(&data, 0xC0A80101);
    try std.testing.expect(result == null);
}

test "Parse ARP reply - not a reply" {
    var data: [64]u8 = [_]u8{0} ** 64;
    // ARP EtherType
    data[12] = 0x08;
    data[13] = 0x06;
    // Hardware and protocol types
    data[14] = 0x00;
    data[15] = 0x01;
    data[16] = 0x08;
    data[17] = 0x00;
    // Opcode = Request (not reply)
    data[20] = 0x00;
    data[21] = 0x01;

    const result = parseArpReply(&data, 0xC0A80101);
    try std.testing.expect(result == null);
}
