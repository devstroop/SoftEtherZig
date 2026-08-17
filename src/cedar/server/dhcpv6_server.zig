//! DHCPv6 server for SecureNAT (RFC 8415).
//!
//! C reference: none — the C SoftEther server does not implement a DHCPv6
//! server (it only filters DHCPv6 traffic). This is a Zig-only addition
//! to provide IPv6 address assignment for hub-side clients.
//!
//! Scope (S23):
//! - Stateful address assignment via IA_NA (Identity Association for
//!   Non-temporary Addresses).
//! - Solicit → Advertise → Request → Reply flow (4-message).
//! - Rapid Commit 2-message flow (Solicit → Reply).
//! - Address pool management with lease expiry.
//! - Server DUID (DUID-LLT, generated from hub MAC + timestamp).
//!
//! Out of scope:
//! - IA_TA (temporary addresses), IA_PD (prefix delegation).
//! - Relay agent support.
//! - Authentication.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const dhcpv6_client = @import("dhcpv6.zig");
const Dhcpv6MessageType = dhcpv6_client.Dhcpv6MessageType;
const Dhcpv6Option = dhcpv6_client.Dhcpv6Option;

// ============================================================================
// Constants
// ============================================================================

/// Default preferred lifetime in seconds (1 hour).
pub const DEFAULT_PREFERRED_LIFETIME: u32 = 3600;
/// Default valid lifetime in seconds (2 hours).
pub const DEFAULT_VALID_LIFETIME: u32 = 7200;
/// Maximum number of concurrent leases.
pub const MAX_LEASES: usize = 4096;
/// Default DNS server (Google).
pub const DEFAULT_DNS: [16]u8 = .{ 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88 };
/// Default DNS server 2 (Cloudflare).
pub const DEFAULT_DNS2: [16]u8 = .{ 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11 };

// ============================================================================
// Server DUID
// ============================================================================

/// DHCPv6 server DUID (14 bytes: 2-byte type + 2-byte hw type + 4-byte timestamp + 6-byte MAC).
pub const ServerDuid = struct {
    bytes: [14]u8,

    /// Build a DUID-LLT from a MAC address and timestamp.
    pub fn fromMac(mac: [6]u8, timestamp: u32) ServerDuid {
        var duid: ServerDuid = .{ .bytes = undefined };
        // Type = 2 (DUID-LLT), big-endian.
        duid.bytes[0] = 0x00;
        duid.bytes[1] = 0x02;
        // Hardware type = 1 (Ethernet), big-endian.
        duid.bytes[2] = 0x00;
        duid.bytes[3] = 0x01;
        // Timestamp (seconds since Jan 1, 2000), big-endian.
        duid.bytes[4] = @intCast((timestamp >> 24) & 0xFF);
        duid.bytes[5] = @intCast((timestamp >> 16) & 0xFF);
        duid.bytes[6] = @intCast((timestamp >> 8) & 0xFF);
        duid.bytes[7] = @intCast(timestamp & 0xFF);
        // Link-layer address.
        @memcpy(duid.bytes[8..14], &mac);
        return duid;
    }
};

// ============================================================================
// Lease table
// ============================================================================

/// A single DHCPv6 lease entry.
pub const Lease = struct {
    /// Client DUID (variable length, up to 20 bytes for DUID-LLT).
    client_duid: [20]u8 = .{0} ** 20,
    client_duid_len: u8 = 0,
    /// Assigned IPv6 address (16 bytes, network byte order).
    address: [16]u8 = .{0} ** 16,
    /// IAID from the client's IA_NA option.
    iaid: u32 = 0,
    /// Preferred lifetime (seconds from assignment).
    preferred_lifetime: u32 = DEFAULT_PREFERRED_LIFETIME,
    /// Valid lifetime (seconds from assignment).
    valid_lifetime: u32 = DEFAULT_VALID_LIFETIME,
    /// Timestamp when the lease was created (ms).
    created: i64 = 0,
    /// True if the client has completed the Request/Reply exchange.
    confirmed: bool = false,
};

// ============================================================================
// Address pool
// ============================================================================

/// Configuration for the DHCPv6 address pool.
pub const Dhcpv6PoolConfig = struct {
    /// Network prefix (e.g. 2001:db8:1::), 16 bytes.
    prefix: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /// Prefix length in bits (typically 64).
    prefix_len: u8 = 64,
    /// First assignable interface ID (bytes 8..15 of the address). E.g. 1 = ::1.
    first_interface_id: u16 = 1,
    /// Last assignable interface ID. E.g. 100 = up to 100 addresses.
    last_interface_id: u16 = 100,
    /// Preferred lifetime in seconds.
    preferred_lifetime: u32 = DEFAULT_PREFERRED_LIFETIME,
    /// Valid lifetime in seconds.
    valid_lifetime: u32 = DEFAULT_VALID_LIFETIME,
};

// ============================================================================
// DHCPv6 Server
// ============================================================================

/// DHCPv6 server providing stateful address assignment to hub-side clients.
pub const Dhcpv6Server = struct {
    allocator: Allocator,
    /// Server DUID.
    server_duid: ServerDuid,
    /// Address pool configuration.
    pool: Dhcpv6PoolConfig,
    /// Active leases.
    leases: std.ArrayListUnmanaged(Lease) = .{},
    /// Next interface ID to assign (round-robin).
    next_id: u16,
    /// Total messages processed.
    total_messages: u64 = 0,
    /// Total addresses assigned.
    total_assigned: u64 = 0,

    pub fn init(allocator: Allocator, hub_mac: [6]u8, pool: Dhcpv6PoolConfig) Dhcpv6Server {
        // Build server DUID from hub MAC + current time.
        const ts: u32 = @intCast(@divTrunc(std.time.timestamp(), 1) +% 946684800); // seconds since 2000-01-01
        return .{
            .allocator = allocator,
            .server_duid = ServerDuid.fromMac(hub_mac, ts),
            .pool = pool,
            .next_id = pool.first_interface_id,
        };
    }

    pub fn deinit(self: *Dhcpv6Server) void {
        self.leases.deinit(self.allocator);
    }

    // ---- Message handling --------------------------------------------------

    /// Handle a DHCPv6 message. Returns a response message to send back,
    /// or null if no response is needed.
    pub fn handleMessage(self: *Dhcpv6Server, message: []const u8) ?[]u8 {
        if (message.len < 4) return null; // min: 1-byte type + 3-byte XID

        const msg_type: Dhcpv6MessageType = @enumFromInt(message[0]);
        const xid: u32 = (@as(u32, message[1]) << 16) | (@as(u32, message[2]) << 8) | @as(u32, message[3]);

        self.total_messages += 1;

        return switch (msg_type) {
            .solicit => self.handleSolicit(message, xid),
            .request => self.handleRequest(message, xid),
            .confirm => self.handleConfirm(message, xid),
            .renew => self.handleRenew(message, xid),
            .release => self.handleRelease(message, xid),
            .information_request => self.handleInfoRequest(message, xid),
            else => null, // ignore other types
        };
    }

    // ---- Solicit handler (RFC 8415 §18.2) ---------------------------------

    fn handleSolicit(self: *Dhcpv6Server, message: []const u8, xid: u32) ?[]u8 {
        const options = message[4..];
        const client_duid = parseOption(options, 1) orelse return null; // Client ID (opt 1)
        const ia_na = parseOption(options, 3) orelse return null; // IA_NA (opt 3)

        // Check for Rapid Commit option (opt 14, zero-length).
        const rapid = hasOption(options, 14);

        // Parse IAID from IA_NA (first 4 bytes).
        if (ia_na.len < 4) return null;
        const iaid = mem.readInt(u32, ia_na[0..4], .big);

        // Assign an address.
        const address = self.allocateAddress(client_duid, iaid) orelse return null;

        // Build response.
        if (rapid) {
            // Rapid Commit: send Reply (RFC 8415 §18.2.1).
            return self.buildReply(xid, client_duid, iaid, address);
        } else {
            // Normal: send Advertise (RFC 8415 §18.2.2).
            return self.buildAdvertise(xid, client_duid, iaid, address);
        }
    }

    // ---- Request handler (RFC 8415 §18.3) ---------------------------------

    fn handleRequest(self: *Dhcpv6Server, message: []const u8, xid: u32) ?[]u8 {
        const options = message[4..];
        const client_duid = parseOption(options, 1) orelse return null;
        const server_duid_opt = parseOption(options, 2) orelse return null; // Server ID
        const ia_na = parseOption(options, 3) orelse return null;

        // Verify the Server ID matches ours.
        if (!mem.eql(u8, server_duid_opt, &self.server_duid.bytes)) return null;

        if (ia_na.len < 4) return null;
        const iaid = mem.readInt(u32, ia_na[0..4], .big);

        // Parse the requested address from IAADDR sub-option (opt 5) inside IA_NA.
        const requested_addr = parseIaAddr(ia_na[4..]) orelse return null;

        // Confirm or assign the address.
        const address = self.confirmOrAssign(client_duid, iaid, requested_addr) orelse return null;

        return self.buildReply(xid, client_duid, iaid, address);
    }

    // ---- Confirm handler (RFC 8415 §18.4) ---------------------------------

    fn handleConfirm(self: *Dhcpv6Server, message: []const u8, xid: u32) ?[]u8 {
        const options = message[4..];
        const client_duid = parseOption(options, 1) orelse return null;
        const ia_na = parseOption(options, 3) orelse return null;

        if (ia_na.len < 4) return null;
        const iaid = mem.readInt(u32, ia_na[0..4], .big);

        // Check if the address is still valid.
        const addr = parseIaAddr(ia_na[4..]) orelse return null;
        if (self.isLeaseValid(client_duid, iaid, addr)) {
            return self.buildReply(xid, client_duid, iaid, addr);
        }

        // Not valid — send Reply with NoAddrAvail status.
        return self.buildStatusReply(xid, 2); // status 2 = NoAddrAvail
    }

    // ---- Renew handler (RFC 8415 §18.5) -----------------------------------

    fn handleRenew(self: *Dhcpv6Server, message: []const u8, xid: u32) ?[]u8 {
        const options = message[4..];
        const client_duid = parseOption(options, 1) orelse return null;
        const server_duid_opt = parseOption(options, 2) orelse return null;
        const ia_na = parseOption(options, 3) orelse return null;

        if (!mem.eql(u8, server_duid_opt, &self.server_duid.bytes)) return null;

        if (ia_na.len < 4) return null;
        const iaid = mem.readInt(u32, ia_na[0..4], .big);
        const addr = parseIaAddr(ia_na[4..]) orelse return null;

        if (self.renewLease(client_duid, iaid, addr)) {
            return self.buildReply(xid, client_duid, iaid, addr);
        }

        return self.buildStatusReply(xid, 2); // NoAddrAvail
    }

    // ---- Release handler (RFC 8415 §18.6) ---------------------------------

    fn handleRelease(self: *Dhcpv6Server, message: []const u8, xid: u32) ?[]u8 {
        const options = message[4..];
        const client_duid = parseOption(options, 1) orelse return null;
        const server_duid_opt = parseOption(options, 2) orelse return null;
        const ia_na = parseOption(options, 3) orelse return null;

        if (!mem.eql(u8, server_duid_opt, &self.server_duid.bytes)) return null;

        if (ia_na.len >= 4) {
            const iaid = mem.readInt(u32, ia_na[0..4], .big);
            const addr = parseIaAddr(ia_na[4..]);
            self.releaseLease(client_duid, iaid, addr);
        }

        return self.buildStatusReply(xid, 0); // Success
    }

    // ---- Information-request handler (RFC 8415 §18.7) ---------------------

    fn handleInfoRequest(self: *Dhcpv6Server, message: []const u8, xid: u32) ?[]u8 {
        _ = message;
        return self.buildInfoReply(xid);
    }

    // ---- Address pool management ------------------------------------------

    /// Allocate a new address from the pool.
    fn allocateAddress(self: *Dhcpv6Server, client_duid: []const u8, iaid: u32) ?[16]u8 {
        // Check for existing lease from same client+IAID.
        for (self.leases.items) |*lease| {
            if (lease.client_duid_len == client_duid.len and
                mem.eql(u8, lease.client_duid[0..lease.client_duid_len], client_duid) and
                lease.iaid == iaid)
            {
                // Already have an address — extend.
                lease.created = std.time.milliTimestamp();
                lease.confirmed = true;
                return lease.address;
            }
        }

        // Check if pool is full.
        if (self.leases.items.len >= MAX_LEASES) return null;

        // Find next available address.
        const now = std.time.milliTimestamp();
        const address = self.findAvailableAddress() orelse return null;

        var lease = Lease{
            .client_duid_len = @intCast(@min(client_duid.len, 20)),
            .iaid = iaid,
            .address = address,
            .preferred_lifetime = self.pool.preferred_lifetime,
            .valid_lifetime = self.pool.valid_lifetime,
            .created = now,
            .confirmed = true,
        };
        @memcpy(lease.client_duid[0..lease.client_duid_len], client_duid[0..lease.client_duid_len]);

        self.leases.append(self.allocator, lease) catch return null;
        self.total_assigned += 1;
        return address;
    }

    /// Find the next available address in the pool.
    fn findAvailableAddress(self: *Dhcpv6Server) ?[16]u8 {
        const now = std.time.milliTimestamp();
        var id = self.next_id;

        while (true) {
            const addr = self.idToAddress(id);

            // Check if this address is already leased and not expired.
            var taken = false;
            for (self.leases.items) |*lease| {
                if (mem.eql(u8, &lease.address, &addr)) {
                    const expires = lease.created + @as(i64, lease.valid_lifetime) * 1000;
                    if (expires > now) {
                        taken = true;
                        break;
                    }
                }
            }

            if (!taken) {
                self.next_id = id +% 1;
                if (self.next_id > self.pool.last_interface_id) {
                    self.next_id = self.pool.first_interface_id;
                }
                return addr;
            }

            id +%= 1;
            if (id > self.pool.last_interface_id) {
                id = self.pool.first_interface_id;
            }

            // Full loop — no addresses available.
            if (id == self.next_id) return null;
        }
    }

    /// Convert an interface ID to a full IPv6 address.
    fn idToAddress(self: *const Dhcpv6Server, id: u16) [16]u8 {
        var addr: [16]u8 = self.pool.prefix;
        // Interface ID goes into bytes 14..16 (the last 2 bytes of a /64).
        addr[14] = @intCast((id >> 8) & 0xFF);
        addr[15] = @intCast(id & 0xFF);
        return addr;
    }

    /// Confirm an existing lease or assign a new address.
    fn confirmOrAssign(self: *Dhcpv6Server, client_duid: []const u8, iaid: u32, requested: [16]u8) ?[16]u8 {
        const now = std.time.milliTimestamp();

        // Look for existing lease.
        for (self.leases.items) |*lease| {
            if (lease.client_duid_len == client_duid.len and
                mem.eql(u8, lease.client_duid[0..lease.client_duid_len], client_duid) and
                lease.iaid == iaid and
                mem.eql(u8, &lease.address, &requested))
            {
                const expires = lease.created + @as(i64, lease.valid_lifetime) * 1000;
                if (expires > now) {
                    lease.created = now;
                    lease.confirmed = true;
                    return lease.address;
                }
            }
        }

        // Not found — try to allocate the requested address if it's in our pool.
        const prefix_match = mem.eql(u8, requested[0..8], self.pool.prefix[0..8]);
        if (prefix_match) {
            // Check if the specific address is available.
            for (self.leases.items) |*lease| {
                if (mem.eql(u8, &lease.address, &requested)) {
                    const expires = lease.created + @as(i64, lease.valid_lifetime) * 1000;
                    if (expires > now) return null; // taken by another client
                }
            }

            // Assign the requested address.
            var lease = Lease{
                .client_duid_len = @intCast(@min(client_duid.len, 20)),
                .iaid = iaid,
                .address = requested,
                .preferred_lifetime = self.pool.preferred_lifetime,
                .valid_lifetime = self.pool.valid_lifetime,
                .created = now,
                .confirmed = true,
            };
            @memcpy(lease.client_duid[0..lease.client_duid_len], client_duid[0..lease.client_duid_len]);
            self.leases.append(self.allocator, lease) catch return null;
            self.total_assigned += 1;
            return requested;
        }

        // Pool prefix doesn't match — allocate from pool instead.
        return self.allocateAddress(client_duid, iaid);
    }

    fn isLeaseValid(self: *const Dhcpv6Server, client_duid: []const u8, iaid: u32, addr: [16]u8) bool {
        const now = std.time.milliTimestamp();
        for (self.leases.items) |*lease| {
            if (lease.client_duid_len == client_duid.len and
                mem.eql(u8, lease.client_duid[0..lease.client_duid_len], client_duid) and
                lease.iaid == iaid and
                mem.eql(u8, &lease.address, &addr))
            {
                const expires = lease.created + @as(i64, lease.valid_lifetime) * 1000;
                return expires > now;
            }
        }
        return false;
    }

    fn renewLease(self: *Dhcpv6Server, client_duid: []const u8, iaid: u32, addr: [16]u8) bool {
        const now = std.time.milliTimestamp();
        for (self.leases.items) |*lease| {
            if (lease.client_duid_len == client_duid.len and
                mem.eql(u8, lease.client_duid[0..lease.client_duid_len], client_duid) and
                lease.iaid == iaid and
                mem.eql(u8, &lease.address, &addr))
            {
                const expires = lease.created + @as(i64, lease.valid_lifetime) * 1000;
                if (expires > now) {
                    lease.created = now;
                    lease.confirmed = true;
                    return true;
                }
            }
        }
        return false;
    }

    fn releaseLease(self: *Dhcpv6Server, client_duid: []const u8, iaid: u32, addr: ?[16]u8) void {
        var i: usize = 0;
        while (i < self.leases.items.len) {
            const lease = &self.leases.items[i];
            const match_uid = lease.client_duid_len == client_duid.len and
                mem.eql(u8, lease.client_duid[0..lease.client_duid_len], client_duid);
            const match_iaid = lease.iaid == iaid;
            const match_addr = if (addr) |a| mem.eql(u8, &lease.address, &a) else true;

            if (match_uid and match_iaid and match_addr) {
                _ = self.leases.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Expire old leases. Returns how many were removed.
    pub fn sweep(self: *Dhcpv6Server) usize {
        const now = std.time.milliTimestamp();
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.leases.items.len) {
            const expires = self.leases.items[i].created + @as(i64, self.leases.items[i].valid_lifetime) * 1000;
            if (expires <= now) {
                _ = self.leases.swapRemove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }

    // ---- Response builders -------------------------------------------------

    fn buildAdvertise(self: *const Dhcpv6Server, xid: u32, client_duid: []const u8, iaid: u32, address: [16]u8) []u8 {
        var buf: [512]u8 = undefined;
        var pos: usize = 0;

        // Message type: Advertise (2).
        buf[0] = 2;
        // Transaction ID (3 bytes).
        buf[1] = @intCast((xid >> 16) & 0xFF);
        buf[2] = @intCast((xid >> 8) & 0xFF);
        buf[3] = @intCast(xid & 0xFF);
        pos = 4;

        // Server ID (option 2).
        pos = writeOptionHeader(&buf, pos, 2, 14);
        @memcpy(buf[pos..][0..14], &self.server_duid.bytes);
        pos += 14;

        // Client ID (option 1) — echo back.
        if (client_duid.len > 0 and client_duid.len <= 251) {
            pos = writeOptionHeader(&buf, pos, 1, @intCast(client_duid.len));
            @memcpy(buf[pos..][0..client_duid.len], client_duid);
            pos += client_duid.len;
        }

        // IA_NA (option 3) with IAADDR sub-option (option 5).
        pos = self.buildIaNaOption(&buf, pos, iaid, address);

        // Preference (option 7) = 255 (preferred server).
        pos = writeOptionHeader(&buf, pos, 7, 1);
        buf[pos] = 255;
        pos += 1;

        // DNS servers (option 23).
        pos = writeOptionHeader(&buf, pos, 23, 32);
        @memcpy(buf[pos..][0..16], &DEFAULT_DNS);
        @memcpy(buf[pos..][16..32], &DEFAULT_DNS2);
        pos += 32;

        return self.allocator.dupe(u8, buf[0..pos]) catch return &.{};
    }

    fn buildReply(self: *const Dhcpv6Server, xid: u32, client_duid: []const u8, iaid: u32, address: [16]u8) []u8 {
        var buf: [512]u8 = undefined;
        var pos: usize = 0;

        // Message type: Reply (7).
        buf[0] = 7;
        buf[1] = @intCast((xid >> 16) & 0xFF);
        buf[2] = @intCast((xid >> 8) & 0xFF);
        buf[3] = @intCast(xid & 0xFF);
        pos = 4;

        // Server ID.
        pos = writeOptionHeader(&buf, pos, 2, 14);
        @memcpy(buf[pos..][0..14], &self.server_duid.bytes);
        pos += 14;

        // Client ID — echo back.
        if (client_duid.len > 0 and client_duid.len <= 251) {
            pos = writeOptionHeader(&buf, pos, 1, @intCast(client_duid.len));
            @memcpy(buf[pos..][0..client_duid.len], client_duid);
            pos += client_duid.len;
        }

        // IA_NA with IAADDR.
        pos = self.buildIaNaOption(&buf, pos, iaid, address);

        // DNS servers.
        pos = writeOptionHeader(&buf, pos, 23, 32);
        @memcpy(buf[pos..][0..16], &DEFAULT_DNS);
        @memcpy(buf[pos..][16..32], &DEFAULT_DNS2);
        pos += 32;

        return self.allocator.dupe(u8, buf[0..pos]) catch return &.{};
    }

    fn buildStatusReply(self: *const Dhcpv6Server, xid: u32, status: u16) []u8 {
        var buf: [64]u8 = undefined;
        var pos: usize = 0;

        buf[0] = 7; // Reply
        buf[1] = @intCast((xid >> 16) & 0xFF);
        buf[2] = @intCast((xid >> 8) & 0xFF);
        buf[3] = @intCast(xid & 0xFF);
        pos = 4;

        // Status Code option (13): 2-byte status + optional message.
        pos = writeOptionHeader(&buf, pos, 13, 2);
        buf[pos] = @intCast((status >> 8) & 0xFF);
        buf[pos + 1] = @intCast(status & 0xFF);
        pos += 2;

        return self.allocator.dupe(u8, buf[0..pos]) catch return &.{};
    }

    fn buildInfoReply(self: *const Dhcpv6Server, xid: u32) []u8 {
        var buf: [128]u8 = undefined;
        var pos: usize = 0;

        buf[0] = 7; // Reply
        buf[1] = @intCast((xid >> 16) & 0xFF);
        buf[2] = @intCast((xid >> 8) & 0xFF);
        buf[3] = @intCast(xid & 0xFF);
        pos = 4;

        // Server ID.
        pos = writeOptionHeader(&buf, pos, 2, 14);
        @memcpy(buf[pos..][0..14], &self.server_duid.bytes);
        pos += 14;

        // DNS servers.
        pos = writeOptionHeader(&buf, pos, 23, 32);
        @memcpy(buf[pos..][0..16], &DEFAULT_DNS);
        @memcpy(buf[pos..][16..32], &DEFAULT_DNS2);
        pos += 32;

        return self.allocator.dupe(u8, buf[0..pos]) catch return &.{};
    }

    fn buildIaNaOption(self: *const Dhcpv6Server, buf: []u8, pos: usize, iaid: u32, address: [16]u8) usize {
        const ia_na_start = pos;
        // Reserve option header (4 bytes).
        var p = pos + 4;

        // IAID (4 bytes).
        mem.writeInt(u32, buf[p..][0..4], iaid, .big);
        p += 4;
        // T1 (preferred lifetime, 4 bytes).
        mem.writeInt(u32, buf[p..][0..4], self.pool.preferred_lifetime, .big);
        p += 4;
        // T2 (valid lifetime, 4 bytes).
        mem.writeInt(u32, buf[p..][0..4], self.pool.valid_lifetime, .big);
        p += 4;

        // IAADDR sub-option (option 5).
        const iaaddr_start = p;
        p += 4; // reserve header
        @memcpy(buf[p..][0..16], &address);
        p += 16;
        // Preferred lifetime.
        mem.writeInt(u32, buf[p..][0..4], self.pool.preferred_lifetime, .big);
        p += 4;
        // Valid lifetime.
        mem.writeInt(u32, buf[p..][0..4], self.pool.valid_lifetime, .big);
        p += 4;

        // Backfill IAADDR header.
        writeOptionHeaderAt(buf, ia_na_start, 3, @intCast(p - ia_na_start - 4)); // IA_NA length
        writeOptionHeaderAt(buf, iaaddr_start, 5, @intCast(p - iaaddr_start - 4)); // IAADDR length

        return p;
    }
};

// ============================================================================
// Wire format helpers (shared with client)
// ============================================================================

fn writeOptionHeader(buffer: []u8, pos: usize, code: u16, length: u16) usize {
    buffer[pos] = @intCast((code >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(code & 0xFF);
    buffer[pos + 2] = @intCast((length >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(length & 0xFF);
    return pos + 4;
}

fn writeOptionHeaderAt(buffer: []u8, pos: usize, code: u16, length: u16) void {
    buffer[pos] = @intCast((code >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(code & 0xFF);
    buffer[pos + 2] = @intCast((length >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(length & 0xFF);
}

// ============================================================================
// Option parsing
// ============================================================================

/// Parse a DHCPv6 option by code from the options buffer. Returns the option
/// data (without the 4-byte header), or null if not found.
fn parseOption(options: []const u8, code: u16) ?[]const u8 {
    var pos: usize = 0;
    while (pos + 4 <= options.len) {
        const opt_code = mem.readInt(u16, options[pos..][0..2], .big);
        const opt_len = mem.readInt(u16, options[pos + 2 ..][0..2], .big);
        if (pos + 4 + opt_len > options.len) return null;
        if (opt_code == code) return options[pos + 4 ..][0..opt_len];
        pos += 4 + opt_len;
    }
    return null;
}

/// Check if an option with the given code exists in the options buffer.
fn hasOption(options: []const u8, code: u16) bool {
    return parseOption(options, code) != null;
}

/// Parse the IAADDR sub-option (option 5) from within an IA_NA option.
/// Returns the 16-byte IPv6 address, or null if not found.
fn parseIaAddr(ia_na_data: []const u8) ?[16]u8 {
    var pos: usize = 0;
    while (pos + 4 <= ia_na_data.len) {
        const opt_code = mem.readInt(u16, ia_na_data[pos..][0..2], .big);
        const opt_len = mem.readInt(u16, ia_na_data[pos + 2 ..][0..2], .big);
        if (pos + 4 + opt_len > ia_na_data.len) return null;
        if (opt_code == 5 and opt_len >= 16) { // IAADDR
            var addr: [16]u8 = undefined;
            @memcpy(&addr, ia_na_data[pos + 4 ..][0..16]);
            return addr;
        }
        pos += 4 + opt_len;
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

const log = std.log.scoped(.dhcpv6_server);

test "Dhcpv6Server init creates DUID from MAC" {
    const mac = [6]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    var server = Dhcpv6Server.init(testing.allocator, mac, .{});
    defer server.deinit();

    // DUID type = 2 (LLT).
    try testing.expectEqual(@as(u8, 0), server.server_duid.bytes[0]);
    try testing.expectEqual(@as(u8, 2), server.server_duid.bytes[1]);
    // HW type = 1 (Ethernet).
    try testing.expectEqual(@as(u8, 0), server.server_duid.bytes[2]);
    try testing.expectEqual(@as(u8, 1), server.server_duid.bytes[3]);
    // MAC at offset 8.
    try testing.expectEqual(@as(u8, 0x02), server.server_duid.bytes[8]);
    try testing.expectEqual(@as(u8, 0x33), server.server_duid.bytes[13]);
}

test "Dhcpv6Server allocateAddress assigns from pool" {
    var server = Dhcpv6Server.init(testing.allocator, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{
        .prefix = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .first_interface_id = 1,
        .last_interface_id = 5,
    });
    defer server.deinit();

    const duid = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 };
    const addr1 = server.allocateAddress(&duid, 1);
    try testing.expect(addr1 != null);
    try testing.expectEqual(@as(u8, 0x20), addr1.?[0]);
    try testing.expectEqual(@as(u8, 0x01), addr1.?[1]);
    // Bytes 14-15 should be the interface ID (0x0001).
    try testing.expectEqual(@as(u8, 0x00), addr1.?[14]);
    try testing.expectEqual(@as(u8, 0x01), addr1.?[15]);
    try testing.expectEqual(@as(usize, 1), server.leases.items.len);
}

test "Dhcpv6Server reuse existing lease" {
    var server = Dhcpv6Server.init(testing.allocator, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{});
    defer server.deinit();

    const duid = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 };
    const addr1 = server.allocateAddress(&duid, 1);
    const addr2 = server.allocateAddress(&duid, 1);
    try testing.expect(addr1 != null and addr2 != null);
    try testing.expectEqualSlices(u8, &addr1.?, &addr2.?.*);
    try testing.expectEqual(@as(usize, 1), server.leases.items.len);
}

test "Dhcpv6Server pool exhaustion" {
    var server = Dhcpv6Server.init(testing.allocator, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{
        .first_interface_id = 1,
        .last_interface_id = 2,
    });
    defer server.deinit();

    const duid1 = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x01 };
    const duid2 = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x02 };
    const duid3 = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x03 };

    try testing.expect(server.allocateAddress(&duid1, 1) != null);
    try testing.expect(server.allocateAddress(&duid2, 2) != null);
    try testing.expect(server.allocateAddress(&duid3, 3) == null); // pool exhausted
}

test "Dhcpv6Server sweep removes expired leases" {
    var server = Dhcpv6Server.init(testing.allocator, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{
        .valid_lifetime = 0, // expires immediately
    });
    defer server.deinit();

    const duid = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 };
    _ = server.allocateAddress(&duid, 1);
    try testing.expectEqual(@as(usize, 1), server.leases.items.len);

    // Force the lease to be expired by backdating created time.
    server.leases.items[0].created = 0;
    const removed = server.sweep();
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expectEqual(@as(usize, 0), server.leases.items.len);
}

test "Dhcpv6Server handleMessage Solicit returns Advertise" {
    var server = Dhcpv6Server.init(testing.allocator, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{});
    defer server.deinit();

    // Build a minimal Solicit message: type=1, XID=0x123456, Client ID option.
    var msg: [64]u8 = .{0};
    msg[0] = 1; // Solicit
    msg[1] = 0x12; // XID
    msg[2] = 0x34;
    msg[3] = 0x56;

    // Client ID (option 1, length 14).
    msg[4] = 0x00;
    msg[5] = 1;
    msg[6] = 0x00;
    msg[7] = 14;
    @memcpy(msg[8..22], &[_]u8{ 0x00, 0x02, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44 });

    // IA_NA (option 3, length 4).
    msg[22] = 0x00;
    msg[23] = 3;
    msg[24] = 0x00;
    msg[25] = 4;
    msg[26] = 0x00; // IAID
    msg[27] = 0x00;
    msg[28] = 0x00;
    msg[29] = 0x01;

    const response = server.handleMessage(&msg);
    try testing.expect(response != null);
    defer server.allocator.free(response.?);

    // Response should be Advertise (type 2).
    try testing.expectEqual(@as(u8, 2), response.?[0]);
    // XID should match.
    try testing.expectEqual(@as(u8, 0x12), response.?[1]);
    try testing.expectEqual(@as(u8, 0x34), response.?[2]);
    try testing.expectEqual(@as(u8, 0x56), response.?[3]);
    // Lease should be created.
    try testing.expectEqual(@as(usize, 1), server.leases.items.len);
}

test "Dhcpv6Server handleMessage ignores unknown types" {
    var server = Dhcpv6Server.init(testing.allocator, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, .{});
    defer server.deinit();

    // Reconfigure (type 10) — should be ignored.
    const msg = [_]u8{ 10, 0x00, 0x00, 0x01 };
    try testing.expect(server.handleMessage(&msg) == null);
}

test "parseOption finds and returns option data" {
    var opts: [32]u8 = .{0};
    // Option code=1, length=2, data=0xAB,0xCD.
    opts[0] = 0x00;
    opts[1] = 1;
    opts[2] = 0x00;
    opts[3] = 2;
    opts[4] = 0xAB;
    opts[5] = 0xCD;

    const found = parseOption(&opts, 1);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u8, 0xAB), found.?[0]);
    try testing.expectEqual(@as(u8, 0xCD), found.?[1]);
    try testing.expect(parseOption(&opts, 2) == null);
}

test "parseIaAddr extracts IPv6 address from IA_NA sub-options" {
    var ia_na: [28]u8 = .{0};
    // IAADDR sub-option: code=5, length=24 (16 addr + 4 pref + 4 valid).
    ia_na[0] = 0x00;
    ia_na[1] = 5;
    ia_na[2] = 0x00;
    ia_na[3] = 24;
    ia_na[4] = 0x20; // address[0]
    ia_na[5] = 0x01; // address[1]

    const addr = parseIaAddr(&ia_na);
    try testing.expect(addr != null);
    try testing.expectEqual(@as(u8, 0x20), addr.?[0]);
    try testing.expectEqual(@as(u8, 0x01), addr.?[1]);
}

test "writeOptionHeader writes big-endian code and length" {
    var buf: [8]u8 = .{0};
    const pos = writeOptionHeader(&buf, 0, 23, 16);
    try testing.expectEqual(@as(usize, 4), pos);
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
    try testing.expectEqual(@as(u8, 23), buf[1]);
    try testing.expectEqual(@as(u8, 0x00), buf[2]);
    try testing.expectEqual(@as(u8, 16), buf[3]);
}

test "hasOption detects presence of option" {
    var opts: [8]u8 = .{0};
    opts[0] = 0x00;
    opts[1] = 14; // Rapid Commit
    opts[2] = 0x00;
    opts[3] = 0;
    try testing.expect(hasOption(&opts, 14));
    try testing.expect(!hasOption(&opts, 6));
}
