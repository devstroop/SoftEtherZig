//! Virtual DHCP server — lease table + DISCOVER/OFFER/REQUEST/ACK.
//!
//! C reference: `VirtualDhcpServer` / `ServeDhcpDiscover` / `ServeDhcpRequest`
//! (Virtual.c:9399). The server listens on UDP port 67, allocates IPs from a
//! configured range, and responds with OFFER/ACK/NAK.
//!
//! This module owns the lease table and IP allocation logic. It does NOT own
//! the UDP socket — callers feed raw DHCP frames in and receive response
//! frames to transmit.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

// ============================================================================
// Constants (duplicated from adapter/dhcp.zig to keep this module self-contained)
// ============================================================================

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

pub const DHCP_MAGIC: u32 = 0x63825363;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_HEADER_SIZE: usize = 236;

/// Default lease time in seconds (C: `DHCP_DEFAULT_LEASE_TIME`).
pub const DEFAULT_LEASE_SECONDS: u32 = 3600;
/// Lease polling interval in milliseconds (C: `DHCP_POLLING_INTERVAL`).
pub const POLLING_INTERVAL_MS: i64 = 1000;
/// Hostname prefix used to detect self-loop packets (C: `NN_HOSTNAME_STARTWITH`).
pub const SELF_LOOP_PREFIX_1 = "securenat-";
pub const SELF_LOOP_PREFIX_2 = "securenat_";

// ============================================================================
// Types
// ============================================================================

/// A single DHCP lease (C: `DHCP_LEASE`).
pub const Lease = struct {
    /// Monotonically increasing lease ID (C: `d->Id`).
    id: u32,
    /// Wall-clock time (ms) when the lease was created (C: `d->LeasedTime`).
    leased_time: i64,
    /// Wall-clock time (ms) when the lease expires; 0 = infinite (C: `d->ExpireTime`).
    expire_time: i64,
    /// Client hardware (MAC) address.
    mac: [6]u8,
    /// Assigned IPv4 address (host byte order).
    ip: u32,
    /// Subnet mask (host byte order).
    mask: u32,
    /// Client hostname (owned slice, may be empty).
    hostname: []u8,
};

/// Server configuration — maps to `VH` DHCP fields (C: `Virtual.h`).
pub const Config = struct {
    /// Enable the DHCP server.
    enabled: bool = false,
    /// Server's own IP (used as DHCP server identifier / siaddr).
    host_ip: u32 = 0,
    /// Start of distributable IP range (host byte order).
    ip_start: u32 = 0,
    /// End of distributable IP range (host byte order).
    ip_end: u32 = 0,
    /// Subnet mask handed to clients.
    subnet_mask: u32 = 0,
    /// Default gateway handed to clients.
    gateway: u32 = 0,
    /// Primary DNS server.
    dns1: u32 = 0,
    /// Secondary DNS server.
    dns2: u32 = 0,
    /// Lease duration in seconds (0 = infinite).
    lease_time: u32 = DEFAULT_LEASE_SECONDS,
    /// Domain name (null-terminated if set).
    domain_name: [128:0]u8 = .{0} ** 128,
};

/// Parsed options from a client DHCP request.
pub const ClientOptions = struct {
    /// DHCP message type (DISCOVER=1, REQUEST=3, INFORM=8).
    msg_type: DhcpMessageType = .discover,
    /// Client-requested IP (from option 50), 0 if not present.
    requested_ip: u32 = 0,
    /// Server identifier the client is responding to (option 54), 0 if not present.
    server_id: u32 = 0,
};

/// A response frame to transmit. `frame` is an Ethernet frame.
pub const DhcpResponse = struct {
    frame: [1024]u8 = undefined,
    len: usize = 0,
};

/// The DHCP server state.
pub const DhcpServer = struct {
    allocator: Allocator,
    config: Config,
    /// Lease table (sorted by MAC for binary search).
    leases: ArrayList(Lease),
    /// Next lease ID (monotonic).
    next_id: u32 = 1,

    pub fn init(allocator: Allocator, config: Config) DhcpServer {
        return .{
            .allocator = allocator,
            .config = config,
            .leases = .{},
        };
    }

    pub fn deinit(self: *DhcpServer) void {
        for (self.leases.items) |*l| {
            self.allocator.free(l.hostname);
        }
        self.leases.deinit(self.allocator);
    }

    // ---- Main entry point --------------------------------------------------

    /// Process an incoming DHCP frame and return a response frame (or null if
    /// no response is needed).
    ///
    /// `frame` must be a full Ethernet frame containing a DHCP/UDP/IPv4
    /// payload. Returns an Ethernet frame ready to transmit.
    pub fn handleFrame(self: *DhcpServer, frame: []const u8, now: i64) ?DhcpResponse {
        if (!self.config.enabled) return null;

        // 1. Parse the incoming packet.
        const pkt = parseIncoming(frame) orelse return null;

        // 2. Self-loop guard.
        if (pkt.hostname_len > 0) {
            if (hasPrefix(pkt.hostname[0..pkt.hostname_len], SELF_LOOP_PREFIX_1) or
                hasPrefix(pkt.hostname[0..pkt.hostname_len], SELF_LOOP_PREFIX_2))
            {
                return null;
            }
        }

        // 3. Age expired leases.
        self.ageLeases(now);

        // 4. Dispatch on message type.
        switch (pkt.options.msg_type) {
            .discover => {
                // DISCOVER: client has no IP yet, always broadcast.
                const ip = self.allocateIp(pkt.mac, pkt.options.requested_ip);
                if (ip == 0) return null;
                return self.buildResponse(.offer, ip, &pkt, true);
            },
            .request => {
                // RFC 2131 §4.4.2: if the client includes a server identifier
                // option and it doesn't match this server, ignore the packet.
                if (pkt.options.server_id != 0 and pkt.options.server_id != self.config.host_ip) {
                    return null;
                }
                const ip = self.allocateIp(pkt.mac, pkt.options.requested_ip);
                if (ip == 0) {
                    return self.buildNak(&pkt);
                }
                // For REQUEST, the assigned IP must match the request exactly
                // (C: ServeDhcpRequest returns 0 if mismatch).
                if (pkt.options.requested_ip != 0 and ip != pkt.options.requested_ip) {
                    return self.buildNak(&pkt);
                }
                self.createLease(pkt.mac, ip, pkt.hostname[0..pkt.hostname_len], now);
                // Unicast if client has a usable ciaddr, else broadcast.
                const use_unicast = pkt.ciaddr != 0;
                return self.buildResponse(.ack, ip, &pkt, !use_unicast);
            },
            .inform => {
                // INFORM — client already has an IP, just wants config params.
                if (pkt.ciaddr == 0) return null;
                // Unicast to the client's known IP.
                return self.buildResponse(.ack, pkt.ciaddr, &pkt, false);
            },
            else => return null,
        }
    }

    // ---- IP allocation -----------------------------------------------------

    /// Allocate an IP for the given MAC. Returns 0 on failure.
    fn allocateIp(self: *DhcpServer, mac: [6]u8, requested_ip: u32) u32 {
        // 1. Check existing lease for this MAC.
        if (self.findLeaseByMac(mac)) |lease| {
            if (requested_ip == 0) {
                if (self.ipInRange(lease.ip)) return lease.ip;
            } else if (requested_ip == lease.ip) {
                return lease.ip;
            }
        }

        // 2. If a specific IP was requested and it's free + in range, use it.
        if (requested_ip != 0) {
            if (self.ipInRange(requested_ip) and self.findLeaseByIp(requested_ip) == null) {
                return requested_ip;
            }
        }

        // 3. Allocate first free IP in range.
        return self.findFreeIp();
    }

    /// Find the first unleased IP in the configured range.
    fn findFreeIp(self: *DhcpServer) u32 {
        const start = self.config.ip_start;
        const end = self.config.ip_end;
        if (start == 0 or end == 0 or start > end) return 0;

        var ip = start;
        while (ip <= end) : (ip += 1) {
            if (self.findLeaseByIp(ip) == null) return ip;
        }
        return 0; // Pool exhausted.
    }

    fn ipInRange(self: *DhcpServer, ip: u32) bool {
        return ip >= self.config.ip_start and ip <= self.config.ip_end;
    }

    // ---- Lease management --------------------------------------------------

    /// Create a new lease record and add it to the table.
    fn createLease(self: *DhcpServer, mac: [6]u8, ip: u32, hostname: []const u8, now: i64) void {
        // Remove any existing lease for this IP.
        if (self.findLeaseByIp(ip)) |idx| {
            const old = self.leases.orderedRemove(idx);
            self.allocator.free(old.hostname);
        }

        // Remove any existing lease for this MAC.
        if (self.findLeaseByMacIdx(mac)) |idx| {
            const old = self.leases.orderedRemove(idx);
            self.allocator.free(old.hostname);
        }

        const lease_time_ms: i64 = if (self.config.lease_time == 0)
            0 // infinite
        else
            @as(i64, self.config.lease_time) * 1000;

        const lease = Lease{
            .id = self.next_id,
            .leased_time = now,
            .expire_time = if (lease_time_ms == 0) 0 else now + lease_time_ms,
            .mac = mac,
            .ip = ip,
            .mask = self.config.subnet_mask,
            .hostname = self.allocator.dupe(u8, hostname) catch &.{},
        };

        self.next_id +|= 1;
        // Insert maintaining MAC-sorted order.
        const idx = self.lowerBoundMac(mac);
        self.leases.insert(self.allocator, idx, lease) catch return;
    }

    /// Remove expired leases.
    fn ageLeases(self: *DhcpServer, now: i64) void {
        var i: usize = 0;
        while (i < self.leases.items.len) {
            const l = self.leases.items[i];
            if (l.expire_time != 0 and l.expire_time < now) {
                const removed = self.leases.orderedRemove(i);
                self.allocator.free(removed.hostname);
            } else {
                i += 1;
            }
        }
    }

    fn findLeaseByMac(self: *DhcpServer, mac: [6]u8) ?Lease {
        const idx = self.lowerBoundMac(mac);
        if (idx < self.leases.items.len and mem.eql(u8, &self.leases.items[idx].mac, &mac)) {
            return self.leases.items[idx];
        }
        return null;
    }

    fn findLeaseByMacIdx(self: *DhcpServer, mac: [6]u8) ?usize {
        const idx = self.lowerBoundMac(mac);
        if (idx < self.leases.items.len and mem.eql(u8, &self.leases.items[idx].mac, &mac)) {
            return idx;
        }
        return null;
    }

    fn findLeaseByIp(self: *DhcpServer, ip: u32) ?usize {
        for (self.leases.items, 0..) |l, i| {
            if (l.ip == ip) return i;
        }
        return null;
    }

    /// Binary-search lower bound by MAC.
    fn lowerBoundMac(self: *DhcpServer, mac: [6]u8) usize {
        var lo: usize = 0;
        var hi: usize = self.leases.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (mem.order(u8, &self.leases.items[mid].mac, &mac) == .lt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    // ---- Response builders -------------------------------------------------

    /// Build a DHCP OFFER or ACK response frame.
    fn buildResponse(
        self: *DhcpServer,
        msg_type: DhcpMessageType,
        assigned_ip: u32,
        pkt: *const IncomingPacket,
        broadcast: bool,
    ) DhcpResponse {
        var opt_buf: [256]u8 = undefined;
        var opt_len: usize = 0;

        // Message type option.
        opt_len = writeOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.message_type), &.{@intFromEnum(msg_type)});
        // Server identifier.
        opt_len = writeIpOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.server_identifier), self.config.host_ip);
        // Lease time (seconds, big-endian).
        if (self.config.lease_time != 0) {
            const lt = [_]u8{ @intCast((self.config.lease_time >> 24) & 0xFF), @intCast((self.config.lease_time >> 16) & 0xFF), @intCast((self.config.lease_time >> 8) & 0xFF), @intCast(self.config.lease_time & 0xFF) };
            opt_len = writeOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.lease_time), &lt);
        }
        // Subnet mask.
        if (self.config.subnet_mask != 0) {
            opt_len = writeIpOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.subnet_mask), self.config.subnet_mask);
        }
        // Default gateway.
        if (self.config.gateway != 0) {
            opt_len = writeIpOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.router), self.config.gateway);
        }
        // DNS servers.
        if (self.config.dns1 != 0 or self.config.dns2 != 0) {
            var dns: [8]u8 = undefined;
            writeIpBytes(&dns, 0, self.config.dns1);
            writeIpBytes(&dns, 4, self.config.dns2);
            opt_len = writeOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.dns_server), &dns);
        }
        // Domain name.
        const domain_len = mem.indexOfScalar(u8, &self.config.domain_name, 0) orelse 0;
        if (domain_len > 0 and self.config.dns1 != 0) {
            opt_len = writeOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.domain_name), self.config.domain_name[0..domain_len]);
        }
        // End option.
        if (opt_len < opt_buf.len) {
            opt_buf[opt_len] = @intFromEnum(DhcpOption.end_option);
            opt_len += 1;
        }

        // Build the full response frame directly into the response struct.
        var resp = DhcpResponse{};
        resp.len = buildDhcpFrame(
            &resp.frame,
            self.config.host_ip,
            assigned_ip,
            pkt.client_mac,
            pkt.xid,
            pkt.client_hw_type,
            pkt.client_hw_addr_size,
            opt_buf[0..opt_len],
            pkt.src_ip,
            broadcast,
        );
        return resp;
    }

    /// Build a DHCP NACK response frame.
    fn buildNak(self: *DhcpServer, pkt: *const IncomingPacket) DhcpResponse {
        var opt_buf: [64]u8 = undefined;
        var opt_len: usize = 0;

        // Message type = NACK.
        opt_len = writeOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.message_type), &.{@intFromEnum(DhcpMessageType.nak)});
        // Server identifier.
        opt_len = writeIpOption(&opt_buf, opt_len, @intFromEnum(DhcpOption.server_identifier), self.config.host_ip);
        // End.
        if (opt_len < opt_buf.len) {
            opt_buf[opt_len] = @intFromEnum(DhcpOption.end_option);
            opt_len += 1;
        }

        var resp = DhcpResponse{};
        resp.len = buildDhcpFrame(
            &resp.frame,
            self.config.host_ip,
            0, // yiaddr = 0 for NACK
            pkt.client_mac,
            pkt.xid,
            pkt.client_hw_type,
            pkt.client_hw_addr_size,
            opt_buf[0..opt_len],
            pkt.src_ip,
            true, // NACK is always broadcast
        );
        return resp;
    }
};

// ============================================================================
// Incoming packet parsing
// ============================================================================

const IncomingPacket = struct {
    mac: [6]u8, // Ethernet source MAC
    client_mac: [6]u8, // DHCP chaddr
    xid: u32,
    ciaddr: u32,
    src_ip: u32,
    client_hw_type: u8,
    client_hw_addr_size: u8,
    options: ClientOptions,
    hostname: [256:0]u8 = .{0} ** 256,
    hostname_len: u8 = 0,
};

/// Parse an incoming Ethernet frame containing a DHCP packet.
/// Returns null if the frame is not a valid DHCP client request.
fn parseIncoming(frame: []const u8) ?IncomingPacket {
    // Ethernet header: 14 bytes minimum.
    if (frame.len < 14) return null;

    // Check EtherType = IPv4 (0x0800).
    if (frame[12] != 0x08 or frame[13] != 0x00) return null;

    // Extract source MAC.
    var src_mac: [6]u8 = undefined;
    @memcpy(&src_mac, frame[6..12]);

    // IPv4 header.
    const ip_start: usize = 14;
    if (frame.len < ip_start + 20) return null;
    const ihl: usize = @as(usize, frame[ip_start] & 0x0F) * 4;
    if (frame.len < ip_start + ihl) return null;

    // Check UDP protocol.
    if (frame[ip_start + 9] != 17) return null;

    const src_ip = ip32(frame[ip_start + 12 ..][0..4]);

    // UDP header.
    const udp_start = ip_start + ihl;
    if (frame.len < udp_start + 8) return null;
    const src_port = (@as(u16, frame[udp_start]) << 8) | frame[udp_start + 1];
    const dst_port = (@as(u16, frame[udp_start + 2]) << 8) | frame[udp_start + 3];

    // Must be to server port 67.
    if (dst_port != DHCP_SERVER_PORT) return null;
    // Must be from client port 68 (or 68 for relayed).
    if (src_port != DHCP_CLIENT_PORT and src_port != DHCP_SERVER_PORT) return null;

    // DHCP header starts after UDP header.
    const dhcp_start = udp_start + 8;
    if (frame.len < dhcp_start + DHCP_HEADER_SIZE) return null;

    // BOOTREQUEST = 1.
    if (frame[dhcp_start] != 1) return null;

    // Hardware type and address size.
    const hw_type = frame[dhcp_start + 1];
    var hw_addr_size = frame[dhcp_start + 2];
    if (hw_addr_size > 16) return null;
    // Ethernet only (RFC 2131: hlen=6 for Ethernet). Cap to 6 for safe MAC copy.
    if (hw_addr_size > 6) hw_addr_size = 6;

    // Transaction ID.
    const xid = (@as(u32, frame[dhcp_start + 4]) << 24) |
        (@as(u32, frame[dhcp_start + 5]) << 16) |
        (@as(u32, frame[dhcp_start + 6]) << 8) |
        frame[dhcp_start + 7];

    // Client IP address (ciaddr) at offset 8.
    const ciaddr = ip32(frame[dhcp_start + 8 ..][0..4]);

    // Client MAC from chaddr field (offset 24 per RFC 2131).
    var client_mac: [6]u8 = .{0} ** 6;
    const chaddr_offset = dhcp_start + 24;
    const copy_len = @min(@as(usize, hw_addr_size), @as(usize, 6));
    @memcpy(client_mac[0..copy_len], frame[chaddr_offset..][0..copy_len]);

    // Magic cookie at offset 232 (after 232-byte fixed header).
    const magic_pos = dhcp_start + 232;
    if (frame.len < magic_pos + 4) return null;
    const magic = (@as(u32, frame[magic_pos]) << 24) |
        (@as(u32, frame[magic_pos + 1]) << 16) |
        (@as(u32, frame[magic_pos + 2]) << 8) |
        frame[magic_pos + 3];
    if (magic != DHCP_MAGIC) return null;

    // Compute the DHCP payload end from the UDP length field (RFC 768).
    // UDP length includes the 8-byte UDP header.
    const udp_len = (@as(u16, frame[udp_start + 4]) << 8) | frame[udp_start + 5];
    const dhcp_payload_end = if (udp_len >= 8) dhcp_start + @as(usize, udp_len - 8) else frame.len;

    // Parse options — bounded by the declared UDP payload, not the raw frame.
    var options = ClientOptions{};
    var hostname_buf: [256:0]u8 = .{0} ** 256;
    var hostname_len: u8 = 0;

    var opt_pos = magic_pos + 4;
    while (opt_pos < dhcp_payload_end) {
        const opt_type = frame[opt_pos];
        if (opt_type == @intFromEnum(DhcpOption.end_option)) break;
        if (opt_type == @intFromEnum(DhcpOption.pad)) {
            opt_pos += 1;
            continue;
        }
        if (opt_pos + 1 >= dhcp_payload_end) break;
        const opt_len = frame[opt_pos + 1];
        if (opt_pos + 2 + @as(usize, opt_len) > dhcp_payload_end) break;

        const opt_data = frame[opt_pos + 2 ..][0..opt_len];

        if (opt_type == @intFromEnum(DhcpOption.message_type) and opt_len >= 1) {
            // Validate the message type before @enumFromInt to avoid safety traps.
            if (opt_data[0] >= @intFromEnum(DhcpMessageType.discover) and
                opt_data[0] <= @intFromEnum(DhcpMessageType.inform))
            {
                options.msg_type = @enumFromInt(opt_data[0]);
            }
        } else if (opt_type == @intFromEnum(DhcpOption.requested_ip) and opt_len >= 4) {
            options.requested_ip = ip32(opt_data[0..4]);
        } else if (opt_type == @intFromEnum(DhcpOption.hostname)) {
            const copy = @min(@as(usize, opt_len), @as(usize, 255));
            @memcpy(hostname_buf[0..copy], opt_data[0..copy]);
            hostname_len = @intCast(copy);
        } else if (opt_type == @intFromEnum(DhcpOption.server_identifier) and opt_len >= 4) {
            options.server_id = ip32(opt_data[0..4]);
        }

        opt_pos += 2 + @as(usize, opt_len);
    }

    return .{
        .mac = src_mac,
        .client_mac = client_mac,
        .xid = xid,
        .ciaddr = ciaddr,
        .src_ip = src_ip,
        .client_hw_type = hw_type,
        .client_hw_addr_size = hw_addr_size,
        .options = options,
        .hostname = hostname_buf,
        .hostname_len = hostname_len,
    };
}

// ============================================================================
// DHCP frame builder (server -> client)
// ============================================================================

/// Build a full Ethernet + IPv4 + UDP + DHCP response frame.
/// Returns the number of bytes written.
fn buildDhcpFrame(
    buf: *[1024]u8,
    server_ip: u32,
    yiaddr: u32,
    client_mac: [6]u8,
    xid: u32,
    hw_type: u8,
    hw_addr_size: u8,
    options: []const u8,
    dest_ip: u32,
    broadcast: bool,
) usize {
    var pos: usize = 0;

    // === Ethernet Header ===
    if (broadcast) {
        // Destination: broadcast.
        @memset(buf[pos..][0..6], 0xFF);
    } else {
        // Destination: unicast to client MAC.
        @memcpy(buf[pos..][0..6], &client_mac);
    }
    pos += 6;
    // Source: server MAC derived from server IP.
    buf[pos] = 0x00;
    buf[pos + 1] = 0xAC;
    buf[pos + 2] = @intCast((server_ip >> 24) & 0xFF);
    buf[pos + 3] = @intCast((server_ip >> 16) & 0xFF);
    buf[pos + 4] = @intCast((server_ip >> 8) & 0xFF);
    buf[pos + 5] = @intCast(server_ip & 0xFF);
    pos += 6;
    // EtherType: IPv4.
    buf[pos] = 0x08;
    buf[pos + 1] = 0x00;
    pos += 2;

    const ip_header_start = pos;

    // === IPv4 Header (20 bytes) ===
    buf[pos] = 0x45; // Version 4, IHL 5
    pos += 1;
    buf[pos] = 0x00; // DSCP/ECN
    pos += 1;
    const ip_len_pos = pos;
    pos += 2; // Total length -- fill later.
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    pos += 2; // ID
    buf[pos] = 0x40; // Flags: Don't Fragment
    buf[pos + 1] = 0x00;
    pos += 2;
    buf[pos] = 0x40; // TTL = 64
    pos += 1;
    buf[pos] = 17; // Protocol: UDP
    pos += 1;
    const ip_checksum_pos = pos;
    pos += 2; // Checksum -- fill later.
    // Source IP: server.
    writeIpBytes(buf, pos, server_ip);
    pos += 4;
    // Destination IP: use dest_ip if unicast, broadcast otherwise.
    if (broadcast or dest_ip == 0 or dest_ip == 0xFFFFFFFF) {
        @memset(buf[pos..][0..4], 0xFF);
    } else {
        writeIpBytes(buf, pos, dest_ip);
    }
    pos += 4;

    // === UDP Header (8 bytes) ===
    const udp_header_start = pos;
    buf[pos] = @intCast((DHCP_SERVER_PORT >> 8) & 0xFF);
    buf[pos + 1] = @intCast(DHCP_SERVER_PORT & 0xFF);
    pos += 2;
    buf[pos] = @intCast((DHCP_CLIENT_PORT >> 8) & 0xFF);
    buf[pos + 1] = @intCast(DHCP_CLIENT_PORT & 0xFF);
    pos += 2;
    const udp_len_pos = pos;
    pos += 2; // Length -- fill later.
    buf[pos] = 0x00;
    buf[pos + 1] = 0x00;
    pos += 2; // Checksum (0 = disabled).

    // === DHCP Header ===
    const dhcp_start = pos;
    buf[pos] = 2; // BOOTREPLY
    pos += 1;
    buf[pos] = hw_type;
    pos += 1;
    buf[pos] = hw_addr_size;
    pos += 1;
    buf[pos] = 0; // Hops
    pos += 1;
    // Transaction ID (big-endian).
    buf[pos] = @intCast((xid >> 24) & 0xFF);
    buf[pos + 1] = @intCast((xid >> 16) & 0xFF);
    buf[pos + 2] = @intCast((xid >> 8) & 0xFF);
    buf[pos + 3] = @intCast(xid & 0xFF);
    pos += 4;
    // ciaddr = 0.
    buf[pos] = 0;
    buf[pos + 1] = 0;
    buf[pos + 2] = 0;
    buf[pos + 3] = 0;
    pos += 4;
    // yiaddr (your IP address).
    writeIpBytes(buf, pos, yiaddr);
    pos += 4;
    // siaddr (server IP).
    writeIpBytes(buf, pos, server_ip);
    pos += 4;
    // giaddr = 0.
    buf[pos] = 0;
    buf[pos + 1] = 0;
    buf[pos + 2] = 0;
    buf[pos + 3] = 0;
    pos += 4;
    // chaddr (client MAC + padding to 16 bytes). Cap at 6 (Ethernet).
    const hw_copy: usize = @min(@as(usize, hw_addr_size), @as(usize, 6));
    @memcpy(buf[pos..][0..hw_copy], client_mac[0..hw_copy]);
    const zero_pad: usize = 16 - hw_copy;
    @memset(buf[pos + hw_copy ..][0..zero_pad], 0);
    pos += 16;
    // sname (64 bytes) + file (128 bytes) = zeros.
    @memset(buf[pos..][0..192], 0);
    pos += 192;

    // Magic cookie.
    buf[pos] = 0x63;
    buf[pos + 1] = 0x82;
    buf[pos + 2] = 0x53;
    buf[pos + 3] = 0x63;
    pos += 4;

    // Options.
    @memcpy(buf[pos..][0..options.len], options);
    pos += options.len;

    // Pad to minimum DHCP size (300 bytes for DHCP header + options).
    const dhcp_len = pos - dhcp_start;
    if (dhcp_len < 300) {
        const pad = 300 - dhcp_len;
        @memset(buf[pos..][0..pad], 0);
        pos += pad;
    }

    // === Fill lengths ===
    const ip_total_len: u16 = @intCast(pos - ip_header_start);
    buf[ip_len_pos] = @intCast((ip_total_len >> 8) & 0xFF);
    buf[ip_len_pos + 1] = @intCast(ip_total_len & 0xFF);

    const udp_len: u16 = @intCast(pos - udp_header_start);
    buf[udp_len_pos] = @intCast((udp_len >> 8) & 0xFF);
    buf[udp_len_pos + 1] = @intCast(udp_len & 0xFF);

    // IP checksum.
    const checksum = computeIpChecksum(buf[ip_header_start..][0..20]);
    buf[ip_checksum_pos] = @intCast((checksum >> 8) & 0xFF);
    buf[ip_checksum_pos + 1] = @intCast(checksum & 0xFF);

    return pos;
}

// ============================================================================
// Helpers
// ============================================================================

/// Write a DHCP option into a buffer. Returns new position.
fn writeOption(buf: []u8, pos: usize, code: u8, data: []const u8) usize {
    if (pos + 2 + data.len > buf.len) return pos;
    buf[pos] = code;
    buf[pos + 1] = @intCast(data.len);
    @memcpy(buf[pos + 2 ..][0..data.len], data);
    return pos + 2 + data.len;
}

/// Write a 4-byte IP option.
fn writeIpOption(buf: []u8, pos: usize, code: u8, ip: u32) usize {
    var data: [4]u8 = undefined;
    writeIpBytes(&data, 0, ip);
    return writeOption(buf, pos, code, &data);
}

/// Write a u32 as 4 big-endian bytes.
fn writeIpBytes(buf: []u8, offset: usize, ip: u32) void {
    buf[offset] = @intCast((ip >> 24) & 0xFF);
    buf[offset + 1] = @intCast((ip >> 16) & 0xFF);
    buf[offset + 2] = @intCast((ip >> 8) & 0xFF);
    buf[offset + 3] = @intCast(ip & 0xFF);
}

/// Read 4 bytes as a big-endian u32.
fn ip32(bytes: *const [4]u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3];
}

/// Simple prefix check.
fn hasPrefix(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return mem.eql(u8, haystack[0..prefix.len], prefix);
}

/// Compute IPv4 header checksum (RFC 1071).
fn computeIpChecksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) {
        sum += (@as(u32, header[i]) << 8) | header[i + 1];
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return @intCast(~sum & 0xFFFF);
}

// ============================================================================
// Tests
// ============================================================================

test "Lease creation and lookup" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001, // 10.0.0.1
        .ip_start = 0x0A000064, // 10.0.0.100
        .ip_end = 0x0A0000C8, // 10.0.0.200
        .subnet_mask = 0xFFFFFF00, // 255.255.255.0
        .gateway = 0x0A000001,
        .dns1 = 0x08080808,
    });
    defer server.deinit();

    const mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    // Allocate IP for first time.
    const ip = server.allocateIp(mac, 0);
    try std.testing.expectEqual(@as(u32, 0x0A000064), ip);

    // Create lease.
    server.createLease(mac, ip, "test-host", 1000);

    // Same MAC should get same IP.
    const ip2 = server.allocateIp(mac, 0);
    try std.testing.expectEqual(ip, ip2);
}

test "IP allocation falls back to free IP" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A000066, // Only 3 IPs.
        .subnet_mask = 0xFFFFFF00,
    });
    defer server.deinit();

    const mac1 = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x01 };
    const mac2 = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x02 };
    const mac3 = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x03 };

    const ip1 = server.allocateIp(mac1, 0);
    server.createLease(mac1, ip1, "", 0);

    const ip2 = server.allocateIp(mac2, 0);
    server.createLease(mac2, ip2, "", 0);

    const ip3 = server.allocateIp(mac3, 0);
    server.createLease(mac3, ip3, "", 0);

    // Pool exhausted.
    const mac4 = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x04 };
    const ip4 = server.allocateIp(mac4, 0);
    try std.testing.expectEqual(@as(u32, 0), ip4);
}

test "Requested IP honored when free" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
    });
    defer server.deinit();

    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const requested: u32 = 0x0A00007B; // 10.0.0.123
    const ip = server.allocateIp(mac, requested);
    try std.testing.expectEqual(requested, ip);
}

test "Lease aging" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
        .lease_time = 60, // 60 seconds
    });
    defer server.deinit();

    const mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    server.createLease(mac, 0x0A000064, "", 1000);
    try std.testing.expectEqual(@as(usize, 1), server.leases.items.len);

    // Age past expiration (60s + 1ms).
    server.ageLeases(1000 + 60_000 + 1);
    try std.testing.expectEqual(@as(usize, 0), server.leases.items.len);
}

test "Self-loop hostname detection" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
    });
    defer server.deinit();

    // Build a minimal DISCOVER frame with a "securenat-" hostname.
    var frame: [400]u8 = .{0} ** 400;
    const len = buildTestDiscoverFrame(&frame, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, 12345, "securenat-test");

    const resp = server.handleFrame(frame[0..len], 0);
    try std.testing.expect(resp == null); // Should be dropped.
}

test "DISCOVER -> OFFER" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
        .gateway = 0x0A000001,
        .dns1 = 0x08080808,
        .lease_time = 3600,
    });
    defer server.deinit();

    var frame: [400]u8 = .{0} ** 400;
    const len = buildTestDiscoverFrame(&frame, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, 42, null);
    const resp = server.handleFrame(frame[0..len], 1000) orelse return error.NoResponse;

    // Verify the response is a valid DHCP OFFER.
    try std.testing.expect(resp.len > 0);
    // DHCP op = BOOTREPLY (2).
    // The DHCP header starts at offset 42 (14 Eth + 20 IP + 8 UDP).
    try std.testing.expectEqual(@as(u8, 2), resp.frame[42]);
}

test "REQUEST -> ACK creates lease" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
        .gateway = 0x0A000001,
        .dns1 = 0x08080808,
        .lease_time = 3600,
    });
    defer server.deinit();

    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    var frame: [400]u8 = .{0} ** 400;
    const len = buildTestRequestFrame(&frame, mac, 42, 0x0A000064, null);
    const resp = server.handleFrame(frame[0..len], 1000) orelse return error.NoResponse;

    // Verify lease was created.
    try std.testing.expectEqual(@as(usize, 1), server.leases.items.len);
    try std.testing.expectEqual(@as(u32, 0x0A000064), server.leases.items[0].ip);
    try std.testing.expectEqual(mac, server.leases.items[0].mac);

    // Response should be ACK.
    try std.testing.expect(resp.len > 0);
}

test "REQUEST with wrong IP -> NACK" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A000066, // Only 3 IPs.
        .subnet_mask = 0xFFFFFF00,
    });
    defer server.deinit();

    const mac1 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 };
    const mac2 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02 };
    const mac3 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03 };
    const mac4 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x04 };

    // Fill all IPs.
    for (&[_][6]u8{ mac1, mac2, mac3 }) |m| {
        var f: [400]u8 = .{0} ** 400;
        const l = buildTestRequestFrame(&f, m, 1, 0x0A000064 + @as(u32, @intCast(@as(usize, m[5]) - 1)), null);
        _ = server.handleFrame(f[0..l], 0);
    }

    // Now try to REQUEST an IP that's taken by another MAC.
    var frame: [400]u8 = .{0} ** 400;
    const len = buildTestRequestFrame(&frame, mac4, 99, 0x0A000064, null);
    // Should NACK because 0x0A000064 is already leased to mac1.
    const resp = server.handleFrame(frame[0..len], 0);

    if (resp) |r| {
        // NACK: yiaddr should be 0. yiaddr is at DHCP offset +12 from dhcp_start.
        try std.testing.expectEqual(@as(u32, 0), ip32(r.frame[42 + 12 ..][0..4]));
    }
}

test "INFORM -> ACK with config params" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
        .gateway = 0x0A000001,
        .dns1 = 0x08080808,
        .dns2 = 0x08080404,
        .lease_time = 7200,
    });
    defer server.deinit();

    // Build an INFORM frame. ciaddr = client's current IP (10.0.0.50).
    var frame: [400]u8 = .{0} ** 400;
    const len = buildTestInformFrame(&frame, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, 77, 0x0A000032);
    const resp = server.handleFrame(frame[0..len], 1000) orelse return error.NoResponse;

    // Should be ACK.
    try std.testing.expect(resp.len > 0);
    try std.testing.expectEqual(@as(u8, 2), resp.frame[42]); // BOOTREPLY

    // yiaddr should be the client's ciaddr.
    try std.testing.expectEqual(@as(u32, 0x0A000032), ip32(resp.frame[42 + 12 ..][0..4]));

    // No lease should be created (INFORM doesn't allocate).
    try std.testing.expectEqual(@as(usize, 0), server.leases.items.len);
}

test "Response contains correct options" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
        .gateway = 0x0A000001,
        .dns1 = 0x08080808,
        .dns2 = 0x08080404,
        .lease_time = 3600,
    });
    defer server.deinit();

    var frame: [400]u8 = .{0} ** 400;
    const len = buildTestDiscoverFrame(&frame, [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, 42, null);
    const resp = server.handleFrame(frame[0..len], 1000) orelse return error.NoResponse;

    // Parse options from the response.
    // DHCP header starts at offset 42. Magic cookie at 42+232=274. Options start at 278.
    const magic = (@as(u32, resp.frame[274]) << 24) |
        (@as(u32, resp.frame[275]) << 16) |
        (@as(u32, resp.frame[276]) << 8) |
        resp.frame[277];
    try std.testing.expectEqual(DHCP_MAGIC, magic);

    // Scan options.
    var found_msg_type = false;
    var found_server_id = false;
    var found_lease_time = false;
    var found_subnet = false;
    var found_gateway = false;
    var found_dns = false;

    var pos: usize = 278;
    while (pos < resp.len) {
        const code = resp.frame[pos];
        if (code == 255) break; // end
        if (code == 0) {
            pos += 1;
            continue;
        }
        const olen = resp.frame[pos + 1];
        if (pos + 2 + olen > resp.len) break;
        const data = resp.frame[pos + 2 ..][0..olen];

        switch (code) {
            53 => { // message type
                try std.testing.expectEqual(@as(u8, 2), data[0]); // OFFER
                found_msg_type = true;
            },
            54 => { // server id
                try std.testing.expectEqual(@as(u32, 0x0A000001), ip32(data[0..4]));
                found_server_id = true;
            },
            51 => { // lease time
                const lt = (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3];
                try std.testing.expectEqual(@as(u32, 3600), lt);
                found_lease_time = true;
            },
            1 => { // subnet mask
                try std.testing.expectEqual(@as(u32, 0xFFFFFF00), ip32(data[0..4]));
                found_subnet = true;
            },
            3 => { // router (gateway)
                try std.testing.expectEqual(@as(u32, 0x0A000001), ip32(data[0..4]));
                found_gateway = true;
            },
            6 => { // dns server
                try std.testing.expectEqual(@as(u32, 0x08080808), ip32(data[0..4]));
                if (olen >= 8) {
                    try std.testing.expectEqual(@as(u32, 0x08080404), ip32(data[4..8]));
                }
                found_dns = true;
            },
            else => {},
        }
        pos += 2 + @as(usize, olen);
    }

    try std.testing.expect(found_msg_type);
    try std.testing.expect(found_server_id);
    try std.testing.expect(found_lease_time);
    try std.testing.expect(found_subnet);
    try std.testing.expect(found_gateway);
    try std.testing.expect(found_dns);
}

test "MAC migration — new IP replaces old lease" {
    var server = DhcpServer.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .ip_start = 0x0A000064,
        .ip_end = 0x0A0000C8,
        .subnet_mask = 0xFFFFFF00,
        .lease_time = 3600,
    });
    defer server.deinit();

    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    // First REQUEST from this MAC.
    var frame1: [400]u8 = .{0} ** 400;
    const len1 = buildTestRequestFrame(&frame1, mac, 1, 0x0A000064, "laptop");
    _ = server.handleFrame(frame1[0..len1], 1000);
    try std.testing.expectEqual(@as(usize, 1), server.leases.items.len);
    try std.testing.expectEqual(@as(u32, 0x0A000064), server.leases.items[0].ip);

    // Second REQUEST from same MAC, different IP.
    var frame2: [400]u8 = .{0} ** 400;
    const len2 = buildTestRequestFrame(&frame2, mac, 2, 0x0A0000C8, "laptop-v2");
    _ = server.handleFrame(frame2[0..len2], 2000);
    try std.testing.expectEqual(@as(usize, 1), server.leases.items.len);
    try std.testing.expectEqual(@as(u32, 0x0A0000C8), server.leases.items[0].ip);
    try std.testing.expectEqual(@as(u32, 2), server.leases.items[0].id);
}

// ============================================================================
// Test helpers -- build minimal DHCP frames
// ============================================================================

/// Build a minimal DHCP DISCOVER Ethernet frame.
fn buildTestDiscoverFrame(buf: *[400]u8, mac: [6]u8, xid: u32, hostname: ?[]const u8) usize {
    @memset(buf, 0);
    var pos: usize = 0;

    // Ethernet header.
    @memset(buf[pos..][0..6], 0xFF); // broadcast dst
    pos += 6;
    @memcpy(buf[pos..][0..6], &mac);
    pos += 6;
    buf[pos] = 0x08;
    buf[pos + 1] = 0x00;
    pos += 2;

    // IPv4 header.
    const ip_start = pos;
    buf[pos] = 0x45;
    pos += 1;
    pos += 1; // DSCP
    pos += 2; // len placeholder
    pos += 4; // id, flags
    buf[pos] = 0x40; // TTL
    pos += 1;
    buf[pos] = 17; // proto UDP
    pos += 1;
    pos += 2; // checksum placeholder
    pos += 4; // src ip (0.0.0.0)
    // dst ip = 255.255.255.255
    @memset(buf[pos..][0..4], 0xFF);
    pos += 4;

    // UDP header.
    const udp_start = pos;
    buf[pos] = 0;
    buf[pos + 1] = 68; // src port = CLIENT
    pos += 2;
    buf[pos] = 0;
    buf[pos + 1] = 67; // dst port = SERVER
    pos += 2;
    pos += 4; // len + checksum placeholder

    // DHCP header.
    const dhcp_start = pos;
    buf[pos] = 1; // BOOTREQUEST
    pos += 1;
    buf[pos] = 1; // htype = Ethernet
    pos += 1;
    buf[pos] = 6; // hlen
    pos += 1;
    pos += 1; // hops
    // XID.
    buf[pos] = @intCast((xid >> 24) & 0xFF);
    buf[pos + 1] = @intCast((xid >> 16) & 0xFF);
    buf[pos + 2] = @intCast((xid >> 8) & 0xFF);
    buf[pos + 3] = @intCast(xid & 0xFF);
    pos += 4;
    pos += 4; // ciaddr
    pos += 4; // yiaddr
    pos += 4; // siaddr
    pos += 4; // giaddr
    // chaddr at dhcp_start + 24.
    @memcpy(buf[dhcp_start + 24 ..][0..6], &mac);
    pos = dhcp_start + 24 + 16; // chaddr (16 bytes)
    pos += 192; // sname + file

    // Magic cookie.
    buf[pos] = 0x63;
    buf[pos + 1] = 0x82;
    buf[pos + 2] = 0x53;
    buf[pos + 3] = 0x63;
    pos += 4;

    // Options: message type = DISCOVER.
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = 1;
    pos += 3;

    // Hostname.
    if (hostname) |h| {
        buf[pos] = 12;
        buf[pos + 1] = @intCast(h.len);
        @memcpy(buf[pos + 2 ..][0..h.len], h);
        pos += 2 + h.len;
    }

    // End.
    buf[pos] = 255;
    pos += 1;

    // Fill IP total length.
    const ip_total_len: u16 = @intCast(pos - ip_start);
    buf[ip_start + 2] = @intCast((ip_total_len >> 8) & 0xFF);
    buf[ip_start + 3] = @intCast(ip_total_len & 0xFF);

    // Fill UDP length.
    const udp_len: u16 = @intCast(pos - udp_start);
    buf[udp_start + 4] = @intCast((udp_len >> 8) & 0xFF);
    buf[udp_start + 5] = @intCast(udp_len & 0xFF);

    return pos;
}

/// Build a minimal DHCP REQUEST Ethernet frame with a requested IP option.
fn buildTestRequestFrame(buf: *[400]u8, mac: [6]u8, xid: u32, requested_ip: u32, hostname: ?[]const u8) usize {
    @memset(buf, 0);
    var pos: usize = 0;

    // Ethernet header.
    @memset(buf[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(buf[pos..][0..6], &mac);
    pos += 6;
    buf[pos] = 0x08;
    buf[pos + 1] = 0x00;
    pos += 2;

    // IPv4 header.
    const ip_start = pos;
    buf[pos] = 0x45;
    pos += 1;
    pos += 1;
    pos += 2;
    pos += 4;
    buf[pos] = 0x40;
    pos += 1;
    buf[pos] = 17;
    pos += 1;
    pos += 2;
    pos += 4;
    @memset(buf[pos..][0..4], 0xFF);
    pos += 4;

    // UDP header.
    const udp_start = pos;
    buf[pos] = 0;
    buf[pos + 1] = 68;
    pos += 2;
    buf[pos] = 0;
    buf[pos + 1] = 67;
    pos += 2;
    pos += 4;

    // DHCP header.
    const dhcp_start = pos;
    buf[pos] = 1; // BOOTREQUEST
    pos += 1;
    buf[pos] = 1;
    pos += 1;
    buf[pos] = 6;
    pos += 1;
    pos += 1;
    buf[pos] = @intCast((xid >> 24) & 0xFF);
    buf[pos + 1] = @intCast((xid >> 16) & 0xFF);
    buf[pos + 2] = @intCast((xid >> 8) & 0xFF);
    buf[pos + 3] = @intCast(xid & 0xFF);
    pos += 4;
    pos += 16; // ciaddr + yiaddr + siaddr + giaddr
    // chaddr at dhcp_start + 24.
    @memcpy(buf[dhcp_start + 24 ..][0..6], &mac);
    pos = dhcp_start + 24 + 16;
    pos += 192;

    // Magic cookie.
    buf[pos] = 0x63;
    buf[pos + 1] = 0x82;
    buf[pos + 2] = 0x53;
    buf[pos + 3] = 0x63;
    pos += 4;

    // Message type = REQUEST.
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = 3;
    pos += 3;

    // Requested IP option (50).
    buf[pos] = 50;
    buf[pos + 1] = 4;
    buf[pos + 2] = @intCast((requested_ip >> 24) & 0xFF);
    buf[pos + 3] = @intCast((requested_ip >> 16) & 0xFF);
    buf[pos + 4] = @intCast((requested_ip >> 8) & 0xFF);
    buf[pos + 5] = @intCast(requested_ip & 0xFF);
    pos += 6;

    // Hostname.
    if (hostname) |h| {
        buf[pos] = 12;
        buf[pos + 1] = @intCast(h.len);
        @memcpy(buf[pos + 2 ..][0..h.len], h);
        pos += 2 + h.len;
    }

    // End.
    buf[pos] = 255;
    pos += 1;

    // Fill lengths.
    const ip_total_len: u16 = @intCast(pos - ip_start);
    buf[ip_start + 2] = @intCast((ip_total_len >> 8) & 0xFF);
    buf[ip_start + 3] = @intCast(ip_total_len & 0xFF);

    const udp_len: u16 = @intCast(pos - udp_start);
    buf[udp_start + 4] = @intCast((udp_len >> 8) & 0xFF);
    buf[udp_start + 5] = @intCast(udp_len & 0xFF);

    return pos;
}

/// Build a minimal DHCP INFORM Ethernet frame.
/// INFORM has ciaddr set to the client's current IP.
fn buildTestInformFrame(buf: *[400]u8, mac: [6]u8, xid: u32, ciaddr: u32) usize {
    @memset(buf, 0);
    var pos: usize = 0;

    // Ethernet header.
    @memset(buf[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(buf[pos..][0..6], &mac);
    pos += 6;
    buf[pos] = 0x08;
    buf[pos + 1] = 0x00;
    pos += 2;

    // IPv4 header.
    const ip_start = pos;
    buf[pos] = 0x45;
    pos += 1;
    pos += 1;
    pos += 2;
    pos += 4;
    buf[pos] = 0x40;
    pos += 1;
    buf[pos] = 17;
    pos += 1;
    pos += 2;
    // Source IP = client's current IP (not 0.0.0.0 for INFORM).
    writeIpBytes(@as([]u8, buf), pos, ciaddr);
    pos += 4;
    @memset(buf[pos..][0..4], 0xFF);
    pos += 4;

    // UDP header.
    const udp_start = pos;
    buf[pos] = 0;
    buf[pos + 1] = 68;
    pos += 2;
    buf[pos] = 0;
    buf[pos + 1] = 67;
    pos += 2;
    pos += 4;

    // DHCP header.
    const dhcp_start = pos;
    buf[pos] = 1; // BOOTREQUEST
    pos += 1;
    buf[pos] = 1; // htype = Ethernet
    pos += 1;
    buf[pos] = 6; // hlen
    pos += 1;
    pos += 1; // hops
    // XID.
    buf[pos] = @intCast((xid >> 24) & 0xFF);
    buf[pos + 1] = @intCast((xid >> 16) & 0xFF);
    buf[pos + 2] = @intCast((xid >> 8) & 0xFF);
    buf[pos + 3] = @intCast(xid & 0xFF);
    pos += 4;
    // ciaddr = client's current IP.
    writeIpBytes(buf, pos, ciaddr);
    pos += 4;
    pos += 4; // yiaddr
    pos += 4; // siaddr
    pos += 4; // giaddr
    // chaddr.
    @memcpy(buf[dhcp_start + 24 ..][0..6], &mac);
    pos = dhcp_start + 24 + 16;
    pos += 192;

    // Magic cookie.
    buf[pos] = 0x63;
    buf[pos + 1] = 0x82;
    buf[pos + 2] = 0x53;
    buf[pos + 3] = 0x63;
    pos += 4;

    // Options: message type = INFORM (8).
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = 8;
    pos += 3;

    // End.
    buf[pos] = 255;
    pos += 1;

    // Fill lengths.
    const ip_total_len2: u16 = @intCast(pos - ip_start);
    buf[ip_start + 2] = @intCast((ip_total_len2 >> 8) & 0xFF);
    buf[ip_start + 3] = @intCast(ip_total_len2 & 0xFF);

    const udp_len2: u16 = @intCast(pos - udp_start);
    buf[udp_start + 4] = @intCast((udp_len2 >> 8) & 0xFF);
    buf[udp_start + 5] = @intCast(udp_len2 & 0xFF);

    return pos;
}
