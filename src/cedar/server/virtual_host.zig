//! Virtual host — ARP responder + ARP cache for the hub gateway.
//!
//! C reference: `Virtual.c` (ARP responder, `VirtualArpResponseRequest`,
//! `VirtualArpSendResponse`, ARP table management, `GenMacAddress`,
//! `SendBeacon` gratuitous ARP).
//!
//! The virtual host represents the gateway IP (e.g. 10.0.0.1) on a hub's
//! subnet. It responds to ARP requests for its own IP and passively learns
//! client MAC/IP mappings from all incoming ARP traffic. Periodic gratuitous
//! ARP beacons announce its presence.
//!
//! This module owns the ARP responder logic and ARP cache. It does NOT own
//! the hub's MAC/IP tables (that's `hub.zig`), nor the UDP socket for the
//! beacon payload — callers feed raw frames in and receive response frames.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;

// ============================================================================
// Constants (C: Cedar.h / Virtual.c / TcpIp.h)
// ============================================================================

/// ARP hardware type: Ethernet (C: `ARP_HARDWARE_TYPE_ETHERNET`).
pub const ARP_HARDWARE_TYPE_ETHERNET: u16 = 0x0001;
/// ARP protocol type: IPv4 (C: `MAC_PROTO_IPV4` = 0x0800).
pub const ARP_PROTOCOL_TYPE_IPV4: u16 = 0x0800;
/// ARP operation: request (C: `ARP_OPERATION_REQUEST` = 1).
pub const ARP_OP_REQUEST: u16 = 1;
/// ARP operation: response (C: `ARP_OPERATION_RESPONSE` = 2).
pub const ARP_OP_RESPONSE: u16 = 2;

/// Ethernet broadcast address.
pub const BROADCAST_MAC = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/// IPv4 broadcast address.
pub const BROADCAST_IP: u32 = 0xFFFFFFFF;

/// ARP cache entry lifetime in milliseconds (C: `ARP_ENTRY_EXPIRES` = 30s).
pub const ARP_ENTRY_EXPIRES_MS: i64 = 30_000;
/// ARP cache polling interval in milliseconds (C: `ARP_ENTRY_POLLING_TIME` = 1s).
pub const ARP_POLLING_INTERVAL_MS: i64 = 1_000;
/// Gratuitous ARP beacon interval in milliseconds (C: `BEACON_SEND_INTERVAL` = 5s).
pub const BEACON_SEND_INTERVAL_MS: i64 = 5_000;

/// ARP wire header size: 28 bytes (C: `ARPV4_HEADER`).
pub const ARP_HEADER_SIZE: usize = 28;

// ============================================================================
// Types
// ============================================================================

/// ARP cache entry — resolved IP-to-MAC mapping (C: `ARP_ENTRY`).
pub const ArpEntry = struct {
    ip: u32,
    mac: [6]u8,
    expire: i64,

    pub fn isExpired(self: *const ArpEntry, now: i64) bool {
        return now > self.expire;
    }
};

/// Virtual host configuration — maps to `VH` gateway fields (C: `Virtual.h`).
pub const VirtualHostConfig = struct {
    /// Enable the virtual host ARP responder.
    enabled: bool = false,
    /// The virtual host's own IP address (gateway IP).
    host_ip: u32 = 0,
    /// Subnet mask.
    host_mask: u32 = 0,
    /// The virtual host's MAC address (synthesized or configured).
    host_mac: [6]u8 = .{ 0 } ** 6,
};

/// A response frame to transmit. `frame` is an Ethernet frame.
pub const ArpResponse = struct {
    frame: [1024]u8 = undefined,
    len: usize = 0,
};

/// The virtual host state.
pub const VirtualHost = struct {
    allocator: Allocator,
    config: VirtualHostConfig,
    /// ARP cache (sorted by IP for binary search).
    arp_table: ArrayList(ArpEntry),
    /// Timestamp of last ARP cache poll (ms).
    last_arp_poll: i64 = 0,
    /// Timestamp of last gratuitous ARP beacon (ms).
    /// Starts at `-BEACON_SEND_INTERVAL_MS` so the first beacon is ready immediately.
    last_beacon: i64 = -BEACON_SEND_INTERVAL_MS,

    pub fn init(allocator: Allocator, config: VirtualHostConfig) VirtualHost {
        return .{
            .allocator = allocator,
            .config = config,
            .arp_table = .{},
        };
    }

    pub fn deinit(self: *VirtualHost) void {
        self.arp_table.deinit(self.allocator);
    }

    // ---- Main entry point --------------------------------------------------

    /// Process an incoming Ethernet frame and return optional response frames.
    /// Returns a list of response frames to transmit (ARP responses, gratuitous ARPs).
    pub fn handleFrame(self: *VirtualHost, frame: []const u8, now: i64) ?ArpResponse {
        if (!self.config.enabled) return null;
        if (frame.len < 14) return null;

        // Only process ARP frames (EtherType 0x0806).
        const ethertype = (@as(u16, frame[12]) << 8) | frame[13];
        if (ethertype != 0x0806) return null;

        // Parse the ARP header.
        if (frame.len < 14 + ARP_HEADER_SIZE) return null;
        const arp_data = frame[14 .. 14 + ARP_HEADER_SIZE];

        // Validate ARP header fields.
        const hw_type = (@as(u16, arp_data[0]) << 8) | arp_data[1];
        const proto_type = (@as(u16, arp_data[2]) << 8) | arp_data[3];
        const hw_size = arp_data[4];
        const proto_size = arp_data[5];
        const operation = (@as(u16, arp_data[6]) << 8) | arp_data[7];

        if (hw_type != ARP_HARDWARE_TYPE_ETHERNET) return null;
        if (proto_type != ARP_PROTOCOL_TYPE_IPV4) return null;
        if (hw_size != 6 or proto_size != 4) return null;

        // Extract sender MAC/IP and target MAC/IP from the ARP payload.
        var sender_mac: [6]u8 = undefined;
        @memcpy(&sender_mac, arp_data[8..14]);
        const sender_ip = ip32(arp_data[14..18]);

        var target_mac: [6]u8 = undefined;
        @memcpy(&target_mac, arp_data[18..24]);
        const target_ip = ip32(arp_data[24..28]);

        // Anti-spoof: the MAC in the ARP payload must match the Ethernet source.
        var eth_src_mac: [6]u8 = undefined;
        @memcpy(&eth_src_mac, frame[6..12]);
        if (!mem.eql(u8, &sender_mac, &eth_src_mac)) return null;

        // 1. Passive learning: always learn the sender's IP→MAC mapping.
        self.learn(sender_ip, sender_mac, now);

        // 2. If this is an ARP request targeting our IP, send a reply.
        if (operation == ARP_OP_REQUEST and target_ip == self.config.host_ip) {
            return self.buildArpReply(sender_mac, sender_ip);
        }

        return null;
    }

    /// Check if a gratuitous ARP beacon should be sent.
    pub fn shouldSendBeacon(self: *const VirtualHost, now: i64) bool {
        if (!self.config.enabled) return false;
        if (self.config.host_ip == 0) return false;
        return now - self.last_beacon >= BEACON_SEND_INTERVAL_MS;
    }

    /// Build a gratuitous ARP response frame announcing our IP→MAC.
    pub fn buildGratuitousArp(self: *VirtualHost, now: i64) ArpResponse {
        self.last_beacon = now;
        // Target is broadcast — this is a gratuitous announcement.
        return self.buildArpResponse(
            BROADCAST_MAC,
            BROADCAST_IP,
            self.config.host_mac,
            self.config.host_ip,
        );
    }

    // ---- ARP cache ---------------------------------------------------------

    /// Passive learning: insert or update a mapping in the ARP cache.
    fn learn(self: *VirtualHost, ip: u32, mac: [6]u8, now: i64) void {
        // Don't learn broadcast or zero MACs.
        if (mem.eql(u8, &mac, &BROADCAST_MAC)) return;
        if (mem.eql(u8, &mac, &[_]u8{ 0, 0, 0, 0, 0, 0 })) return;

        // Search for existing entry by IP (linear scan — cache is small).
        for (self.arp_table.items) |*entry| {
            if (entry.ip == ip) {
                // Update existing entry.
                entry.mac = mac;
                entry.expire = now + ARP_ENTRY_EXPIRES_MS;
                return;
            }
        }

        // Insert new entry.
        self.arp_table.append(self.allocator, .{
            .ip = ip,
            .mac = mac,
            .expire = now + ARP_ENTRY_EXPIRES_MS,
        }) catch {};
    }

    /// Look up a MAC address by IP in the ARP cache.
    pub fn lookupMac(self: *const VirtualHost, ip: u32) ?[6]u8 {
        for (self.arp_table.items) |entry| {
            if (entry.ip == ip and !entry.isExpired(0)) {
                return entry.mac;
            }
        }
        return null;
    }

    /// Remove expired ARP cache entries (C: `RefreshArpTable`).
    pub fn refreshCache(self: *VirtualHost, now: i64) void {
        var i: usize = 0;
        while (i < self.arp_table.items.len) {
            if (self.arp_table.items[i].isExpired(now)) {
                _ = self.arp_table.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Periodic ARP cache maintenance (C: `PollingArpTable`).
    /// Call this every tick; it polls at `ARP_POLLING_INTERVAL_MS`.
    pub fn poll(self: *VirtualHost, now: i64) void {
        if (now - self.last_arp_poll >= ARP_POLLING_INTERVAL_MS) {
            self.last_arp_poll = now;
            self.refreshCache(now);
        }
    }

    // ---- Response builders -------------------------------------------------

    /// Build a unicast ARP reply in response to a request for our IP.
    fn buildArpReply(self: *VirtualHost, dest_mac: [6]u8, dest_ip: u32) ArpResponse {
        return self.buildArpResponse(dest_mac, dest_ip, self.config.host_mac, self.config.host_ip);
    }

    /// Build a full Ethernet + ARP response frame.
    fn buildArpResponse(
        self: *VirtualHost,
        dest_mac: [6]u8,
        dest_ip: u32,
        src_mac: [6]u8,
        src_ip: u32,
    ) ArpResponse {
        _ = self;
        var resp = ArpResponse{};
        var pos: usize = 0;

        // === Ethernet Header (14 bytes) ===
        @memcpy(resp.frame[pos..][0..6], &dest_mac);
        pos += 6;
        @memcpy(resp.frame[pos..][0..6], &src_mac);
        pos += 6;
        resp.frame[pos] = 0x08;
        resp.frame[pos + 1] = 0x06; // EtherType = ARP
        pos += 2;

        // === ARP Header (28 bytes) ===
        // Hardware type: Ethernet.
        resp.frame[pos] = @intCast((ARP_HARDWARE_TYPE_ETHERNET >> 8) & 0xFF);
        resp.frame[pos + 1] = @intCast(ARP_HARDWARE_TYPE_ETHERNET & 0xFF);
        pos += 2;
        // Protocol type: IPv4.
        resp.frame[pos] = @intCast((ARP_PROTOCOL_TYPE_IPV4 >> 8) & 0xFF);
        resp.frame[pos + 1] = @intCast(ARP_PROTOCOL_TYPE_IPV4 & 0xFF);
        pos += 2;
        // Hardware size: 6, Protocol size: 4.
        resp.frame[pos] = 6;
        resp.frame[pos + 1] = 4;
        pos += 2;
        // Operation: reply.
        resp.frame[pos] = @intCast((ARP_OP_RESPONSE >> 8) & 0xFF);
        resp.frame[pos + 1] = @intCast(ARP_OP_RESPONSE & 0xFF);
        pos += 2;
        // Sender MAC.
        @memcpy(resp.frame[pos..][0..6], &src_mac);
        pos += 6;
        // Sender IP.
        writeIpBytes(&resp.frame, pos, src_ip);
        pos += 4;
        // Target MAC.
        @memcpy(resp.frame[pos..][0..6], &dest_mac);
        pos += 6;
        // Target IP.
        writeIpBytes(&resp.frame, pos, dest_ip);
        pos += 4;

        resp.len = pos;
        return resp;
    }
};

// ============================================================================
// Helpers
// ============================================================================

/// Read 4 bytes as a big-endian u32.
fn ip32(bytes: *const [4]u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3];
}

/// Write a u32 as 4 big-endian bytes.
fn writeIpBytes(buf: []u8, offset: usize, ip: u32) void {
    buf[offset] = @intCast((ip >> 24) & 0xFF);
    buf[offset + 1] = @intCast((ip >> 16) & 0xFF);
    buf[offset + 2] = @intCast((ip >> 8) & 0xFF);
    buf[offset + 3] = @intCast(ip & 0xFF);
}

// ============================================================================
// Tests
// ============================================================================

fn makeArpRequestFrame(eth_src: [6]u8, arp_sender_ip: u32, target_ip: u32) [42]u8 {
    var frame: [42]u8 = undefined;

    // Ethernet header: dst=broadcast, src=eth_src, type=ARP.
    @memset(frame[0..6], 0xFF); // broadcast dest
    @memcpy(frame[6..12], &eth_src);
    frame[12] = 0x08;
    frame[13] = 0x06;

    // ARP header starts at offset 14.
    frame[14] = 0x00; frame[15] = 0x01; // Hardware type: Ethernet.
    frame[16] = 0x08; frame[17] = 0x00; // Protocol type: IPv4.
    frame[18] = 6; // Hardware size.
    frame[19] = 4; // Protocol size.
    frame[20] = 0x00; frame[21] = 0x01; // Operation: request.
    @memcpy(frame[22..28], &eth_src); // Sender MAC.
    writeIpBytes(&frame, 28, arp_sender_ip); // Sender IP.
    @memset(frame[32..38], 0x00); // Target MAC (unknown).
    writeIpBytes(&frame, 38, target_ip); // Target IP.

    return frame;
}

fn makeArpReplyFrame(eth_src: [6]u8, arp_sender_mac: [6]u8, arp_sender_ip: u32, target_mac: [6]u8, target_ip: u32) [42]u8 {
    var frame: [42]u8 = undefined;

    // Ethernet header: dst=target_mac, src=eth_src, type=ARP.
    @memcpy(frame[0..6], &target_mac);
    @memcpy(frame[6..12], &eth_src);
    frame[12] = 0x08;
    frame[13] = 0x06;

    // ARP header starts at offset 14.
    frame[14] = 0x00; frame[15] = 0x01; // Hardware type: Ethernet.
    frame[16] = 0x08; frame[17] = 0x00; // Protocol type: IPv4.
    frame[18] = 6; // Hardware size.
    frame[19] = 4; // Protocol size.
    frame[20] = 0x00; frame[21] = 0x02; // Operation: reply.
    @memcpy(frame[22..28], &arp_sender_mac); // Sender MAC.
    writeIpBytes(&frame, 28, arp_sender_ip); // Sender IP.
    @memcpy(frame[32..38], &target_mac); // Target MAC.
    writeIpBytes(&frame, 38, target_ip); // Target IP.

    return frame;
}

// ---- Test: init / deinit ----

test "VirtualHost init defaults" {
    const host = VirtualHost.init(std.testing.allocator, .{});
    try std.testing.expect(!host.config.enabled);
    try std.testing.expectEqual(@as(u32, 0), host.config.host_ip);
    try std.testing.expectEqual(@as(usize, 0), host.arp_table.items.len);
}

// ---- Test: ARP request for our IP → reply ----

test "ARP request for gateway IP triggers reply" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001, // 10.0.0.1
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const client_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const client_ip: u32 = 0x0A000064; // 10.0.0.100

    const frame = makeArpRequestFrame(client_mac, client_ip, host.config.host_ip);
    const resp = host.handleFrame(&frame, 1000);

    try std.testing.expect(resp != null);
    const r = resp.?;

    // Response should be 42 bytes: 14 Ethernet + 28 ARP.
    try std.testing.expectEqual(@as(usize, 42), r.len);

    // Ethernet destination should be the client's MAC.
    try std.testing.expectEqualSlices(u8, &client_mac, r.frame[0..6]);
    // Ethernet source should be our MAC.
    try std.testing.expectEqualSlices(u8, &host.config.host_mac, r.frame[6..12]);
    // EtherType should be ARP (0x0806).
    try std.testing.expectEqual(@as(u8, 0x08), r.frame[12]);
    try std.testing.expectEqual(@as(u8, 0x06), r.frame[13]);

    // ARP operation should be reply (2).
    try std.testing.expectEqual(@as(u16, ARP_OP_RESPONSE), (@as(u16, r.frame[20]) << 8) | r.frame[21]);
    // ARP sender MAC should be our MAC.
    try std.testing.expectEqualSlices(u8, &host.config.host_mac, r.frame[22..28]);
    // ARP sender IP should be our IP.
    try std.testing.expectEqual(host.config.host_ip, (@as(u32, r.frame[28]) << 24 | (@as(u32, r.frame[29]) << 16) | (@as(u32, r.frame[30]) << 8) | r.frame[31]));
    // ARP target MAC should be the client's MAC.
    try std.testing.expectEqualSlices(u8, &client_mac, r.frame[32..38]);
    // ARP target IP should be the client's IP.
    try std.testing.expectEqual(client_ip, (@as(u32, r.frame[38]) << 24 | (@as(u32, r.frame[39]) << 16) | (@as(u32, r.frame[40]) << 8) | r.frame[41]));
}

// ---- Test: ARP request for different IP → no reply ----

test "ARP request for different IP is ignored" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const client_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const frame = makeArpRequestFrame(client_mac, 0x0A000064, 0x0A000099); // target ≠ our IP
    try std.testing.expect(host.handleFrame(&frame, 1000) == null);
}

// ---- Test: ARP reply is learned but no response sent ----

test "ARP reply is learned passively" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const peer_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const peer_ip: u32 = 0x0A000064;

    const frame = makeArpReplyFrame(peer_mac, peer_mac, peer_ip, host.config.host_mac, host.config.host_ip);
    // ARP reply should not produce a response frame.
    try std.testing.expect(host.handleFrame(&frame, 1000) == null);
    // But the mapping should be learned.
    try std.testing.expect(host.lookupMac(peer_ip) != null);
    const learned = host.lookupMac(peer_ip).?;
    try std.testing.expectEqualSlices(u8, &peer_mac, &learned);
}

// ---- Test: ARP cache learning from requests ----

test "ARP request sender is learned in cache" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const client_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const client_ip: u32 = 0x0A000064;

    const frame = makeArpRequestFrame(client_mac, client_ip, host.config.host_ip);
    _ = host.handleFrame(&frame, 1000);

    // Client should now be in the cache.
    const learned = host.lookupMac(client_ip).?;
    try std.testing.expectEqualSlices(u8, &client_mac, &learned);
}

// ---- Test: anti-spoof — mismatched MAC/IP in ARP is rejected ----

test "ARP with spoofed sender MAC is rejected" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    // Build a frame where the Ethernet source differs from the ARP sender MAC.
    var frame = makeArpRequestFrame(
        .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        0x0A000064,
        host.config.host_ip,
    );
    // Overwrite the Ethernet source to differ from the ARP sender MAC.
    @memcpy(frame[6..12], &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 });

    try std.testing.expect(host.handleFrame(&frame, 1000) == null);
}

// ---- Test: ARP cache expiration ----

test "ARP cache entries expire" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const client_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const client_ip: u32 = 0x0A000064;

    // Learn at t=1000.
    const frame = makeArpRequestFrame(client_mac, client_ip, host.config.host_ip);
    _ = host.handleFrame(&frame, 1000);
    try std.testing.expect(host.lookupMac(client_ip) != null);

    // Still valid at t=30000.
    host.refreshCache(30000);
    try std.testing.expect(host.lookupMac(client_ip) != null);

    // Expired at t=31001 (30s + 1ms).
    host.refreshCache(31001);
    try std.testing.expect(host.lookupMac(client_ip) == null);
}

// ---- Test: gratuitous ARP beacon ----

test "Gratuitous ARP beacon timing" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    // Disabled host doesn't send beacons.
    var disabled = VirtualHost.init(std.testing.allocator, .{ .enabled = false });
    defer disabled.deinit();
    try std.testing.expect(!disabled.shouldSendBeacon(10000));

    // No beacon without IP.
    var no_ip = VirtualHost.init(std.testing.allocator, .{ .enabled = true });
    defer no_ip.deinit();
    try std.testing.expect(!no_ip.shouldSendBeacon(10000));

    // Beacon ready at start (last_beacon = 0).
    try std.testing.expect(host.shouldSendBeacon(1000));

    // After sending, not ready until next interval.
    const resp = host.buildGratuitousArp(1000);
    try std.testing.expectEqual(@as(usize, 42), resp.len);

    // Not ready again until 5s later.
    try std.testing.expect(!host.shouldSendBeacon(1000 + BEACON_SEND_INTERVAL_MS - 1));
    try std.testing.expect(host.shouldSendBeacon(1000 + BEACON_SEND_INTERVAL_MS));
}

// ---- Test: gratuitous ARP frame content ----

test "Gratuitous ARP frame has broadcast dest and our IP→MAC" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const resp = host.buildGratuitousArp(5000);

    // Ethernet dest: broadcast.
    try std.testing.expectEqualSlices(u8, &BROADCAST_MAC, resp.frame[0..6]);
    // Ethernet src: our MAC.
    try std.testing.expectEqualSlices(u8, &host.config.host_mac, resp.frame[6..12]);
    // ARP op: reply.
    try std.testing.expectEqual(@as(u16, ARP_OP_RESPONSE), (@as(u16, resp.frame[20]) << 8) | resp.frame[21]);
    // ARP sender: our MAC + our IP.
    try std.testing.expectEqualSlices(u8, &host.config.host_mac, resp.frame[22..28]);
    try std.testing.expectEqual(host.config.host_ip, (@as(u32, resp.frame[28]) << 24 | (@as(u32, resp.frame[29]) << 16) | (@as(u32, resp.frame[30]) << 8) | resp.frame[31]));
    // ARP target: broadcast MAC + broadcast IP.
    try std.testing.expectEqualSlices(u8, &BROADCAST_MAC, resp.frame[32..38]);
    try std.testing.expectEqual(BROADCAST_IP, (@as(u32, resp.frame[38]) << 24 | (@as(u32, resp.frame[39]) << 16) | (@as(u32, resp.frame[40]) << 8) | resp.frame[41]));
}

// ---- Test: disabled host returns null ----

test "Disabled host drops all frames" {
    var host = VirtualHost.init(std.testing.allocator, .{ .enabled = false });
    defer host.deinit();

    const client_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const frame = makeArpRequestFrame(client_mac, 0x0A000064, 0x0A000001);
    try std.testing.expect(host.handleFrame(&frame, 1000) == null);
}

// ---- Test: too-short frames ----

test "Short frames are rejected" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
    });
    defer host.deinit();

    // Too short for Ethernet header.
    var short: [5]u8 = .{ 0 } ** 5;
    try std.testing.expect(host.handleFrame(&short, 1000) == null);

    // Too short for ARP header.
    var medium: [30]u8 = .{ 0 } ** 30;
    medium[12] = 0x08; medium[13] = 0x06; // ARP ethertype
    try std.testing.expect(host.handleFrame(&medium, 1000) == null);
}

// ---- Test: non-ARP frames ignored ----

test "Non-ARP frames are ignored" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
    });
    defer host.deinit();

    // IPv4 frame (0x0800).
    var frame: [42]u8 = .{ 0 } ** 42;
    frame[12] = 0x08; frame[13] = 0x00;
    try std.testing.expect(host.handleFrame(&frame, 1000) == null);
}

// ---- Test: cache multiple entries ----

test "ARP cache handles multiple clients" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const mac1 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 };
    const mac2 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02 };
    const ip1: u32 = 0x0A000064;
    const ip2: u32 = 0x0A000065;

    const f1 = makeArpRequestFrame(mac1, ip1, host.config.host_ip);
    _ = host.handleFrame(&f1, 1000);

    const f2 = makeArpRequestFrame(mac2, ip2, host.config.host_ip);
    _ = host.handleFrame(&f2, 2000);

    try std.testing.expectEqual(@as(usize, 2), host.arp_table.items.len);

    const learned1 = host.lookupMac(ip1) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &mac1, &learned1);
    const learned2 = host.lookupMac(ip2) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &mac2, &learned2);
}

// ---- Test: MAC update on same IP ----

test "ARP cache updates MAC for same IP" {
    var host = VirtualHost.init(std.testing.allocator, .{
        .enabled = true,
        .host_ip = 0x0A000001,
        .host_mask = 0xFFFFFF00,
        .host_mac = .{ 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 },
    });
    defer host.deinit();

    const mac1 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 };
    const mac2 = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02 };
    const ip: u32 = 0x0A000064;

    const f1 = makeArpRequestFrame(mac1, ip, host.config.host_ip);
    _ = host.handleFrame(&f1, 1000);

    const f2 = makeArpRequestFrame(mac2, ip, host.config.host_ip);
    _ = host.handleFrame(&f2, 2000);

    // Only one entry (same IP).
    try std.testing.expectEqual(@as(usize, 1), host.arp_table.items.len);
    // MAC should be updated to mac2.
    const updated = host.lookupMac(ip) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualSlices(u8, &mac2, &updated);
}
