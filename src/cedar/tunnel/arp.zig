//! ARP Handler
//!
//! Handles ARP requests/replies for the VPN tunnel.
//! Learns gateway MAC and responds to ARP requests for our IP.

const std = @import("std");

/// ARP handler for gateway MAC learning and request handling
pub const ArpHandler = struct {
    /// Our MAC address
    our_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    /// Our IP address (set after DHCP)
    our_ip: u32 = 0,
    /// Gateway IP address
    gateway_ip: u32 = 0,
    /// Gateway MAC address (learned from ARP replies)
    gateway_mac: [6]u8 = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    /// Whether gateway MAC has been learned
    gateway_mac_known: bool = false,

    /// Pending ARP reply info
    pending_reply: ?PendingArpReply = null,
    /// Need to send gratuitous ARP
    need_gratuitous_arp: bool = false,
    /// Need to send gateway ARP request
    need_gateway_arp: bool = false,

    /// Last gratuitous ARP send time
    last_garp_time: i64 = 0,

    const Self = @This();
    const GARP_INTERVAL_MS: i64 = 10000; // 10 seconds

    /// Pending ARP reply to send
    pub const PendingArpReply = struct {
        target_mac: [6]u8,
        target_ip: u32,
    };

    /// Initialize ARP handler
    pub fn init(mac: [6]u8) Self {
        return .{ .our_mac = mac };
    }

    /// Configure our IP and gateway after DHCP
    pub fn configure(self: *Self, our_ip: u32, gateway_ip: u32) void {
        self.our_ip = our_ip;
        self.gateway_ip = gateway_ip;
        // Queue gratuitous ARP and gateway ARP request
        self.need_gratuitous_arp = true;
        self.need_gateway_arp = true;
    }

    /// Check if we should send periodic gratuitous ARP
    pub fn shouldSendPeriodicGarp(self: *const Self, now: i64) bool {
        if (self.our_ip == 0) return false;
        return now - self.last_garp_time >= GARP_INTERVAL_MS;
    }

    /// Record that gratuitous ARP was sent
    pub fn markGarpSent(self: *Self, now: i64) void {
        self.need_gratuitous_arp = false;
        self.last_garp_time = now;
    }

    /// Record that gateway ARP request was sent
    pub fn markGatewayArpSent(self: *Self) void {
        self.need_gateway_arp = false;
    }

    /// Process an incoming ARP packet
    /// Returns true if the packet was handled
    pub fn processArpPacket(self: *Self, data: []const u8) bool {
        if (data.len < 42) return false;

        const ethertype = (@as(u16, data[12]) << 8) | data[13];
        if (ethertype != 0x0806) return false; // Not ARP

        const arp_op = (@as(u16, data[20]) << 8) | data[21];

        if (arp_op == 2) {
            // ARP Reply - learn gateway MAC
            return self.handleArpReply(data);
        } else if (arp_op == 1) {
            // ARP Request - queue reply if asking for our IP
            return self.handleArpRequest(data);
        }

        return false;
    }

    fn handleArpReply(self: *Self, data: []const u8) bool {
        // Extract sender IP (bytes 28-31 in big-endian)
        const sender_ip = (@as(u32, data[28]) << 24) |
            (@as(u32, data[29]) << 16) |
            (@as(u32, data[30]) << 8) |
            data[31];

        // If from gateway, learn its MAC
        if (self.gateway_ip != 0 and sender_ip == self.gateway_ip) {
            @memcpy(&self.gateway_mac, data[22..28]);
            self.gateway_mac_known = true;
            return true;
        }

        return false;
    }

    fn handleArpRequest(self: *Self, data: []const u8) bool {
        // Extract target IP (bytes 38-41)
        const target_ip = (@as(u32, data[38]) << 24) |
            (@as(u32, data[39]) << 16) |
            (@as(u32, data[40]) << 8) |
            data[41];

        // If asking for our IP, queue reply
        if (target_ip == self.our_ip and self.our_ip != 0) {
            var target_mac: [6]u8 = undefined;
            @memcpy(&target_mac, data[22..28]);

            const requester_ip = (@as(u32, data[28]) << 24) |
                (@as(u32, data[29]) << 16) |
                (@as(u32, data[30]) << 8) |
                data[31];

            self.pending_reply = .{
                .target_mac = target_mac,
                .target_ip = requester_ip,
            };
            return true;
        }

        return false;
    }

    /// Get and clear pending ARP reply
    pub fn takePendingReply(self: *Self) ?PendingArpReply {
        const reply = self.pending_reply;
        self.pending_reply = null;
        return reply;
    }

    /// Get gateway MAC (defaults to broadcast if not learned)
    pub fn getGatewayMac(self: *const Self) [6]u8 {
        return self.gateway_mac;
    }

    /// Check if gateway MAC is known
    pub fn isGatewayMacKnown(self: *const Self) bool {
        return self.gateway_mac_known;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ArpHandler init" {
    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const handler = ArpHandler.init(mac);

    try std.testing.expectEqualSlices(u8, &mac, &handler.our_mac);
    try std.testing.expect(handler.our_ip == 0);
    try std.testing.expect(!handler.gateway_mac_known);
}

test "ArpHandler configure" {
    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var handler = ArpHandler.init(mac);

    handler.configure(0x0A150001, 0x0A150001);

    try std.testing.expect(handler.our_ip == 0x0A150001);
    try std.testing.expect(handler.gateway_ip == 0x0A150001);
    try std.testing.expect(handler.need_gratuitous_arp);
    try std.testing.expect(handler.need_gateway_arp);
}

test "ArpHandler periodic GARP timing" {
    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var handler = ArpHandler.init(mac);

    // No GARP without IP configured
    try std.testing.expect(!handler.shouldSendPeriodicGarp(0));

    handler.configure(0x0A150001, 0x0A150001);
    handler.markGarpSent(0);

    // Too soon
    try std.testing.expect(!handler.shouldSendPeriodicGarp(5000));

    // After interval
    try std.testing.expect(handler.shouldSendPeriodicGarp(10001));
}

test "ArpHandler take pending reply" {
    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var handler = ArpHandler.init(mac);

    // No pending reply initially
    try std.testing.expect(handler.takePendingReply() == null);

    // Set a pending reply
    handler.pending_reply = .{
        .target_mac = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        .target_ip = 0xC0A80001,
    };

    // Take clears it
    const reply = handler.takePendingReply();
    try std.testing.expect(reply != null);
    try std.testing.expect(handler.takePendingReply() == null);
}
