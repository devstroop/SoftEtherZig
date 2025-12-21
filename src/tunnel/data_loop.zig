//! Data Loop
//!
//! Main packet processing loop for VPN tunnel.
//! Handles bidirectional packet flow between TLS socket and TUN device.
//!
//! This module provides:
//! - DataLoopState: State machine for DHCP/ARP/routing
//! - Utility functions for Ethernet frame handling
//! - IP packet parsing helpers for logging

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import protocol tunnel for TunnelConnection
const protocol_tunnel = @import("../protocol/tunnel.zig");
const TunnelConnection = protocol_tunnel.TunnelConnection;

// Import adapter for packet building
const adapter_mod = @import("../adapter/mod.zig");

// Import local modules
const dhcp_mod = @import("dhcp.zig");
const arp_mod = @import("arp.zig");

pub const DhcpState = dhcp_mod.DhcpState;
pub const DhcpHandler = dhcp_mod.DhcpHandler;
pub const ArpHandler = arp_mod.ArpHandler;

/// Parsed IPv4 header info for logging
pub const Ipv4Info = struct {
    src_ip: u32,
    dst_ip: u32,
    protocol: u8,
    total_len: u16,
};

/// Parse IPv4 header from packet
pub fn parseIpv4Header(packet: []const u8) ?Ipv4Info {
    if (packet.len < 20) return null;

    const version = (packet[0] >> 4) & 0x0F;
    if (version != 4) return null;

    return .{
        .src_ip = (@as(u32, packet[12]) << 24) |
            (@as(u32, packet[13]) << 16) |
            (@as(u32, packet[14]) << 8) |
            packet[15],
        .dst_ip = (@as(u32, packet[16]) << 24) |
            (@as(u32, packet[17]) << 16) |
            (@as(u32, packet[18]) << 8) |
            packet[19],
        .protocol = packet[9],
        .total_len = (@as(u16, packet[2]) << 8) | packet[3],
    };
}

/// Extract sender IP from ARP packet (bytes 28-31)
pub fn getArpSenderIp(eth_frame: []const u8) ?u32 {
    if (eth_frame.len < 32) return null;
    if (!isArpPacket(eth_frame)) return null;
    return (@as(u32, eth_frame[28]) << 24) |
        (@as(u32, eth_frame[29]) << 16) |
        (@as(u32, eth_frame[30]) << 8) |
        eth_frame[31];
}

/// Extract sender MAC from ARP packet (bytes 22-27)
pub fn getArpSenderMac(eth_frame: []const u8) ?[6]u8 {
    if (eth_frame.len < 28) return null;
    if (!isArpPacket(eth_frame)) return null;
    var mac: [6]u8 = undefined;
    @memcpy(&mac, eth_frame[22..28]);
    return mac;
}

/// Extract target IP from ARP packet (bytes 38-41)
pub fn getArpTargetIp(eth_frame: []const u8) ?u32 {
    if (eth_frame.len < 42) return null;
    if (!isArpPacket(eth_frame)) return null;
    return (@as(u32, eth_frame[38]) << 24) |
        (@as(u32, eth_frame[39]) << 16) |
        (@as(u32, eth_frame[40]) << 8) |
        eth_frame[41];
}

/// Configuration for the data loop
pub const DataLoopConfig = struct {
    /// Keepalive interval in milliseconds
    keepalive_interval_ms: i64 = 5000,
    /// Gratuitous ARP interval in milliseconds
    garp_interval_ms: i64 = 10000,
    /// DHCP retry interval in milliseconds
    dhcp_retry_interval_ms: i64 = 3000,
    /// Maximum DHCP retries
    max_dhcp_retries: u32 = 5,
    /// Enable full tunnel routing
    full_tunnel: bool = true,
    /// Initial delay before DHCP discover (ms)
    initial_delay_ms: u32 = 300,
};

/// Timing state for the data loop
pub const TimingState = struct {
    last_keepalive: i64,
    last_garp_time: i64,
    last_dhcp_time: i64,

    pub fn init() TimingState {
        const now = std.time.milliTimestamp();
        return .{
            .last_keepalive = now,
            .last_garp_time = 0,
            .last_dhcp_time = 0,
        };
    }

    pub fn shouldSendKeepalive(self: *const TimingState, now: i64, interval_ms: i64) bool {
        return now - self.last_keepalive >= interval_ms;
    }

    pub fn shouldSendGarp(self: *const TimingState, now: i64, interval_ms: i64) bool {
        return now - self.last_garp_time >= interval_ms;
    }

    pub fn shouldRetryDhcp(self: *const TimingState, now: i64, retry_interval_ms: i64) bool {
        return now - self.last_dhcp_time >= retry_interval_ms;
    }
};

/// Callbacks for data loop events
pub const DataLoopCallbacks = struct {
    /// Called when DHCP configuration is complete
    on_dhcp_configured: ?*const fn (ip: u32, mask: u32, gateway: u32, user_data: ?*anyopaque) void = null,
    /// Called when stats should be updated
    on_stats_sent: ?*const fn (bytes: usize, user_data: ?*anyopaque) void = null,
    on_stats_received: ?*const fn (bytes: usize, user_data: ?*anyopaque) void = null,
    /// User data passed to callbacks
    user_data: ?*anyopaque = null,
};

/// Result of processing a single iteration
pub const LoopResult = enum {
    /// Continue processing
    continue_loop,
    /// Stop requested
    stop_requested,
    /// Connection closed by server
    connection_closed,
    /// Error occurred
    error_occurred,
};

/// State for the data loop
pub const DataLoopState = struct {
    // DHCP state
    dhcp: DhcpHandler,
    dhcp_retry_count: u32 = 0,

    // ARP state
    arp: ArpHandler,

    // Pending ARP actions
    need_gateway_arp: bool = false,
    need_gratuitous_arp: bool = false,
    need_arp_reply: bool = false,
    arp_reply_target_mac: [6]u8 = undefined,
    arp_reply_target_ip: u32 = 0,

    // Assigned addresses
    our_ip: u32 = 0,
    our_gateway: u32 = 0,
    gateway_mac: [6]u8 = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    server_ip: u32 = 0,

    // MAC address
    mac: [6]u8,

    // Timing
    timing: TimingState,

    // Flags
    is_configured: bool = false,

    const Self = @This();

    pub fn init(mac: [6]u8) Self {
        return .{
            .dhcp = DhcpHandler.init(),
            .arp = ArpHandler.init(mac),
            .mac = mac,
            .timing = TimingState.init(),
        };
    }

    pub fn isConfigured(self: *const Self) bool {
        return self.dhcp.state.isConfigured();
    }

    pub fn configure(self: *Self, ip: u32, gateway: u32) void {
        self.our_ip = ip;
        self.our_gateway = gateway;
        self.arp.configure(ip, gateway);
        self.is_configured = true;
        // Queue required ARP operations
        self.need_gratuitous_arp = true;
        self.need_gateway_arp = true;
    }

    /// Process an ARP reply - learn MAC if it's from gateway
    pub fn processArpReply(self: *Self, eth_frame: []const u8) void {
        const sender_ip = getArpSenderIp(eth_frame) orelse return;
        if (self.our_gateway != 0 and sender_ip == self.our_gateway) {
            if (getArpSenderMac(eth_frame)) |sender_mac| {
                self.gateway_mac = sender_mac;
                std.log.debug("Learned gateway MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                    sender_mac[0], sender_mac[1], sender_mac[2],
                    sender_mac[3], sender_mac[4], sender_mac[5],
                });
            }
        }
    }

    /// Process an ARP request - queue reply if asking for our IP
    pub fn processArpRequest(self: *Self, eth_frame: []const u8) void {
        const target_ip = getArpTargetIp(eth_frame) orelse return;
        if (target_ip == self.our_ip and self.our_ip != 0) {
            if (getArpSenderMac(eth_frame)) |sender_mac| {
                self.arp_reply_target_mac = sender_mac;
            }
            self.arp_reply_target_ip = getArpSenderIp(eth_frame) orelse return;
            self.need_arp_reply = true;
        }
    }
};

/// Format an IP address for logging
pub fn formatIpForLog(ip: u32) struct { a: u8, b: u8, c: u8, d: u8 } {
    return .{
        .a = @truncate(ip >> 24),
        .b = @truncate(ip >> 16),
        .c = @truncate(ip >> 8),
        .d = @truncate(ip),
    };
}

/// Build an Ethernet frame from an IP packet
pub fn wrapIpInEthernet(
    ip_packet: []const u8,
    dst_mac: [6]u8,
    src_mac: [6]u8,
    buffer: []u8,
) ?[]u8 {
    if (ip_packet.len == 0 or ip_packet.len > 1500) return null;
    if (buffer.len < 14 + ip_packet.len) return null;

    const ip_version = (ip_packet[0] >> 4) & 0x0F;

    // Set destination MAC
    @memcpy(buffer[0..6], &dst_mac);
    // Set source MAC
    @memcpy(buffer[6..12], &src_mac);

    // Set EtherType
    if (ip_version == 4) {
        buffer[12] = 0x08;
        buffer[13] = 0x00;
    } else if (ip_version == 6) {
        buffer[12] = 0x86;
        buffer[13] = 0xDD;
    } else {
        return null;
    }

    // Copy IP packet
    @memcpy(buffer[14..][0..ip_packet.len], ip_packet);

    return buffer[0 .. 14 + ip_packet.len];
}

/// Extract IP packet from Ethernet frame (strip header)
pub fn unwrapEthernetToIp(eth_frame: []const u8) ?[]const u8 {
    if (eth_frame.len <= 14) return null;

    const ethertype_hi = eth_frame[12];
    const ethertype_lo = eth_frame[13];

    // Check for IPv4 (0x0800) or IPv6 (0x86DD)
    if ((ethertype_hi == 0x08 and ethertype_lo == 0x00) or
        (ethertype_hi == 0x86 and ethertype_lo == 0xDD))
    {
        return eth_frame[14..];
    }

    return null;
}

/// Check if an Ethernet frame is an ARP packet
pub fn isArpPacket(eth_frame: []const u8) bool {
    if (eth_frame.len < 14) return false;
    return eth_frame[12] == 0x08 and eth_frame[13] == 0x06;
}

/// Get ARP operation from frame (1=request, 2=reply)
pub fn getArpOperation(eth_frame: []const u8) ?u16 {
    if (eth_frame.len < 22) return null;
    if (!isArpPacket(eth_frame)) return null;
    return (@as(u16, eth_frame[20]) << 8) | eth_frame[21];
}

// ============================================================================
// Tests
// ============================================================================

test "DataLoopState init" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 };
    var state = DataLoopState.init(mac);

    try std.testing.expect(!state.isConfigured());
    try std.testing.expectEqual(@as(u32, 0), state.our_ip);
}

test "DataLoopState configure" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 };
    var state = DataLoopState.init(mac);

    state.configure(0x0A150001, 0x0A150001);

    try std.testing.expect(state.is_configured);
    try std.testing.expectEqual(@as(u32, 0x0A150001), state.our_ip);
}

test "formatIpForLog" {
    const ip: u32 = 0xC0A80101; // 192.168.1.1
    const parts = formatIpForLog(ip);

    try std.testing.expectEqual(@as(u8, 192), parts.a);
    try std.testing.expectEqual(@as(u8, 168), parts.b);
    try std.testing.expectEqual(@as(u8, 1), parts.c);
    try std.testing.expectEqual(@as(u8, 1), parts.d);
}

test "wrapIpInEthernet IPv4" {
    const ip_packet = [_]u8{ 0x45, 0x00, 0x00, 0x14 } ++ [_]u8{0} ** 16; // Minimal IPv4 header
    const dst_mac = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const src_mac = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 };
    var buffer: [2048]u8 = undefined;

    const result = wrapIpInEthernet(&ip_packet, dst_mac, src_mac, &buffer);

    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 14 + 20), result.?.len);
    // Check EtherType is IPv4
    try std.testing.expectEqual(@as(u8, 0x08), result.?[12]);
    try std.testing.expectEqual(@as(u8, 0x00), result.?[13]);
}

test "wrapIpInEthernet IPv6" {
    const ip_packet = [_]u8{ 0x60, 0x00, 0x00, 0x00 } ++ [_]u8{0} ** 36; // Minimal IPv6 header
    const dst_mac = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const src_mac = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 };
    var buffer: [2048]u8 = undefined;

    const result = wrapIpInEthernet(&ip_packet, dst_mac, src_mac, &buffer);

    try std.testing.expect(result != null);
    // Check EtherType is IPv6
    try std.testing.expectEqual(@as(u8, 0x86), result.?[12]);
    try std.testing.expectEqual(@as(u8, 0xDD), result.?[13]);
}

test "unwrapEthernetToIp" {
    // Build a fake Ethernet frame with IPv4
    var frame: [34]u8 = undefined;
    frame[12] = 0x08; // EtherType IPv4
    frame[13] = 0x00;
    frame[14] = 0x45; // IP version 4

    const ip_packet = unwrapEthernetToIp(&frame);

    try std.testing.expect(ip_packet != null);
    try std.testing.expectEqual(@as(usize, 20), ip_packet.?.len);
    try std.testing.expectEqual(@as(u8, 0x45), ip_packet.?[0]);
}

test "isArpPacket" {
    var arp_frame: [42]u8 = undefined;
    arp_frame[12] = 0x08;
    arp_frame[13] = 0x06;

    try std.testing.expect(isArpPacket(&arp_frame));

    var ip_frame: [34]u8 = undefined;
    ip_frame[12] = 0x08;
    ip_frame[13] = 0x00;

    try std.testing.expect(!isArpPacket(&ip_frame));
}

test "getArpOperation" {
    var arp_request: [42]u8 = undefined;
    arp_request[12] = 0x08;
    arp_request[13] = 0x06;
    arp_request[20] = 0x00;
    arp_request[21] = 0x01; // ARP Request

    try std.testing.expectEqual(@as(?u16, 1), getArpOperation(&arp_request));

    var arp_reply: [42]u8 = undefined;
    arp_reply[12] = 0x08;
    arp_reply[13] = 0x06;
    arp_reply[20] = 0x00;
    arp_reply[21] = 0x02; // ARP Reply

    try std.testing.expectEqual(@as(?u16, 2), getArpOperation(&arp_reply));
}
