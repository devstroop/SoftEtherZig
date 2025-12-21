//! SoftEther VPN Client Module
//!
//! High-level VPN client API.
//!
//! This module provides a complete VPN client implementation
//! without any C dependencies.
//!
//! ## Components
//!
//! - `vpn_client`: Main VPN client facade and configuration
//! - `state`: Connection state machine
//! - `stats`: Connection statistics and disconnect reasons
//! - `events`: Event types and callbacks
//! - `connection`: TCP/TLS connection management
//! - `packet_processor`: Packet classification and processing
//!
//! ## Usage
//!
//! ```zig
//! const client = @import("client");
//!
//! // Create configuration
//! var builder = client.ClientConfigBuilder.init("vpn.example.com", "DEFAULT");
//! const config = builder
//!     .setPort(443)
//!     .setPasswordAuth("user", "pass")
//!     .setFullTunnel(true)
//!     .build();
//!
//! // Create and connect
//! var vpn = client.VpnClient.init(allocator, config);
//! defer vpn.deinit();
//!
//! try vpn.connect();
//! defer vpn.disconnect() catch {};
//!
//! // Check status
//! if (vpn.isConnected()) {
//!     const stats = vpn.getStats();
//!     std.debug.print("Bytes sent: {}\n", .{stats.bytes_sent});
//! }
//! ```

const std = @import("std");

// Submodules
pub const vpn_client = @import("vpn_client.zig");
pub const connection = @import("connection.zig");
pub const packet_processor = @import("packet_processor.zig");
pub const state = @import("state.zig");
pub const stats = @import("stats.zig");
pub const events = @import("events.zig");

// Main client types
pub const VpnClient = vpn_client.VpnClient;
pub const ClientConfig = vpn_client.ClientConfig;
pub const ClientConfigBuilder = vpn_client.ClientConfigBuilder;

// State machine (from state.zig)
pub const ClientState = state.ClientState;

// Statistics (from stats.zig)
pub const ConnectionStats = stats.ConnectionStats;
pub const DisconnectReason = stats.DisconnectReason;

// Events (from events.zig)
pub const ClientEvent = events.ClientEvent;
pub const ClientError = events.ClientError;
pub const EventCallback = events.EventCallback;
pub const EventDispatcher = events.EventDispatcher;

// Configuration types
pub const AuthMethod = vpn_client.AuthMethod;
pub const ReconnectConfig = vpn_client.ReconnectConfig;
pub const StaticIpConfig = vpn_client.StaticIpConfig;
pub const RoutingConfig = vpn_client.RoutingConfig;

// Connection types
pub const TcpConnection = connection.TcpConnection;
pub const ConnectionPool = connection.ConnectionPool;
pub const ConnectionParams = connection.ConnectionParams;
pub const ConnectionState = connection.ConnectionState;
pub const ConnectionStatistics = connection.ConnectionStatistics;
pub const ConnectionError = connection.ConnectionError;
pub const TransportType = connection.TransportType;
pub const ProxyConfig = connection.ProxyConfig;

// Keep-alive and reconnection
pub const KeepAliveManager = connection.KeepAliveManager;
pub const ReconnectManager = connection.ReconnectManager;
pub const ReconnectStrategy = connection.ReconnectStrategy;

// Packet processing types
pub const PacketProcessor = packet_processor.PacketProcessor;
pub const PacketQueue = packet_processor.PacketQueue;
pub const PacketInfo = packet_processor.PacketInfo;
pub const PacketClass = packet_processor.PacketClass;
pub const PacketAction = packet_processor.PacketAction;

// Protocol headers
pub const EthernetHeader = packet_processor.EthernetHeader;
pub const Ipv4Header = packet_processor.Ipv4Header;
pub const Ipv6Header = packet_processor.Ipv6Header;
pub const ArpHeader = packet_processor.ArpHeader;
pub const EtherType = packet_processor.EtherType;
pub const IpProtocol = packet_processor.IpProtocol;

// Packet classification
pub const classifyPacket = packet_processor.classifyPacket;

// ============================================================================
// Convenience Functions
// ============================================================================

/// Create a simple VPN client with password authentication
pub fn createPasswordClient(
    allocator: std.mem.Allocator,
    host: []const u8,
    hub: []const u8,
    username: []const u8,
    password: []const u8,
) VpnClient {
    var builder = ClientConfigBuilder.init(host, hub);
    const config = builder
        .setPasswordAuth(username, password)
        .setFullTunnel(true)
        .build();

    return VpnClient.init(allocator, config);
}

/// Create a VPN client with anonymous authentication
pub fn createAnonymousClient(
    allocator: std.mem.Allocator,
    host: []const u8,
    hub: []const u8,
) VpnClient {
    const config = ClientConfig{
        .server_host = host,
        .hub_name = hub,
        .auth = .{ .anonymous = {} },
    };

    return VpnClient.init(allocator, config);
}

/// Format IP address as string
pub fn formatIp(ip: u32, buffer: []u8) []const u8 {
    const len = std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    }) catch return "";
    return buffer[0..len.len];
}

/// Format MAC address as string
pub fn formatMac(mac: [6]u8, buffer: []u8) []const u8 {
    const len = std.fmt.bufPrint(buffer, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch return "";
    return buffer[0..len.len];
}

// ============================================================================
// Tests
// ============================================================================

test "module imports" {
    // Verify all types are accessible
    _ = VpnClient;
    _ = ClientConfig;
    _ = ClientConfigBuilder;
    _ = TcpConnection;
    _ = PacketProcessor;
    _ = EthernetHeader;
}

test "createPasswordClient" {
    var client = createPasswordClient(
        std.testing.allocator,
        "192.168.1.1",
        "VPN",
        "user",
        "pass",
    );
    defer client.deinit();

    try std.testing.expectEqual(ClientState.disconnected, client.getState());
}

test "createAnonymousClient" {
    var client = createAnonymousClient(
        std.testing.allocator,
        "192.168.1.1",
        "DEFAULT",
    );
    defer client.deinit();

    try std.testing.expect(!client.isConnected());
}

test "formatIp" {
    var buffer: [16]u8 = undefined;
    const str = formatIp(0xC0A80101, &buffer);
    try std.testing.expectEqualStrings("192.168.1.1", str);
}

test "formatMac" {
    var buffer: [18]u8 = undefined;
    const str = formatMac(.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, &buffer);
    try std.testing.expectEqualStrings("00:11:22:33:44:55", str);
}

// Run all submodule tests
test {
    std.testing.refAllDecls(@This());
}
