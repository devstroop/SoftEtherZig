//! SoftEther VPN Client Library
//!
//! Public API for embedding the VPN client in other applications.
//!
//! ## Quick Start
//! ```zig
//! const softether = @import("softether");
//!
//! // Create a simple config
//! var builder = softether.ClientConfigBuilder.init("vpn.example.com", "VPN");
//! _ = builder.setPasswordAuth("user", "pass").setFullTunnel(true);
//! const config = builder.build();
//!
//! // Create and connect client
//! var client = softether.VpnClient.init(allocator, config);
//! defer client.deinit();
//!
//! try client.connect();
//! // ... run data loop in separate thread
//! ```

const std = @import("std");

// ============================================================================
// Core Client API
// ============================================================================

/// Main VPN client - use this to establish and manage VPN connections
pub const VpnClient = @import("client/mod.zig").VpnClient;

/// Client configuration struct
pub const ClientConfig = @import("client/mod.zig").ClientConfig;

/// Builder pattern for creating client configurations
pub const ClientConfigBuilder = @import("client/mod.zig").ClientConfigBuilder;

// ============================================================================
// Client State & Events
// ============================================================================

/// Connection state machine states
pub const ClientState = @import("client/mod.zig").ClientState;

/// Events emitted by the VPN client
pub const ClientEvent = @import("client/mod.zig").ClientEvent;

/// Errors that can occur during client operations
pub const ClientError = @import("client/mod.zig").ClientError;

/// Connection statistics
pub const ConnectionStats = @import("client/mod.zig").ConnectionStats;

/// Reasons for disconnection
pub const DisconnectReason = @import("client/mod.zig").DisconnectReason;

/// Event callback function type
pub const EventCallback = @import("client/mod.zig").EventCallback;

// ============================================================================
// Configuration Types
// ============================================================================

/// Authentication methods
pub const AuthMethod = @import("client/mod.zig").AuthMethod;

/// IP version preference (IPv4, IPv6, dual-stack)
pub const IpVersionPreference = @import("client/mod.zig").IpVersionPreference;

/// Reconnection behavior configuration
pub const ReconnectConfig = @import("client/mod.zig").ReconnectConfig;

// ============================================================================
// Utility Types
// ============================================================================

/// Core utilities (IP parsing, etc.)
pub const core = @import("core/mod.zig");

/// Parse an IPv4 address string to u32
pub const parseIpv4 = core.parseIpv4;

/// Format a u32 IP address to string
pub const formatIpv4 = core.formatIpv4;

// ============================================================================
// Version Information
// ============================================================================

/// Library version
pub const version = "0.2.0";

/// Get version string
pub fn getVersion() []const u8 {
    return version;
}

// ============================================================================
// Tests
// ============================================================================

test "library exports" {
    // Verify all exports are accessible
    _ = VpnClient;
    _ = ClientConfig;
    _ = ClientConfigBuilder;
    _ = ClientState;
    _ = ClientEvent;
    _ = ClientError;
    _ = ConnectionStats;
    _ = DisconnectReason;
    _ = EventCallback;
    _ = AuthMethod;
    _ = IpVersionPreference;
    _ = ReconnectConfig;
    _ = core;
    _ = parseIpv4;
    _ = formatIpv4;
}

test "version" {
    try std.testing.expectEqualStrings("0.2.0", getVersion());
}
