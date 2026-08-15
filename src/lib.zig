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
//! _ = builder.setPasswordAuth("user", "pass").setDefaultRoute(true);
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
pub const VpnClient = @import("cedar/client/mod.zig").VpnClient;

/// Client configuration struct
pub const ClientConfig = @import("cedar/client/mod.zig").ClientConfig;

/// Builder pattern for creating client configurations
pub const ClientConfigBuilder = @import("cedar/client/mod.zig").ClientConfigBuilder;

// ============================================================================
// Client State & Events
// ============================================================================

/// Connection state machine states
pub const ClientState = @import("cedar/client/mod.zig").ClientState;

/// Events emitted by the VPN client
pub const ClientEvent = @import("cedar/client/mod.zig").ClientEvent;

/// Errors that can occur during client operations
pub const ClientError = @import("cedar/client/mod.zig").ClientError;

/// Connection statistics
pub const ConnectionStats = @import("cedar/client/mod.zig").ConnectionStats;

/// Reasons for disconnection
pub const DisconnectReason = @import("cedar/client/mod.zig").DisconnectReason;

/// Event callback function type
pub const EventCallback = @import("cedar/client/mod.zig").EventCallback;

// ============================================================================
// Configuration Types
// ============================================================================

/// Authentication methods
pub const AuthMethod = @import("cedar/client/mod.zig").AuthMethod;

/// Reconnection behavior configuration
pub const ReconnectConfig = @import("cedar/client/mod.zig").ReconnectConfig;

// ============================================================================
// Utility Types
// ============================================================================

/// Core utilities (IP parsing, etc.)
pub const core = @import("mayaqua/kernel/mod.zig");

// L2 bridge core (proposal §4.3) — pure logic, no I/O
pub const bridge = struct {
    pub const fdb = @import("bridge/fdb.zig");
    pub const engine = @import("bridge/engine.zig");
};

// Server core (M1 epic) — session keys, data-channel encryption, session loop
pub const server = struct {
    pub const auth = @import("cedar/server/auth.zig");
    pub const session = @import("cedar/server/session.zig");
    pub const session_main = @import("cedar/server/session_main.zig");
};

/// Parse an IPv4 address string to u32
pub const parseIpv4 = core.parseIpv4;

/// Format a u32 IP address to string
pub const formatIpv4 = core.formatIpv4;

// ============================================================================
// Version Information
// ============================================================================

/// Library version (from build.zig.zon via build_options)
pub const version = @import("build_options").version;

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
    _ = ReconnectConfig;
    _ = core;
    _ = bridge;
    _ = server;
    _ = parseIpv4;
    _ = formatIpv4;
}

test "version" {
    try std.testing.expectEqualStrings(@import("build_options").version, getVersion());
}
