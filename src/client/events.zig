//! Client Events
//!
//! Event types and callbacks for VPN client state notifications.

const std = @import("std");
const state = @import("state.zig");
const stats = @import("stats.zig");

const ClientState = state.ClientState;
const ConnectionStats = stats.ConnectionStats;
const DisconnectReason = stats.DisconnectReason;

/// Client error types
pub const ClientError = error{
    NotInitialized,
    AlreadyConnected,
    NotConnected,
    ConnectionFailed,
    ConnectionLost,
    AuthenticationFailed,
    DnsResolutionFailed,
    SslHandshakeFailed,
    SessionEstablishmentFailed,
    AdapterConfigurationFailed,
    Timeout,
    NetworkError,
    ProtocolError,
    InvalidConfiguration,
    InvalidState,
    InvalidParameter,
    OutOfMemory,
    OperationCancelled,
};

/// Event types for client callbacks
pub const ClientEvent = union(enum) {
    /// State machine transition
    state_changed: struct {
        old_state: ClientState,
        new_state: ClientState,
    },

    /// Successfully connected to VPN
    connected: struct {
        server_ip: u32,
        assigned_ip: u32,
        gateway_ip: u32,
        dns_servers: [4]u32,
    },

    /// Disconnected from VPN
    disconnected: struct {
        reason: DisconnectReason,
    },

    /// Statistics updated
    stats_updated: ConnectionStats,

    /// Error occurred
    error_occurred: struct {
        code: ClientError,
        message: []const u8,
    },

    /// DHCP configuration received
    dhcp_configured: struct {
        ip: u32,
        mask: u32,
        gateway: u32,
    },

    /// Get event type name
    pub fn name(self: ClientEvent) []const u8 {
        return switch (self) {
            .state_changed => "state_changed",
            .connected => "connected",
            .disconnected => "disconnected",
            .stats_updated => "stats_updated",
            .error_occurred => "error_occurred",
            .dhcp_configured => "dhcp_configured",
        };
    }
};

/// Event callback function type
pub const EventCallback = *const fn (event: ClientEvent, user_data: ?*anyopaque) void;

/// Event dispatcher for managing callbacks
pub const EventDispatcher = struct {
    callback: ?EventCallback = null,
    user_data: ?*anyopaque = null,

    /// Set the event callback
    pub fn setCallback(self: *EventDispatcher, callback: ?EventCallback, user_data: ?*anyopaque) void {
        self.callback = callback;
        self.user_data = user_data;
    }

    /// Dispatch an event to the callback
    pub fn dispatch(self: *const EventDispatcher, event: ClientEvent) void {
        if (self.callback) |cb| {
            cb(event, self.user_data);
        }
    }

    /// Convenience: dispatch state change event
    pub fn stateChanged(self: *const EventDispatcher, old_state: ClientState, new_state: ClientState) void {
        self.dispatch(.{ .state_changed = .{
            .old_state = old_state,
            .new_state = new_state,
        } });
    }

    /// Convenience: dispatch connected event
    pub fn connected(self: *const EventDispatcher, server_ip: u32, assigned_ip: u32, gateway_ip: u32) void {
        self.dispatch(.{ .connected = .{
            .server_ip = server_ip,
            .assigned_ip = assigned_ip,
            .gateway_ip = gateway_ip,
        } });
    }

    /// Convenience: dispatch disconnected event
    pub fn disconnected(self: *const EventDispatcher, reason: DisconnectReason) void {
        self.dispatch(.{ .disconnected = .{ .reason = reason } });
    }

    /// Convenience: dispatch error event
    pub fn errorOccurred(self: *const EventDispatcher, code: ClientError, message: []const u8) void {
        self.dispatch(.{ .error_occurred = .{
            .code = code,
            .message = message,
        } });
    }

    /// Convenience: dispatch DHCP configured event
    pub fn dhcpConfigured(self: *const EventDispatcher, ip: u32, mask: u32, gateway: u32) void {
        self.dispatch(.{ .dhcp_configured = .{
            .ip = ip,
            .mask = mask,
            .gateway = gateway,
        } });
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ClientEvent name" {
    const event = ClientEvent{ .connected = .{ .server_ip = 0, .assigned_ip = 0, .gateway_ip = 0 } };
    try std.testing.expectEqualStrings("connected", event.name());
}

test "EventDispatcher dispatch" {
    const TestContext = struct {
        var event_count: u32 = 0;

        fn callback(event: ClientEvent, user_data: ?*anyopaque) void {
            _ = event;
            _ = user_data;
            event_count += 1;
        }
    };

    TestContext.event_count = 0;

    var dispatcher = EventDispatcher{};
    dispatcher.setCallback(TestContext.callback, null);

    dispatcher.stateChanged(.disconnected, .connecting_tcp);
    try std.testing.expectEqual(@as(u32, 1), TestContext.event_count);

    dispatcher.connected(0, 0, 0);
    try std.testing.expectEqual(@as(u32, 2), TestContext.event_count);
}

test "EventDispatcher no callback" {
    var dispatcher = EventDispatcher{};
    // Should not crash when no callback set
    dispatcher.stateChanged(.disconnected, .connecting_tcp);
}
