//! Client Statistics
//!
//! Connection statistics and disconnect reasons.

const std = @import("std");

/// Connection statistics
pub const ConnectionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    connect_time_ms: i64 = 0,
    connected_duration_ms: u64 = 0,
    reconnect_count: u32 = 0,
    last_activity_time_ms: i64 = 0,

    /// Update last activity timestamp
    pub fn updateActivity(self: *ConnectionStats) void {
        self.last_activity_time_ms = std.time.milliTimestamp();
    }

    /// Record bytes/packets sent
    pub fn recordSent(self: *ConnectionStats, bytes: usize) void {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
        self.updateActivity();
    }

    /// Record bytes/packets received
    pub fn recordReceived(self: *ConnectionStats, bytes: usize) void {
        self.bytes_received += bytes;
        self.packets_received += 1;
        self.updateActivity();
    }

    /// Get connection uptime in milliseconds
    pub fn getUptime(self: *const ConnectionStats) u64 {
        if (self.connect_time_ms == 0) return 0;
        const now = std.time.milliTimestamp();
        if (now < self.connect_time_ms) return 0;
        return @intCast(now - self.connect_time_ms);
    }

    /// Reset all statistics
    pub fn reset(self: *ConnectionStats) void {
        self.* = ConnectionStats{};
    }

    /// Get throughput in bytes per second (approximate)
    pub fn getThroughput(self: *const ConnectionStats) struct { send_bps: u64, recv_bps: u64 } {
        const uptime_sec = self.getUptime() / 1000;
        if (uptime_sec == 0) return .{ .send_bps = 0, .recv_bps = 0 };
        return .{
            .send_bps = self.bytes_sent / uptime_sec,
            .recv_bps = self.bytes_received / uptime_sec,
        };
    }
};

/// Disconnect reason
pub const DisconnectReason = enum {
    none,
    user_requested,
    server_closed,
    auth_failed,
    timeout,
    network_error,
    protocol_error,
    configuration_error,

    /// Check if disconnect was intentional
    pub fn isIntentional(self: DisconnectReason) bool {
        return self == .user_requested;
    }

    /// Check if reconnection should be attempted
    pub fn shouldReconnect(self: DisconnectReason) bool {
        return switch (self) {
            .none, .user_requested, .auth_failed, .configuration_error => false,
            .server_closed, .timeout, .network_error, .protocol_error => true,
        };
    }

    /// Get human-readable description
    pub fn description(self: DisconnectReason) []const u8 {
        return switch (self) {
            .none => "No disconnect",
            .user_requested => "Disconnected by user",
            .server_closed => "Server closed connection",
            .auth_failed => "Authentication failed",
            .timeout => "Connection timed out",
            .network_error => "Network error",
            .protocol_error => "Protocol error",
            .configuration_error => "Configuration error",
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ConnectionStats tracking" {
    var stats = ConnectionStats{};
    stats.recordSent(100);
    try std.testing.expectEqual(@as(u64, 100), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1), stats.packets_sent);
    stats.recordReceived(200);
    try std.testing.expectEqual(@as(u64, 200), stats.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), stats.packets_received);
}

test "ConnectionStats reset" {
    var stats = ConnectionStats{};
    stats.recordSent(100);
    stats.recordReceived(200);
    stats.reset();
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_received);
}

test "DisconnectReason shouldReconnect" {
    try std.testing.expect(!DisconnectReason.user_requested.shouldReconnect());
    try std.testing.expect(!DisconnectReason.auth_failed.shouldReconnect());
    try std.testing.expect(DisconnectReason.server_closed.shouldReconnect());
    try std.testing.expect(DisconnectReason.network_error.shouldReconnect());
}

test "DisconnectReason isIntentional" {
    try std.testing.expect(DisconnectReason.user_requested.isIntentional());
    try std.testing.expect(!DisconnectReason.server_closed.isIntentional());
}
