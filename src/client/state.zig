//! Client State Machine
//!
//! Connection state management for the VPN client.

const std = @import("std");

/// Connection state
pub const ClientState = enum {
    disconnected,
    resolving_dns,
    connecting_tcp,
    ssl_handshake,
    authenticating,
    establishing_session,
    configuring_adapter,
    connected,
    reconnecting,
    disconnecting,
    error_state,

    /// Check if currently connected
    pub fn isConnected(self: ClientState) bool {
        return self == .connected;
    }

    /// Check if in a connecting state
    pub fn isConnecting(self: ClientState) bool {
        return switch (self) {
            .resolving_dns,
            .connecting_tcp,
            .ssl_handshake,
            .authenticating,
            .establishing_session,
            .configuring_adapter,
            => true,
            else => false,
        };
    }

    /// Check if a state transition is valid
    pub fn canTransitionTo(self: ClientState, next: ClientState) bool {
        return switch (self) {
            .disconnected => next == .resolving_dns or next == .error_state,
            .resolving_dns => next == .connecting_tcp or next == .error_state or next == .disconnecting,
            .connecting_tcp => next == .ssl_handshake or next == .error_state or next == .disconnecting,
            .ssl_handshake => next == .authenticating or next == .error_state or next == .disconnecting,
            .authenticating => next == .establishing_session or next == .error_state or next == .disconnecting,
            .establishing_session => next == .configuring_adapter or next == .error_state or next == .disconnecting,
            .configuring_adapter => next == .connected or next == .error_state or next == .disconnecting,
            .connected => next == .disconnecting or next == .reconnecting or next == .error_state,
            .reconnecting => next == .resolving_dns or next == .disconnected or next == .error_state,
            .disconnecting => next == .disconnected or next == .reconnecting,
            .error_state => next == .disconnected or next == .reconnecting,
        };
    }

    /// Get human-readable state name
    pub fn name(self: ClientState) []const u8 {
        return @tagName(self);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ClientState transitions" {
    try std.testing.expect(ClientState.disconnected.canTransitionTo(.resolving_dns));
    try std.testing.expect(ClientState.resolving_dns.canTransitionTo(.connecting_tcp));
    try std.testing.expect(ClientState.connected.canTransitionTo(.disconnecting));
    try std.testing.expect(!ClientState.disconnected.canTransitionTo(.connected));
}

test "ClientState predicates" {
    try std.testing.expect(ClientState.connected.isConnected());
    try std.testing.expect(!ClientState.disconnected.isConnected());
    try std.testing.expect(ClientState.resolving_dns.isConnecting());
    try std.testing.expect(ClientState.authenticating.isConnecting());
    try std.testing.expect(!ClientState.connected.isConnecting());
}

test "ClientState name" {
    try std.testing.expectEqualStrings("connected", ClientState.connected.name());
    try std.testing.expectEqualStrings("disconnected", ClientState.disconnected.name());
}
