//! DHCP State Machine
//!
//! Handles DHCP discovery, request, and configuration for the VPN tunnel.

const std = @import("std");

/// DHCP state machine states
pub const DhcpState = enum {
    /// Initial state - no DHCP activity
    init,
    /// DHCP DISCOVER sent, waiting for OFFER
    discover_sent,
    /// DHCP REQUEST sent, waiting for ACK
    request_sent,
    /// DHCP configuration complete
    configured,

    /// Check if DHCP is fully configured
    pub fn isConfigured(self: DhcpState) bool {
        return self == .configured;
    }

    /// Check if DHCP is in progress
    pub fn isInProgress(self: DhcpState) bool {
        return self == .discover_sent or self == .request_sent;
    }
};

/// DHCP configuration received from server
pub const DhcpConfig = struct {
    ip_address: u32 = 0,
    subnet_mask: u32 = 0,
    gateway: u32 = 0,
    dns_servers: [4]u32 = .{ 0, 0, 0, 0 },
    lease_time: u32 = 0,
    server_id: u32 = 0,
};

/// DHCP handler state
pub const DhcpHandler = struct {
    state: DhcpState = .init,
    xid: u32 = 0,
    last_send_time: i64 = 0,
    retry_count: u32 = 0,
    config: DhcpConfig = .{},

    const Self = @This();
    const MAX_RETRIES: u32 = 5;
    const RETRY_INTERVAL_MS: i64 = 3000;

    /// Initialize DHCP handler with random transaction ID
    pub fn init() Self {
        var xid: u32 = 0;
        std.crypto.random.bytes(std.mem.asBytes(&xid));
        return .{ .xid = xid };
    }

    /// Check if we should send/retry DHCP discover
    pub fn shouldSendDiscover(self: *const Self, now: i64) bool {
        if (self.state == .init) return true;
        if (self.state == .discover_sent and self.retry_count < MAX_RETRIES) {
            return now - self.last_send_time >= RETRY_INTERVAL_MS;
        }
        return false;
    }

    /// Record that DISCOVER was sent
    pub fn markDiscoverSent(self: *Self, now: i64) void {
        if (self.state == .discover_sent) {
            self.retry_count += 1;
        } else {
            self.state = .discover_sent;
            self.retry_count = 0;
        }
        self.last_send_time = now;
    }

    /// Record that REQUEST was sent
    pub fn markRequestSent(self: *Self, now: i64) void {
        self.state = .request_sent;
        self.last_send_time = now;
    }

    /// Record that configuration is complete
    pub fn markConfigured(self: *Self, config: DhcpConfig) void {
        self.state = .configured;
        self.config = config;
    }

    /// Get the transaction ID
    pub fn getXid(self: *const Self) u32 {
        return self.xid;
    }

    /// Get current configuration (valid only if configured)
    pub fn getConfig(self: *const Self) ?DhcpConfig {
        if (self.state == .configured) {
            return self.config;
        }
        return null;
    }

    /// Reset to initial state
    pub fn reset(self: *Self) void {
        self.state = .init;
        self.retry_count = 0;
        self.last_send_time = 0;
        self.config = .{};
        // Generate new XID for next attempt
        std.crypto.random.bytes(std.mem.asBytes(&self.xid));
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DhcpState transitions" {
    try std.testing.expect(DhcpState.init.isConfigured() == false);
    try std.testing.expect(DhcpState.configured.isConfigured() == true);
    try std.testing.expect(DhcpState.discover_sent.isInProgress() == true);
    try std.testing.expect(DhcpState.request_sent.isInProgress() == true);
    try std.testing.expect(DhcpState.configured.isInProgress() == false);
}

test "DhcpHandler init" {
    const handler = DhcpHandler.init();
    try std.testing.expect(handler.state == .init);
    try std.testing.expect(handler.xid != 0);
    try std.testing.expect(handler.retry_count == 0);
}

test "DhcpHandler shouldSendDiscover" {
    var handler = DhcpHandler.init();

    // Initial state should send
    try std.testing.expect(handler.shouldSendDiscover(0));

    // After marking sent, shouldn't send immediately
    handler.markDiscoverSent(0);
    try std.testing.expect(!handler.shouldSendDiscover(1000));

    // After retry interval, should send again
    try std.testing.expect(handler.shouldSendDiscover(3001));
}

test "DhcpHandler configuration flow" {
    var handler = DhcpHandler.init();

    handler.markDiscoverSent(0);
    try std.testing.expect(handler.state == .discover_sent);

    handler.markRequestSent(100);
    try std.testing.expect(handler.state == .request_sent);

    const config = DhcpConfig{
        .ip_address = 0x0A150001, // 10.21.0.1
        .gateway = 0x0A150001,
    };
    handler.markConfigured(config);
    try std.testing.expect(handler.state == .configured);
    try std.testing.expect(handler.getConfig().?.ip_address == 0x0A150001);
}

test "DhcpHandler reset" {
    var handler = DhcpHandler.init();
    const original_xid = handler.xid;

    handler.markDiscoverSent(0);
    handler.reset();

    try std.testing.expect(handler.state == .init);
    try std.testing.expect(handler.retry_count == 0);
    // XID should change after reset
    try std.testing.expect(handler.xid != original_xid);
}
