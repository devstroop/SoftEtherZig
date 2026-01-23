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
    /// Renewing lease (unicast to original server, T1 elapsed)
    renewing,
    /// Rebinding lease (broadcast to any server, T2 elapsed)
    rebinding,

    /// Check if DHCP is fully configured
    pub fn isConfigured(self: DhcpState) bool {
        return self == .configured;
    }

    /// Check if DHCP is in progress
    pub fn isInProgress(self: DhcpState) bool {
        return self == .discover_sent or self == .request_sent or self == .renewing or self == .rebinding;
    }
};

/// DHCP configuration received from server
pub const DhcpConfig = struct {
    ip_address: u32 = 0,
    subnet_mask: u32 = 0,
    gateway: u32 = 0,
    dns_servers: [4]u32 = .{ 0, 0, 0, 0 },
    lease_time: u32 = 0,
    /// Renewal time (T1) in seconds - time to renew with original server.
    /// Default: lease_time / 2
    renewal_time: u32 = 0,
    /// Rebinding time (T2) in seconds - time to rebind with any server.
    /// Default: lease_time * 7 / 8
    rebinding_time: u32 = 0,
    server_id: u32 = 0,
};

/// DHCP handler state
pub const DhcpHandler = struct {
    state: DhcpState = .init,
    xid: u32 = 0,
    last_send_time: i64 = 0,
    retry_count: u32 = 0,
    config: DhcpConfig = .{},
    /// When the lease was obtained (timestamp in milliseconds)
    lease_obtained_at: i64 = 0,

    const Self = @This();
    const MAX_RETRIES: u32 = 5;
    const RETRY_INTERVAL_MS: i64 = 3000;

    /// Initialize DHCP handler with random transaction ID
    pub fn init() Self {
        var xid: u32 = 0;
        std.crypto.random.bytes(std.mem.asBytes(&xid));
        return .{ .xid = xid };
    }

    /// Check if lease needs renewal (T1 elapsed).
    /// Returns true if we're in configured state and T1 time has elapsed.
    pub fn needsRenewal(self: *const Self, now: i64) bool {
        if (self.state != .configured) return false;
        if (self.lease_obtained_at == 0) return false;
        const renewal_time = if (self.config.renewal_time > 0)
            self.config.renewal_time
        else
            self.config.lease_time / 2;
        if (renewal_time == 0) return false;
        const elapsed_seconds = @divTrunc(now - self.lease_obtained_at, 1000);
        return elapsed_seconds >= renewal_time;
    }

    /// Check if lease needs rebinding (T2 elapsed).
    /// Returns true if we're in configured or renewing state and T2 time has elapsed.
    pub fn needsRebinding(self: *const Self, now: i64) bool {
        if (self.state != .configured and self.state != .renewing) return false;
        if (self.lease_obtained_at == 0) return false;
        const rebinding_time = if (self.config.rebinding_time > 0)
            self.config.rebinding_time
        else
            self.config.lease_time * 7 / 8;
        if (rebinding_time == 0) return false;
        const elapsed_seconds = @divTrunc(now - self.lease_obtained_at, 1000);
        return elapsed_seconds >= rebinding_time;
    }

    /// Check if lease has expired.
    pub fn isLeaseExpired(self: *const Self, now: i64) bool {
        if (self.lease_obtained_at == 0 or self.config.lease_time == 0) return false;
        const elapsed_seconds = @divTrunc(now - self.lease_obtained_at, 1000);
        return elapsed_seconds >= self.config.lease_time;
    }

    /// Start renewal process (T1 elapsed)
    pub fn startRenewal(self: *Self, now: i64) void {
        if (self.state != .configured) return;
        self.state = .renewing;
        self.retry_count = 0;
        self.last_send_time = now;
        std.log.info("Starting DHCP renewal (T1 elapsed)", .{});
    }

    /// Start rebinding process (T2 elapsed)
    pub fn startRebinding(self: *Self, now: i64) void {
        if (self.state != .configured and self.state != .renewing) return;
        self.state = .rebinding;
        self.retry_count = 0;
        self.last_send_time = now;
        std.log.info("Starting DHCP rebind (T2 elapsed)", .{});
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
    pub fn markConfigured(self: *Self, config: DhcpConfig, now: i64) void {
        self.state = .configured;
        self.config = config;
        self.lease_obtained_at = now;
        self.retry_count = 0;

        // Calculate default T1/T2 if not provided
        if (self.config.renewal_time == 0 and self.config.lease_time > 0) {
            self.config.renewal_time = self.config.lease_time / 2;
        }
        if (self.config.rebinding_time == 0 and self.config.lease_time > 0) {
            self.config.rebinding_time = self.config.lease_time * 7 / 8;
        }

        std.log.info("DHCP configured: lease={}s, T1={}s, T2={}s", .{
            self.config.lease_time,
            self.config.renewal_time,
            self.config.rebinding_time,
        });
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
        self.lease_obtained_at = 0;
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
        .lease_time = 3600, // 1 hour
    };
    handler.markConfigured(config, 200);
    try std.testing.expect(handler.state == .configured);
    try std.testing.expect(handler.getConfig().?.ip_address == 0x0A150001);
    try std.testing.expect(handler.lease_obtained_at == 200);
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
