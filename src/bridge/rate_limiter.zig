//! Per-port token-bucket rate limiter for the L2 bridge.
//!
//! Used by the bridge loop to enforce per-port ingress/egress bandwidth
//! limits. Each port gets an independent bucket that refills at the
//! configured rate up to a burst capacity.
//!
//! The limiter is not thread-safe — the bridge loop is the sole caller.

const std = @import("std");

/// Token bucket rate limiter. `capacity` is the burst size in bytes;
/// `rate` is bytes per second refill rate. Tokens are consumed by
/// frame size; frames exceeding the remaining tokens are dropped.
pub const TokenBucket = struct {
    /// Maximum burst size in bytes.
    capacity: u64,
    /// Refill rate in bytes per second.
    rate: u64,
    /// Current available tokens (bytes).
    tokens: u64,
    /// Last refill timestamp (nanoseconds).
    last_refill_ns: i64,

    pub const Config = struct {
        /// Burst capacity in bytes. 0 = unlimited (no rate limiting).
        capacity: u64 = 0,
        /// Sustained rate in bytes/second. 0 = unlimited.
        rate: u64 = 0,
    };

    pub fn init(config: Config) TokenBucket {
        return .{
            .capacity = config.capacity,
            .rate = config.rate,
            .tokens = config.capacity,
            .last_refill_ns = @intCast(std.time.nanoTimestamp()),
        };
    }

    /// Try to consume `bytes` tokens. Returns true if allowed, false if
    /// rate-limited. Refills tokens based on elapsed time since last call.
    /// A config with rate=0 OR capacity=0 means unlimited (always allowed).
    pub fn consume(self: *TokenBucket, bytes: u64) bool {
        if (self.rate == 0 or self.capacity == 0) return true; // unlimited

        const now_ns: i64 = @intCast(std.time.nanoTimestamp());
        const elapsed_ns: u64 = @intCast(@max(0, now_ns - self.last_refill_ns));
        self.last_refill_ns = now_ns;

        // Refill tokens based on elapsed time.
        const max_refill = self.capacity - self.tokens;
        const raw_refill = self.rate * elapsed_ns / std.time.ns_per_s;
        const refill = @min(max_refill, raw_refill);
        self.tokens += refill;

        if (bytes <= self.tokens) {
            self.tokens -= bytes;
            return true;
        }
        return false;
    }

    /// Update rate/capacity without resetting the token count.
    pub fn reconfigure(self: *TokenBucket, config: Config) void {
        self.capacity = config.capacity;
        self.rate = config.rate;
        if (self.tokens > self.capacity) self.tokens = self.capacity;
    }
};

/// Per-port rate limit configuration stored alongside the engine.
pub const PortRateLimit = struct {
    ingress: TokenBucket.Config = .{},
    egress: TokenBucket.Config = .{},
};

// ============================================================================
// Tests
// ============================================================================

test "token bucket: unlimited (rate=0) always allows" {
    var tb = TokenBucket.init(.{ .rate = 0, .capacity = 0 });
    try std.testing.expect(tb.consume(1500));
    try std.testing.expect(tb.consume(1_000_000));
}

test "token bucket: consume within burst capacity" {
    var tb = TokenBucket.init(.{ .rate = 1000, .capacity = 2000 });
    // Initially full (2000 tokens). Consuming 1500 should succeed.
    try std.testing.expect(tb.consume(1500));
    // Remaining: 500. Consuming 600 should fail.
    try std.testing.expect(!tb.consume(600));
    // Consuming 500 should succeed.
    try std.testing.expect(tb.consume(500));
}

test "token bucket: refill over time" {
    var tb = TokenBucket.init(.{ .rate = 1000, .capacity = 1000 });
    // Drain completely.
    try std.testing.expect(tb.consume(1000));
    try std.testing.expect(!tb.consume(1));

    // Manually advance the clock by 1 second.
    tb.last_refill_ns -= @as(i64, std.time.ns_per_s);
    // Should refill ~1000 tokens (rate * 1s).
    try std.testing.expect(tb.consume(999));
}

test "token bucket: never exceeds capacity" {
    var tb = TokenBucket.init(.{ .rate = 5000, .capacity = 1000 });
    // Even after a long time, tokens cap at capacity.
    tb.last_refill_ns -= @as(i64, 10 * std.time.ns_per_s);
    try std.testing.expect(tb.consume(1000));
    // Should be exactly 0 now, not refilled past capacity on next consume.
    try std.testing.expect(!tb.consume(1));
}

test "token bucket: reconfigure clamps tokens" {
    var tb = TokenBucket.init(.{ .rate = 1000, .capacity = 2000 });
    tb.tokens = 2000;
    tb.reconfigure(.{ .rate = 500, .capacity = 1000 });
    try std.testing.expectEqual(@as(u64, 1000), tb.tokens);
}
