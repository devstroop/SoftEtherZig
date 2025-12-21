//! Session Wrapper
//!
//! Bridges the VPN client to the underlying session implementation.
//! Provides encryption/decryption and session state management.

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import session module
const session_mod = @import("../session/mod.zig");
const RealSession = session_mod.Session;
pub const SessionOptions = session_mod.SessionOptions;
pub const TrafficStats = session_mod.TrafficStats;

/// Session wrapper that bridges VpnClient to the real session implementation
pub const SessionWrapper = struct {
    allocator: Allocator,
    real_session: ?RealSession,
    connected: bool,
    use_encryption: bool,

    const Self = @This();

    /// Initialize with default options
    pub fn init(allocator: Allocator, use_encryption: bool) Self {
        return .{
            .allocator = allocator,
            .real_session = null,
            .connected = false,
            .use_encryption = use_encryption,
        };
    }

    /// Initialize with full session options
    pub fn initWithOptions(allocator: Allocator, options: SessionOptions) Self {
        return .{
            .allocator = allocator,
            .real_session = RealSession.init(allocator, options),
            .connected = false,
            .use_encryption = options.use_encryption,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        if (self.real_session) |*sess| {
            sess.deinit();
        }
        self.connected = false;
    }

    /// Disconnect the session
    pub fn disconnect(self: *Self) void {
        if (self.real_session) |*sess| {
            sess.setState(.disconnecting) catch {};
        }
        self.connected = false;
    }

    /// Connect the session
    pub fn connect(self: *Self) void {
        if (self.real_session) |*sess| {
            sess.setState(.connecting) catch {};
        }
        self.connected = true;
    }

    /// Check if session is connected
    pub fn isConnected(self: *const Self) bool {
        if (self.real_session) |*sess| {
            return sess.isConnected();
        }
        return self.connected;
    }

    /// Encrypt data using session encryption
    pub fn encrypt(self: *Self, allocator: Allocator, data: []const u8) ![]u8 {
        _ = allocator; // Session uses its own allocator
        if (self.real_session) |*sess| {
            if (self.use_encryption) {
                return sess.encryptPacket(data);
            }
        }
        // No encryption or no session - return copy
        return try self.allocator.dupe(u8, data);
    }

    /// Decrypt data using session decryption
    pub fn decrypt(self: *Self, allocator: Allocator, data: []const u8) ![]u8 {
        _ = allocator; // Session uses its own allocator
        if (self.real_session) |*sess| {
            if (self.use_encryption) {
                return sess.decryptPacket(data);
            }
        }
        // No decryption or no session - return copy
        return try self.allocator.dupe(u8, data);
    }

    /// Initialize encryption keys (after authentication)
    pub fn initEncryption(self: *Self, password_hash: *const [20]u8, challenge: *const [20]u8) void {
        if (self.real_session) |*sess| {
            sess.initEncryption(password_hash, challenge);
        }
    }

    /// Get traffic statistics
    pub fn getTrafficStats(self: *const Self) ?TrafficStats {
        if (self.real_session) |*sess| {
            return sess.traffic;
        }
        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SessionWrapper init" {
    var wrapper = SessionWrapper.init(std.testing.allocator, true);
    defer wrapper.deinit();

    try std.testing.expect(!wrapper.isConnected());
    try std.testing.expect(wrapper.use_encryption);
}

test "SessionWrapper connect/disconnect" {
    var wrapper = SessionWrapper.init(std.testing.allocator, false);
    defer wrapper.deinit();

    try std.testing.expect(!wrapper.isConnected());

    wrapper.connect();
    try std.testing.expect(wrapper.isConnected());

    wrapper.disconnect();
    try std.testing.expect(!wrapper.isConnected());
}

test "SessionWrapper encrypt passthrough without encryption" {
    var wrapper = SessionWrapper.init(std.testing.allocator, false);
    defer wrapper.deinit();

    const data = "test data";
    const result = try wrapper.encrypt(std.testing.allocator, data);
    defer wrapper.allocator.free(result);

    try std.testing.expectEqualStrings(data, result);
}
