//! Application State Management
//!
//! Manages the global application state for the VPN client.

const std = @import("std");
const Allocator = std.mem.Allocator;

const cli = @import("../cli/mod.zig");
const client = @import("../client/mod.zig");

/// Application state container
pub const AppState = struct {
    allocator: Allocator,
    vpn_client: ?*client.VpnClient,
    display: cli.DisplayContext,
    cli_args: cli.CliArgs,
    running: bool,
    exit_code: u8,

    const Self = @This();

    /// Initialize application state with defaults
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .vpn_client = null,
            .display = cli.DisplayContext.init(),
            .cli_args = .{},
            .running = true,
            .exit_code = 0,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        if (self.vpn_client) |vpn| {
            vpn.deinit();
            self.allocator.destroy(vpn);
            self.vpn_client = null;
        }
        self.cli_args.deinit();
    }

    /// Mark state as stopped
    pub fn stop(self: *Self) void {
        self.running = false;
    }

    /// Check if application is running
    pub fn isRunning(self: *const Self) bool {
        return self.running;
    }

    /// Set exit code
    pub fn setExitCode(self: *Self, code: u8) void {
        self.exit_code = code;
    }

    /// Get the VPN client (if available)
    pub fn getVpnClient(self: *Self) ?*client.VpnClient {
        return self.vpn_client;
    }

    /// Set the VPN client
    pub fn setVpnClient(self: *Self, vpn: *client.VpnClient) void {
        self.vpn_client = vpn;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "AppState init and deinit" {
    var state = AppState.init(std.testing.allocator);
    defer state.deinit();

    try std.testing.expect(state.isRunning());
    try std.testing.expect(state.vpn_client == null);
    try std.testing.expectEqual(@as(u8, 0), state.exit_code);
}

test "AppState stop" {
    var state = AppState.init(std.testing.allocator);
    defer state.deinit();

    try std.testing.expect(state.isRunning());
    state.stop();
    try std.testing.expect(!state.isRunning());
}

test "AppState exit code" {
    var state = AppState.init(std.testing.allocator);
    defer state.deinit();

    state.setExitCode(42);
    try std.testing.expectEqual(@as(u8, 42), state.exit_code);
}
