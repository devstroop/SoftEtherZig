//! Signal Handling
//!
//! POSIX signal handlers for graceful shutdown.

const std = @import("std");
const builtin = @import("builtin");

const state_mod = @import("state.zig");
const AppState = state_mod.AppState;

/// Global state pointer for signal handling (must be set before setupSignalHandlers)
var global_state: ?*AppState = null;

/// Set the global state for signal handlers
pub fn setGlobalState(s: *AppState) void {
    global_state = s;
}

/// Clear the global state
pub fn clearGlobalState() void {
    global_state = null;
}

/// Set up POSIX signal handlers for SIGINT and SIGTERM
pub fn setupSignalHandlers() void {
    if (builtin.os.tag != .windows) {
        const handler = std.posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.INT, &handler, null);
        std.posix.sigaction(std.posix.SIG.TERM, &handler, null);
    }
}

/// Signal handler callback
fn handleSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_state) |s| {
        s.running = false;
        // Just set should_stop flag - don't try to acquire mutex from signal handler
        // as this can deadlock if the main thread holds the mutex
        if (s.vpn_client) |vpn| {
            vpn.requestStop();
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "setGlobalState and clearGlobalState" {
    var s = AppState.init(std.testing.allocator);
    defer s.deinit();

    try std.testing.expect(global_state == null);

    setGlobalState(&s);
    try std.testing.expect(global_state != null);

    clearGlobalState();
    try std.testing.expect(global_state == null);
}

test "setupSignalHandlers does not crash" {
    // Just verify it doesn't panic
    setupSignalHandlers();
}
