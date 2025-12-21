//! Interactive Mode
//!
//! Runs the VPN client in interactive shell mode.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const state_mod = @import("state.zig");

const AppState = state_mod.AppState;

/// Run the VPN client in interactive shell mode
pub fn run(state: *AppState) !void {
    // Create shell with VPN client hooks
    var sh = cli.Shell.init(state.allocator);
    defer sh.deinit();

    // Set up callbacks if we have a VPN client
    if (state.getVpnClient()) |_| {
        // Shell callbacks would be set here
    }

    try sh.run();
}
