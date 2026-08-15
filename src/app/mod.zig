//! Application Module
//!
//! High-level application logic for the VPN client.
//! Handles state management, signal handling, and run modes.

const std = @import("std");

// Submodules
pub const state = @import("state.zig");
pub const signals = @import("signals.zig");
pub const events = @import("events.zig");
pub const config = @import("config.zig");
pub const daemon = @import("daemon.zig");
pub const interactive = @import("interactive.zig");
pub const password_hash = @import("password_hash.zig");

// Re-export main types
pub const AppState = state.AppState;
pub const buildClientConfig = config.buildClientConfig;
pub const ConfigBuildError = config.ConfigBuildError;

// ============================================================================
// Tests
// ============================================================================

test {
    std.testing.refAllDecls(@This());
}
