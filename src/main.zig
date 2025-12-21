//! SoftEther VPN Client - Zig Implementation
//!
//! Main entry point for the VPN client.

const std = @import("std");
const builtin = @import("builtin");

// Modules
const cli = @import("cli/mod.zig");
const app = @import("app/mod.zig");

// ============================================================================
// Logging Configuration
// ============================================================================

/// Configure log levels per scope to filter out noisy per-packet logs
pub const std_options: std.Options = .{
    .log_level = .debug, // Default level for most scopes
    .log_scope_levels = &.{
        // Silence per-packet trace logs (use --log-level trace to see them)
        .{ .scope = .packet_trace, .level = .err },
    },
};

// Version info
pub const version = "0.2.0";
pub const build_date = "2024-12-21";

// ============================================================================
// Entry Point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = app.AppState.init(allocator);
    defer state.deinit();

    app.signals.setGlobalState(&state);
    defer app.signals.clearGlobalState();

    // Setup signal handlers
    app.signals.setupSignalHandlers();

    // Parse command line arguments
    const args = std.process.argsAlloc(allocator) catch |err| {
        cli.display.failure(&state.display, "Failed to get arguments: {s}", .{@errorName(err)});
        return;
    };
    defer std.process.argsFree(allocator, args);

    // Parse using CLI module
    state.cli_args = cli.parseArgs(allocator, args) catch |err| {
        cli.display.failure(&state.display, "Argument parsing error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    // Load config file if specified
    cli.loadConfig(allocator, &state.cli_args) catch {};

    // Handle special modes
    if (state.cli_args.help) {
        cli.showUsage(version);
        return;
    }

    if (state.cli_args.version) {
        cli.showVersion(version);
        return;
    }

    if (state.cli_args.gen_hash_user) |user| {
        app.password_hash.generate(user, state.cli_args.gen_hash_pass orelse "");
        return;
    }

    // Validate required fields
    const validation = try cli.args.validate(&state.cli_args, allocator);
    defer allocator.free(validation.missing_fields);
    defer allocator.free(validation.errors);

    if (!validation.valid) {
        if (validation.missing_fields.len > 0) {
            cli.display.failure(&state.display, "Missing required fields:", .{});
            for (validation.missing_fields) |field| {
                state.display.print("  - {s}\n", .{field});
            }
        }
        if (validation.errors.len > 0) {
            cli.display.failure(&state.display, "Configuration errors:", .{});
            for (validation.errors) |err| {
                state.display.print("  - {s}\n", .{err});
            }
        }
        state.display.print("\nRun with --help for usage information.\n", .{});
        std.process.exit(1);
    }

    // Run the application
    if (state.cli_args.interactive) {
        try app.interactive.run(&state);
    } else {
        try app.daemon.run(&state);
    }

    std.process.exit(state.exit_code);
}

// ============================================================================
// Tests
// ============================================================================

test "app module imports" {
    _ = app;
}
