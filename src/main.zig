//! SoftEther VPN Client - Zig Implementation
//!
//! Main entry point for the VPN client.

const std = @import("std");
const builtin = @import("builtin");

// Modules
const cli = @import("cli/mod.zig");
const app = @import("app/mod.zig");
const lib = @import("lib.zig");

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
pub const version = lib.version;
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

    // Check for subcommand (argv[1] without leading dash)
    var connect_mode = false;
    var effective_args: []const []const u8 = args;
    if (args.len >= 2 and args[1][0] != '-') {
        if (std.mem.eql(u8, args[1], "connect")) {
            connect_mode = true;
            const tmp = try allocator.alloc([]const u8, args.len - 1);
            tmp[0] = args[0];
            for (args[2..], 0..) |a, j| tmp[j + 1] = a;
            effective_args = tmp;
        } else if (std.mem.eql(u8, args[1], "help")) {
            cli.showUsage(version);
            return;
        } else if (std.mem.eql(u8, args[1], "version")) {
            cli.showVersion(version);
            return;
        } else if (std.mem.eql(u8, args[1], "passhash")) {
            var hash_user: ?[]const u8 = null;
            var hash_pass: ?[]const u8 = null;
            var i: usize = 2;
            while (i < args.len) : (i += 1) {
                const a = args[i];
                if (std.mem.eql(u8, a, "-u") or std.mem.eql(u8, a, "--user")) {
                    i += 1;
                    if (i >= args.len) {
                        cli.display.failure(&state.display, "Missing value for {s}", .{a});
                        std.process.exit(1);
                    }
                    hash_user = args[i];
                } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--password")) {
                    i += 1;
                    if (i >= args.len) {
                        cli.display.failure(&state.display, "Missing value for {s}", .{a});
                        std.process.exit(1);
                    }
                    hash_pass = args[i];
                } else {
                    cli.display.failure(&state.display, "Unknown passhash option: {s}", .{a});
                    std.process.exit(1);
                }
            }
            if (hash_user == null or hash_pass == null) {
                cli.display.failure(&state.display, "Usage: vpnclient passhash --user <username> --password <password>", .{});
                std.process.exit(1);
            }
            app.password_hash.generate(hash_user.?, hash_pass.?);
            return;
        } else if (std.mem.eql(u8, args[1], "cleanup")) {
            // Aggressively clean up stale VPN routing state left over from a
            // previous killed/crashed run. Removes all routes pointing
            // through dead utun interfaces, then restores a default route
            // via the physical interface if the host was left with no
            // internet. Safe to run at any time.
            const route_heal = @import("adapter/route_heal.zig");
            const n1 = route_heal.purgeStaleRoutes(allocator);
            const n2 = route_heal.purgeStaleUtunState(allocator);
            const total = n1 + n2;
            if (total > 0) {
                cli.display.success(&state.display, "Cleaned up {d} stale route(s) (purge={d}, utun-state={d})", .{ total, n1, n2 });
            } else {
                cli.display.debug(&state.display, "No stale routes to clean", .{});
            }
            return;
        } else {
            cli.display.failure(&state.display, "Unknown subcommand: '{s}'. Use 'vpnclient connect --help' or 'vpnclient --help'.", .{args[1]});
            std.process.exit(1);
        }
    }

    // Parse using CLI module
    state.cli_args = cli.parseArgs(allocator, effective_args) catch |err| {
        cli.display.failure(&state.display, "Argument parsing error: {s}", .{@errorName(err)});
        std.process.exit(1);
    };

    // Load config file if specified
    cli.loadConfig(allocator, &state.cli_args) catch {};

    // Handle special modes (no subcommand needed)
    if (state.cli_args.help) {
        cli.showUsage(version);
        return;
    }

    if (state.cli_args.version) {
        cli.showVersion(version);
        return;
    }

    // Everything else requires 'connect' subcommand
    if (!connect_mode) {
        cli.display.failure(&state.display, "No subcommand. Use 'vpnclient connect <options>' to connect, or 'vpnclient --help' for usage.", .{});
        std.process.exit(1);
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
