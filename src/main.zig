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

/// Configure log levels per scope to filter out noisy per-packet logs.
/// Scope naming follows the module hierarchy: subsystem.component
///   - cedar.*     VPN protocol layer (client, session, tunnel, auth, pack)
///   - mayaqua.*   Platform abstraction (tls, net, dns, udp)
///   - adapter.*   TUN/TAP adapters (tun, route)
///   - app.*       Application lifecycle
///   - ffi         C FFI layer
///   - *.debug     Per-packet I/O trace (noisiest)
pub const std_options: std.Options = .{
    .log_level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
    .log_scope_levels = &.{
        // Per-packet I/O: only show in debug builds
        .{ .scope = .packet_trace, .level = .err },
        .{ .scope = .mayaqua, .level = .info },
        .{ .scope = .adapter, .level = .info },
        // Cedar protocol scopes
        .{ .scope = .cedar_client, .level = .info },
        .{ .scope = .cedar_conn, .level = .info },
        .{ .scope = .cedar_proto, .level = .info },
        .{ .scope = .cedar_tunnel, .level = .info },
        .{ .scope = .cedar_auth, .level = .info },
        .{ .scope = .cedar_pack, .level = .info },
        .{ .scope = .cedar_session, .level = .info },
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
        } else if (std.mem.eql(u8, args[1], "passhash") or std.mem.eql(u8, args[1], "password-hash")) {
            // M19 #253 — `vpnclient passhash` is deprecated; `vpncmd tools
            // generatehashedpassword` is the canonical generator (parity to
            // `SoftEtherVPN/src/vpncmd/Tools.c:GenerateHashedPassword`).
            // Keep consumption (`--password-hash`) in vpnclient, but generation
            // now warns and delegates conceptually to vpncmd. Functional for
            // one release (non-breaking), removal in M21 P2.
            // Deprecation goes to stderr to preserve stdout contract for
            // scripts that parse `vpnclient passhash` output (see review).
            std.debug.print("[warning] vpnclient passhash is deprecated — use `vpncmd tools generatehashedpassword` (see `vpncmd tools --help`)\n", .{});
            std.debug.print("[info] This verb will be removed in a future release; `vpnclient` will only consume `--password-hash`.\n", .{});

            var hash_user: ?[]const u8 = null;
            var hash_pass: ?[]const u8 = null;

            if (args.len >= 4 and args[2].len > 0 and args[3].len > 0 and args[2][0] != '-' and args[3][0] != '-') {
                hash_user = args[2];
                hash_pass = args[3];
            } else {
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
            }

            if (hash_user == null or hash_pass == null) {
                cli.display.failure(&state.display, "Usage: vpnclient passhash [<username> <password>]  (deprecated)", .{});
                cli.display.failure(&state.display, "       vpnclient passhash --user <username> --password <password>", .{});
                cli.display.failure(&state.display, "  Prefer: vpncmd tools generatehashedpassword -u <user> -p <pass>", .{});
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
        } else if (std.mem.eql(u8, args[1], "install")) {
            // M20 #256 — install service (systemd/launchd/SCM)
            var scope: app.daemon.ServiceScope = .user; // default --user for vpnclient (no sudo)
            var i: usize = 2;
            while (i < args.len) : (i += 1) {
                const a = args[i];
                if (std.mem.eql(u8, a, "--system")) {
                    scope = .system;
                } else if (std.mem.eql(u8, a, "--user")) {
                    scope = .user;
                } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
                    cli.display.info(&state.display, "Usage: vpnclient install [--user|--system]", .{});
                    cli.display.info(&state.display, "  --user    Install for current user (~/.config/systemd/user, no sudo) [default]", .{});
                    cli.display.info(&state.display, "  --system  Install system-wide (/etc/systemd/system, requires sudo)", .{});
                    return;
                } else {
                    cli.display.failure(&state.display, "Unknown install option: {s}", .{a});
                    std.process.exit(1);
                }
            }
            app.daemon.installService(allocator, &state.display, scope) catch |err| {
                cli.display.failure(&state.display, "install failed: {s}", .{@errorName(err)});
                std.process.exit(1);
            };
            return;
        } else if (std.mem.eql(u8, args[1], "uninstall")) {
            var scope: app.daemon.ServiceScope = .user;
            var i: usize = 2;
            while (i < args.len) : (i += 1) {
                const a = args[i];
                if (std.mem.eql(u8, a, "--system")) {
                    scope = .system;
                } else if (std.mem.eql(u8, a, "--user")) {
                    scope = .user;
                } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
                    cli.display.info(&state.display, "Usage: vpnclient uninstall [--user|--system]", .{});
                    return;
                } else {
                    cli.display.failure(&state.display, "Unknown uninstall option: {s}", .{a});
                    std.process.exit(1);
                }
            }
            app.daemon.uninstallService(allocator, &state.display, scope) catch |err| {
                cli.display.failure(&state.display, "uninstall failed: {s}", .{@errorName(err)});
                std.process.exit(1);
            };
            return;
        } else if (std.mem.eql(u8, args[1], "start") or std.mem.eql(u8, args[1], "stop") or std.mem.eql(u8, args[1], "restart") or std.mem.eql(u8, args[1], "status") or std.mem.eql(u8, args[1], "enable") or std.mem.eql(u8, args[1], "disable")) {
            var scope: app.daemon.ServiceScope = .user;
            for (args[2..]) |a| {
                if (std.mem.eql(u8, a, "--system")) scope = .system;
                if (std.mem.eql(u8, a, "--user")) scope = .user;
                if (a.len > 0 and a[0] == '-' and !std.mem.eql(u8, a, "--system") and !std.mem.eql(u8, a, "--user")) {
                    cli.display.failure(&state.display, "Unknown option for {s}: {s}", .{ args[1], a });
                    std.process.exit(1);
                }
            }
            var has_system = false;
            var has_user = false;
            for (args[2..]) |a| {
                if (std.mem.eql(u8, a, "--system")) has_system = true;
                if (std.mem.eql(u8, a, "--user")) has_user = true;
            }
            if (has_system and has_user) {
                cli.display.failure(&state.display, "Cannot specify both --system and --user", .{});
                std.process.exit(1);
            }
            const cmd = args[1];
            if (std.mem.eql(u8, cmd, "start")) {
                app.daemon.startService(allocator, &state.display, scope) catch |err| {
                    cli.display.failure(&state.display, "Start failed: {s}", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, cmd, "stop")) {
                app.daemon.stopService(allocator, &state.display, scope) catch |err| {
                    cli.display.failure(&state.display, "Stop failed: {s}", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, cmd, "restart")) {
                app.daemon.restartService(allocator, &state.display, scope) catch |err| {
                    cli.display.failure(&state.display, "Restart failed: {s}", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, cmd, "status")) {
                app.daemon.statusService(allocator, &state.display, scope) catch |err| {
                    cli.display.failure(&state.display, "Status failed: {s}", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, cmd, "enable")) {
                app.daemon.enableService(allocator, &state.display, scope) catch |err| {
                    cli.display.failure(&state.display, "Enable failed: {s}", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, cmd, "disable")) {
                app.daemon.disableService(allocator, &state.display, scope) catch |err| {
                    cli.display.failure(&state.display, "Disable failed: {s}", .{@errorName(err)});
                    std.process.exit(1);
                };
            }
            return;
        } else if (std.mem.eql(u8, args[1], "list")) {
            var child = std.process.Child.init(&[_][]const u8{ "vpncmd", "client", "AccountList" }, allocator);
            child.stdout_behavior = .Inherit;
            child.stderr_behavior = .Inherit;
            const res = child.spawnAndWait() catch {
                cli.display.info(&state.display, "No vpncmd store — use `vpncmd client AccountCreate` (see docs/ACCOUNT.md)", .{});
                return;
            };
            switch (res) {
                .Exited => |code| {
                    if (code != 0) cli.display.info(&state.display, "vpncmd AccountList exited with {d} — no accounts or vpncmd not installed", .{code});
                },
                else => cli.display.info(&state.display, "vpncmd AccountList terminated abnormally", .{}),
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

    // Generate a server TLS certificate/key pair and exit (server bootstrap).
    // C parity: vpnserver / SiGenerateDefaultCertEx first-run self-signed cert.
    if (state.cli_args.gen_cert) {
        try app.gen_cert.generateServerCertFiles(allocator, &state.display, state.cli_args.gen_cert_name);
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
