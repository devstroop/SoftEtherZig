//! SoftEther VPN Client - Pure Zig Entry Point
//!
//! Phase 9: Main entry point using pure Zig implementation
//! No C dependencies required.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

// Pure Zig modules
const cli = @import("cli/mod.zig");
const client = @import("client/mod.zig");
const crypto = @import("crypto/crypto.zig");

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
pub const version = "0.2.0-pure";
pub const build_date = "2024-12-20";

// ============================================================================
// Application State
// ============================================================================

const AppState = struct {
    allocator: Allocator,
    vpn_client: ?*client.VpnClient,
    display: cli.DisplayContext,
    cli_args: cli.CliArgs,
    running: bool,
    exit_code: u8,

    const Self = @This();

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

    pub fn deinit(self: *Self) void {
        if (self.vpn_client) |vpn| {
            vpn.deinit();
            self.allocator.destroy(vpn);
            self.vpn_client = null;
        }
        self.cli_args.deinit();
    }
};

// Global state for signal handling
var global_state: ?*AppState = null;

// ============================================================================
// Signal Handling
// ============================================================================

fn setupSignalHandlers() void {
    // On POSIX systems, set up signal handlers for graceful shutdown
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

fn handleSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_state) |state| {
        state.running = false;
        // Just set should_stop flag - don't try to acquire mutex from signal handler
        // as this can deadlock if the main thread holds the mutex
        if (state.vpn_client) |vpn| {
            vpn.requestStop();
        }
    }
}

// ============================================================================
// Event Handling
// ============================================================================

fn handleVpnEvent(event: client.ClientEvent, user_data: ?*anyopaque) void {
    const state: *AppState = @ptrCast(@alignCast(user_data orelse return));

    switch (event) {
        .state_changed => |sc| {
            cli.display.info(&state.display, "State: {s} → {s}", .{
                @tagName(sc.old_state),
                @tagName(sc.new_state),
            });
        },
        .connected => |c| {
            var ip_buf: [16]u8 = undefined;
            var gw_buf: [16]u8 = undefined;
            cli.display.success(&state.display, "Connected!", .{});
            cli.display.info(&state.display, "  Assigned IP: {s}", .{
                cli.display.formatIpv4(c.assigned_ip, &ip_buf),
            });
            cli.display.info(&state.display, "  Gateway: {s}", .{
                cli.display.formatIpv4(c.gateway_ip, &gw_buf),
            });
        },
        .disconnected => |d| {
            cli.display.warning(&state.display, "Disconnected: {s}", .{@tagName(d.reason)});
        },
        .error_occurred => |e| {
            cli.display.failure(&state.display, "Error: {s}", .{e.message});
        },
        .stats_updated => {},
        .dhcp_configured => |dhcp| {
            var ip_buf: [16]u8 = undefined;
            cli.display.info(&state.display, "DHCP configured: {s}", .{
                cli.display.formatIpv4(dhcp.ip, &ip_buf),
            });
        },
    }
}

// ============================================================================
// Configuration Building
// ============================================================================

fn buildClientConfig(args: *const cli.CliArgs) !client.ClientConfig {
    // Validate required fields
    const server = args.server orelse return error.MissingServer;
    const hub = args.hub orelse return error.MissingHub;

    // Build auth method
    const auth: client.AuthMethod = blk: {
        if (args.password_hash) |hash| {
            break :blk .{ .password = .{
                .username = args.username orelse "anonymous",
                .password = hash,
                .is_hashed = true,
            } };
        } else if (args.password) |pass| {
            break :blk .{ .password = .{
                .username = args.username orelse "anonymous",
                .password = pass,
                .is_hashed = false,
            } };
        } else if (args.username) |_| {
            return error.MissingPassword;
        } else {
            break :blk .{ .anonymous = {} };
        }
    };

    // Build IP version preference
    const ip_version: client.IpVersionPreference = switch (args.ip_version) {
        .auto => .auto,
        .ipv4 => .ipv4_only,
        .ipv6 => .ipv6_only,
        .dual => .dual_stack,
    };

    // Build reconnect config
    const reconnect = client.ReconnectConfig{
        .enabled = args.reconnect,
        .max_attempts = args.max_retries,
        .min_backoff_ms = args.min_backoff_sec * 1000,
        .max_backoff_ms = args.max_backoff_sec * 1000,
        .backoff_multiplier = 2.0,
    };

    return .{
        .server_host = server,
        .server_port = args.port,
        .hub_name = hub,
        .auth = auth,
        .ip_version = ip_version,
        .max_connections = @intCast(args.max_connection),
        .use_compression = false,
        .use_encryption = true,
        .full_tunnel = true,
        .reconnect = reconnect,
        .connect_timeout_ms = 30000,
        .read_timeout_ms = 60000,
        .keepalive_interval_ms = 10000,
    };
}

// ============================================================================
// Main Run Loop
// ============================================================================

fn runDaemon(state: *AppState) !void {
    cli.display.info(&state.display, "Running in daemon mode...", .{});

    // Create VPN client
    const config = buildClientConfig(&state.cli_args) catch |err| {
        cli.display.failure(&state.display, "Invalid configuration: {s}", .{@errorName(err)});
        state.exit_code = 1;
        return;
    };

    const vpn = try state.allocator.create(client.VpnClient);
    vpn.* = client.VpnClient.init(state.allocator, config);
    state.vpn_client = vpn;

    // Set event callback
    vpn.setEventCallback(handleVpnEvent, state);

    // Connect
    cli.display.info(&state.display, "Connecting to {s}:{d}...", .{ config.server_host, config.server_port });

    vpn.connect() catch |err| {
        cli.display.failure(&state.display, "Connection failed: {s}", .{@errorName(err)});
        state.exit_code = 1;
        return;
    };

    // Run the data channel loop in a separate thread
    const data_thread = std.Thread.spawn(.{}, struct {
        fn run(v: *client.VpnClient) void {
            v.runDataLoop() catch |err| {
                std.log.err("Data loop error: {}", .{err});
            };
        }
    }.run, .{vpn}) catch |err| {
        cli.display.failure(&state.display, "Failed to start data thread: {s}", .{@errorName(err)});
        state.exit_code = 1;
        return;
    };

    // Main loop - wait for signals
    while (state.running) {
        if (vpn.isConnected()) {
            // Update stats periodically
            const stats = vpn.getStats();
            if (stats.connected_duration_ms > 0 and stats.connected_duration_ms % 60000 < 1000) {
                var sent_buf: [32]u8 = undefined;
                var recv_buf: [32]u8 = undefined;
                cli.display.debug(&state.display, "Traffic: ↑{s} ↓{s}", .{
                    cli.display.formatBytes(stats.bytes_sent, &sent_buf),
                    cli.display.formatBytes(stats.bytes_received, &recv_buf),
                });
            }
        } else if (!vpn.isConnecting()) {
            // Disconnected unexpectedly
            if (config.reconnect.enabled and state.running) {
                cli.display.warning(&state.display, "Connection lost, reconnecting...", .{});
                vpn.reconnect() catch {
                    std.Thread.sleep(1 * std.time.ns_per_s);
                };
            } else {
                state.running = false;
            }
        }

        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Cleanup
    cli.display.info(&state.display, "Shutting down...", .{});

    // Signal stop first (doesn't free resources yet)
    vpn.requestStop();

    // Wait for data thread to exit cleanly (it will see should_stop flag)
    data_thread.join();

    // Now safe to disconnect and free resources
    vpn.disconnect() catch {};
}

fn runInteractive(state: *AppState) !void {
    // Create shell with VPN client hooks
    var sh = cli.Shell.init(state.allocator);
    defer sh.deinit();

    // Set up callbacks if we have a VPN client
    if (state.vpn_client) |vpn| {
        _ = vpn;
        // Shell callbacks would be set here
    }

    try sh.run();
}

// ============================================================================
// Password Hash Generation
// ============================================================================

fn generatePasswordHash(user: []const u8, pass: []const u8) void {
    var ctx = cli.DisplayContext.init();

    // SoftEther password hash: SHA-0(password + UPPERCASE(username))
    // See: SoftEtherVPN/src/Cedar/Account.c HashPassword()
    ctx.print("\n", .{});
    cli.display.info(&ctx, "Password Hash Generator", .{});
    ctx.print("Username: {s}\n", .{user});
    ctx.print("Password: [hidden]\n", .{});

    // Generate hash using SHA-0 (SoftEther compatibility)
    // SoftEther format: SHA0(password + UPPERCASE(username))
    var input_buf: [512]u8 = undefined;
    var username_upper: [256]u8 = undefined;

    const pass_len = @min(pass.len, 256);
    const user_len = @min(user.len, 256);

    // Copy password first
    @memcpy(input_buf[0..pass_len], pass[0..pass_len]);

    // Convert username to uppercase and append
    for (user[0..user_len], 0..) |c, i| {
        username_upper[i] = std.ascii.toUpper(c);
    }
    @memcpy(input_buf[pass_len..][0..user_len], username_upper[0..user_len]);

    const input_len = pass_len + user_len;

    const hash = crypto.sha0.hash(input_buf[0..input_len]);

    // Base64 encode (SHA-0 produces 20 bytes)
    const base64 = std.base64.standard;
    var b64_buf: [32]u8 = undefined;
    const encoded = base64.Encoder.encode(&b64_buf, &hash);

    ctx.print("\nPassword Hash (base64):\n", .{});
    ctx.printColored(.green, "{s}\n", .{encoded});
    ctx.print("\nUse with: --password-hash \"{s}\"\n", .{encoded});
}

// ============================================================================
// Entry Point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var state = AppState.init(allocator);
    defer state.deinit();

    global_state = &state;
    defer global_state = null;

    // Setup signal handlers
    setupSignalHandlers();

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
        generatePasswordHash(user, state.cli_args.gen_hash_pass orelse "");
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
        try runInteractive(&state);
    } else {
        try runDaemon(&state);
    }

    std.process.exit(state.exit_code);
}

// ============================================================================
// Tests
// ============================================================================

test "AppState init and deinit" {
    var state = AppState.init(std.testing.allocator);
    defer state.deinit();

    try std.testing.expect(state.running);
    try std.testing.expect(state.vpn_client == null);
    try std.testing.expectEqual(@as(u8, 0), state.exit_code);
}

test "buildClientConfig valid" {
    var args = cli.CliArgs{
        .server = "test.example.com",
        .hub = "VPN",
        .username = "user",
        .password = "pass",
        .port = 443,
    };
    defer args.deinit();

    const config = try buildClientConfig(&args);
    try std.testing.expectEqualStrings("test.example.com", config.server_host);
    try std.testing.expectEqualStrings("VPN", config.hub_name);
    try std.testing.expectEqual(@as(u16, 443), config.server_port);
}

test "buildClientConfig missing server" {
    var args = cli.CliArgs{
        .hub = "VPN",
        .username = "user",
        .password = "pass",
    };
    defer args.deinit();

    try std.testing.expectError(error.MissingServer, buildClientConfig(&args));
}

test "buildClientConfig missing hub" {
    var args = cli.CliArgs{
        .server = "test.com",
        .username = "user",
        .password = "pass",
    };
    defer args.deinit();

    try std.testing.expectError(error.MissingHub, buildClientConfig(&args));
}

test "buildClientConfig anonymous auth" {
    var args = cli.CliArgs{
        .server = "test.com",
        .hub = "VPN",
    };
    defer args.deinit();

    const config = try buildClientConfig(&args);
    try std.testing.expect(config.auth == .anonymous);
}

test "buildClientConfig password hash" {
    var args = cli.CliArgs{
        .server = "test.com",
        .hub = "VPN",
        .username = "user",
        .password_hash = "base64hash==",
    };
    defer args.deinit();

    const config = try buildClientConfig(&args);
    switch (config.auth) {
        .password => |p| {
            try std.testing.expect(p.is_hashed);
            try std.testing.expectEqualStrings("base64hash==", p.password);
        },
        else => try std.testing.expect(false),
    }
}
