//! Daemon Mode
//!
//! Runs the VPN client in daemon (non-interactive) mode.
//! Supports PID file management and connection progress display.

const std = @import("std");
const builtin = @import("builtin");

const cli = @import("../cli/mod.zig");
const client = @import("../client/mod.zig");
const state_mod = @import("state.zig");
const config_mod = @import("config.zig");
const events_mod = @import("events.zig");

const AppState = state_mod.AppState;

// ============================================================================
// PID File Management (S-038)
// ============================================================================

const pid_filename = "softether.pid";

fn getPidFilePath(buf: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    // Try XDG_RUNTIME_DIR first (e.g. /run/user/1000/)
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "XDG_RUNTIME_DIR")) |dir| {
        defer std.heap.page_allocator.free(dir);
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, pid_filename }) catch null;
    } else |_| {}

    // Fall back to /tmp
    return std.fmt.bufPrint(buf, "/tmp/{s}", .{pid_filename}) catch null;
}

fn getCurrentPid() u32 {
    if (builtin.os.tag == .windows) {
        return @intCast(std.os.windows.GetCurrentProcessId());
    } else {
        return @intCast(std.c.getpid());
    }
}

fn writePidFile(display_ctx: *cli.display.DisplayContext) bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf) orelse return false;

    // Check for stale PID file
    if (std.fs.cwd().openFile(pid_path, .{})) |file| {
        defer file.close();
        var read_buf: [32]u8 = undefined;
        const n = file.readAll(&read_buf) catch 0;
        if (n > 0) {
            const content = std.mem.trim(u8, read_buf[0..n], " \n\r\t");
            if (std.fmt.parseInt(u32, content, 10)) |old_pid| {
                // Check if process still exists (signal 0 = check only)
                if (builtin.os.tag != .windows) {
                    if (std.posix.kill(@as(i32, @intCast(old_pid)), 0)) {
                        cli.display.failure(display_ctx, "Another instance is running (PID {d})", .{old_pid});
                        return false;
                    } else |_| {}
                }
            } else |_| {}
        }
    } else |_| {}

    // Write current PID
    const pid = getCurrentPid();
    const file = std.fs.cwd().createFile(pid_path, .{}) catch |err| {
        cli.display.warning(display_ctx, "Could not write PID file: {s}", .{@errorName(err)});
        return true; // Non-fatal
    };
    defer file.close();

    var pid_buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{pid}) catch return true;
    file.writeAll(pid_str) catch {};

    cli.display.debug(display_ctx, "PID file: {s} (PID {d})", .{ pid_path, pid });
    return true;
}

fn removePidFile() void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf) orelse return;
    std.fs.cwd().deleteFile(pid_path) catch {};
}

// ============================================================================
// Connection Progress Display (S-040)
// ============================================================================

const ConnectPhase = struct {
    name: []const u8,
    number: u8,
    total: u8,
};

fn stateToPhase(state: client.ClientState) ?ConnectPhase {
    return switch (state) {
        .resolving_dns => .{ .name = "Resolving DNS", .number = 1, .total = 7 },
        .connecting_tcp => .{ .name = "Connecting", .number = 2, .total = 7 },
        .ssl_handshake => .{ .name = "TLS Handshake", .number = 3, .total = 7 },
        .authenticating => .{ .name = "Authenticating", .number = 4, .total = 7 },
        .establishing_session => .{ .name = "Establishing Session", .number = 5, .total = 7 },
        .configuring_adapter => .{ .name = "Configuring Network", .number = 6, .total = 7 },
        .connected => .{ .name = "Connected", .number = 7, .total = 7 },
        else => null,
    };
}

fn showConnectProgress(display_ctx: *cli.display.DisplayContext, vpn: *client.VpnClient) void {
    var spinner = cli.display.Spinner.init("Connecting...");
    var last_state: client.ClientState = .disconnected;
    var msg_buf: [128]u8 = undefined;

    // Poll state changes during connect
    while (vpn.isConnecting()) {
        const current_state = vpn.getState();
        if (current_state != last_state) {
            if (stateToPhase(current_state)) |phase| {
                const msg = std.fmt.bufPrint(&msg_buf, "{s} ({d}/{d})", .{
                    phase.name,
                    phase.number,
                    phase.total,
                }) catch phase.name;

                spinner.message = msg;
            }
            last_state = current_state;
        }
        spinner.render(display_ctx);
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Show final result
    if (vpn.isConnected()) {
        spinner.finish(display_ctx, true);
        cli.display.success(display_ctx, "Connected successfully!", .{});

        // Show connection info
        const ip = vpn.getAssignedIp();
        const gw = vpn.getGatewayIp();
        if (ip != 0) {
            var ip_buf: [16]u8 = undefined;
            cli.display.info(display_ctx, "  VPN IP:   {s}", .{cli.display.formatIpv4(ip, &ip_buf)});
        }
        if (gw != 0) {
            var gw_buf: [16]u8 = undefined;
            cli.display.info(display_ctx, "  Gateway:  {s}", .{cli.display.formatIpv4(gw, &gw_buf)});
        }
    } else {
        spinner.finish(display_ctx, false);
    }
}

// ============================================================================
// Daemon Entry Point
// ============================================================================

/// Run the VPN client in daemon mode
pub fn run(state: *AppState) !void {
    cli.display.info(&state.display, "Running in daemon mode...", .{});

    // Write PID file (S-038)
    if (!writePidFile(&state.display)) {
        state.setExitCode(1);
        return;
    }
    defer removePidFile();

    // Create VPN client
    const config = config_mod.buildClientConfig(&state.cli_args) catch |err| {
        cli.display.failure(&state.display, "Invalid configuration: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

    const vpn = try state.allocator.create(client.VpnClient);
    vpn.* = client.VpnClient.init(state.allocator, config);
    state.setVpnClient(vpn);

    // Set event callback
    vpn.setEventCallback(events_mod.handleVpnEvent, state);

    // Connect with progress display (S-040)
    cli.display.info(&state.display, "Connecting to {s}:{d}...", .{ config.server_host, config.server_port });

    // Spawn connect in a thread so we can show progress
    const connect_thread = std.Thread.spawn(.{}, struct {
        fn doConnect(v: *client.VpnClient) void {
            v.connect() catch {};
        }
    }.doConnect, .{vpn}) catch |err| {
        cli.display.failure(&state.display, "Failed to start connect thread: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

    // Show animated progress while connecting
    showConnectProgress(&state.display, vpn);
    connect_thread.join();

    if (!vpn.isConnected()) {
        cli.display.failure(&state.display, "Connection failed", .{});
        state.setExitCode(1);
        return;
    }

    // Run the data channel loop in a separate thread
    const data_thread = std.Thread.spawn(.{}, struct {
        fn dataLoop(v: *client.VpnClient) void {
            v.runDataLoop() catch |err| {
                std.log.err("Data loop error: {}", .{err});
            };
        }
    }.dataLoop, .{vpn}) catch |err| {
        cli.display.failure(&state.display, "Failed to start data thread: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

    // Main loop - wait for signals
    while (state.isRunning()) {
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
            if (config.reconnect.enabled and state.isRunning()) {
                cli.display.warning(&state.display, "Connection lost, reconnecting...", .{});
                vpn.reconnect() catch {
                    std.Thread.sleep(1 * std.time.ns_per_s);
                };
            } else {
                state.stop();
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
