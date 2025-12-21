//! Daemon Mode
//!
//! Runs the VPN client in daemon (non-interactive) mode.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const client = @import("../client/mod.zig");
const state_mod = @import("state.zig");
const config_mod = @import("config.zig");
const events_mod = @import("events.zig");

const AppState = state_mod.AppState;

/// Run the VPN client in daemon mode
pub fn run(state: *AppState) !void {
    cli.display.info(&state.display, "Running in daemon mode...", .{});

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

    // Connect
    cli.display.info(&state.display, "Connecting to {s}:{d}...", .{ config.server_host, config.server_port });

    vpn.connect() catch |err| {
        cli.display.failure(&state.display, "Connection failed: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

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
