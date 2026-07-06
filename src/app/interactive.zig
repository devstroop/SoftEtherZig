//! Interactive Mode
//!
//! Runs the VPN client in interactive shell mode with full VPN
//! operation callbacks wired to the VpnClient instance.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const client = @import("../cedar/client/mod.zig");
const state_mod = @import("state.zig");
const config_mod = @import("config.zig");
const events_mod = @import("events.zig");

const AppState = state_mod.AppState;

// ============================================================================
// Static context for Shell callbacks (Shell uses bare fn pointers)
// ============================================================================

var g_vpn: *client.VpnClient = undefined;
var g_state: *AppState = undefined;
var g_config: client.ClientConfig = undefined;

fn onConnect() anyerror!void {
    try g_vpn.connect();
}

fn onDisconnect() anyerror!void {
    try g_vpn.disconnect();
}

fn onReconnect() anyerror!void {
    try g_vpn.reconnect();
}

fn onGetStatus() ?cli.display.ConnectionStatus {
    if (!g_vpn.isConnected() and !g_vpn.isConnecting()) {
        return cli.display.ConnectionStatus{
            .state = "Disconnected",
            .server = g_config.server_hostname orelse g_config.server_address,
            .port = g_config.server_port,
            .hub = g_config.hub_name,
            .device_name = if (g_vpn.getDeviceName()) |d| d else "none",
            .assigned_ip = null,
            .gateway_ip = null,
            .bytes_sent = 0,
            .bytes_received = 0,
            .packets_sent = 0,
            .packets_received = 0,
            .connected_duration_ms = 0,
            .reconnect_count = 0,
        };
    }

    const stats = g_vpn.getStats();
    const ip = g_vpn.getAssignedIp();
    const gw = g_vpn.getGatewayIp();

    return cli.display.ConnectionStatus{
        .state = if (g_vpn.isConnected()) "Connected" else "Connecting",
        .server = g_config.server_hostname orelse g_config.server_address,
        .port = g_config.server_port,
        .hub = g_config.hub_name,
        .device_name = if (g_vpn.getDeviceName()) |d| d else "none",
        .assigned_ip = if (ip != 0) ip else null,
        .gateway_ip = if (gw != 0) gw else null,
        .bytes_sent = stats.bytes_sent,
        .bytes_received = stats.bytes_received,
        .packets_sent = stats.packets_sent,
        .packets_received = stats.packets_received,
        .connected_duration_ms = stats.getUptime(),
        .reconnect_count = stats.reconnect_count,
    };
}

// ============================================================================
// Entry Point
// ============================================================================

/// Run the VPN client in interactive shell mode
pub fn run(state: *AppState) !void {
    // Build client config
    const config = config_mod.buildClientConfig(&state.cli_args) catch |err| {
        cli.display.failure(&state.display, "Invalid configuration: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

    // Create VPN client
    const vpn = try state.allocator.create(client.VpnClient);
    vpn.* = client.VpnClient.init(state.allocator, config);
    state.setVpnClient(vpn);

    // Set event callback
    vpn.setEventCallback(events_mod.handleVpnEvent, state);

    // Store in module-level statics for shell callbacks
    g_vpn = vpn;
    g_state = state;
    g_config = config;

    // Create shell with VPN client hooks
    var sh = cli.Shell.init(state.allocator);
    defer sh.deinit();

    // Wire callbacks (S-039)
    sh.on_connect = &onConnect;
    sh.on_disconnect = &onDisconnect;
    sh.on_reconnect = &onReconnect;
    sh.on_get_status = &onGetStatus;

    // Pre-populate shell state from config
    sh.updateState(false, config.server_hostname orelse config.server_address, config.hub_name);

    // Run shell (blocks until user types quit/exit)
    try sh.run();

    // Cleanup — disconnect if still connected
    if (vpn.isConnected() or vpn.isConnecting()) {
        cli.display.info(&state.display, "Disconnecting...", .{});
        vpn.requestStop();
        vpn.disconnect() catch {};
    }
}
