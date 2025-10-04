// Example: How to integrate profiling into your client
// This shows the pattern - you'll adapt it to src/cli.zig

const std = @import("std");
const profiling = @import("profiling.zig");
const client = @import("client.zig");

pub fn connectWithProfiling(vpn_client: *client.VpnClient) !void {
    // Initialize metrics
    var metrics = try profiling.Metrics.init(vpn_client.allocator);
    defer metrics.deinit();

    std.debug.print("🔬 Performance profiling enabled\n", .{});

    // Connect
    try vpn_client.connect();

    // Status reporting thread
    const status_thread = try std.Thread.spawn(.{}, statusLoop, .{ &metrics, vpn_client });
    defer status_thread.join();

    // Main connection loop with profiling
    var last_status: u64 = 0;
    while (vpn_client.isConnected()) {
        const current_pps = metrics.packets_received.load(.monotonic);

        // Print status every 1000 packets
        if (current_pps - last_status >= 1000) {
            metrics.printStatus();
            last_status = current_pps;
        }

        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Final report
    metrics.report();
}

fn statusLoop(metrics: *profiling.Metrics, vpn_client: *client.VpnClient) void {
    _ = vpn_client;
    while (true) {
        std.Thread.sleep(5 * std.time.ns_per_s);
        metrics.printStatus();
    }
}
