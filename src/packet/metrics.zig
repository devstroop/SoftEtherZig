// Performance Monitoring and Metrics Collection
// Real-time throughput, latency, and system health tracking

const std = @import("std");

pub const PerfMetrics = struct {
    // Throughput metrics
    bytes_per_sec: std.atomic.Value(u64),
    packets_per_sec: std.atomic.Value(u64),
    total_bytes: std.atomic.Value(u64),
    total_packets: std.atomic.Value(u64),

    // Latency metrics (microseconds)
    avg_latency_us: std.atomic.Value(u64),
    min_latency_us: std.atomic.Value(u64),
    max_latency_us: std.atomic.Value(u64),
    p99_latency_us: std.atomic.Value(u64),

    // System metrics
    syscalls_per_sec: std.atomic.Value(u64),
    context_switches: std.atomic.Value(u64),

    // Memory metrics
    allocations_per_sec: std.atomic.Value(u64),
    bytes_allocated: std.atomic.Value(u64),
    pool_utilization: std.atomic.Value(u32), // Percentage * 100

    // Error/drop metrics
    queue_drops: std.atomic.Value(u64),
    buffer_full: std.atomic.Value(u64),
    allocation_failures: std.atomic.Value(u64),

    // Timestamps
    last_update_time: std.atomic.Value(i64),
    start_time: i64,

    pub fn init() PerfMetrics {
        const now = std.time.milliTimestamp();
        return PerfMetrics{
            .bytes_per_sec = std.atomic.Value(u64).init(0),
            .packets_per_sec = std.atomic.Value(u64).init(0),
            .total_bytes = std.atomic.Value(u64).init(0),
            .total_packets = std.atomic.Value(u64).init(0),
            .avg_latency_us = std.atomic.Value(u64).init(0),
            .min_latency_us = std.atomic.Value(u64).init(std.math.maxInt(u64)),
            .max_latency_us = std.atomic.Value(u64).init(0),
            .p99_latency_us = std.atomic.Value(u64).init(0),
            .syscalls_per_sec = std.atomic.Value(u64).init(0),
            .context_switches = std.atomic.Value(u64).init(0),
            .allocations_per_sec = std.atomic.Value(u64).init(0),
            .bytes_allocated = std.atomic.Value(u64).init(0),
            .pool_utilization = std.atomic.Value(u32).init(0),
            .queue_drops = std.atomic.Value(u64).init(0),
            .buffer_full = std.atomic.Value(u64).init(0),
            .allocation_failures = std.atomic.Value(u64).init(0),
            .last_update_time = std.atomic.Value(i64).init(now),
            .start_time = now,
        };
    }

    /// Record packet transmission
    pub fn recordPacket(self: *PerfMetrics, bytes: usize, latency_us: u64) void {
        _ = self.total_bytes.fetchAdd(bytes, .monotonic);
        _ = self.total_packets.fetchAdd(1, .monotonic);

        // Update latency stats
        self.updateLatency(latency_us);
    }

    /// Update latency statistics
    fn updateLatency(self: *PerfMetrics, latency_us: u64) void {
        // Update min
        var current_min = self.min_latency_us.load(.monotonic);
        while (latency_us < current_min) {
            const result = self.min_latency_us.cmpxchgWeak(
                current_min,
                latency_us,
                .monotonic,
                .monotonic,
            );
            if (result == null) break;
            current_min = result.?;
        }

        // Update max
        var current_max = self.max_latency_us.load(.monotonic);
        while (latency_us > current_max) {
            const result = self.max_latency_us.cmpxchgWeak(
                current_max,
                latency_us,
                .monotonic,
                .monotonic,
            );
            if (result == null) break;
            current_max = result.?;
        }

        // Simple moving average for avg latency
        const current_avg = self.avg_latency_us.load(.monotonic);
        const new_avg = (current_avg * 9 + latency_us) / 10; // 90% old, 10% new
        self.avg_latency_us.store(new_avg, .monotonic);
    }

    /// Record queue drop
    pub fn recordDrop(self: *PerfMetrics) void {
        _ = self.queue_drops.fetchAdd(1, .monotonic);
    }

    /// Record buffer full event
    pub fn recordBufferFull(self: *PerfMetrics) void {
        _ = self.buffer_full.fetchAdd(1, .monotonic);
    }

    /// Record allocation failure
    pub fn recordAllocationFailure(self: *PerfMetrics) void {
        _ = self.allocation_failures.fetchAdd(1, .monotonic);
    }

    /// Update throughput metrics (call periodically, e.g., every second)
    pub fn updateThroughput(self: *PerfMetrics) void {
        const now = std.time.milliTimestamp();
        const last = self.last_update_time.swap(now, .monotonic);
        const elapsed_ms = now - last;

        if (elapsed_ms <= 0) return;

        // Calculate bytes/sec and packets/sec
        const total_bytes = self.total_bytes.load(.monotonic);
        const total_packets = self.total_packets.load(.monotonic);

        // Calculate rates (approximate, good enough for monitoring)
        const bytes_per_sec = (total_bytes * 1000) / @as(u64, @intCast(elapsed_ms));
        const packets_per_sec = (total_packets * 1000) / @as(u64, @intCast(elapsed_ms));

        self.bytes_per_sec.store(bytes_per_sec, .monotonic);
        self.packets_per_sec.store(packets_per_sec, .monotonic);
    }

    /// Get current throughput in Mbps
    pub fn getThroughputMbps(self: *PerfMetrics) f64 {
        const bytes_per_sec = self.bytes_per_sec.load(.monotonic);
        return @as(f64, @floatFromInt(bytes_per_sec * 8)) / 1_000_000.0;
    }

    /// Get drop rate (0.0 - 1.0)
    pub fn getDropRate(self: *PerfMetrics) f64 {
        const drops = self.queue_drops.load(.monotonic);
        const total = self.total_packets.load(.monotonic);
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(drops)) / @as(f64, @floatFromInt(total));
    }

    /// Print formatted metrics
    pub fn print(self: *PerfMetrics) void {
        const throughput_mbps = self.getThroughputMbps();
        const pps = self.packets_per_sec.load(.monotonic);
        const avg_latency = self.avg_latency_us.load(.monotonic);
        const min_latency = self.min_latency_us.load(.monotonic);
        const max_latency = self.max_latency_us.load(.monotonic);
        const drops = self.queue_drops.load(.monotonic);
        const drop_rate = self.getDropRate();

        std.debug.print(
            \\
            \\╔════════════════════════════════════════════════════════════════╗
            \\║  Performance Metrics                                           ║
            \\╠════════════════════════════════════════════════════════════════╣
            \\║  Throughput: {d:>8.2} Mbps  |  {d:>8} pps                       ║
            \\║  Latency:    {d:>8} µs avg  |  {d:>8} µs min |  {d:>8} µs max  ║
            \\║  Drops:      {d:>8} total   |  {d:>7.3}% rate                   ║
            \\╚════════════════════════════════════════════════════════════════╝
            \\
        ,
            .{
                throughput_mbps,
                pps,
                avg_latency,
                min_latency,
                max_latency,
                drops,
                drop_rate * 100.0,
            },
        );
    }

    /// Print compact one-line metrics
    pub fn printCompact(self: *PerfMetrics) void {
        const throughput_mbps = self.getThroughputMbps();
        const pps = self.packets_per_sec.load(.monotonic);
        const avg_latency = self.avg_latency_us.load(.monotonic);
        const drops = self.queue_drops.load(.monotonic);

        std.debug.print(
            "📊 {d:.2} Mbps | {d} pps | {d}µs latency | {d} drops\n",
            .{ throughput_mbps, pps, avg_latency, drops },
        );
    }

    /// Reset all metrics
    pub fn reset(self: *PerfMetrics) void {
        self.bytes_per_sec.store(0, .monotonic);
        self.packets_per_sec.store(0, .monotonic);
        self.total_bytes.store(0, .monotonic);
        self.total_packets.store(0, .monotonic);
        self.avg_latency_us.store(0, .monotonic);
        self.min_latency_us.store(std.math.maxInt(u64), .monotonic);
        self.max_latency_us.store(0, .monotonic);
        self.queue_drops.store(0, .monotonic);
        self.buffer_full.store(0, .monotonic);
        self.allocation_failures.store(0, .monotonic);
        self.start_time = std.time.milliTimestamp();
        self.last_update_time.store(self.start_time, .monotonic);
    }
};

test "perf metrics initialization" {
    var metrics = PerfMetrics.init();
    try std.testing.expectEqual(@as(u64, 0), metrics.total_packets.load(.monotonic));
    try std.testing.expectEqual(@as(f64, 0.0), metrics.getThroughputMbps());
}

test "perf metrics record packet" {
    var metrics = PerfMetrics.init();

    metrics.recordPacket(1500, 100); // 1500 bytes, 100µs latency
    metrics.recordPacket(1500, 200);
    metrics.recordPacket(1500, 150);

    try std.testing.expectEqual(@as(u64, 3), metrics.total_packets.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 4500), metrics.total_bytes.load(.monotonic));

    const avg_latency = metrics.avg_latency_us.load(.monotonic);
    try std.testing.expect(avg_latency > 0);
}

test "perf metrics drop rate" {
    var metrics = PerfMetrics.init();

    metrics.recordPacket(1000, 100);
    metrics.recordPacket(1000, 100);
    metrics.recordDrop();

    const drop_rate = metrics.getDropRate();
    try std.testing.expect(drop_rate > 0.0);
    try std.testing.expect(drop_rate < 1.0);
}
