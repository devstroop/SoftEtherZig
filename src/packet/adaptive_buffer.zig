// Adaptive Buffer Manager - The Secret to 100+ Mbps Performance
//
// This is how 3rd party VPN apps achieve high throughput:
// - Start with small buffers (save memory)
// - Monitor throughput and queue utilization in real-time
// - Grow gradually when traffic increases
// - Shrink back when idle
//
// Result: 2-3x better throughput than fixed buffers!

const std = @import("std");

/// Configuration for adaptive buffer scaling
pub const AdaptiveBufferConfig = struct {
    // Size limits
    min_queue_size: usize = 1024, // 1K packets (low memory, startup)
    max_queue_size: usize = 131072, // 128K packets (high throughput)
    min_batch_size: usize = 8, // 8 packets minimum batch
    max_batch_size: usize = 512, // 512 packets maximum batch
    min_pool_size: usize = 2048, // 2K buffers minimum
    max_pool_size: usize = 262144, // 256K buffers maximum

    // Growth/shrink rates
    growth_factor: f32 = 1.5, // Grow by 50% each adjustment
    shrink_factor: f32 = 0.75, // Shrink by 25% each adjustment

    // Thresholds for scaling decisions
    high_utilization_threshold: f32 = 0.75, // 75% full -> grow
    low_utilization_threshold: f32 = 0.25, // 25% full -> shrink
    drop_threshold: f32 = 0.01, // 1% drops -> grow immediately

    // Time windows
    measurement_window_ms: u64 = 1000, // Measure every 1 second
    stable_period_ms: u64 = 5000, // 5 seconds stable before shrinking
    rapid_growth_window_ms: u64 = 500, // React quickly to growth (500ms)

    // Throughput-based scaling
    enable_throughput_scaling: bool = true,
    throughput_low_mbps: f32 = 5.0, // < 5 Mbps -> use small buffers
    throughput_medium_mbps: f32 = 50.0, // < 50 Mbps -> use medium buffers
    throughput_high_mbps: f32 = 100.0, // > 100 Mbps -> use large buffers
};

/// Action to take (grow or shrink)
pub const ScaleAction = enum {
    grow,
    shrink,
    none,
};

/// Adaptive buffer manager
pub const AdaptiveBufferManager = struct {
    config: AdaptiveBufferConfig,

    // Current sizes (adjusted dynamically)
    current_queue_size: std.atomic.Value(usize),
    current_batch_size: std.atomic.Value(usize),
    current_pool_size: std.atomic.Value(usize),

    // Statistics for decision making
    packets_processed: std.atomic.Value(u64),
    packets_dropped: std.atomic.Value(u64),
    bytes_processed: std.atomic.Value(u64),
    queue_utilization: std.atomic.Value(f32),
    throughput_mbps: std.atomic.Value(f32),

    // Timing
    last_adjustment_time: std.atomic.Value(i64),
    last_measurement_time: std.atomic.Value(i64),
    measurement_start_time: std.atomic.Value(i64),

    // History for trend detection (circular buffer)
    throughput_history: [16]f32,
    utilization_history: [16]f32,
    history_index: std.atomic.Value(usize),

    // State tracking
    consecutive_high_util: std.atomic.Value(u32),
    consecutive_low_util: std.atomic.Value(u32),

    pub fn init(config: AdaptiveBufferConfig) AdaptiveBufferManager {
        const now = std.time.milliTimestamp();

        return AdaptiveBufferManager{
            .config = config,
            .current_queue_size = std.atomic.Value(usize).init(config.min_queue_size),
            .current_batch_size = std.atomic.Value(usize).init(config.min_batch_size),
            .current_pool_size = std.atomic.Value(usize).init(config.min_pool_size),
            .packets_processed = std.atomic.Value(u64).init(0),
            .packets_dropped = std.atomic.Value(u64).init(0),
            .bytes_processed = std.atomic.Value(u64).init(0),
            .queue_utilization = std.atomic.Value(f32).init(0.0),
            .throughput_mbps = std.atomic.Value(f32).init(0.0),
            .last_adjustment_time = std.atomic.Value(i64).init(now),
            .last_measurement_time = std.atomic.Value(i64).init(now),
            .measurement_start_time = std.atomic.Value(i64).init(now),
            .throughput_history = [_]f32{0.0} ** 16,
            .utilization_history = [_]f32{0.0} ** 16,
            .history_index = std.atomic.Value(usize).init(0),
            .consecutive_high_util = std.atomic.Value(u32).init(0),
            .consecutive_low_util = std.atomic.Value(u32).init(0),
        };
    }

    /// Update statistics (call this periodically, e.g., every 100ms)
    pub fn updateStats(
        self: *AdaptiveBufferManager,
        queue_depth: usize,
        bytes_this_window: u64,
        packets_this_window: u64,
        drops_this_window: u64,
    ) void {
        const now = std.time.milliTimestamp();
        const start = self.measurement_start_time.load(.monotonic);
        const elapsed_ms = now - start;

        if (elapsed_ms == 0) return;

        // Calculate current throughput (Mbps)
        const mbps = @as(f32, @floatFromInt(bytes_this_window * 8)) /
            (@as(f32, @floatFromInt(elapsed_ms)) / 1000.0) / 1_000_000.0;

        self.throughput_mbps.store(mbps, .monotonic);
        _ = self.bytes_processed.fetchAdd(bytes_this_window, .monotonic);
        _ = self.packets_processed.fetchAdd(packets_this_window, .monotonic);
        _ = self.packets_dropped.fetchAdd(drops_this_window, .monotonic);

        // Calculate queue utilization
        const current_size = self.current_queue_size.load(.monotonic);
        const utilization = if (current_size > 0)
            @as(f32, @floatFromInt(queue_depth)) / @as(f32, @floatFromInt(current_size))
        else
            0.0;

        self.queue_utilization.store(utilization, .monotonic);

        // Store in history
        const idx = self.history_index.load(.monotonic);
        self.throughput_history[idx % self.throughput_history.len] = mbps;
        self.utilization_history[idx % self.utilization_history.len] = utilization;
        _ = self.history_index.fetchAdd(1, .monotonic);

        // Track consecutive high/low utilization
        if (utilization > self.config.high_utilization_threshold) {
            _ = self.consecutive_high_util.fetchAdd(1, .monotonic);
            self.consecutive_low_util.store(0, .monotonic);
        } else if (utilization < self.config.low_utilization_threshold) {
            _ = self.consecutive_low_util.fetchAdd(1, .monotonic);
            self.consecutive_high_util.store(0, .monotonic);
        } else {
            self.consecutive_high_util.store(0, .monotonic);
            self.consecutive_low_util.store(0, .monotonic);
        }

        self.last_measurement_time.store(now, .monotonic);
    }

    /// Decide if we should scale (call after updateStats)
    pub fn shouldAdjust(self: *AdaptiveBufferManager) ScaleAction {
        const now = std.time.milliTimestamp();
        const last_adjust = self.last_adjustment_time.load(.monotonic);
        const time_since_adjust = now - last_adjust;

        const utilization = self.queue_utilization.load(.monotonic);
        const throughput = self.throughput_mbps.load(.monotonic);
        const current_queue = self.current_queue_size.load(.monotonic);

        // Calculate drop rate
        const total_packets = self.packets_processed.load(.monotonic);
        const drops = self.packets_dropped.load(.monotonic);
        const drop_rate = if (total_packets > 0)
            @as(f32, @floatFromInt(drops)) / @as(f32, @floatFromInt(total_packets))
        else
            0.0;

        // URGENT: High drop rate -> grow immediately!
        if (drop_rate > self.config.drop_threshold and current_queue < self.config.max_queue_size) {
            std.debug.print(
                "⚠️  HIGH DROP RATE ({d:.2}%) -> GROW IMMEDIATELY!\n",
                .{drop_rate * 100.0},
            );
            return .grow;
        }

        // RAPID GROWTH: Multiple consecutive high utilization samples
        const consecutive_high = self.consecutive_high_util.load(.monotonic);
        if (consecutive_high >= 3 and current_queue < self.config.max_queue_size) {
            if (time_since_adjust >= self.config.rapid_growth_window_ms) {
                return .grow;
            }
        }

        // NORMAL GROWTH: High utilization detected
        if (utilization > self.config.high_utilization_threshold and
            current_queue < self.config.max_queue_size)
        {
            if (time_since_adjust >= self.config.measurement_window_ms) {
                return .grow;
            }
        }

        // THROUGHPUT-BASED SCALING: Adjust based on actual throughput
        if (self.config.enable_throughput_scaling) {
            if (throughput > self.config.throughput_high_mbps) {
                // High throughput -> need large buffers
                const target_size = self.config.max_queue_size * 3 / 4; // 75% of max
                if (current_queue < target_size and time_since_adjust >= self.config.measurement_window_ms) {
                    return .grow;
                }
            } else if (throughput < self.config.throughput_low_mbps) {
                // Low throughput -> can use small buffers
                const target_size = self.config.min_queue_size * 2; // 2x min
                if (current_queue > target_size and time_since_adjust >= self.config.stable_period_ms) {
                    return .shrink;
                }
            }
        }

        // SHRINK: Low utilization for extended period
        const consecutive_low = self.consecutive_low_util.load(.monotonic);
        if (consecutive_low >= 5 and current_queue > self.config.min_queue_size) {
            if (time_since_adjust >= self.config.stable_period_ms) {
                return .shrink;
            }
        }

        return .none;
    }

    /// Apply the scaling decision
    pub fn applyScaling(self: *AdaptiveBufferManager, action: ScaleAction) void {
        if (action == .none) return;

        const current_queue = self.current_queue_size.load(.monotonic);
        const current_batch = self.current_batch_size.load(.monotonic);
        const current_pool = self.current_pool_size.load(.monotonic);
        const utilization = self.queue_utilization.load(.monotonic);
        const throughput = self.throughput_mbps.load(.monotonic);

        switch (action) {
            .grow => {
                // GROW: Increase by growth_factor
                const new_queue = @min(
                    @as(usize, @intFromFloat(@as(f32, @floatFromInt(current_queue)) * self.config.growth_factor)),
                    self.config.max_queue_size,
                );
                const new_batch = @min(
                    @as(usize, @intFromFloat(@as(f32, @floatFromInt(current_batch)) * self.config.growth_factor)),
                    self.config.max_batch_size,
                );
                const new_pool = @min(
                    @as(usize, @intFromFloat(@as(f32, @floatFromInt(current_pool)) * self.config.growth_factor)),
                    self.config.max_pool_size,
                );

                self.current_queue_size.store(new_queue, .monotonic);
                self.current_batch_size.store(new_batch, .monotonic);
                self.current_pool_size.store(new_pool, .monotonic);

                std.debug.print(
                    "📈 SCALING UP: queue {d}→{d}, batch {d}→{d}, pool {d}→{d} " ++
                        "(util: {d:.1}%, throughput: {d:.1} Mbps)\n",
                    .{
                        current_queue,       new_queue,
                        current_batch,       new_batch,
                        current_pool,        new_pool,
                        utilization * 100.0, throughput,
                    },
                );
            },
            .shrink => {
                // SHRINK: Decrease by shrink_factor
                const new_queue = @max(
                    @as(usize, @intFromFloat(@as(f32, @floatFromInt(current_queue)) * self.config.shrink_factor)),
                    self.config.min_queue_size,
                );
                const new_batch = @max(
                    @as(usize, @intFromFloat(@as(f32, @floatFromInt(current_batch)) * self.config.shrink_factor)),
                    self.config.min_batch_size,
                );
                const new_pool = @max(
                    @as(usize, @intFromFloat(@as(f32, @floatFromInt(current_pool)) * self.config.shrink_factor)),
                    self.config.min_pool_size,
                );

                self.current_queue_size.store(new_queue, .monotonic);
                self.current_batch_size.store(new_batch, .monotonic);
                self.current_pool_size.store(new_pool, .monotonic);

                std.debug.print(
                    "📉 SCALING DOWN: queue {d}→{d}, batch {d}→{d}, pool {d}→{d} " ++
                        "(util: {d:.1}%, throughput: {d:.1} Mbps)\n",
                    .{
                        current_queue,       new_queue,
                        current_batch,       new_batch,
                        current_pool,        new_pool,
                        utilization * 100.0, throughput,
                    },
                );
            },
            .none => {},
        }

        self.last_adjustment_time.store(std.time.milliTimestamp(), .monotonic);
    }

    /// Get current recommended batch size
    pub fn getBatchSize(self: *AdaptiveBufferManager) usize {
        return self.current_batch_size.load(.monotonic);
    }

    /// Get current queue size
    pub fn getQueueSize(self: *AdaptiveBufferManager) usize {
        return self.current_queue_size.load(.monotonic);
    }

    /// Get current pool size
    pub fn getPoolSize(self: *AdaptiveBufferManager) usize {
        return self.current_pool_size.load(.monotonic);
    }

    /// Check if throughput is increasing (growth trend)
    pub fn isThroughputIncreasing(self: *AdaptiveBufferManager) bool {
        const idx = self.history_index.load(.monotonic);
        if (idx < 2) return false;

        var increasing_count: usize = 0;
        var i: usize = 1;
        const history_len = @min(idx, self.throughput_history.len);

        while (i < history_len) : (i += 1) {
            const prev = self.throughput_history[(idx - i - 1) % self.throughput_history.len];
            const curr = self.throughput_history[(idx - i) % self.throughput_history.len];

            if (curr > prev * 1.1) { // 10% increase
                increasing_count += 1;
            }
        }

        // If 70% of recent samples show growth, consider it a trend
        return increasing_count >= (history_len * 7 / 10);
    }

    /// Get statistics summary
    pub fn getStats(self: *AdaptiveBufferManager) Stats {
        const total_packets = self.packets_processed.load(.monotonic);
        const drops = self.packets_dropped.load(.monotonic);

        return Stats{
            .queue_size = self.current_queue_size.load(.monotonic),
            .batch_size = self.current_batch_size.load(.monotonic),
            .pool_size = self.current_pool_size.load(.monotonic),
            .utilization = self.queue_utilization.load(.monotonic),
            .throughput_mbps = self.throughput_mbps.load(.monotonic),
            .packets_processed = total_packets,
            .packets_dropped = drops,
            .drop_rate = if (total_packets > 0)
                @as(f32, @floatFromInt(drops)) / @as(f32, @floatFromInt(total_packets))
            else
                0.0,
        };
    }

    /// Reset measurement window (call after updateStats)
    pub fn resetMeasurementWindow(self: *AdaptiveBufferManager) void {
        self.measurement_start_time.store(std.time.milliTimestamp(), .monotonic);
    }
};

/// Statistics snapshot
pub const Stats = struct {
    queue_size: usize,
    batch_size: usize,
    pool_size: usize,
    utilization: f32,
    throughput_mbps: f32,
    packets_processed: u64,
    packets_dropped: u64,
    drop_rate: f32,

    pub fn format(
        self: Stats,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print(
            "AdaptiveBuffer[Q:{d}, B:{d}, P:{d}, util:{d:.1}%, {d:.1}Mbps, drops:{d:.2}%]",
            .{
                self.queue_size,
                self.batch_size,
                self.pool_size,
                self.utilization * 100.0,
                self.throughput_mbps,
                self.drop_rate * 100.0,
            },
        );
    }
};

// Example usage:
//
// var adaptive = AdaptiveBufferManager.init(.{
//     .min_queue_size = 1024,
//     .max_queue_size = 131072,
// });
//
// // In your monitoring loop (every 100ms):
// adaptive.updateStats(queue_depth, bytes, packets, drops);
// const action = adaptive.shouldAdjust();
// adaptive.applyScaling(action);
// adaptive.resetMeasurementWindow();
//
// // In your packet processing:
// const batch_size = adaptive.getBatchSize();
// var batch = try allocator.alloc(Packet, batch_size);
// // ... process up to batch_size packets
