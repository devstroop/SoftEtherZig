const std = @import("std");
const builtin = @import("builtin");

/// Performance metrics tracker
pub const Metrics = struct {
    packets_received: u64 = 0,
    packets_sent: u64 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,

    start_time: i64 = 0,
    syscall_count: u64 = 0,
    malloc_count: u64 = 0,

    latency_samples: std.ArrayList(u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Metrics {
        return .{
            .latency_samples = .{},
            .allocator = allocator,
            .start_time = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *Metrics) void {
        self.latency_samples.deinit(self.allocator);
    }

    pub fn recordPacketReceived(self: *Metrics, size: usize) void {
        self.packets_received += 1;
        self.bytes_received += size;
    }

    pub fn recordPacketSent(self: *Metrics, size: usize) void {
        self.packets_sent += 1;
        self.bytes_sent += size;
    }

    pub fn recordLatency(self: *Metrics, microseconds: u64) !void {
        try self.latency_samples.append(microseconds);
    }

    pub fn recordSyscall(self: *Metrics) void {
        self.syscall_count += 1;
    }

    pub fn recordMalloc(self: *Metrics) void {
        self.malloc_count += 1;
    }

    pub fn report(self: *Metrics) void {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_sec = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;

        const rx_mbps = if (elapsed_sec > 0)
            (@as(f64, @floatFromInt(self.bytes_received * 8)) / 1_000_000.0) / elapsed_sec
        else
            0.0;

        const tx_mbps = if (elapsed_sec > 0)
            (@as(f64, @floatFromInt(self.bytes_sent * 8)) / 1_000_000.0) / elapsed_sec
        else
            0.0;

        const rx_pps = if (elapsed_sec > 0)
            @as(f64, @floatFromInt(self.packets_received)) / elapsed_sec
        else
            0.0;

        const tx_pps = if (elapsed_sec > 0)
            @as(f64, @floatFromInt(self.packets_sent)) / elapsed_sec
        else
            0.0;

        // Calculate latency percentiles
        var p50: u64 = 0;
        var p99: u64 = 0;
        if (self.latency_samples.items.len > 0) {
            std.mem.sort(u64, self.latency_samples.items, {}, std.sort.asc(u64));
            const p50_idx = self.latency_samples.items.len / 2;
            const p99_idx = (self.latency_samples.items.len * 99) / 100;
            p50 = self.latency_samples.items[p50_idx];
            p99 = self.latency_samples.items[p99_idx];
        }

        const syscalls_per_pkt = if (self.packets_received > 0)
            @as(f64, @floatFromInt(self.syscall_count)) / @as(f64, @floatFromInt(self.packets_received))
        else
            0.0;

        const mallocs_per_pkt = if (self.packets_received > 0)
            @as(f64, @floatFromInt(self.malloc_count)) / @as(f64, @floatFromInt(self.packets_received))
        else
            0.0;

        std.debug.print(
            \\
            \\=== Performance Metrics ===
            \\Elapsed Time: {d:.2}s
            \\
            \\Throughput:
            \\  RX: {d:.2} Mbps ({d:.0} pps)
            \\  TX: {d:.2} Mbps ({d:.0} pps)
            \\
            \\Packets:
            \\  Received: {d}
            \\  Sent: {d}
            \\
            \\Latency:
            \\  p50: {d}µs
            \\  p99: {d}µs
            \\
            \\Efficiency:
            \\  Syscalls/packet: {d:.2}
            \\  Mallocs/packet: {d:.2}
            \\
            \\
        , .{
            elapsed_sec,
            rx_mbps,
            rx_pps,
            tx_mbps,
            tx_pps,
            self.packets_received,
            self.packets_sent,
            p50,
            p99,
            syscalls_per_pkt,
            mallocs_per_pkt,
        });
    }

    /// Print a quick status update (called periodically during operation)
    pub fn printStatus(self: *Metrics) void {
        const elapsed_ms = std.time.milliTimestamp() - self.start_time;
        const elapsed_sec = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;

        const rx_mbps = if (elapsed_sec > 0)
            (@as(f64, @floatFromInt(self.bytes_received * 8)) / 1_000_000.0) / elapsed_sec
        else
            0.0;

        std.debug.print("  [{d:.1}s] RX: {d:.2} Mbps ({d} packets)\r", .{
            elapsed_sec,
            rx_mbps,
            self.packets_received,
        });
    }
};

/// Timer for measuring latency
pub const Timer = struct {
    start_ns: i128,

    pub fn start() Timer {
        return .{ .start_ns = std.time.nanoTimestamp() };
    }

    pub fn elapsed(self: Timer) u64 {
        const now = std.time.nanoTimestamp();
        const elapsed_ns = now - self.start_ns;
        return @intCast(@divFloor(elapsed_ns, 1000)); // Convert to microseconds
    }
};
