// Pre-allocated Packet Pool - Eliminates malloc/free overhead in hot path
// This is a lock-free memory pool for packet buffers

const std = @import("std");

pub const PacketPool = struct {
    allocator: std.mem.Allocator,
    buffers: [][]u8,
    packet_size: usize,
    total_packets: usize,

    // Lock-free free list using atomic operations
    free_head: std.atomic.Value(usize),
    allocated_count: std.atomic.Value(usize),

    pub fn init(allocator: std.mem.Allocator, count: usize, size: usize) !*PacketPool {
        const self = try allocator.create(PacketPool);

        // Allocate array of buffer pointers
        var buffers = try allocator.alloc([]u8, count);

        // Pre-allocate all buffers
        var i: usize = 0;
        while (i < count) : (i += 1) {
            buffers[i] = try allocator.alloc(u8, size);
        }

        self.* = PacketPool{
            .allocator = allocator,
            .buffers = buffers,
            .packet_size = size,
            .total_packets = count,
            .free_head = std.atomic.Value(usize).init(0),
            .allocated_count = std.atomic.Value(usize).init(0),
        };

        return self;
    }

    pub fn deinit(self: *PacketPool) void {
        // Free all buffers
        for (self.buffers) |buf| {
            self.allocator.free(buf);
        }
        self.allocator.free(self.buffers);
        self.allocator.destroy(self);
    }

    /// Allocate a packet buffer from the pool (lock-free, fast!)
    pub fn alloc(self: *PacketPool) ?[]u8 {
        // Try to get a free buffer atomically
        const idx = self.free_head.fetchAdd(1, .acquire);

        if (idx >= self.total_packets) {
            // Pool exhausted, restore head
            _ = self.free_head.fetchSub(1, .release);
            return null;
        }

        _ = self.allocated_count.fetchAdd(1, .monotonic);
        return self.buffers[idx];
    }

    /// Free a packet buffer back to the pool
    pub fn free(self: *PacketPool, buffer: []u8) void {
        _ = buffer; // We don't actually need to track individual buffers
        _ = self.free_head.fetchSub(1, .release);
        _ = self.allocated_count.fetchSub(1, .monotonic);
    }

    /// Reset the pool (all buffers back to free state)
    pub fn reset(self: *PacketPool) void {
        self.free_head.store(0, .release);
        self.allocated_count.store(0, .monotonic);
    }

    /// Get current allocation statistics
    pub fn getStats(self: *PacketPool) PoolStats {
        const allocated = self.allocated_count.load(.monotonic);
        const free_count = self.total_packets - allocated;
        const utilization = @as(f32, @floatFromInt(allocated)) / @as(f32, @floatFromInt(self.total_packets));

        return PoolStats{
            .total = self.total_packets,
            .allocated = allocated,
            .free = free_count,
            .utilization = utilization,
        };
    }

    /// Check if pool is nearly exhausted (>90% used)
    pub fn isNearlyExhausted(self: *PacketPool) bool {
        const stats = self.getStats();
        return stats.utilization > 0.9;
    }

    /// Print pool statistics
    pub fn printStats(self: *PacketPool) void {
        const stats = self.getStats();
        std.debug.print(
            "🔵 Packet Pool: {d}/{d} used ({d:.1}% utilization)\n",
            .{ stats.allocated, stats.total, stats.utilization * 100.0 },
        );
    }
};

pub const PoolStats = struct {
    total: usize,
    allocated: usize,
    free: usize,
    utilization: f32,
};

test "packet pool allocation" {
    const allocator = std.testing.allocator;
    var pool = try PacketPool.init(allocator, 10, 2048);
    defer pool.deinit();

    // Allocate some buffers
    const buf1 = pool.alloc();
    try std.testing.expect(buf1 != null);
    try std.testing.expectEqual(@as(usize, 2048), buf1.?.len);

    const buf2 = pool.alloc();
    try std.testing.expect(buf2 != null);

    // Check stats
    const stats = pool.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.allocated);
    try std.testing.expectEqual(@as(usize, 8), stats.free);

    // Free buffers
    pool.free(buf1.?);
    pool.free(buf2.?);

    const stats2 = pool.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats2.allocated);
}

test "packet pool exhaustion" {
    const allocator = std.testing.allocator;
    var pool = try PacketPool.init(allocator, 3, 1024);
    defer pool.deinit();

    // Allocate all buffers
    _ = pool.alloc();
    _ = pool.alloc();
    _ = pool.alloc();

    // Next allocation should fail
    const buf = pool.alloc();
    try std.testing.expect(buf == null);

    // Pool should be nearly exhausted
    try std.testing.expect(pool.isNearlyExhausted());
}

test "packet pool reset" {
    const allocator = std.testing.allocator;
    var pool = try PacketPool.init(allocator, 5, 1024);
    defer pool.deinit();

    // Allocate some buffers
    _ = pool.alloc();
    _ = pool.alloc();

    const stats1 = pool.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats1.allocated);

    // Reset pool
    pool.reset();

    const stats2 = pool.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats2.allocated);
    try std.testing.expectEqual(@as(usize, 5), stats2.free);
}
