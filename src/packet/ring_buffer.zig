// Lock-free SPSC (Single Producer Single Consumer) Ring Buffer
// Optimized for high-throughput packet processing with zero allocations

const std = @import("std");
const Allocator = std.mem.Allocator;
const atomic = std.atomic;

/// Lock-free ring buffer for packet data
/// Uses atomic operations for synchronization between reader/writer threads
/// ZIGSE-25: Refactored to support runtime capacity (was comptime)
pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        // Allocator for heap storage
        allocator: Allocator,

        // Ring buffer storage (heap-allocated to avoid large struct size)
        items: []?T,

        // Runtime capacity (was comptime)
        capacity: usize,

        // Atomic indices for lock-free operation
        write_idx: atomic.Value(usize),
        read_idx: atomic.Value(usize),

        // Statistics
        drops: atomic.Value(u64),
        total_pushed: atomic.Value(u64),
        total_popped: atomic.Value(u64),

        /// Initialize empty ring buffer with runtime capacity
        /// ZIGSE-25: Capacity is now a runtime parameter (was comptime)
        pub fn init(allocator: Allocator, capacity: usize) !Self {
            if (capacity == 0) return error.InvalidCapacity;

            const items = try allocator.alloc(?T, capacity);
            errdefer allocator.free(items);

            // Initialize all slots to null
            for (items) |*item| {
                item.* = null;
            }

            return Self{
                .allocator = allocator,
                .items = items,
                .capacity = capacity,
                .write_idx = atomic.Value(usize).init(0),
                .read_idx = atomic.Value(usize).init(0),
                .drops = atomic.Value(u64).init(0),
                .total_pushed = atomic.Value(u64).init(0),
                .total_popped = atomic.Value(u64).init(0),
            };
        }

        /// Clean up heap-allocated items array
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
        }

        /// Push single item (returns false if full)
        pub fn push(self: *Self, item: T) bool {
            const write = self.write_idx.load(.acquire);
            const read = self.read_idx.load(.acquire);

            // Check if buffer is full
            const next_write = (write + 1) % self.capacity;
            if (next_write == read) {
                _ = self.drops.fetchAdd(1, .monotonic);
                return false; // Full
            }

            // Write item
            self.items[write] = item;

            // Update write index (release ensures item is visible before index update)
            self.write_idx.store(next_write, .release);
            _ = self.total_pushed.fetchAdd(1, .monotonic);

            return true;
        }

        /// Pop single item (returns null if empty)
        pub fn pop(self: *Self) ?T {
            const read = self.read_idx.load(.acquire);
            const write = self.write_idx.load(.acquire);

            // Check if buffer is empty
            if (read == write) {
                return null; // Empty
            }

            // Read item
            const item = self.items[read];
            self.items[read] = null;

            // Update read index
            const next_read = (read + 1) % self.capacity;
            self.read_idx.store(next_read, .release);
            _ = self.total_popped.fetchAdd(1, .monotonic);

            return item;
        }

        /// Batch pop up to N items (returns actual count)
        pub fn popBatch(self: *Self, out: []?T) usize {
            var count: usize = 0;

            while (count < out.len) {
                if (self.pop()) |item| {
                    out[count] = item;
                    count += 1;
                } else {
                    break;
                }
            }

            return count;
        }

        /// Get number of items available to read
        pub fn available(self: *Self) usize {
            const write = self.write_idx.load(.acquire);
            const read = self.read_idx.load(.acquire);

            if (write >= read) {
                return write - read;
            } else {
                return self.capacity - read + write;
            }
        }

        /// Get free space available
        pub fn freeSpace(self: *Self) usize {
            return self.capacity - 1 - self.available();
        }

        /// Check if empty
        pub fn isEmpty(self: *Self) bool {
            return self.read_idx.load(.acquire) == self.write_idx.load(.acquire);
        }

        /// Check if full
        pub fn isFull(self: *Self) bool {
            const write = self.write_idx.load(.acquire);
            const read = self.read_idx.load(.acquire);
            const next_write = (write + 1) % self.capacity;
            return next_write == read;
        }

        /// Get statistics
        pub fn getStats(self: *Self) Stats {
            return .{
                .capacity = self.capacity,
                .available = self.available(),
                .free_space = self.freeSpace(),
                .total_pushed = self.total_pushed.load(.monotonic),
                .total_popped = self.total_popped.load(.monotonic),
                .drops = self.drops.load(.monotonic),
            };
        }

        pub const Stats = struct {
            capacity: usize,
            available: usize,
            free_space: usize,
            total_pushed: u64,
            total_popped: u64,
            drops: u64,

            pub fn format(
                self: Stats,
                comptime _: []const u8,
                _: std.fmt.FormatOptions,
                writer: anytype,
            ) !void {
                try writer.print(
                    "RingBuffer[cap={d}, avail={d}, free={d}, push={d}, pop={d}, drops={d}]",
                    .{ self.capacity, self.available, self.free_space, self.total_pushed, self.total_popped, self.drops },
                );
            }
        };
    };
}

// Tests
test "RingBuffer basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var ring = try RingBuffer(u32).init(allocator, 4);
    defer ring.deinit();

    // Test empty
    try testing.expect(ring.isEmpty());
    try testing.expect(!ring.isFull());
    try testing.expectEqual(@as(usize, 0), ring.available());

    // Test push
    try testing.expect(ring.push(1));
    try testing.expect(ring.push(2));
    try testing.expect(ring.push(3));
    try testing.expectEqual(@as(usize, 3), ring.available());

    // Test pop
    try testing.expectEqual(@as(?u32, 1), ring.pop());
    try testing.expectEqual(@as(?u32, 2), ring.pop());
    try testing.expectEqual(@as(usize, 1), ring.available());

    // Test push after pop
    try testing.expect(ring.push(4));
    try testing.expect(ring.push(5));

    // Test full
    try testing.expect(!ring.push(6)); // Should fail (full)

    // Pop all
    try testing.expectEqual(@as(?u32, 3), ring.pop());
    try testing.expectEqual(@as(?u32, 4), ring.pop());
    try testing.expectEqual(@as(?u32, 5), ring.pop());
    try testing.expectEqual(@as(?u32, null), ring.pop());

    try testing.expect(ring.isEmpty());
}

test "RingBuffer batch operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var ring = try RingBuffer(u32).init(allocator, 8);
    defer ring.deinit();

    // Push multiple items
    for (0..5) |i| {
        try testing.expect(ring.push(@intCast(i)));
    }

    // Batch pop
    var batch: [3]?u32 = undefined;
    const count = ring.popBatch(&batch);

    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(@as(?u32, 0), batch[0]);
    try testing.expectEqual(@as(?u32, 1), batch[1]);
    try testing.expectEqual(@as(?u32, 2), batch[2]);

    // Remaining items
    try testing.expectEqual(@as(usize, 2), ring.available());
}

test "RingBuffer wrapping" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var ring = try RingBuffer(u32).init(allocator, 4);
    defer ring.deinit();

    // Fill and empty multiple times to test wrapping
    for (0..10) |cycle| {
        for (0..3) |i| {
            try testing.expect(ring.push(@intCast(cycle * 10 + i)));
        }

        for (0..3) |i| {
            try testing.expectEqual(@as(?u32, @intCast(cycle * 10 + i)), ring.pop());
        }
    }

    try testing.expect(ring.isEmpty());
}
