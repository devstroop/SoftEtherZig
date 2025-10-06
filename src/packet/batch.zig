// Batch Processing Module - Process multiple packets at once
// This reduces system call overhead and improves cache efficiency

const std = @import("std");

pub const BatchConfig = struct {
    max_batch_size: usize = 256,
    batch_timeout_us: u64 = 100, // Wait up to 100µs to fill batch
};

pub fn BatchProcessor(comptime T: type) type {
    return struct {
        const Self = @This();

        config: BatchConfig,
        batch_buffer: []T,
        current_count: usize,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, config: BatchConfig) !*Self {
            const batch_buffer = try allocator.alloc(T, config.max_batch_size);

            const self = try allocator.create(Self);
            self.* = Self{
                .config = config,
                .batch_buffer = batch_buffer,
                .current_count = 0,
                .allocator = allocator,
            };

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.batch_buffer);
            self.allocator.destroy(self);
        }

        /// Add item to batch, returns true if batch is full
        pub fn add(self: *Self, item: T) bool {
            if (self.current_count >= self.batch_buffer.len) {
                return true; // Batch full
            }

            self.batch_buffer[self.current_count] = item;
            self.current_count += 1;

            return self.current_count >= self.batch_buffer.len;
        }

        /// Get current batch and reset
        pub fn flush(self: *Self) []T {
            const result = self.batch_buffer[0..self.current_count];
            self.current_count = 0;
            return result;
        }

        /// Check if batch is full
        pub fn isFull(self: *Self) bool {
            return self.current_count >= self.batch_buffer.len;
        }

        /// Check if batch has any items
        pub fn hasItems(self: *Self) bool {
            return self.current_count > 0;
        }

        /// Get current batch size
        pub fn len(self: *Self) usize {
            return self.current_count;
        }
    };
}

test "batch processor basic operations" {
    const allocator = std.testing.allocator;
    const config = BatchConfig{ .max_batch_size = 4 };

    var processor = try BatchProcessor(u32).init(allocator, config);
    defer processor.deinit();

    try std.testing.expectEqual(@as(usize, 0), processor.len());

    // Add items
    try std.testing.expect(!processor.add(1));
    try std.testing.expect(!processor.add(2));
    try std.testing.expect(!processor.add(3));
    const full = processor.add(4);
    try std.testing.expect(full); // Should be full now

    try std.testing.expectEqual(@as(usize, 4), processor.len());

    // Flush
    const batch = processor.flush();
    try std.testing.expectEqual(@as(usize, 4), batch.len);
    try std.testing.expectEqual(@as(u32, 1), batch[0]);
    try std.testing.expectEqual(@as(u32, 4), batch[3]);

    // After flush, should be empty
    try std.testing.expectEqual(@as(usize, 0), processor.len());
}
