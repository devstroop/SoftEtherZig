//! Memory Management Module
//!
//! Pure Zig replacement for Mayaqua/Memory.c
//! Provides allocator wrappers, memory pools, and debugging utilities.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Tracking allocator that counts allocations for debugging
pub const TrackingAllocator = struct {
    backing_allocator: Allocator,
    allocations: usize = 0,
    deallocations: usize = 0,
    bytes_allocated: usize = 0,
    peak_bytes: usize = 0,
    current_bytes: usize = 0,

    pub fn init(backing: Allocator) TrackingAllocator {
        return .{ .backing_allocator = backing };
    }

    /// Get stats without being a full allocator - simpler approach for debugging
    pub fn wrap(self: *TrackingAllocator, comptime T: type, n: usize) ![]T {
        const slice = try self.backing_allocator.alloc(T, n);
        self.allocations += 1;
        self.bytes_allocated += n * @sizeOf(T);
        self.current_bytes += n * @sizeOf(T);
        if (self.current_bytes > self.peak_bytes) {
            self.peak_bytes = self.current_bytes;
        }
        return slice;
    }

    pub fn unwrap(self: *TrackingAllocator, comptime T: type, slice: []T) void {
        const size = slice.len * @sizeOf(T);
        self.deallocations += 1;
        self.current_bytes -= size;
        self.backing_allocator.free(slice);
    }

    /// Print allocation statistics
    pub fn printStats(self: *const TrackingAllocator) void {
        std.debug.print(
            \\Memory Statistics:
            \\  Allocations:   {}
            \\  Deallocations: {}
            \\  Current bytes: {}
            \\  Peak bytes:    {}
            \\  Total bytes:   {}
            \\
        , .{
            self.allocations,
            self.deallocations,
            self.current_bytes,
            self.peak_bytes,
            self.bytes_allocated,
        });
    }

    /// Check for memory leaks
    pub fn checkLeaks(self: *const TrackingAllocator) bool {
        return self.allocations != self.deallocations or self.current_bytes != 0;
    }
};

/// Fixed-size pool allocator for packet buffers
/// Reduces allocation overhead for frequently allocated same-size objects
pub fn PoolAllocator(comptime T: type) type {
    return struct {
        const Self = @This();
        const Pool = std.heap.MemoryPool(T);

        pool: Pool,

        pub fn init(backing: Allocator) Self {
            return .{
                .pool = Pool.init(backing),
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.deinit();
        }

        pub fn create(self: *Self) !*T {
            return self.pool.create();
        }

        pub fn destroy(self: *Self, ptr: *T) void {
            self.pool.destroy(ptr);
        }
    };
}

/// Buffer - dynamic byte array (replaces Mayaqua BUF)
pub const Buffer = struct {
    data: std.ArrayListUnmanaged(u8),
    allocator: Allocator,

    pub fn init(allocator: Allocator) Buffer {
        return .{
            .data = .{},
            .allocator = allocator,
        };
    }

    pub fn initCapacity(allocator: Allocator, capacity: usize) !Buffer {
        var data = std.ArrayListUnmanaged(u8){};
        try data.ensureTotalCapacity(allocator, capacity);
        return .{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Buffer) void {
        self.data.deinit(self.allocator);
    }

    pub fn append(self: *Buffer, bytes: []const u8) !void {
        try self.data.appendSlice(self.allocator, bytes);
    }

    pub fn appendByte(self: *Buffer, byte: u8) !void {
        try self.data.append(self.allocator, byte);
    }

    /// Write u16 big-endian
    pub fn writeU16BE(self: *Buffer, value: u16) !void {
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, value, .big);
        try self.append(&buf);
    }

    /// Write u32 big-endian
    pub fn writeU32BE(self: *Buffer, value: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .big);
        try self.append(&buf);
    }

    /// Write u64 big-endian
    pub fn writeU64BE(self: *Buffer, value: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .big);
        try self.append(&buf);
    }

    pub fn toOwnedSlice(self: *Buffer) ![]u8 {
        return self.data.toOwnedSlice(self.allocator);
    }

    pub fn items(self: *const Buffer) []const u8 {
        return self.data.items;
    }

    pub fn len(self: *const Buffer) usize {
        return self.data.items.len;
    }

    pub fn clear(self: *Buffer) void {
        self.data.clearRetainingCapacity();
    }
};

/// BufferReader - for parsing binary data
pub const BufferReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) BufferReader {
        return .{ .data = data };
    }

    pub fn remaining(self: *const BufferReader) usize {
        return self.data.len - self.pos;
    }

    pub fn readByte(self: *BufferReader) !u8 {
        if (self.pos >= self.data.len) return error.EndOfBuffer;
        const byte = self.data[self.pos];
        self.pos += 1;
        return byte;
    }

    pub fn readBytes(self: *BufferReader, n: usize) ![]const u8 {
        if (self.pos + n > self.data.len) return error.EndOfBuffer;
        const slice = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    pub fn readU16BE(self: *BufferReader) !u16 {
        const bytes = try self.readBytes(2);
        return std.mem.readInt(u16, bytes[0..2], .big);
    }

    pub fn readU32BE(self: *BufferReader) !u32 {
        const bytes = try self.readBytes(4);
        return std.mem.readInt(u32, bytes[0..4], .big);
    }

    pub fn readU64BE(self: *BufferReader) !u64 {
        const bytes = try self.readBytes(8);
        return std.mem.readInt(u64, bytes[0..8], .big);
    }

    pub fn skip(self: *BufferReader, n: usize) !void {
        if (self.pos + n > self.data.len) return error.EndOfBuffer;
        self.pos += n;
    }

    pub fn peek(self: *const BufferReader, n: usize) ?[]const u8 {
        if (self.pos + n > self.data.len) return null;
        return self.data[self.pos .. self.pos + n];
    }
};

// ============================================================================
// C-compatible wrappers (for gradual migration)
// These can be exported with @export for C interop during transition
// ============================================================================

/// Allocate zeroed memory (like ZeroMalloc)
pub fn zeroAlloc(allocator: Allocator, comptime T: type, n: usize) ![]T {
    const slice = try allocator.alloc(T, n);
    @memset(slice, std.mem.zeroes(T));
    return slice;
}

/// Clone/duplicate memory
pub fn clone(allocator: Allocator, data: []const u8) ![]u8 {
    return allocator.dupe(u8, data);
}

/// Secure memory zeroing (for passwords, keys)
pub fn secureZero(slice: []u8) void {
    // Use volatile to prevent optimization
    for (slice) |*byte| {
        @as(*volatile u8, byte).* = 0;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "TrackingAllocator tracks allocations" {
    var tracking = TrackingAllocator.init(testing.allocator);

    const ptr = try tracking.wrap(u8, 100);
    try testing.expectEqual(@as(usize, 1), tracking.allocations);
    try testing.expectEqual(@as(usize, 100), tracking.current_bytes);

    tracking.unwrap(u8, ptr);
    try testing.expectEqual(@as(usize, 1), tracking.deallocations);
    try testing.expectEqual(@as(usize, 0), tracking.current_bytes);
    try testing.expect(!tracking.checkLeaks());
}

test "Buffer write and read" {
    var buf = Buffer.init(testing.allocator);
    defer buf.deinit();

    try buf.writeU32BE(0x12345678);
    try buf.append("hello");

    try testing.expectEqual(@as(usize, 9), buf.len());
    try testing.expectEqual(@as(u8, 0x12), buf.items()[0]);
    try testing.expectEqual(@as(u8, 0x34), buf.items()[1]);
}

test "BufferReader parses correctly" {
    const data = [_]u8{ 0x00, 0x00, 0x04, 0x13, 'h', 'i' };
    var reader = BufferReader.init(&data);

    const version = try reader.readU32BE();
    try testing.expectEqual(@as(u32, 0x0413), version);

    const str = try reader.readBytes(2);
    try testing.expectEqualStrings("hi", str);
}

test "secureZero clears memory" {
    var secret = [_]u8{ 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
    secureZero(&secret);

    for (secret) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}
