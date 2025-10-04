// High-performance packet structures and allocator
// Zero-copy design with memory pool for packet buffers

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

/// Maximum packet size (MTU + headers)
pub const MAX_PACKET_SIZE: usize = 2048;

/// Packet buffer with metadata
pub const Packet = struct {
    /// Packet data (slice into pool allocation)
    data: []u8,

    /// Actual packet length (may be less than data.len)
    len: usize,

    /// Timestamp when packet was received (nanoseconds)
    timestamp: i64,

    /// Packet type/flags
    flags: u8,

    pub const Flags = struct {
        pub const IPV4: u8 = 0x01;
        pub const IPV6: u8 = 0x02;
        pub const ARP: u8 = 0x04;
        pub const ETHERNET: u8 = 0x08;
    };

    /// Initialize packet from slice
    pub fn init(data: []u8, len: usize) Packet {
        assert(len <= data.len);

        return .{
            .data = data,
            .len = len,
            .timestamp = @intCast(std.time.nanoTimestamp()),
            .flags = detectType(data[0..len]),
        };
    }

    /// Detect packet type from first bytes
    fn detectType(data: []const u8) u8 {
        if (data.len == 0) return 0;

        // Check if Ethernet frame (14+ bytes with valid EtherType)
        if (data.len >= 14) {
            const ethertype = (@as(u16, data[12]) << 8) | data[13];
            if (ethertype == 0x0800 or ethertype == 0x0806 or ethertype == 0x86DD) {
                var flags = Flags.ETHERNET;
                if (ethertype == 0x0800) flags |= Flags.IPV4;
                if (ethertype == 0x86DD) flags |= Flags.IPV6;
                if (ethertype == 0x0806) flags |= Flags.ARP;
                return flags;
            }
        }

        // Raw IP packet
        const version = (data[0] >> 4) & 0x0F;
        if (version == 4) return Flags.IPV4;
        if (version == 6) return Flags.IPV6;

        return 0;
    }

    /// Check if IPv4 packet
    pub fn isIPv4(self: Packet) bool {
        return (self.flags & Flags.IPV4) != 0;
    }

    /// Check if IPv6 packet
    pub fn isIPv6(self: Packet) bool {
        return (self.flags & Flags.IPV6) != 0;
    }

    /// Check if ARP packet
    pub fn isARP(self: Packet) bool {
        return (self.flags & Flags.ARP) != 0;
    }

    /// Check if Ethernet frame
    pub fn isEthernet(self: Packet) bool {
        return (self.flags & Flags.ETHERNET) != 0;
    }

    /// Get active packet data
    pub fn bytes(self: Packet) []const u8 {
        return self.data[0..self.len];
    }
};

/// Memory pool for packet buffers
/// Pre-allocates fixed-size buffers to avoid malloc/free per packet
pub const PacketPool = struct {
    allocator: Allocator,
    buffers: [][]u8,
    free_list: std.ArrayList([]u8),
    buffer_size: usize,

    /// Statistics
    allocated: usize = 0,
    freed: usize = 0,
    reused: usize = 0,

    pub fn init(allocator: Allocator, pool_size: usize, buffer_size: usize) !PacketPool {
        var buffers = try allocator.alloc([]u8, pool_size);
        errdefer allocator.free(buffers);

        // Pre-allocate all buffers
        for (buffers, 0..) |*buf, i| {
            buf.* = try allocator.alloc(u8, buffer_size);
            errdefer {
                for (buffers[0..i]) |b| allocator.free(b);
            }
        }

        var free_list = try std.ArrayList([]u8).initCapacity(allocator, pool_size);
        errdefer free_list.deinit(allocator);

        try free_list.ensureTotalCapacity(allocator, pool_size);

        // Add all buffers to free list
        for (buffers) |buf| {
            free_list.appendAssumeCapacity(buf);
        }

        return .{
            .allocator = allocator,
            .buffers = buffers,
            .free_list = free_list,
            .buffer_size = buffer_size,
        };
    }

    pub fn deinit(self: *PacketPool) void {
        for (self.buffers) |buf| {
            self.allocator.free(buf);
        }
        self.allocator.free(self.buffers);
        self.free_list.deinit(self.allocator);
    }

    /// Allocate buffer from pool
    pub fn alloc(self: *PacketPool) ?[]u8 {
        if (self.free_list.getLastOrNull()) |buf| {
            _ = self.free_list.pop();
            self.allocated += 1;
            self.reused += 1;
            return buf;
        }

        // Pool exhausted - fall back to direct allocation
        const buf = self.allocator.alloc(u8, self.buffer_size) catch return null;
        self.allocated += 1;
        return buf;
    }

    /// Return buffer to pool
    pub fn free(self: *PacketPool, buf: []u8) void {
        self.freed += 1;

        // Only return to pool if it's the right size
        if (buf.len == self.buffer_size) {
            self.free_list.append(self.allocator, buf) catch {
                // Pool full - free buffer
                self.allocator.free(buf);
            };
        } else {
            self.allocator.free(buf);
        }
    }

    /// Get pool statistics
    pub fn getStats(self: *const PacketPool) Stats {
        return .{
            .pool_size = self.buffers.len,
            .available = self.free_list.items.len,
            .allocated = self.allocated,
            .freed = self.freed,
            .reused = self.reused,
            .reuse_rate = if (self.allocated > 0)
                @as(f64, @floatFromInt(self.reused)) / @as(f64, @floatFromInt(self.allocated)) * 100.0
            else
                0.0,
        };
    }

    pub const Stats = struct {
        pool_size: usize,
        available: usize,
        allocated: usize,
        freed: usize,
        reused: usize,
        reuse_rate: f64,

        pub fn format(
            self: Stats,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print(
                "PacketPool[size={d}, avail={d}, alloc={d}, free={d}, reuse={d:.1}%]",
                .{ self.pool_size, self.available, self.allocated, self.freed, self.reuse_rate },
            );
        }
    };
};

// Tests
test "Packet detection" {
    const testing = std.testing;

    // IPv4 packet
    var ipv4_data = [_]u8{0x45} ++ [_]u8{0} ** 19;
    var pkt = Packet.init(&ipv4_data, 20);
    try testing.expect(pkt.isIPv4());
    try testing.expect(!pkt.isIPv6());

    // IPv6 packet
    var ipv6_data = [_]u8{0x60} ++ [_]u8{0} ** 39;
    pkt = Packet.init(&ipv6_data, 40);
    try testing.expect(pkt.isIPv6());
    try testing.expect(!pkt.isIPv4());

    // Ethernet frame with IPv4
    var eth_data = [_]u8{0xFF} ** 6 ++ [_]u8{0xAA} ** 6 ++ [_]u8{ 0x08, 0x00 } ++ [_]u8{0x45} ++ [_]u8{0} ** 5;
    pkt = Packet.init(&eth_data, 20);
    try testing.expect(pkt.isEthernet());
    try testing.expect(pkt.isIPv4());
}

test "PacketPool basic operations" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var pool = try PacketPool.init(allocator, 4, 1500);
    defer pool.deinit();

    // Allocate buffers
    const buf1 = pool.alloc().?;
    const buf2 = pool.alloc().?;

    try testing.expectEqual(@as(usize, 1500), buf1.len);
    try testing.expectEqual(@as(usize, 1500), buf2.len);

    // Free buffers
    pool.free(buf1);
    pool.free(buf2);

    // Reuse buffers
    const buf3 = pool.alloc().?;
    try testing.expectEqual(@as(usize, 1500), buf3.len);

    pool.free(buf3);

    const stats = pool.getStats();
    try testing.expectEqual(@as(usize, 3), stats.allocated);
    try testing.expectEqual(@as(usize, 3), stats.freed);
}
