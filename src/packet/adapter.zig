// High-performance Zig packet adapter
// Replaces C implementation with lock-free queues and batch processing

const std = @import("std");
const RingBuffer = @import("ring_buffer.zig").RingBuffer;
const Packet = @import("packet.zig").Packet;
const PacketPool = @import("packet.zig").PacketPool;
const MAX_PACKET_SIZE = @import("packet.zig").MAX_PACKET_SIZE;

// C FFI declarations for macOS utun
const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/kern_control.h");
    @cInclude("sys/sys_domain.h");
});

const SYSPROTO_CONTROL = 2;
const AF_SYS_CONTROL = 2;

/// Packet adapter configuration
pub const Config = struct {
    /// Ring buffer size (must be power of 2)
    recv_queue_size: usize = 8192,
    send_queue_size: usize = 4096,

    /// Packet pool size
    packet_pool_size: usize = 16384,

    /// Batch size for processing
    batch_size: usize = 32,

    /// TUN device name
    device_name: []const u8 = "utun",
};

/// Packet with owned buffer
const PacketBuffer = struct {
    data: []u8,
    len: usize,
    timestamp: i64,
};

/// High-performance packet adapter using Zig primitives
pub const ZigPacketAdapter = struct {
    allocator: std.mem.Allocator,
    config: Config,

    // TUN device handle
    tun_fd: std.posix.fd_t,
    device_name: []u8,

    // Lock-free queues
    recv_queue: RingBuffer(PacketBuffer, 8192),
    send_queue: RingBuffer(PacketBuffer, 4096),

    // Memory pool
    packet_pool: PacketPool,

    // Threads
    read_thread: ?std.Thread = null,
    write_thread: ?std.Thread = null,
    running: std.atomic.Value(bool),

    // Statistics
    stats: Stats,

    pub const Stats = struct {
        packets_read: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        packets_written: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        bytes_read: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        bytes_written: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        read_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        write_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        recv_queue_drops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        send_queue_drops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub fn format(
            self: Stats,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print(
                "Stats[rx_pkt={d}, tx_pkt={d}, rx_bytes={d}, tx_bytes={d}, rx_err={d}, tx_err={d}]",
                .{
                    self.packets_read.load(.monotonic),
                    self.packets_written.load(.monotonic),
                    self.bytes_read.load(.monotonic),
                    self.bytes_written.load(.monotonic),
                    self.read_errors.load(.monotonic),
                    self.write_errors.load(.monotonic),
                },
            );
        }
    };

    /// Initialize packet adapter
    pub fn init(allocator: std.mem.Allocator, config: Config) !*ZigPacketAdapter {
        const self = try allocator.create(ZigPacketAdapter);
        errdefer allocator.destroy(self);

        // Allocate device name
        const device_name = try allocator.alloc(u8, config.device_name.len);
        errdefer allocator.free(device_name);
        @memcpy(device_name, config.device_name);

        // Initialize packet pool
        var packet_pool = try PacketPool.init(allocator, config.packet_pool_size, MAX_PACKET_SIZE);
        errdefer packet_pool.deinit();

        self.* = .{
            .allocator = allocator,
            .config = config,
            .tun_fd = -1,
            .device_name = device_name,
            .recv_queue = RingBuffer(PacketBuffer, 8192).init(),
            .send_queue = RingBuffer(PacketBuffer, 4096).init(),
            .packet_pool = packet_pool,
            .running = std.atomic.Value(bool).init(false),
            .stats = .{},
        };

        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *ZigPacketAdapter) void {
        self.stop();

        if (self.tun_fd >= 0) {
            std.posix.close(self.tun_fd);
        }

        self.allocator.free(self.device_name);
        self.packet_pool.deinit();
        self.allocator.destroy(self);
    }

    /// Open TUN device (macOS utun)
    pub fn open(self: *ZigPacketAdapter) !void {
        // Open /dev/utun control socket
        const fd = try std.posix.socket(std.posix.AF.SYSTEM, std.posix.SOCK.DGRAM, SYSPROTO_CONTROL);
        errdefer std.posix.close(fd);

        // Get utun control ID
        var info: c.ctl_info = std.mem.zeroes(c.ctl_info);
        const utun_control = "com.apple.net.utun_control";
        @memcpy(info.ctl_name[0..utun_control.len], utun_control);

        if (c.ioctl(fd, c.CTLIOCGINFO, &info) < 0) {
            return error.IoctlFailed;
        }

        // Connect to utun
        var addr: c.sockaddr_ctl = std.mem.zeroes(c.sockaddr_ctl);
        addr.sc_len = @sizeOf(c.sockaddr_ctl);
        addr.sc_family = std.posix.AF.SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0; // Auto-assign unit number

        const conn_result = c.connect(fd, @ptrCast(&addr), @sizeOf(c.sockaddr_ctl));
        if (conn_result < 0) {
            return error.ConnectFailed;
        }

        // Set non-blocking
        const O_NONBLOCK: c_int = 0x0004; // macOS O_NONBLOCK
        const flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags | O_NONBLOCK);

        self.tun_fd = fd;

        std.debug.print("[Zig] Opened TUN device fd={d}\n", .{fd});
    }

    /// Start read/write threads
    pub fn start(self: *ZigPacketAdapter) !void {
        if (self.running.load(.acquire)) {
            return error.AlreadyRunning;
        }

        self.running.store(true, .release);

        // Start read thread
        self.read_thread = try std.Thread.spawn(.{}, readThreadFn, .{self});

        // Start write thread
        self.write_thread = try std.Thread.spawn(.{}, writeThreadFn, .{self});

        std.debug.print("[Zig] Started read/write threads\n", .{});
    }

    /// Stop threads
    pub fn stop(self: *ZigPacketAdapter) void {
        if (!self.running.load(.acquire)) {
            return;
        }

        self.running.store(false, .release);

        if (self.read_thread) |thread| {
            thread.join();
            self.read_thread = null;
        }

        if (self.write_thread) |thread| {
            thread.join();
            self.write_thread = null;
        }

        std.debug.print("[Zig] Stopped threads\n", .{});
    }

    /// Read thread - continuously reads from TUN device
    fn readThreadFn(self: *ZigPacketAdapter) void {
        std.debug.print("[Zig] Read thread started\n", .{});

        while (self.running.load(.acquire)) {
            // Get buffer from pool
            const buffer = self.packet_pool.alloc() orelse {
                std.Thread.sleep(100 * std.time.ns_per_us); // 100 µs
                continue;
            };

            // Read from TUN device (with 4-byte header on macOS)
            const bytes_read = std.posix.read(self.tun_fd, buffer) catch |err| {
                if (err == error.WouldBlock) {
                    self.packet_pool.free(buffer);
                    std.Thread.sleep(100 * std.time.ns_per_us); // 100 µs
                    continue;
                }

                _ = self.stats.read_errors.fetchAdd(1, .monotonic);
                self.packet_pool.free(buffer);
                continue;
            };

            if (bytes_read <= 4) {
                // Too small or just header
                self.packet_pool.free(buffer);
                continue;
            }

            // Skip 4-byte header (protocol family)
            const packet_data = buffer[4..bytes_read];

            // Create packet buffer
            const pkt = PacketBuffer{
                .data = buffer,
                .len = bytes_read - 4, // Actual IP packet length
                .timestamp = @intCast(std.time.nanoTimestamp()),
            };

            // Push to queue
            if (!self.recv_queue.push(pkt)) {
                // Queue full - drop packet
                _ = self.stats.recv_queue_drops.fetchAdd(1, .monotonic);
                self.packet_pool.free(buffer);
                continue;
            }

            // Update stats
            _ = self.stats.packets_read.fetchAdd(1, .monotonic);
            _ = self.stats.bytes_read.fetchAdd(packet_data.len, .monotonic);
        }

        std.debug.print("[Zig] Read thread stopped\n", .{});
    }

    /// Write thread - continuously writes to TUN device
    fn writeThreadFn(self: *ZigPacketAdapter) void {
        std.debug.print("[Zig] Write thread started\n", .{});

        var batch: [32]?PacketBuffer = undefined;

        while (self.running.load(.acquire)) {
            // Batch pop from queue
            const count = self.send_queue.popBatch(&batch);

            if (count == 0) {
                std.Thread.sleep(100 * std.time.ns_per_us); // 100 µs
                continue;
            }

            // Write batch
            for (batch[0..count]) |pkt_opt| {
                const pkt = pkt_opt orelse continue;

                // Prepare buffer with 4-byte header
                var header: [4]u8 = undefined;
                const version = (pkt.data[4] >> 4) & 0x0F;

                if (version == 4) {
                    // AF_INET
                    std.mem.writeInt(u32, &header, 0x02000000, .big);
                } else {
                    // AF_INET6
                    std.mem.writeInt(u32, &header, 0x1E000000, .big);
                }

                // Write header + packet
                _ = std.posix.write(self.tun_fd, &header) catch {
                    _ = self.stats.write_errors.fetchAdd(1, .monotonic);
                    self.packet_pool.free(pkt.data);
                    continue;
                };

                _ = std.posix.write(self.tun_fd, pkt.data[4 .. 4 + pkt.len]) catch {
                    _ = self.stats.write_errors.fetchAdd(1, .monotonic);
                    self.packet_pool.free(pkt.data);
                    continue;
                };

                // Update stats
                _ = self.stats.packets_written.fetchAdd(1, .monotonic);
                _ = self.stats.bytes_written.fetchAdd(pkt.len, .monotonic);

                // Return buffer to pool
                self.packet_pool.free(pkt.data);
            }
        }

        std.debug.print("[Zig] Write thread stopped\n", .{});
    }

    /// Get next packet (called by SoftEther protocol layer)
    pub fn getNextPacket(self: *ZigPacketAdapter) ?PacketBuffer {
        return self.recv_queue.pop();
    }

    /// Get batch of packets (NEW API for batch processing)
    pub fn getPacketBatch(self: *ZigPacketAdapter, out: []?PacketBuffer) usize {
        return self.recv_queue.popBatch(out);
    }

    /// Put packet for transmission
    pub fn putPacket(self: *ZigPacketAdapter, data: []const u8) bool {
        // Get buffer from pool
        const buffer = self.packet_pool.alloc() orelse return false;

        // Copy packet data (skip 4 bytes for header)
        if (data.len + 4 > buffer.len) {
            self.packet_pool.free(buffer);
            return false;
        }

        @memcpy(buffer[4 .. 4 + data.len], data);

        const pkt = PacketBuffer{
            .data = buffer,
            .len = data.len,
            .timestamp = @intCast(std.time.nanoTimestamp()),
        };

        if (!self.send_queue.push(pkt)) {
            _ = self.stats.send_queue_drops.fetchAdd(1, .monotonic);
            self.packet_pool.free(buffer);
            return false;
        }

        return true;
    }

    /// Get statistics
    pub fn getStats(self: *ZigPacketAdapter) StatsSnapshot {
        return .{
            .adapter = self.stats,
            .recv_queue = self.recv_queue.getStats(),
            .send_queue = self.send_queue.getStats(),
            .packet_pool = self.packet_pool.getStats(),
        };
    }

    pub const StatsSnapshot = struct {
        adapter: Stats,
        recv_queue: RingBuffer(PacketBuffer, 8192).Stats,
        send_queue: RingBuffer(PacketBuffer, 4096).Stats,
        packet_pool: PacketPool.Stats,

        pub fn print(self: StatsSnapshot) void {
            std.debug.print("\n=== Zig Packet Adapter Stats ===\n", .{});
            std.debug.print("Adapter: {any}\n", .{self.adapter});
            std.debug.print("RX Queue: {any}\n", .{self.recv_queue});
            std.debug.print("TX Queue: {any}\n", .{self.send_queue});
            std.debug.print("Pool: {any}\n", .{self.packet_pool});
            std.debug.print("================================\n\n", .{});
        }
    };
};

// Export C-compatible functions for FFI
export fn zig_adapter_create(config: *const Config) ?*ZigPacketAdapter {
    const allocator = std.heap.c_allocator;
    return ZigPacketAdapter.init(allocator, config.*) catch null;
}

export fn zig_adapter_destroy(adapter: *ZigPacketAdapter) void {
    adapter.deinit();
}

export fn zig_adapter_open(adapter: *ZigPacketAdapter) bool {
    adapter.open() catch return false;
    return true;
}

export fn zig_adapter_start(adapter: *ZigPacketAdapter) bool {
    adapter.start() catch return false;
    return true;
}

export fn zig_adapter_stop(adapter: *ZigPacketAdapter) void {
    adapter.stop();
}

export fn zig_adapter_get_packet(adapter: *ZigPacketAdapter, out_data: *[*]u8, out_len: *usize) bool {
    const pkt = adapter.getNextPacket() orelse return false;

    out_data.* = pkt.data.ptr + 4; // Skip header
    out_len.* = pkt.len;

    return true;
}

export fn zig_adapter_get_packet_batch(adapter: *ZigPacketAdapter, out_array: [*]PacketBuffer, max_count: usize) usize {
    var batch = std.heap.c_allocator.alloc(?PacketBuffer, max_count) catch return 0;
    defer std.heap.c_allocator.free(batch);

    const count = adapter.getPacketBatch(batch);

    for (batch[0..count], 0..) |pkt_opt, i| {
        if (pkt_opt) |pkt| {
            out_array[i] = pkt;
        }
    }

    return count;
}

export fn zig_adapter_put_packet(adapter: *ZigPacketAdapter, data: [*]const u8, len: usize) bool {
    return adapter.putPacket(data[0..len]);
}

export fn zig_adapter_print_stats(adapter: *ZigPacketAdapter) void {
    const stats = adapter.getStats();
    stats.print();
}
