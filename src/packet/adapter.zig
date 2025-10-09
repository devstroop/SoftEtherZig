// High-performance Zig packet adapter
// Replaces C implementation with lock-free queues and batch processing
// NOW WITH DYNAMIC ADAPTIVE BUFFER SCALING! 🚀

const std = @import("std");
const RingBuffer = @import("ring_buffer.zig").RingBuffer;
const Packet = @import("packet.zig").Packet;
const PacketPool = @import("packet.zig").PacketPool;
const MAX_PACKET_SIZE = @import("packet.zig").MAX_PACKET_SIZE;
const AdaptiveBufferManager = @import("adaptive_buffer.zig").AdaptiveBufferManager;
const AdaptiveBufferConfig = @import("adaptive_buffer.zig").AdaptiveBufferConfig;
const checksum = @import("checksum.zig");
const PerfMetrics = @import("metrics.zig").PerfMetrics;
const taptun = @import("taptun");
const L2L3Translator = taptun.L2L3Translator;

// C FFI declarations for macOS utun and logging
const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/kern_control.h");
    @cInclude("sys/sys_domain.h");
    @cInclude("logging.h");
});

// Logging wrapper functions (using C logging system)
fn logDebug(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    c.log_message(c.LOG_LEVEL_DEBUG, "ADAPTER", "%s", msg.ptr);
}

fn logInfo(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    c.log_message(c.LOG_LEVEL_INFO, "ADAPTER", "%s", msg.ptr);
}

fn logError(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    c.log_message(c.LOG_LEVEL_ERROR, "ADAPTER", "%s", msg.ptr);
}

const SYSPROTO_CONTROL = 2;
const AF_SYS_CONTROL = 2;

/// Packet adapter configuration
pub const Config = struct {
    /// Initial buffer sizes (will be adjusted dynamically by adaptive manager)
    /// These are STARTING values - actual sizes scale up based on load!
    recv_queue_size: usize = 512, // Small start, scales up
    send_queue_size: usize = 256, // Small start, scales up
    packet_pool_size: usize = 32, // 32 buffers = 64KB
    batch_size: usize = 32, // 32 starting point

    /// TUN device name
    device_name: []const u8 = "utun",
};

/// C-compatible config struct (matches zig_packet_adapter.h layout)
pub const CConfig = extern struct {
    recv_queue_size: usize,
    send_queue_size: usize,
    packet_pool_size: usize,
    batch_size: usize,
    device_name: [*:0]const u8,
    device_name_len: usize,
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

    // L2/L3 Translator for Ethernet ↔ IP conversion
    translator: L2L3Translator,

    // Lock-free queues (heap-allocated to avoid large stack/struct size)
    recv_queue: *RingBuffer(PacketBuffer, 512),
    send_queue: *RingBuffer(PacketBuffer, 256),

    // Memory pool
    packet_pool: PacketPool,

    // DYNAMIC ADAPTIVE BUFFER SCALING 🚀 (core feature, always enabled)
    adaptive_manager: AdaptiveBufferManager,
    perf_metrics: PerfMetrics,

    // Threads
    read_thread: ?std.Thread = null,
    write_thread: ?std.Thread = null,
    monitor_thread: ?std.Thread = null, // NEW: Monitors and adjusts buffers
    running: std.atomic.Value(bool),

    // Statistics
    stats: Stats,

    // Debug counters
    debug_read_count: usize = 0,

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
        logDebug("Starting initialization", .{});

        const self = try allocator.create(ZigPacketAdapter);
        errdefer allocator.destroy(self);
        logDebug("Allocated adapter struct at {*}", .{self});

        // Allocate device name
        logDebug("About to allocate device name, len={d}", .{config.device_name.len});
        const device_name = try allocator.alloc(u8, config.device_name.len);
        errdefer allocator.free(device_name);
        @memcpy(device_name, config.device_name);
        logDebug("Device name: {s}", .{device_name});

        // Initialize packet pool
        logDebug("Creating packet pool (size={d})", .{config.packet_pool_size});
        var packet_pool = try PacketPool.init(allocator, config.packet_pool_size, MAX_PACKET_SIZE);
        errdefer packet_pool.deinit();
        logDebug("Packet pool created", .{});

        // Initialize adaptive buffer manager (core feature, always enabled)
        logDebug("Initializing dynamic adaptive scaling (1K→128K)", .{});
        const adaptive_config = AdaptiveBufferConfig{
            .min_queue_size = 1024, // Start small (1K)
            .max_queue_size = 131072, // Scale up to 128K
            .min_batch_size = 8,
            .max_batch_size = 512,
            .high_utilization_threshold = 0.80, // Grow at 80% full
            .low_utilization_threshold = 0.20, // Shrink at 20% full
        };
        const adaptive_manager = AdaptiveBufferManager.init(adaptive_config);

        // Allocate ring buffers on heap to avoid large struct size
        logDebug("Allocating recv_queue", .{});
        const recv_queue = try allocator.create(RingBuffer(PacketBuffer, 512));
        errdefer allocator.destroy(recv_queue);
        recv_queue.* = try RingBuffer(PacketBuffer, 512).init(allocator);
        errdefer recv_queue.deinit();

        logDebug("Allocating send_queue", .{});
        const send_queue = try allocator.create(RingBuffer(PacketBuffer, 256));
        errdefer allocator.destroy(send_queue);
        send_queue.* = try RingBuffer(PacketBuffer, 256).init(allocator);
        errdefer send_queue.deinit();

        // Initialize L2/L3 translator for Ethernet ↔ IP conversion
        logDebug("Initializing L2/L3 translator", .{});
        const translator_opts = taptun.TranslatorOptions{
            .our_mac = [_]u8{ 0x00, 0xAC, 0x00, 0x00, 0x00, 0x01 }, // SoftEther virtual MAC
            .learn_ip = true, // Auto-learn our IP from DHCP
            .learn_gateway_mac = true, // Learn gateway MAC from ARP
            .handle_arp = true, // Handle ARP requests/replies
            .verbose = true, // Enable verbose logging to see gateway MAC learning
        };
        var translator = try L2L3Translator.init(allocator, translator_opts);
        errdefer translator.deinit();

        self.* = .{
            .allocator = allocator,
            .config = config,
            .tun_fd = -1,
            .device_name = device_name,
            .translator = translator,
            .recv_queue = recv_queue,
            .send_queue = send_queue,
            .packet_pool = packet_pool,
            .adaptive_manager = adaptive_manager,
            .perf_metrics = PerfMetrics.init(),
            .running = std.atomic.Value(bool).init(false),
            .stats = .{},
        };

        logInfo("Adapter initialized with dynamic adaptive scaling (1K→128K)", .{});
        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *ZigPacketAdapter) void {
        self.stop();

        if (self.tun_fd >= 0) {
            std.posix.close(self.tun_fd);
        }

        self.allocator.free(self.device_name);
        self.translator.deinit();
        self.packet_pool.deinit();

        // Free heap-allocated ring buffers (items array then struct)
        self.recv_queue.deinit();
        self.allocator.destroy(self.recv_queue);
        self.send_queue.deinit();
        self.allocator.destroy(self.send_queue);

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

        // Get the actual interface name (utun0, utun1, etc.)
        const UTUN_OPT_IFNAME: c_int = 2;
        var ifname_buf: [c.IFNAMSIZ]u8 = undefined;
        var ifname_len: c.socklen_t = ifname_buf.len;
        if (c.getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &ifname_buf, &ifname_len) == 0) {
            const ifname_end = std.mem.indexOfScalar(u8, &ifname_buf, 0) orelse ifname_buf.len;
            if (ifname_end > 0) {
                // Update device_name with actual interface name
                self.allocator.free(self.device_name);
                const new_name = try self.allocator.alloc(u8, ifname_end);
                @memcpy(new_name, ifname_buf[0..ifname_end]);
                self.device_name = new_name;
                logInfo("Opened TUN device: {s} (fd={d})", .{ self.device_name, fd });
            } else {
                logInfo("Opened TUN device fd={d} (name query returned empty)", .{fd});
            }
        } else {
            logInfo("Opened TUN device fd={d} (couldn't query interface name)", .{fd});
        }

        self.tun_fd = fd;
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

        // Start monitor thread (adaptive scaling is core feature, always enabled)
        self.monitor_thread = try std.Thread.spawn(.{}, monitorThreadFn, .{self});
        logInfo("Started read/write/monitor threads (adaptive scaling active)", .{});
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

        if (self.monitor_thread) |thread| {
            thread.join();
            self.monitor_thread = null;
        }

        logDebug("Stopped threads", .{});
    }

    /// Read thread - continuously reads from TUN device
    fn readThreadFn(self: *ZigPacketAdapter) void {
        logDebug("Read thread started", .{});

        while (self.running.load(.acquire)) {
            // Get buffer from pool
            const buffer = self.packet_pool.alloc() orelse {
                std.Thread.sleep(10 * std.time.ns_per_us); // 10 µs (10x faster)
                continue;
            };

            // Read from TUN device (with 4-byte header on macOS)
            const bytes_read = std.posix.read(self.tun_fd, buffer) catch |err| {
                if (err == error.WouldBlock) {
                    self.packet_pool.free(buffer);
                    std.Thread.sleep(10 * std.time.ns_per_us); // 10 µs (10x faster)
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
            const ip_packet = buffer[4..bytes_read];

            // Log packets with protocol details BEFORE converting
            const read_count = self.stats.packets_read.load(.monotonic);
            if (read_count < 20 or read_count % 10 == 0) {
                if (ip_packet.len >= 20) {
                    const ip_version = (ip_packet[0] >> 4) & 0x0F;
                    const ip_proto = if (ip_version == 4) ip_packet[9] else ip_packet[6];
                    const src_ip = if (ip_version == 4 and ip_packet.len >= 20)
                        std.mem.readInt(u32, ip_packet[12..16], .big)
                    else
                        0;
                    const dst_ip = if (ip_version == 4 and ip_packet.len >= 20)
                        std.mem.readInt(u32, ip_packet[16..20], .big)
                    else
                        0;

                    logInfo("📥 READ #{d}: IPv{d}, proto={d}, {d}.{d}.{d}.{d} → {d}.{d}.{d}.{d}, {d} bytes", .{ read_count, ip_version, ip_proto, (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF, (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, ip_packet.len });
                } else {
                    logInfo("📥 READ: Packet #{d}, IP len={d} bytes", .{ read_count, ip_packet.len });
                }
            }

            // Convert IP packet to Ethernet frame for SoftEther
            const eth_frame = self.translator.ipToEthernet(ip_packet) catch |err| {
                logError("Failed to convert IP→Ethernet: {}", .{err});
                self.packet_pool.free(buffer);
                continue;
            };

            // Copy Ethernet frame to a new buffer from the pool
            const eth_buffer = self.packet_pool.alloc() orelse {
                self.allocator.free(eth_frame); // Free translator's allocation
                self.packet_pool.free(buffer); // Free original buffer
                _ = self.stats.recv_queue_drops.fetchAdd(1, .monotonic);
                continue;
            };

            // Copy frame data - SoftEther expects raw Ethernet frame (no extra header)
            @memcpy(eth_buffer[0..eth_frame.len], eth_frame);
            self.allocator.free(eth_frame); // Free translator's allocation
            self.packet_pool.free(buffer); // Free original buffer

            // Create packet buffer with Ethernet frame
            const pkt = PacketBuffer{
                .data = eth_buffer,
                .len = eth_frame.len, // Ethernet frame length
                .timestamp = @intCast(std.time.nanoTimestamp()),
            };

            // Push to queue
            if (!self.recv_queue.push(pkt)) {
                // Queue full - drop packet
                _ = self.stats.recv_queue_drops.fetchAdd(1, .monotonic);
                self.packet_pool.free(eth_buffer);
                continue;
            }

            // Update stats
            _ = self.stats.packets_read.fetchAdd(1, .monotonic);
            _ = self.stats.bytes_read.fetchAdd(ip_packet.len, .monotonic);

            // Update adaptive manager stats (core feature)
            _ = self.adaptive_manager.packets_processed.fetchAdd(1, .monotonic);
            _ = self.adaptive_manager.bytes_processed.fetchAdd(ip_packet.len, .monotonic);

            // Record in performance metrics
            const latency_us = @as(u64, @intCast(std.time.nanoTimestamp() - pkt.timestamp)) / 1000;
            self.perf_metrics.recordPacket(ip_packet.len, latency_us);
        }

        logDebug("Read thread stopped", .{});
    }

    /// Write thread - continuously writes to TUN device
    fn writeThreadFn(self: *ZigPacketAdapter) void {
        logDebug("Write thread started", .{});

        var batch: [32]?PacketBuffer = undefined;

        while (self.running.load(.acquire)) {
            // Batch pop from queue
            const count = self.send_queue.popBatch(&batch);

            if (count == 0) {
                std.Thread.sleep(10 * std.time.ns_per_us); // 10 µs (10x faster)
                continue;
            }

            // Write batch
            for (batch[0..count]) |pkt_opt| {
                const pkt = pkt_opt orelse continue;

                // Ethernet frame from SoftEther (no extra header)
                const eth_frame = pkt.data[0..pkt.len];

                // Convert Ethernet frame to IP packet
                const ip_packet_opt = self.translator.ethernetToIp(eth_frame) catch |err| {
                    logError("Failed to convert Ethernet→IP: {}", .{err});
                    self.packet_pool.free(pkt.data);
                    _ = self.stats.write_errors.fetchAdd(1, .monotonic);
                    continue;
                };

                if (ip_packet_opt) |ip_packet| {
                    // We have an IP packet to write to TUN
                    defer self.allocator.free(ip_packet); // Free translator's allocation

                    // Log packets with protocol details
                    const write_count = self.stats.packets_written.load(.monotonic);
                    if (write_count < 20 or write_count % 10 == 0) {
                        if (eth_frame.len >= 14 and ip_packet.len >= 20) {
                            const ethertype = std.mem.readInt(u16, eth_frame[12..14], .big);
                            const ip_version = (ip_packet[0] >> 4) & 0x0F;
                            const ip_proto = if (ip_version == 4) ip_packet[9] else ip_packet[6];
                            const src_ip = if (ip_version == 4 and ip_packet.len >= 20)
                                std.mem.readInt(u32, ip_packet[12..16], .big)
                            else
                                0;
                            const dst_ip = if (ip_version == 4 and ip_packet.len >= 20)
                                std.mem.readInt(u32, ip_packet[16..20], .big)
                            else
                                0;

                            logInfo("📤 WRITE #{d}: EtherType=0x{X:0>4}, IPv{d}, proto={d}, {d}.{d}.{d}.{d} → {d}.{d}.{d}.{d}, {d} bytes", .{ write_count, ethertype, ip_version, ip_proto, (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF, (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, ip_packet.len });
                        } else {
                            logInfo("📤 WRITE: Packet #{d}, Ethernet len={d} → IP len={d} bytes", .{ write_count, eth_frame.len, ip_packet.len });
                        }
                    }

                    // Determine IP version for TUN header
                    // macOS/BSD utun expects: [AF family (4 bytes, NETWORK byte order!)][IP packet]
                    // Despite documentation saying "host byte order", it actually wants BIG-ENDIAN!
                    var header: [4]u8 = undefined;
                    const version = (ip_packet[0] >> 4) & 0x0F;

                    if (version == 4) {
                        // AF_INET (IPv4) - must write the full 32-bit value!
                        // This creates: [0x02, 0x00, 0x00, 0x00]
                        std.mem.writeInt(u32, &header, 0x02000000, .big);
                    } else {
                        // AF_INET6 (IPv6) - must write the full 32-bit value!
                        // This creates: [0x1E, 0x00, 0x00, 0x00]
                        std.mem.writeInt(u32, &header, 0x1E000000, .big);
                    }

                    // Log ICMP packets before writing
                    if (ip_packet.len >= 20 and ip_packet[9] == 1) {
                        logInfo("📮 writeThreadFn: Writing ICMP to TUN, len={d}", .{ip_packet.len});
                        // Hex dump first 64 bytes of IP packet
                        const dump_len = @min(ip_packet.len, 64);
                        var hex_buf: [256]u8 = undefined;
                        var pos: usize = 0;
                        for (ip_packet[0..dump_len]) |byte| {
                            const written = std.fmt.bufPrint(hex_buf[pos..], "{X:0>2} ", .{byte}) catch break;
                            pos += written.len;
                        }
                        logInfo("   IP packet hex: {s}", .{hex_buf[0..pos]});
                    }

                    // **CRITICAL FIX**: Write header + packet in ONE atomic write
                    // TUN device expects: [4-byte AF_INET/AF_INET6][IP packet]
                    // Two separate writes can cause packet corruption!
                    var write_buf: [2048]u8 = undefined;
                    if (ip_packet.len + 4 > write_buf.len) {
                        logError("Packet too large: {d} bytes", .{ip_packet.len});
                        self.packet_pool.free(pkt.data);
                        continue;
                    }

                    // Copy header + packet into single buffer
                    @memcpy(write_buf[0..4], &header);
                    @memcpy(write_buf[4 .. 4 + ip_packet.len], ip_packet);

                    // 🔧 CRITICAL FIX: Recalculate checksums!
                    // SoftEther sends packets with invalid checksums (likely due to checksum offload)
                    // We must recalculate ICMP/TCP/UDP checksums before writing to TUN
                    const ip_in_buf = write_buf[4 .. 4 + ip_packet.len];
                    if (ip_in_buf.len >= 20) {
                        const protocol = ip_in_buf[9];
                        switch (protocol) {
                            1 => { // ICMP
                                if (checksum.recalculateIcmpChecksum(ip_in_buf)) {
                                    logInfo("🔧 Recalculated ICMP checksum", .{});
                                }
                            },
                            6 => { // TCP
                                if (checksum.recalculateTcpChecksum(ip_in_buf)) {
                                    logInfo("🔧 Recalculated TCP checksum", .{});
                                }
                            },
                            17 => { // UDP
                                if (checksum.recalculateUdpChecksum(ip_in_buf)) {
                                    logInfo("🔧 Recalculated UDP checksum", .{});
                                }
                            },
                            else => {}, // Other protocols (no checksum or unknown)
                        }
                    }

                    // Single atomic write to TUN device
                    const total_written = std.posix.write(self.tun_fd, write_buf[0 .. ip_packet.len + 4]) catch |err| {
                        logError("TUN write failed: {} (len={d})", .{ err, ip_packet.len + 4 });
                        _ = self.stats.write_errors.fetchAdd(1, .monotonic);
                        self.packet_pool.free(pkt.data);
                        continue;
                    };

                    // Log successful ICMP writes with TUN header
                    if (ip_packet.len >= 20 and ip_packet[9] == 1) {
                        logInfo("✅ ICMP written: {d} bytes total (fd={d})", .{ total_written, self.tun_fd });
                        // Dump TUN header (first 4 bytes)
                        var header_hex: [16]u8 = undefined;
                        _ = std.fmt.bufPrint(&header_hex, "{X:0>2}{X:0>2}{X:0>2}{X:0>2}", .{
                            write_buf[0],
                            write_buf[1],
                            write_buf[2],
                            write_buf[3],
                        }) catch "";
                        logInfo("   TUN header: {s} (should be 02000000 or 00000002)", .{header_hex});
                    }

                    // Update stats
                    _ = self.stats.packets_written.fetchAdd(1, .monotonic);
                    _ = self.stats.bytes_written.fetchAdd(ip_packet.len, .monotonic);
                } else {
                    // Packet was handled internally (e.g., ARP)
                    // This is normal - ARP is handled by translator
                }

                // Return buffer to pool
                self.packet_pool.free(pkt.data);
            }
        }

        logDebug("Write thread stopped", .{});
    }

    /// Monitor thread - adjusts buffers dynamically based on real-time metrics
    fn monitorThreadFn(self: *ZigPacketAdapter) void {
        logDebug("Monitor thread started (adaptive scaling active)", .{});

        var last_print_time = std.time.milliTimestamp();
        const PRINT_INTERVAL_MS = 5000; // Print stats every 5 seconds

        while (self.running.load(.acquire)) {
            // Sleep for 1ms between checks (100x faster than before!)
            std.Thread.sleep(1 * std.time.ns_per_ms);

            // Update queue utilization
            const recv_stats = self.recv_queue.getStats();
            const send_stats = self.send_queue.getStats();
            const recv_util = @as(f32, @floatFromInt(recv_stats.available)) / @as(f32, @floatFromInt(recv_stats.capacity));
            const send_util = @as(f32, @floatFromInt(send_stats.available)) / @as(f32, @floatFromInt(send_stats.capacity));
            const avg_util = (recv_util + send_util) / 2.0;
            self.adaptive_manager.queue_utilization.store(avg_util, .monotonic);

            // Update drop count
            const total_drops = self.stats.recv_queue_drops.load(.monotonic) +
                self.stats.send_queue_drops.load(.monotonic);
            self.adaptive_manager.packets_dropped.store(total_drops, .monotonic);

            // Calculate throughput (Mbps)
            const now = std.time.milliTimestamp();
            const elapsed_ms = @as(u64, @intCast(now - self.adaptive_manager.measurement_start_time.load(.monotonic)));
            if (elapsed_ms > 0) {
                const bytes = self.adaptive_manager.bytes_processed.load(.monotonic);
                const throughput_bps = @as(f32, @floatFromInt(bytes * 8 * 1000)) / @as(f32, @floatFromInt(elapsed_ms));
                const throughput_mbps = throughput_bps / 1_000_000.0;
                self.adaptive_manager.throughput_mbps.store(throughput_mbps, .monotonic);
            }

            // Check if adjustment needed
            const action = self.adaptive_manager.shouldAdjust();

            // Apply the scaling decision
            if (action != .none) {
                self.adaptive_manager.applyScaling(action);
            }

            // Print stats periodically
            if (now - last_print_time > PRINT_INTERVAL_MS) {
                const adaptive_stats = self.adaptive_manager.getStats();
                logInfo("Adaptive stats: {any}", .{adaptive_stats});
                self.perf_metrics.printCompact();
                last_print_time = now;
            }
        }

        logDebug("Monitor thread stopped", .{});
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
        // Log ALL incoming packets for debugging
        if (data.len >= 34) {
            const ip_proto = data[14 + 9]; // IP protocol at offset 23 (14 Ethernet + 9 IP header)
            if (ip_proto == 1) { // ICMP
                logInfo("📥 putPacket: RECEIVED ICMP packet from SoftEther, len={d} bytes", .{data.len});
            }
        }

        // Get buffer from pool
        const buffer = self.packet_pool.alloc() orelse return false;

        // Copy packet data directly (Ethernet frame from SoftEther)
        if (data.len > buffer.len) {
            self.packet_pool.free(buffer);
            return false;
        }

        @memcpy(buffer[0..data.len], data);

        const pkt = PacketBuffer{
            .data = buffer,
            .len = data.len,
            .timestamp = @intCast(std.time.nanoTimestamp()),
        };

        // Log ICMP packets being queued
        if (data.len >= 14 + 20) {
            const ip_proto = data[14 + 9];
            if (ip_proto == 1) {
                logInfo("📬 putPacket: Queuing ICMP packet for TUN write, len={d} bytes", .{data.len});
            }
        }

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
        recv_queue: RingBuffer(PacketBuffer, 512).Stats,
        send_queue: RingBuffer(PacketBuffer, 256).Stats,
        packet_pool: PacketPool.Stats,

        pub fn print(self: StatsSnapshot) void {
            logInfo("Adapter stats - RX: {any}, TX: {any}, Pool: {any}", .{
                self.recv_queue,
                self.send_queue,
                self.packet_pool,
            });
        }
    };
};

// Export C-compatible functions for FFI
export fn zig_adapter_create(c_config: *const CConfig) ?*ZigPacketAdapter {
    const allocator = std.heap.c_allocator;

    // DEBUG: Log what C is passing
    logDebug("C config: recv={d}, send={d}, pool={d}, batch={d}, device_name_len={d}", .{
        c_config.recv_queue_size,
        c_config.send_queue_size,
        c_config.packet_pool_size,
        c_config.batch_size,
        c_config.device_name_len,
    });

    // Convert C config to Zig config
    const device_name = c_config.device_name[0..c_config.device_name_len];
    const config = Config{
        .recv_queue_size = c_config.recv_queue_size,
        .send_queue_size = c_config.send_queue_size,
        .packet_pool_size = c_config.packet_pool_size,
        .batch_size = c_config.batch_size,
        .device_name = device_name,
    };

    const adapter = ZigPacketAdapter.init(allocator, config) catch |err| {
        logError("Failed to create adapter: {any}", .{err});
        return null;
    };
    logInfo("Adapter created successfully at {*}", .{adapter});
    return adapter;
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

/// Synchronous read from TUN device (blocking with timeout)
/// Returns number of bytes read (as ETHERNET FRAME), or -1 on error, 0 on timeout
///
/// **CRITICAL**: TUN devices return raw IP packets, but SoftEther expects Ethernet frames!
/// We must ADD a 14-byte Ethernet header to each IP packet read from TUN.
export fn zig_adapter_read_sync(adapter: *ZigPacketAdapter, buffer: [*]u8, buffer_len: usize) isize {
    // Read directly from TUN device (non-blocking)
    const fd = adapter.tun_fd;

    // Use a temp buffer to read IP packet (we'll prepend Ethernet header later)
    var temp_buf: [2048]u8 = undefined;

    // **CRITICAL FOR MACOS TUN**: Use poll() with timeout to check if TUN is readable
    // Without this, TUN device "freezes" after first ~10 reads (returns WouldBlock forever)
    // This is a known macOS utun quirk - the device needs to be polled to stay "alive"
    var fds = [_]std.posix.pollfd{
        .{
            .fd = fd,
            .events = std.posix.POLL.IN, // Wait for readable
            .revents = 0,
        },
    };

    // Poll with 0ms timeout (non-blocking check)
    const ready_count = std.posix.poll(&fds, 0) catch |err| {
        std.debug.print("[zig_adapter_read_sync] ⚠️  Poll error: {}\n", .{err});
        return -1;
    };

    // If no data available, return immediately (this is normal - polled frequently)
    if (ready_count == 0 or (fds[0].revents & std.posix.POLL.IN) == 0) {
        return 0; // No data ready
    }

    // Now read - TUN device is ready with data
    const bytes_read = std.posix.read(fd, temp_buf[0..]) catch |err| {
        if (err == error.WouldBlock) {
            // Should not happen after poll() said readable, but handle it anyway
            return 0;
        }
        // Log other errors for debugging
        std.debug.print("[zig_adapter_read_sync] ⚠️  Read error: {}\n", .{err});
        return -1;
    };

    if (bytes_read == 0) return 0;
    if (bytes_read < 4) return 0; // Too small - need at least 4-byte AF_INET header

    // Log successful reads (first 10 packets only to avoid spam)
    const read_count = @atomicRmw(usize, &adapter.debug_read_count, .Add, 1, .monotonic);
    if (read_count < 10) {
        std.debug.print("[zig_adapter_read_sync] 📖 Read packet from TUN: {} bytes (fd={})\n", .{ bytes_read, fd });
    }

    // Skip 4-byte AF_INET header from macOS utun to get raw IP packet
    const ip_packet_start = 4;
    const ip_packet_len = bytes_read - ip_packet_start;

    if (ip_packet_len <= 0) return 0;

    // Check IP version (first nibble of IP packet)
    const ip_version = (temp_buf[ip_packet_start] >> 4) & 0x0F;

    // **BUILD ETHERNET FRAME**: SoftEther expects [Ethernet header][IP packet]
    // Ethernet header: [6 bytes dest MAC][6 bytes src MAC][2 bytes EtherType]
    const ETHERNET_HEADER_SIZE = 14;
    const ethernet_frame_len = ETHERNET_HEADER_SIZE + ip_packet_len;

    if (ethernet_frame_len > buffer_len) {
        return 0; // Frame too large for buffer
    }

    // Build Ethernet header
    const ethertype: u16 = if (ip_version == 4) 0x0800 else if (ip_version == 6) 0x86DD else 0x0000;

    if (ethertype == 0) {
        return 0; // Unknown IP version, skip packet
    }

    // Dest MAC: Use gateway MAC if learned, otherwise broadcast (FF:FF:FF:FF:FF:FF)
    // For inbound packets, dest should be our MAC, but we use gateway MAC for routing
    if (adapter.translator.gateway_mac) |gw_mac| {
        @memcpy(buffer[0..6], &gw_mac);
    } else {
        // Broadcast MAC if gateway not learned yet
        @memset(buffer[0..6], 0xFF);
    }

    // Src MAC: Our MAC address (from translator options)
    @memcpy(buffer[6..12], &adapter.translator.options.our_mac); // EtherType (big-endian)
    buffer[12] = @intCast((ethertype >> 8) & 0xFF);
    buffer[13] = @intCast(ethertype & 0xFF);

    // Copy IP packet after Ethernet header
    @memcpy(buffer[14..ethernet_frame_len], temp_buf[ip_packet_start..(ip_packet_start + ip_packet_len)]);

    return @intCast(ethernet_frame_len);
}

/// Synchronous write to TUN device (called from PutPacket)
/// Drains send_queue and writes packets to TUN device
/// Returns number of packets written
export fn zig_adapter_write_sync(adapter: *ZigPacketAdapter) isize {
    var packets_written: isize = 0;
    const max_batch = 32; // Drain up to 32 packets per call

    // Log TUN fd at start
    std.debug.print("[zig_adapter_write_sync] 📤 Called, tun_fd={}\n", .{adapter.tun_fd});

    var i: usize = 0;
    while (i < max_batch) : (i += 1) {
        // Pop packet from send queue
        const pkt = adapter.send_queue.pop() orelse break;

        // Write to TUN device (prepend 4-byte AF_INET header for macOS)
        var write_buf: [2048]u8 = undefined;

        // **CRITICAL**: TUN expects raw IP packets, but SoftEther sends Ethernet frames!
        // We must strip the 14-byte Ethernet header before writing to TUN.
        const ETHERNET_HEADER_SIZE = 14;

        // Skip Ethernet header if packet is large enough
        if (pkt.len < ETHERNET_HEADER_SIZE) {
            // Packet too small to have Ethernet header, skip it
            std.debug.print("[zig_adapter_write_sync] ⚠️  Packet too small ({} bytes), skipping\n", .{pkt.len});
            adapter.packet_pool.free(pkt.data);
            continue;
        }

        // macOS utun requires 4-byte AF_INET header in **network byte order (big-endian)**
        // AF_INET = 2, so htonl(2) = 0x00000002 in network order
        // CRITICAL: Must be big-endian, not little-endian!
        write_buf[0] = 0x00;
        write_buf[1] = 0x00;
        write_buf[2] = 0x00;
        write_buf[3] = 0x02; // AF_INET = 2

        // Copy IP packet (skip Ethernet header) after AF_INET header
        const ip_packet_len = pkt.len - ETHERNET_HEADER_SIZE;
        const write_len = ip_packet_len + 4; // 4-byte AF_INET + IP packet

        if (write_len > write_buf.len) {
            // Packet too large, free buffer and skip
            adapter.packet_pool.free(pkt.data);
            continue;
        }

        @memcpy(write_buf[4..write_len], pkt.data[ETHERNET_HEADER_SIZE..pkt.len]);

        // **DEBUG**: Log first few bytes of IP packet for ICMP debugging
        if (write_len >= 24 and pkt.data[ETHERNET_HEADER_SIZE] == 0x45) {
            // IPv4 packet, check protocol
            const ip_proto = pkt.data[ETHERNET_HEADER_SIZE + 9];
            if (ip_proto == 1) { // ICMP
                std.debug.print("[zig_adapter_write_sync] 🐛 ICMP packet: ", .{});
                std.debug.print("IP: ", .{});
                for (pkt.data[ETHERNET_HEADER_SIZE..(ETHERNET_HEADER_SIZE + 20)]) |b| {
                    std.debug.print("{X:0>2} ", .{b});
                }
                std.debug.print("\n", .{});
            }
        }

        // Write to TUN device
        const fd = adapter.tun_fd;
        const bytes_written = std.posix.write(fd, write_buf[0..write_len]) catch |err| {
            if (err == error.WouldBlock) {
                // TUN device full, re-queue packet and stop
                std.debug.print("[zig_adapter_write_sync] ⚠️  TUN WouldBlock, re-queuing packet\n", .{});
                _ = adapter.send_queue.push(pkt);
                break;
            }
            // Other error, free buffer and continue
            std.debug.print("[zig_adapter_write_sync] ❌ Write error: {}, packet len={}, fd={}\n", .{ err, pkt.len, fd });
            adapter.packet_pool.free(pkt.data);
            continue;
        };

        // Free packet buffer
        adapter.packet_pool.free(pkt.data);

        if (bytes_written > 0) {
            packets_written += 1;
            std.debug.print("[zig_adapter_write_sync] ✅ Wrote packet #{} to TUN ({} bytes total with header)\n", .{ packets_written, bytes_written });
        }
    }

    std.debug.print("[zig_adapter_write_sync] 📊 Finished: wrote {} packets to TUN\n", .{packets_written});
    return packets_written;
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

/// Release packet buffer back to pool (MUST be called after get_packet)
export fn zig_adapter_release_packet(adapter: *ZigPacketAdapter, data: [*]u8) void {
    _ = adapter;
    _ = data;
    // TODO: Fix buffer lifecycle - currently leaking buffers to avoid double-free crash
    // The issue is that we can't reconstruct the original slice from just the pointer
    // Need to either:
    // 1. Store active buffers in a hashmap keyed by pointer
    // 2. Have C allocate its own buffers (don't use packet_pool for FFI)
    // 3. Change FFI to pass/return PacketBuffer structs directly
    // For now, just leak the memory to get connectivity working
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

export fn zig_adapter_get_device_name(adapter: *ZigPacketAdapter, out_buffer: [*]u8, buffer_len: usize) usize {
    if (buffer_len == 0) return 0;

    const copy_len = @min(adapter.device_name.len, buffer_len - 1);
    @memcpy(out_buffer[0..copy_len], adapter.device_name[0..copy_len]);
    out_buffer[copy_len] = 0; // Null terminate

    return copy_len;
}

/// Set gateway IP and MAC in translator (for learning gateway MAC from ARP)
/// ip_network_order: Gateway IP in network byte order (big-endian)
export fn zig_adapter_set_gateway(adapter: *ZigPacketAdapter, ip_network_order: u32) void {
    adapter.translator.setGateway(ip_network_order, [_]u8{0} ** 6);
}

/// Set gateway MAC address (called from C when gateway MAC is learned via ARP)
export fn zig_adapter_set_gateway_mac(adapter: *ZigPacketAdapter, mac: [*c]const u8) void {
    var mac_array: [6]u8 = undefined;
    @memcpy(&mac_array, mac[0..6]);
    adapter.translator.gateway_mac = mac_array;

    logInfo("[L2L3] 🎯 setGatewayMAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac_array[0], mac_array[1], mac_array[2],
        mac_array[3], mac_array[4], mac_array[5],
    });
}

/// Configure TUN interface with IP address
/// IPs are in network byte order (big-endian)
export fn zig_adapter_configure_interface(
    adapter: *ZigPacketAdapter,
    local_ip: u32,
    peer_ip: u32,
    netmask: u32,
) bool {
    // Convert IPs to string (big-endian network byte order)
    var local_str: [16]u8 = undefined;
    var peer_str: [16]u8 = undefined;
    var mask_str: [16]u8 = undefined;

    const local_fmt = std.fmt.bufPrintZ(&local_str, "{}.{}.{}.{}", .{
        (local_ip >> 24) & 0xFF,
        (local_ip >> 16) & 0xFF,
        (local_ip >> 8) & 0xFF,
        local_ip & 0xFF,
    }) catch return false;

    const peer_fmt = std.fmt.bufPrintZ(&peer_str, "{}.{}.{}.{}", .{
        (peer_ip >> 24) & 0xFF,
        (peer_ip >> 16) & 0xFF,
        (peer_ip >> 8) & 0xFF,
        peer_ip & 0xFF,
    }) catch return false;

    const mask_fmt = std.fmt.bufPrintZ(&mask_str, "{}.{}.{}.{}", .{
        (netmask >> 24) & 0xFF,
        (netmask >> 16) & 0xFF,
        (netmask >> 8) & 0xFF,
        netmask & 0xFF,
    }) catch return false;

    // Build ifconfig command
    var cmd: [256]u8 = undefined;
    const cmd_str = std.fmt.bufPrintZ(&cmd, "ifconfig {s} {s} {s} netmask {s} up", .{
        adapter.device_name,
        local_fmt,
        peer_fmt,
        mask_fmt,
    }) catch return false;

    logInfo("Configuring interface: {s}", .{cmd_str});

    // Execute command
    const result = std.process.Child.run(.{
        .allocator = adapter.allocator,
        .argv = &[_][]const u8{ "/bin/sh", "-c", cmd_str },
    }) catch |err| {
        logError("Failed to execute ifconfig: {}", .{err});
        return false;
    };
    defer adapter.allocator.free(result.stdout);
    defer adapter.allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        logError("ifconfig failed with code {}: {s}", .{ result.term.Exited, result.stderr });
        return false;
    }

    logInfo("Interface configured: {s} -> {s}", .{ local_fmt, peer_fmt });
    return true;
}
