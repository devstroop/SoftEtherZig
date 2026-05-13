// SoftEther VPN Client - Foreign File Descriptor Adapter
// For mobile platforms (iOS/Android) where the OS manages the TUN device
// and provides an fd to read/write packets.
//
// iOS uses direct synchronous writes (no ring buffer) because the
// AF_UNIX SOCK_DGRAM socketpair buffer is tiny (~2-4KB after sandbox
// clamping). A ring buffer + writer thread would batch drops rather
// than distributing them, making TCP retrans storms worse.
//
// Android uses a ring buffer + async writer thread because the TUN fd
// kernel buffer is large (64KB+) and the ring decouples the data loop
// from TUN write latency efficiently.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const TUN_MTU: usize = 1500;
pub const MAX_PACKET_SIZE: usize = TUN_MTU + 14;
pub const RECV_QUEUE_MAX: usize = 64;

const is_android = builtin.os.tag == .linux and
    (builtin.abi == .android or builtin.abi == .androideabi);
const is_ios = builtin.os.tag == .ios;

// Ring buffer is only used on Android (and potentially other non-iOS platforms).
// iOS uses direct writes — see comment at top of file.
// Writer-thread ring sizing. 1024 slots * ~1518 bytes = ~1.5 MB.
// Doubled from 512 (2026-05-14) to absorb longer bursts at higher throughput.
const TX_RING_SLOTS: usize = 1024;
const TX_SLOT_BYTES: usize = MAX_PACKET_SIZE;

const TxSlot = struct {
    len: u16,
    data: [TX_SLOT_BYTES]u8,
};

const TxRing = struct {
    slots: [TX_RING_SLOTS]TxSlot,
};

pub const FdAdapterError = error{
    InvalidFd,
    DeviceNotOpen,
    ReadFailed,
    WriteFailed,
    ConfigureFailed,
    OpenFailed,
};

pub const TunStats = struct {
    send_packets: u64 = 0,
    send_bytes: u64 = 0,
    recv_packets: u64 = 0,
    recv_bytes: u64 = 0,
};

/// A virtual adapter that wraps an externally-provided file descriptor.
/// Used on iOS (NEPacketTunnelProvider) and Android (VpnService.Builder.establish())
/// where the OS creates the TUN device and hands us the fd.
///
/// Write path:
///   - iOS: direct posix.write() — one syscall, immediate. If EWOULDBLOCK,
///     drops 1 packet. The data loop retries next iteration.
///   - Android: ring buffer + async writer thread — decouples the data loop
///     from TUN fd write latency. Writer thread polls POLLOUT on congestion.
pub const FdAdapter = struct {
    allocator: std.mem.Allocator,

    // File descriptor provided by the platform
    fd: posix.fd_t,

    // Device info
    device_name: [64]u8,
    device_name_len: usize,
    mac_address: [6]u8,

    // IP configuration (set by caller after DHCP)
    ipv4_address: u32,
    ipv4_netmask: u32,
    ipv4_gateway: u32,

    // Statistics
    stats: TunStats,

    // State
    is_open: bool,
    halt: bool,
    connection_start_time: i64,

    // --- Ring buffer state (Android only; unused on iOS) ---
    // Async writer: dedicated thread drains tx_ring -> fd. The libsoftether
    // data loop never blocks on bridge backpressure; if the ring fills, we
    // drop (and count). This decouples the single-threaded data loop's read
    // side (UL + ACKs) from the write side (DL packets to bridge).
    //
    // On iOS, all these fields are initialized but NEVER used — no ring is
    // allocated, no writer thread is spawned.
    tx_ring: ?*TxRing,
    tx_head: usize,
    tx_tail: usize,
    tx_count: usize,
    tx_drops: u64,
    tx_mutex: std.Thread.Mutex,
    tx_cond: std.Thread.Condition,
    tx_thread: ?std.Thread,
    tx_stop: bool,

    /// Create a FdAdapter wrapping an existing file descriptor.
    /// The fd should already be open and configured by the platform.
    /// `name` is a display label (e.g. "utun3" on iOS, "tun0" on Android).
    pub fn initWithFd(allocator: std.mem.Allocator, fd: posix.fd_t, name: []const u8) FdAdapterError!*FdAdapter {
        if (fd < 0) return FdAdapterError.InvalidFd;

        const device = allocator.create(FdAdapter) catch {
            return FdAdapterError.OpenFailed;
        };

        var name_buf: [64]u8 = [_]u8{0} ** 64;
        const len = @min(name.len, name_buf.len);
        @memcpy(name_buf[0..len], name[0..len]);

        // Generate random MAC
        var mac: [6]u8 = undefined;
        std.crypto.random.bytes(&mac);
        mac[0] = (mac[0] & 0xFC) | 0x02;

        device.* = .{
            .allocator = allocator,
            .fd = fd,
            .device_name = name_buf,
            .device_name_len = len,
            .mac_address = mac,
            .ipv4_address = 0,
            .ipv4_netmask = 0,
            .ipv4_gateway = 0,
            .stats = .{},
            .is_open = true,
            .halt = false,
            .connection_start_time = std.time.milliTimestamp(),
            .tx_ring = null,
            .tx_head = 0,
            .tx_tail = 0,
            .tx_count = 0,
            .tx_drops = 0,
            .tx_mutex = .{},
            .tx_cond = .{},
            .tx_thread = null,
            .tx_stop = false,
        };

        // Set non-blocking using C fcntl. O_NONBLOCK value differs per OS:
        // Darwin/iOS: 0x0004, Linux/Android: 0x0800
        if (setNonBlocking(fd) < 0) {
            allocator.destroy(device);
            return FdAdapterError.OpenFailed;
        }

        // Android: allocate ring buffer + spawn async writer thread.
        // iOS: direct writes — no ring, no writer thread.
        if (!is_ios) {
            const ring = allocator.create(TxRing) catch {
                allocator.destroy(device);
                return FdAdapterError.OpenFailed;
            };
            device.tx_ring = ring;
            device.tx_thread = std.Thread.spawn(.{}, writerLoop, .{device}) catch {
                allocator.destroy(ring);
                device.tx_ring = null;
                allocator.destroy(device);
                return FdAdapterError.OpenFailed;
            };
            std.log.info("FdAdapter wrapping fd={d} name={s} (writer thread + {d}-slot ring)", .{ fd, name, TX_RING_SLOTS });
        } else {
            std.log.info("FdAdapter wrapping fd={d} name={s} (direct writes — no ring buffer for iOS)", .{ fd, name });
        }

        return device;
    }

    /// Background thread: drain tx_ring -> fd with non-blocking writes.
    /// After each write attempt (regardless of outcome), signals the condition
    /// variable so a blocked producer (data loop) can re-check ring space.
    /// Poll timeout reduced to 10ms (from 100ms, 2026-05-14) so congestion
    /// recover is ~10x faster — at 60 Mbps the ring fills ~75KB per retry.
    /// Only runs on Android (not iOS — iOS uses direct writes).
    fn writerLoop(self: *FdAdapter) void {
        var local: [TX_SLOT_BYTES]u8 = undefined;
        while (true) {
            self.tx_mutex.lock();
            while (self.tx_count == 0 and !self.tx_stop) {
                self.tx_cond.wait(&self.tx_mutex);
            }
            if (self.tx_stop and self.tx_count == 0) {
                self.tx_mutex.unlock();
                return;
            }
            const ring = self.tx_ring orelse {
                self.tx_mutex.unlock();
                return;
            };
            const idx = self.tx_tail;
            const slot = &ring.slots[idx];
            const len = @as(usize, slot.len);
            @memcpy(local[0..len], slot.data[0..len]);
            self.tx_tail = (idx + 1) % TX_RING_SLOTS;
            self.tx_count -= 1;
            self.tx_mutex.unlock();

            // Signal producer that we consumed a slot (ring may have room now).
            self.tx_cond.signal();

            // Non-blocking write with poll() retry on EWOULDBLOCK. Safe to
            // block here because we are NOT on the data loop thread.
            var remaining: []const u8 = local[0..len];
            while (remaining.len > 0) {
                const fd = @atomicLoad(posix.fd_t, &self.fd, .acquire);
                const w = posix.write(fd, remaining) catch |err| switch (err) {
                    error.WouldBlock => blk: {
                        var pfd = [_]std.posix.pollfd{.{
                            .fd = fd,
                            .events = std.posix.POLL.OUT,
                            .revents = 0,
                        }};
                        _ = std.posix.poll(&pfd, 10) catch {};
                        break :blk @as(usize, 0);
                    },
                    else => {
                        break;
                    },
                };
                if (w == 0) {
                    if (self.tx_stop) return;
                    continue;
                }
                remaining = remaining[w..];
            }
        }
    }

    fn setNonBlocking(fd: posix.fd_t) c_int {
        const F_GETFL = 3;
        const F_SETFL = 4;
        const O_NONBLOCK: c_int = if (builtin.os.tag == .linux) 0x0800 else 0x0004;
        const flags = std.c.fcntl(fd, F_GETFL, @as(c_int, 0));
        if (flags < 0) return -1;
        if (std.c.fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
        return 0;
    }

    /// Replace the wrapped fd with a new one (e.g. after Android VpnService.Builder
    /// reconfiguration with DHCP-assigned IP). Does NOT close the old fd — the
    /// caller (platform) owns its lifecycle and will close the old PFD itself.
    pub fn replaceFd(self: *FdAdapter, new_fd: posix.fd_t) FdAdapterError!void {
        if (new_fd < 0) return FdAdapterError.InvalidFd;
        if (setNonBlocking(new_fd) < 0) return FdAdapterError.OpenFailed;
        const old_fd = self.fd;
        @atomicStore(posix.fd_t, &self.fd, new_fd, .release);
        std.log.info("FdAdapter swapped fd {d} -> {d}", .{ old_fd, new_fd });
    }

    /// Close the adapter. Does NOT close the fd (owned by the platform).
    pub fn close(self: *FdAdapter) void {
        self.is_open = false;

        // Stop and join writer thread (Android only).
        if (!is_ios) {
            if (self.tx_thread) |t| {
                self.tx_mutex.lock();
                self.tx_stop = true;
                self.tx_cond.broadcast();
                self.tx_mutex.unlock();
                t.join();
                self.tx_thread = null;
            }
            if (self.tx_ring) |r| {
                self.allocator.destroy(r);
                self.tx_ring = null;
            }
        }

        self.allocator.destroy(self);
    }

    /// Get device name
    pub fn getName(self: *const FdAdapter) []const u8 {
        return self.device_name[0..self.device_name_len];
    }

    /// Get MAC address
    pub fn getMac(self: *const FdAdapter) [6]u8 {
        return self.mac_address;
    }

    /// Get file descriptor for polling
    pub fn getFd(self: *const FdAdapter) posix.fd_t {
        return self.fd;
    }

    /// Check if adapter is open
    pub fn isOpen(self: *const FdAdapter) bool {
        return self.is_open;
    }

    /// Configure IP addresses (informational — actual config done by platform)
    pub fn configure(self: *FdAdapter, ip: u32, mask: u32, gateway: u32) !void {
        self.ipv4_address = ip;
        self.ipv4_netmask = mask;
        self.ipv4_gateway = gateway;
    }

    /// No-op on mobile — the platform configures the interface
    pub fn configureTemporary(self: *FdAdapter) !void {
        _ = self;
    }

    /// Read a packet from the fd
    pub fn read(self: *FdAdapter, buffer: []u8) !?usize {
        if (!self.is_open) return FdAdapterError.DeviceNotOpen;

        const result = posix.read(self.fd, buffer);
        if (result) |bytes_read| {
            if (bytes_read > 0) {
                self.stats.recv_bytes += bytes_read;
                self.stats.recv_packets += 1;
                return bytes_read;
            }
            return null;
        } else |err| {
            if (err == error.WouldBlock) return null;
            return FdAdapterError.ReadFailed;
        }
    }

    /// Write a packet to the fd.
    ///
    /// iOS: direct non-blocking posix.write(). If the socketpair buffer is full
    /// (EWOULDBLOCK), drops 1 packet. The data loop retries next iteration.
    /// No ring buffer, no writer thread — keeps drops individual, not bursty.
    ///
    /// Android: ring buffer enqueue + async writer thread. When the ring is full,
    /// waits on a condition variable (up to ~10ms) for the writer thread to drain
    /// a slot. This applies natural TCP backpressure instead of silent drops.
    /// Only falls through to drop if the timed wait expires.
    pub fn write(self: *FdAdapter, data: []const u8) !usize {
        if (!self.is_open) return FdAdapterError.DeviceNotOpen;
        if (data.len == 0) return 0;

        if (is_ios) {
            // iOS direct write path: one syscall, immediate.
            // If the socketpair buffer is full, EWOULDBLOCK → drop 1 packet.
            // The data loop retries next iteration — individual drops are
            // handled gracefully by TCP congestion control.
            const written = posix.write(self.fd, data) catch |err| switch (err) {
                error.WouldBlock => return FdAdapterError.WriteFailed,
                else => return FdAdapterError.WriteFailed,
            };
            if (written == 0) return FdAdapterError.WriteFailed;
            self.stats.send_bytes += written;
            self.stats.send_packets += 1;
            return written;
        }

        // Android ring buffer path.
        if (data.len > TX_SLOT_BYTES) return FdAdapterError.WriteFailed;
        const ring = self.tx_ring orelse return FdAdapterError.WriteFailed;

        self.tx_mutex.lock();
        // Wait for ring space with backpressure — don't drop immediately.
        var waited: bool = false;
        while (self.tx_count >= TX_RING_SLOTS) {
            if (self.tx_stop or !self.is_open) {
                self.tx_mutex.unlock();
                return FdAdapterError.WriteFailed;
            }
            waited = true;
            self.tx_cond.timedWait(&self.tx_mutex, 10 * std.time.ns_per_ms) catch {
                self.tx_drops += 1;
                self.tx_mutex.unlock();
                return FdAdapterError.WriteFailed;
            };
        }
        if (waited) {
            std.log.debug("FdAdapter write waited for ring space (count={d})", .{self.tx_count});
        }

        const idx = self.tx_head;
        const slot = &ring.slots[idx];
        slot.len = @intCast(data.len);
        @memcpy(slot.data[0..data.len], data);
        self.tx_head = (idx + 1) % TX_RING_SLOTS;
        self.tx_count += 1;
        self.tx_cond.signal();
        self.tx_mutex.unlock();

        self.stats.send_bytes += data.len;
        self.stats.send_packets += 1;
        return data.len;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const FdAdapter) TunStats {
        return self.stats;
    }

    /// Get total dropped packet count since creation.
    /// On iOS: always 0 (no ring buffer drops). On Android: tracks ring overflow.
    pub fn getTxDrops(self: *const FdAdapter) u64 {
        if (is_ios) return 0;
        return @atomicLoad(u64, &self.tx_drops, .acquire);
    }
};
