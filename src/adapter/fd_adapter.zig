// SoftEther VPN Client - Foreign File Descriptor Adapter
// For mobile platforms (iOS/Android) where the OS manages the TUN device
// and provides an fd to read/write packets.
//
// ALL mobile platforms use direct synchronous writes (no ring buffer):
// - iOS: AF_UNIX SOCK_DGRAM socketpair buffer is tiny (~2-4KB after sandbox
//   clamping). A ring buffer + writer thread would batch drops rather than
//   distribute them, making TCP retrans storms worse. Direct write is optimal.
// - Android: VpnService TUN fd kernel buffer is 64KB+ — large enough that
//   direct non-blocking writes don't block the data loop. The ring buffer
//   adds a SECOND congestion point: writer thread stalls when TUN backs up,
//   data loop fills the ring, packets drop (tx_drops++), TCP retrans storms.
//   Direct write keeps drops individual and TCP-friendly, exactly like iOS.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const TUN_MTU: usize = 1500;
pub const MAX_PACKET_SIZE: usize = TUN_MTU + 14;
pub const RECV_QUEUE_MAX: usize = 64;

const is_ios = builtin.os.tag == .ios;

fn fdToInt(fd: posix.fd_t) usize {
    return @as(usize, @bitCast(fd));
}

// Ring buffer structs are preserved in layout for ABI stability but are
// never allocated on iOS/Android since direct writes replaced the ring path.
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
/// Both platforms use direct non-blocking posix.write() — one syscall, immediate.
/// If the downstream buffer is full (EWOULDBLOCK), drops 1 packet. The data loop
/// retries next iteration. Individual drops are handled gracefully by TCP congestion
/// control. No ring buffer, no writer thread, no batching delays.
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

    // Ring buffer state (struct layout preserved for ABI; ring is never
    // allocated on iOS/Android since direct writes replaced the ring path).
    // tx_drops IS live — direct writes increment it when EWOULDBLOCK causes a drop.
    tx_ring: ?*TxRing,
    tx_head: usize,
    tx_tail: usize,
    tx_count: usize,
    // Stored as usize so 32-bit targets (Android armeabi-v7a) can use native
    // atomic ops. Zig disallows @atomicStore(u64, ...) on 32-bit ARM.
    tx_drops: usize,
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

        // All mobile platforms: direct writes, no ring buffer, no writer thread.
        const fd_val = fdToInt(fd);
        std.log.info("FdAdapter wrapping fd={d} name={s} (direct writes, no ring buffer)", .{ fd_val, name });

        return device;
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
        const old_fd_val = fdToInt(old_fd);
        const new_fd_val = fdToInt(new_fd);
        std.log.info("FdAdapter swapped fd {d} -> {d}", .{ old_fd_val, new_fd_val });
    }

    /// Close the adapter. Does NOT close the fd (owned by the platform).
    pub fn close(self: *FdAdapter) void {
        self.is_open = false;

        // No writer thread on iOS/Android — nothing to join.
        if (self.tx_ring) |r| {
            self.allocator.destroy(r);
            self.tx_ring = null;
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
    /// iOS and Android: direct non-blocking posix.write(). If the downstream
    /// buffer is full (EWOULDBLOCK), drops 1 packet. The data loop retries next
    /// iteration — individual drops are handled gracefully by TCP congestion
    /// control. No ring buffer, no writer thread, no batching delays.
    pub fn write(self: *FdAdapter, data: []const u8) !usize {
        if (!self.is_open) return FdAdapterError.DeviceNotOpen;
        if (data.len == 0) return 0;

        // Direct write on all mobile platforms — iOS and Android.
        const written = posix.write(self.fd, data) catch |err| switch (err) {
            error.WouldBlock => {
                @atomicStore(usize, &self.tx_drops, self.tx_drops + 1, .release);
                return FdAdapterError.WriteFailed;
            },
            else => {
                @atomicStore(usize, &self.tx_drops, self.tx_drops + 1, .release);
                return FdAdapterError.WriteFailed;
            },
        };
        if (written == 0) {
            @atomicStore(usize, &self.tx_drops, self.tx_drops + 1, .release);
            return FdAdapterError.WriteFailed;
        }
        self.stats.send_bytes += written;
        self.stats.send_packets += 1;
        return written;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const FdAdapter) TunStats {
        return self.stats;
    }

    /// Get total dropped packet count since creation.
    /// Tracks EWOULDBLOCK drops from direct writes on all mobile platforms.
    pub fn getTxDrops(self: *const FdAdapter) u64 {
        return @intCast(@atomicLoad(usize, &self.tx_drops, .acquire));
    }
};
