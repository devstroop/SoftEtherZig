// SoftEther VPN Client - Foreign File Descriptor Adapter
// For mobile platforms (iOS/Android) where the OS manages the TUN device
// and provides an fd to read/write packets.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const TUN_MTU: usize = 1500;
pub const MAX_PACKET_SIZE: usize = TUN_MTU + 14;
pub const RECV_QUEUE_MAX: usize = 64;

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
        };

        // Set non-blocking
        const flags = posix.fcntl(fd, .F_GETFL) catch {
            return FdAdapterError.OpenFailed;
        };
        _ = posix.fcntl(fd, .F_SETFL, .{ .raw = @as(u32, @bitCast(flags)) | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })) }) catch {
            return FdAdapterError.OpenFailed;
        };

        std.log.info("FdAdapter wrapping fd={d} name={s}", .{ fd, name });
        return device;
    }

    /// Close the adapter. Does NOT close the fd (owned by the platform).
    pub fn close(self: *FdAdapter) void {
        self.is_open = false;
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

    /// Write a packet to the fd
    pub fn write(self: *FdAdapter, data: []const u8) !usize {
        if (!self.is_open) return FdAdapterError.DeviceNotOpen;

        const written = posix.write(self.fd, data) catch {
            return FdAdapterError.WriteFailed;
        };

        self.stats.send_bytes += written;
        self.stats.send_packets += 1;
        return written;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const FdAdapter) TunStats {
        return self.stats;
    }
};
