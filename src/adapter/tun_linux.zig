// SoftEther VPN Client - Linux TUN Device
// Linux TUN/TAP network adapter implementation

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const TUN_MTU: usize = 1500;
pub const MAX_PACKET_SIZE: usize = TUN_MTU + 14; // + Ethernet header
pub const RECV_QUEUE_MAX: usize = 64;

// Linux TUN/TAP constants
const IFF_TUN: u16 = 0x0001;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;

// IOCTL numbers for TUN/TAP
const TUNSETIFF: u32 = 0x400454ca;
const TUNSETPERSIST: u32 = 0x400454cb;
const TUNSETOWNER: u32 = 0x400454cc;

const SIOCSIFMTU: c_int = 0x8922;
const SIOCSIFFLAGS: c_int = 0x8914;
const SIOCGIFFLAGS: c_int = 0x8913;
const SIOCSIFADDR: c_int = 0x8916;
const SIOCSIFNETMASK: c_int = 0x891c;
const SIOCSIFDSTADDR: c_int = 0x8918;

const IFF_UP: c_short = 0x1;
const IFF_RUNNING: c_short = 0x40;
const IFF_NOARP: c_short = 0x80;
const IFF_POINTOPOINT: c_short = 0x10;

const SIOCSIFHWADDR: c_int = 0x8924;

pub const TunLinuxError = error{
    NotLinux,
    OpenFailed,
    IoctlFailed,
    SocketFailed,
    ConfigureFailed,
    DeviceNotOpen,
    ReadFailed,
    WriteFailed,
    PermissionDenied,
};

// Linux ifreq structure
const IfreqFlags = extern struct {
    ifrn_name: [16]u8,
    ifru_flags: c_short,
    padding: [22]u8,
};

const IfreqAddr = extern struct {
    ifrn_name: [16]u8,
    ifru_addr: posix.sockaddr,
    padding: [8]u8,
};

const IfreqMtu = extern struct {
    ifrn_name: [16]u8,
    ifru_mtu: c_int,
    padding: [20]u8,
};

const IfreqHwaddr = extern struct {
    ifrn_name: [16]u8,
    /// Raw sockaddr bytes (2 bytes sa_family + 14 bytes sa_data).
    /// Constructed as raw bytes to avoid UB from directly initialising posix.sockaddr.
    ifru_hwaddr: [16]u8,
    padding: [8]u8,
};

/// Linux TUN device structure
pub const TunLinuxDevice = struct {
    allocator: std.mem.Allocator,

    // File descriptor for the TUN device
    fd: ?posix.fd_t,

    // Device name (e.g., "tun0")
    device_name: [16]u8,

    // MAC address (generated)
    mac_address: [6]u8,

    // Configuration
    ipv4_address: u32,
    ipv4_netmask: u32,
    ipv4_gateway: u32,

    // Statistics
    stats: TunStats,

    // State
    is_open: bool,
    is_configured: bool,
    halt: bool,

    connection_start_time: i64,

    /// Set the MTU on this device via SIOCSIFMTU ioctl.
    pub fn setMtu(self: *TunLinuxDevice, mtu: u16) TunLinuxError!void {
        _ = self.fd orelse return TunLinuxError.DeviceNotOpen;
        // SIOCSIFMTU must be called on a socket (AF_INET, SOCK_DGRAM), not on
        // the TUN device fd. Using the tun fd causes EINVAL.
        const sock_fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |err| {
            std.log.warn("setMtu: failed to create control socket: {}", .{err});
            return TunLinuxError.SocketFailed;
        };
        defer posix.close(sock_fd);
        var mtu_req = IfreqMtu{
            .ifrn_name = self.device_name,
            .ifru_mtu = mtu,
            .padding = [_]u8{0} ** 20,
        };
        if (std.c.ioctl(sock_fd, SIOCSIFMTU, @intFromPtr(&mtu_req)) < 0) {
            std.log.warn("Failed to set MTU {d}: errno={}", .{ mtu, std.c._errno().* });
            return TunLinuxError.IoctlFailed;
        }
        std.log.info("Set MTU to {d} on {s}", .{ mtu, self.getName() });
    }

    /// Open a Linux TAP (L2 Ethernet) device
    /// Uses IFF_TAP instead of IFF_TUN. Returns a TunLinuxDevice that reads/writes
    /// full Ethernet frames (L2) rather than raw IP packets (L3).
    pub fn openTap(allocator: std.mem.Allocator) TunLinuxError!*TunLinuxDevice {
        if (builtin.os.tag != .linux) {
            return TunLinuxError.NotLinux;
        }

        const fd = posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0) catch |err| {
            std.log.err("Failed to open /dev/net/tun: {}", .{err});
            if (err == error.AccessDenied) {
                return TunLinuxError.PermissionDenied;
            }
            return TunLinuxError.OpenFailed;
        };
        errdefer posix.close(fd);

        var ifr = IfreqFlags{
            .ifrn_name = [_]u8{0} ** 16,
            .ifru_flags = @intCast(IFF_TAP | IFF_NO_PI),
            .padding = [_]u8{0} ** 22,
        };

        const tap_pattern = "tap%d";
        @memcpy(ifr.ifrn_name[0..tap_pattern.len], tap_pattern);

        const ioctl_result = std.c.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        if (ioctl_result < 0) {
            std.log.err("TAP open: TUNSETIFF ioctl failed: errno={}", .{std.c._errno().*});
            return TunLinuxError.IoctlFailed;
        }

        var device_name: [16]u8 = ifr.ifrn_name;
        var name_len: usize = 0;
        for (device_name) |c| {
            if (c == 0) break;
            name_len += 1;
        }

        std.log.info("Created TAP device: {s}", .{device_name[0..name_len]});

        var mac: [6]u8 = undefined;
        std.crypto.random.bytes(&mac);
        mac[0] = (mac[0] & 0xFC) | 0x02;

        // Apply MAC to the TAP interface via SIOCSIFHWADDR.
        // This requires CAP_NET_ADMIN on the ioctl socket.
        {
            const sock_fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |err| blk: {
                std.log.warn("TAP open: failed to open control socket for MAC setup: {}", .{err});
                break :blk -1;
            };
            if (sock_fd >= 0) {
                defer posix.close(sock_fd);
                var hwreq = IfreqHwaddr{
                    .ifrn_name = device_name,
                    .ifru_hwaddr = [_]u8{0} ** 16,
                    .padding = [_]u8{0} ** 8,
                };
                // Set sa_family = ARPHRD_ETHER (1) in network byte order
                hwreq.ifru_hwaddr[0] = 1; // sa_family low byte
                hwreq.ifru_hwaddr[1] = 0; // sa_family high byte
                @memcpy(hwreq.ifru_hwaddr[2..8], &mac);
                if (std.c.ioctl(sock_fd, SIOCSIFHWADDR, @intFromPtr(&hwreq)) < 0) {
                    std.log.warn("TAP open: SIOCSIFHWADDR failed (non-fatal): errno={}", .{std.c._errno().*});
                } else {
                    std.log.info("TAP device MAC set to {any}", .{mac});
                }
            }
        }

        const device = allocator.create(TunLinuxDevice) catch {
            return TunLinuxError.OpenFailed;
        };

        device.* = TunLinuxDevice{
            .allocator = allocator,
            .fd = fd,
            .device_name = device_name,
            .mac_address = mac,
            .ipv4_address = 0,
            .ipv4_netmask = 0,
            .ipv4_gateway = 0,
            .stats = TunStats{},
            .is_open = true,
            .is_configured = false,
            .halt = false,
            .connection_start_time = std.time.milliTimestamp(),
        };

        return device;
    }

    /// Open a Linux TUN device
    pub fn open(allocator: std.mem.Allocator) TunLinuxError!*TunLinuxDevice {
        if (builtin.os.tag != .linux) {
            return TunLinuxError.NotLinux;
        }

        // Open /dev/net/tun
        const fd = posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0) catch |err| {
            std.log.err("Failed to open /dev/net/tun: {}", .{err});
            if (err == error.AccessDenied) {
                return TunLinuxError.PermissionDenied;
            }
            return TunLinuxError.OpenFailed;
        };
        errdefer posix.close(fd);

        // Set up the TUN device
        var ifr = IfreqFlags{
            .ifrn_name = [_]u8{0} ** 16,
            .ifru_flags = @intCast(IFF_TUN | IFF_NO_PI),
            .padding = [_]u8{0} ** 22,
        };

        // Try to create a new TUN device with automatic name
        // Copy "tun%d" to let kernel assign name
        const tun_pattern = "tun%d";
        @memcpy(ifr.ifrn_name[0..tun_pattern.len], tun_pattern);

        const ioctl_result = std.c.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        if (ioctl_result < 0) {
            std.log.err("TUNSETIFF ioctl failed: errno={}", .{std.c._errno().*});
            return TunLinuxError.IoctlFailed;
        }

        // Extract the device name that was assigned
        var device_name: [16]u8 = ifr.ifrn_name;

        // Find the end of the name
        var name_len: usize = 0;
        for (device_name) |c| {
            if (c == 0) break;
            name_len += 1;
        }

        std.log.info("Created TUN device: {s}", .{device_name[0..name_len]});

        // Generate a random MAC address
        var mac: [6]u8 = undefined;
        std.crypto.random.bytes(&mac);
        mac[0] = (mac[0] & 0xFC) | 0x02; // Set locally administered bit, clear multicast bit

        // Allocate device structure
        const device = allocator.create(TunLinuxDevice) catch {
            return TunLinuxError.OpenFailed;
        };

        device.* = TunLinuxDevice{
            .allocator = allocator,
            .fd = fd,
            .device_name = device_name,
            .mac_address = mac,
            .ipv4_address = 0,
            .ipv4_netmask = 0,
            .ipv4_gateway = 0,
            .stats = TunStats{},
            .is_open = true,
            .is_configured = false,
            .halt = false,
            .connection_start_time = std.time.milliTimestamp(),
        };

        return device;
    }

    /// Close the TUN device
    pub fn close(self: *TunLinuxDevice) void {
        if (self.fd) |fd| {
            // Bring the interface down first
            self.bringInterfaceDown() catch {};
            posix.close(fd);
            self.fd = null;
        }
        self.is_open = false;
        self.is_configured = false;
        self.allocator.destroy(self);
    }

    /// Get device name
    pub fn getName(self: *const TunLinuxDevice) []const u8 {
        var len: usize = 0;
        for (self.device_name) |c| {
            if (c == 0) break;
            len += 1;
        }
        return self.device_name[0..len];
    }

    /// Get MAC address
    pub fn getMac(self: *const TunLinuxDevice) [6]u8 {
        return self.mac_address;
    }

    /// Get file descriptor
    pub fn getFd(self: *const TunLinuxDevice) posix.fd_t {
        return self.fd orelse -1;
    }

    /// Check if device is open
    pub fn isOpen(self: *const TunLinuxDevice) bool {
        return self.is_open and self.fd != null;
    }

    /// Configure temporary IP (for DHCP)
    pub fn configureTemporary(self: *TunLinuxDevice) !void {
        try self.bringInterfaceUp();
    }

    /// Configure the TUN device with IP settings
    pub fn configure(self: *TunLinuxDevice, ip: u32, mask: u32, gateway: u32) !void {
        _ = self.fd orelse return TunLinuxError.DeviceNotOpen;

        self.ipv4_address = ip;
        self.ipv4_netmask = mask;
        self.ipv4_gateway = gateway;

        // IP addresses from DHCP are in network byte order (big-endian)
        // Extract bytes correctly for display
        const ip_b0: u8 = @truncate((ip >> 24) & 0xFF);
        const ip_b1: u8 = @truncate((ip >> 16) & 0xFF);
        const ip_b2: u8 = @truncate((ip >> 8) & 0xFF);
        const ip_b3: u8 = @truncate(ip & 0xFF);

        // Calculate prefix from netmask (also in network byte order)
        var prefix: u8 = 0;
        var m = mask;
        while (m & 0x80000000 != 0) : (m <<= 1) {
            prefix += 1;
            if (prefix >= 32) break;
        }
        // Default to /16 if we got 0 (common VPN subnet)
        if (prefix == 0) prefix = 16;

        // Use ip command to configure interface (more reliable than ioctl)
        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "ip addr add {d}.{d}.{d}.{d}/{d} dev {s}", .{
            ip_b0,  ip_b1,          ip_b2, ip_b3,
            prefix, self.getName(),
        }) catch return TunLinuxError.ConfigureFailed;

        std.log.info("Running: {s}", .{cmd});

        // Run the command
        var child = std.process.Child.init(
            &[_][]const u8{ "sh", "-c", cmd },
            self.allocator,
        );
        child.stdout_behavior = .Close;
        child.stderr_behavior = .Close;

        child.spawn() catch {
            std.log.err("Failed to spawn ip addr command", .{});
            return TunLinuxError.ConfigureFailed;
        };

        const result = child.wait() catch {
            std.log.err("Failed to wait for ip addr command", .{});
            return TunLinuxError.ConfigureFailed;
        };

        switch (result) {
            .Exited => |code| {
                if (code != 0) {
                    std.log.warn("ip addr command returned non-zero: {}", .{code});
                    // Continue anyway - address might already be set
                }
            },
            else => {
                std.log.warn("ip addr command terminated abnormally", .{});
            },
        }

        // Set MTU using ip link
        var mtu_cmd_buf: [256]u8 = undefined;
        const mtu_cmd = std.fmt.bufPrint(&mtu_cmd_buf, "ip link set dev {s} mtu {d}", .{
            self.getName(),
            TUN_MTU,
        }) catch return TunLinuxError.ConfigureFailed;

        var mtu_child = std.process.Child.init(
            &[_][]const u8{ "sh", "-c", mtu_cmd },
            self.allocator,
        );
        mtu_child.stdout_behavior = .Close;
        mtu_child.stderr_behavior = .Close;

        mtu_child.spawn() catch {};
        _ = mtu_child.wait() catch {};

        // Bring interface up
        try self.bringInterfaceUp();

        self.is_configured = true;

        // Log configuration
        std.log.info("TUN device {s} configured: {d}.{d}.{d}.{d}/{d}", .{
            self.getName(),
            ip_b0,
            ip_b1,
            ip_b2,
            ip_b3,
            prefix,
        });
    }

    /// Configure an IPv6 address on the TUN interface.
    /// Uses the 'ip -6 addr add' command (standard Linux netlink tool).
    pub fn configureIpv6(self: *TunLinuxDevice, address: [16]u8, prefix_len: u8) !void {
        if (builtin.os.tag != .linux) return TunLinuxError.NotLinux;
        _ = self.fd orelse return TunLinuxError.DeviceNotOpen;

        // Format IPv6 address as colon-hex string
        var addr_buf: [40]u8 = undefined;
        const addr_str = std.fmt.bufPrint(&addr_buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            address[0],  address[1],  address[2],  address[3],
            address[4],  address[5],  address[6],  address[7],
            address[8],  address[9],  address[10], address[11],
            address[12], address[13], address[14], address[15],
        }) catch return TunLinuxError.ConfigureFailed;

        var cmd_buf: [256]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "ip -6 addr add {s}/{d} dev {s}", .{
            addr_str,
            prefix_len,
            self.getName(),
        }) catch return TunLinuxError.ConfigureFailed;

        std.log.info("Running: {s}", .{cmd});

        var child = std.process.Child.init(
            &[_][]const u8{ "sh", "-c", cmd },
            self.allocator,
        );
        child.stdout_behavior = .Close;
        child.stderr_behavior = .Close;

        child.spawn() catch {
            std.log.err("Failed to spawn ip -6 addr command", .{});
            return TunLinuxError.ConfigureFailed;
        };

        const result = child.wait() catch {
            std.log.err("Failed to wait for ip -6 addr command", .{});
            return TunLinuxError.ConfigureFailed;
        };

        switch (result) {
            .Exited => |code| {
                if (code != 0) {
                    std.log.warn("ip -6 addr command returned non-zero: {}", .{code});
                }
            },
            else => {
                std.log.warn("ip -6 addr command terminated abnormally", .{});
            },
        }
    }

    /// Bring interface up
    fn bringInterfaceUp(self: *TunLinuxDevice) !void {
        const sock_fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
            return TunLinuxError.SocketFailed;
        };
        defer posix.close(sock_fd);

        var flags_req = IfreqFlags{
            .ifrn_name = self.device_name,
            .ifru_flags = 0,
            .padding = [_]u8{0} ** 22,
        };

        // Get current flags
        if (std.c.ioctl(sock_fd, SIOCGIFFLAGS, @intFromPtr(&flags_req)) < 0) {
            std.log.err("Failed to get interface flags: errno={}", .{std.c._errno().*});
            return TunLinuxError.ConfigureFailed;
        }

        // Add UP and RUNNING flags
        flags_req.ifru_flags |= (IFF_UP | IFF_RUNNING);

        if (std.c.ioctl(sock_fd, SIOCSIFFLAGS, @intFromPtr(&flags_req)) < 0) {
            std.log.err("Failed to bring interface up: errno={}", .{std.c._errno().*});
            return TunLinuxError.ConfigureFailed;
        }

        std.log.debug("Interface {s} is now UP", .{self.getName()});
    }

    /// Bring interface down
    fn bringInterfaceDown(self: *TunLinuxDevice) !void {
        const sock_fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
            return TunLinuxError.SocketFailed;
        };
        defer posix.close(sock_fd);

        var flags_req = IfreqFlags{
            .ifrn_name = self.device_name,
            .ifru_flags = 0,
            .padding = [_]u8{0} ** 22,
        };

        // Get current flags
        if (std.c.ioctl(sock_fd, SIOCGIFFLAGS, @intFromPtr(&flags_req)) < 0) {
            return; // Interface might already be gone
        }

        // Remove UP flag
        flags_req.ifru_flags &= ~IFF_UP;

        _ = std.c.ioctl(sock_fd, SIOCSIFFLAGS, @intFromPtr(&flags_req));
    }

    /// Read a packet from the TUN device
    pub fn read(self: *TunLinuxDevice, buffer: []u8) !?usize {
        const fd = self.fd orelse return TunLinuxError.DeviceNotOpen;

        const result = posix.read(fd, buffer);
        if (result) |bytes_read| {
            if (bytes_read > 0) {
                self.stats.recv_bytes += bytes_read;
                self.stats.recv_packets += 1;
                return bytes_read;
            }
            return null;
        } else |err| {
            if (err == error.WouldBlock) {
                return null;
            }
            return TunLinuxError.ReadFailed;
        }
    }

    /// Write a packet to the TUN device
    pub fn write(self: *TunLinuxDevice, data: []const u8) !usize {
        const fd = self.fd orelse return TunLinuxError.DeviceNotOpen;

        const written = posix.write(fd, data) catch {
            return TunLinuxError.WriteFailed;
        };

        self.stats.send_bytes += written;
        self.stats.send_packets += 1;

        return written;
    }

    /// Get statistics
    pub fn getStats(self: *const TunLinuxDevice) TunStats {
        return self.stats;
    }
};

/// Traffic statistics
pub const TunStats = struct {
    send_packets: u64 = 0,
    send_bytes: u64 = 0,
    recv_packets: u64 = 0,
    recv_bytes: u64 = 0,
};
