// SoftEther VPN Zig Client - macOS utun Virtual Adapter
// Pure Zig implementation of macOS utun kernel interface for packet forwarding

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Maximum TUN MTU (standard Ethernet)
pub const TUN_MTU: usize = 1500;

/// Maximum packet size including overhead
pub const MAX_PACKET_SIZE: usize = 2048;

/// Receive queue maximum entries
pub const RECV_QUEUE_MAX: usize = 1024;

/// macOS-specific constants for utun kernel control
pub const AF_SYSTEM: u8 = 32;
pub const AF_SYS_CONTROL: u16 = 2;
pub const SYSPROTO_CONTROL: u8 = 2;
pub const UTUN_OPT_IFNAME: u32 = 2;

/// CTLIOCGINFO ioctl number for macOS kernel control
/// _IOWR('N', 3, struct ctl_info) = 0xC0644E03
pub const CTLIOCGINFO: u32 = 0xC0644E03;

/// utun control name
pub const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

/// ctl_info structure for kernel control
pub const CtlInfo = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

/// sockaddr_ctl structure for connecting to kernel control
pub const SockaddrCtl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

/// Protocol family for IP packets (prepended to utun packets)
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 30;

/// TUN device errors
pub const UtunError = error{
    SocketCreationFailed,
    CtlInfoFailed,
    ConnectFailed,
    GetNameFailed,
    SetNonBlockingFailed,
    DeviceNotOpen,
    ReadFailed,
    WriteFailed,
    PacketTooLarge,
    InterfaceConfigFailed,
    OutOfMemory,
    InvalidPacket,
    QueueFull,
    NotMacOS,
};

/// Packet wrapper for TUN device I/O
pub const TunPacket = struct {
    data: []u8,
    size: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, size: usize) !*TunPacket {
        const self = try allocator.create(TunPacket);
        self.data = try allocator.alloc(u8, size);
        self.size = size;
        self.allocator = allocator;
        return self;
    }

    pub fn deinit(self: *TunPacket) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }

    /// Create packet from existing data (copies)
    pub fn fromData(allocator: std.mem.Allocator, data: []const u8) !*TunPacket {
        const self = try allocator.create(TunPacket);
        self.data = try allocator.dupe(u8, data);
        self.size = data.len;
        self.allocator = allocator;
        return self;
    }
};

/// DHCP state machine
pub const DhcpState = enum {
    init,
    arp_announce_sent,
    ipv6_na_sent,
    ipv6_rs_sent,
    discover_sent,
    offer_received,
    request_sent,
    arp_probe_sent,
    configured,
};

/// IPv4 address configuration
pub const Ipv4Config = struct {
    address: u32 = 0,
    netmask: u32 = 0,
    gateway: u32 = 0,
    dns1: u32 = 0,
    dns2: u32 = 0,

    /// Format address as string
    pub fn formatAddress(self: *const Ipv4Config) [16]u8 {
        var buf: [16]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
            (self.address >> 24) & 0xFF,
            (self.address >> 16) & 0xFF,
            (self.address >> 8) & 0xFF,
            self.address & 0xFF,
        }) catch {};
        return buf;
    }
};

/// IPv6 address configuration
pub const Ipv6Config = struct {
    address: [16]u8 = [_]u8{0} ** 16,
    prefix_len: u8 = 64,
    gateway: [16]u8 = [_]u8{0} ** 16,
    configured: bool = false,

    /// Generate link-local address from MAC
    pub fn generateLinkLocal(mac: [6]u8) Ipv6Config {
        var cfg = Ipv6Config{};
        // fe80::
        cfg.address[0] = 0xfe;
        cfg.address[1] = 0x80;
        // EUI-64 from MAC
        cfg.address[8] = mac[0] ^ 0x02; // Flip universal/local bit
        cfg.address[9] = mac[1];
        cfg.address[10] = mac[2];
        cfg.address[11] = 0xff;
        cfg.address[12] = 0xfe;
        cfg.address[13] = mac[3];
        cfg.address[14] = mac[4];
        cfg.address[15] = mac[5];
        cfg.configured = true;
        return cfg;
    }
};

/// Traffic statistics
pub const TunStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    errors: u64 = 0,
    dropped: u64 = 0,
};

/// Thread-safe packet queue
pub const PacketQueue = struct {
    packets: std.ArrayListUnmanaged(*TunPacket),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    max_size: usize,

    pub fn init(allocator: std.mem.Allocator, max_size: usize) PacketQueue {
        return .{
            .packets = .{},
            .allocator = allocator,
            .mutex = .{},
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.packets.items) |pkt| {
            pkt.deinit();
        }
        self.packets.deinit(self.allocator);
    }

    pub fn push(self: *PacketQueue, pkt: *TunPacket) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.packets.items.len >= self.max_size) {
            return UtunError.QueueFull;
        }
        try self.packets.append(self.allocator, pkt);
    }

    pub fn pop(self: *PacketQueue) ?*TunPacket {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.packets.items.len == 0) {
            return null;
        }
        return self.packets.orderedRemove(0);
    }

    pub fn len(self: *PacketQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.packets.items.len;
    }
};

/// macOS utun Virtual Network Adapter
pub const UtunDevice = struct {
    allocator: std.mem.Allocator,
    fd: posix.fd_t,
    device_name: [64]u8,
    device_name_len: usize,

    // Network configuration
    mac_address: [6]u8,
    ipv4_config: Ipv4Config,
    ipv6_config: Ipv6Config,

    // DHCP state
    dhcp_state: DhcpState,
    dhcp_xid: u32,
    dhcp_server_ip: u32,
    dhcp_retry_count: u32,
    last_dhcp_time: i64,

    // Packet queues
    recv_queue: PacketQueue,
    send_queue: PacketQueue,

    // Statistics
    stats: TunStats,

    // State
    is_open: bool,
    halt: bool,

    // Connection timing
    connection_start_time: i64,

    /// Open a macOS utun device
    pub fn open(allocator: std.mem.Allocator) UtunError!*UtunDevice {
        if (builtin.os.tag != .macos) {
            return UtunError.NotMacOS;
        }

        // Create control socket to get utun control ID
        const temp_fd = posix.socket(AF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL) catch {
            return UtunError.SocketCreationFailed;
        };
        defer posix.close(temp_fd);

        // Get control ID
        var info = CtlInfo{
            .ctl_id = 0,
            .ctl_name = [_]u8{0} ** 96,
        };
        @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

        const ioctl_result = std.c.ioctl(temp_fd, @bitCast(CTLIOCGINFO), @intFromPtr(&info));
        if (ioctl_result < 0) {
            return UtunError.CtlInfoFailed;
        }

        // Try to find an available utun device (0-15)
        var fd: posix.fd_t = undefined;
        var unit_number: u32 = 0;
        var found = false;

        while (unit_number < 16) : (unit_number += 1) {
            fd = posix.socket(AF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL) catch {
                continue;
            };

            var addr = SockaddrCtl{
                .sc_len = @sizeOf(SockaddrCtl),
                .sc_family = AF_SYSTEM,
                .ss_sysaddr = AF_SYS_CONTROL,
                .sc_id = info.ctl_id,
                .sc_unit = unit_number + 1, // utun0 = 1, utun1 = 2, etc.
                .sc_reserved = [_]u32{0} ** 5,
            };

            // Use C connect directly to avoid "unexpected errno" noise for EBUSY (16)
            const connect_result = std.c.connect(fd, @ptrCast(&addr), @sizeOf(SockaddrCtl));
            if (connect_result < 0) {
                posix.close(fd);
                continue;
            }
            found = true;
            break;
        }

        if (!found) {
            return UtunError.ConnectFailed;
        }

        // Get device name
        var device_name: [64]u8 = [_]u8{0} ** 64;
        var optlen: u32 = 64;
        const getsockopt_result = std.c.getsockopt(
            fd,
            SYSPROTO_CONTROL,
            @intCast(UTUN_OPT_IFNAME),
            &device_name,
            &optlen,
        );
        if (getsockopt_result < 0) {
            posix.close(fd);
            return UtunError.GetNameFailed;
        }

        // Set non-blocking mode
        // O_NONBLOCK on macOS is 0x0004 (bit 2)
        const O_NONBLOCK: usize = 0x0004;
        const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch {
            posix.close(fd);
            return UtunError.SetNonBlockingFailed;
        };
        _ = posix.fcntl(fd, posix.F.SETFL, flags | O_NONBLOCK) catch {
            posix.close(fd);
            return UtunError.SetNonBlockingFailed;
        };

        // Allocate device
        const self = allocator.create(UtunDevice) catch {
            posix.close(fd);
            return UtunError.OutOfMemory;
        };

        // Calculate device name length
        var name_len: usize = 0;
        while (name_len < 64 and device_name[name_len] != 0) : (name_len += 1) {}

        self.* = UtunDevice{
            .allocator = allocator,
            .fd = fd,
            .device_name = device_name,
            .device_name_len = name_len,
            .mac_address = generateMac(),
            .ipv4_config = .{},
            .ipv6_config = .{},
            .dhcp_state = .init,
            .dhcp_xid = generateXid(),
            .dhcp_server_ip = 0,
            .dhcp_retry_count = 0,
            .last_dhcp_time = 0,
            .recv_queue = PacketQueue.init(allocator, RECV_QUEUE_MAX),
            .send_queue = PacketQueue.init(allocator, RECV_QUEUE_MAX),
            .stats = .{},
            .is_open = true,
            .halt = false,
            .connection_start_time = std.time.milliTimestamp(),
        };

        // Generate IPv6 link-local from MAC
        self.ipv6_config = Ipv6Config.generateLinkLocal(self.mac_address);

        return self;
    }

    /// Close the utun device
    pub fn close(self: *UtunDevice) void {
        if (self.is_open) {
            self.halt = true;
            posix.close(self.fd);
            self.is_open = false;
        }
        self.recv_queue.deinit();
        self.send_queue.deinit();
        self.allocator.destroy(self);
    }

    /// Get device name as slice
    pub fn getName(self: *const UtunDevice) []const u8 {
        return self.device_name[0..self.device_name_len];
    }

    /// Read a packet from the utun device (non-blocking)
    pub fn read(self: *UtunDevice, buffer: []u8) UtunError!?usize {
        if (!self.is_open) {
            return UtunError.DeviceNotOpen;
        }

        // Buffer must have room for 4-byte protocol header
        var read_buf: [MAX_PACKET_SIZE + 4]u8 = undefined;

        const n = posix.read(self.fd, &read_buf) catch |err| {
            switch (err) {
                error.WouldBlock => return null,
                else => return UtunError.ReadFailed,
            }
        };

        if (n < 4) {
            return null;
        }

        // Skip 4-byte protocol header (AF_INET/AF_INET6)
        const payload_len = n - 4;
        if (payload_len > buffer.len) {
            return UtunError.PacketTooLarge;
        }

        @memcpy(buffer[0..payload_len], read_buf[4..n]);

        self.stats.bytes_received += payload_len;
        self.stats.packets_received += 1;

        return payload_len;
    }

    /// Write a packet to the utun device
    pub fn write(self: *UtunDevice, data: []const u8) UtunError!usize {
        if (!self.is_open) {
            return UtunError.DeviceNotOpen;
        }

        if (data.len > MAX_PACKET_SIZE) {
            return UtunError.PacketTooLarge;
        }

        // Prepend protocol family header
        var write_buf: [MAX_PACKET_SIZE + 4]u8 = undefined;

        // Determine IP version from packet
        const ip_version = (data[0] >> 4) & 0x0F;
        const proto: u32 = if (ip_version == 6) AF_INET6 else AF_INET;

        // Write protocol family in network byte order
        write_buf[0] = @intCast((proto >> 24) & 0xFF);
        write_buf[1] = @intCast((proto >> 16) & 0xFF);
        write_buf[2] = @intCast((proto >> 8) & 0xFF);
        write_buf[3] = @intCast(proto & 0xFF);

        @memcpy(write_buf[4..][0..data.len], data);

        const written = posix.write(self.fd, write_buf[0 .. data.len + 4]) catch {
            self.stats.errors += 1;
            return UtunError.WriteFailed;
        };

        if (written < 4) {
            return UtunError.WriteFailed;
        }

        const payload_written = written - 4;
        self.stats.bytes_sent += payload_written;
        self.stats.packets_sent += 1;

        return payload_written;
    }

    /// Configure interface with IP address using ifconfig
    pub fn configure(self: *UtunDevice, ip: u32, netmask: u32, gateway: u32) !void {
        if (!self.is_open) {
            return UtunError.DeviceNotOpen;
        }

        self.ipv4_config.address = ip;
        self.ipv4_config.netmask = netmask;
        self.ipv4_config.gateway = gateway;

        // Build ifconfig command
        var cmd_buf: [512]u8 = undefined;
        const cmd = try std.fmt.bufPrint(&cmd_buf, "ifconfig {s} {d}.{d}.{d}.{d} {d}.{d}.{d}.{d} netmask {d}.{d}.{d}.{d} up", .{
            self.getName(),
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF,
            (gateway >> 24) & 0xFF,
            (gateway >> 16) & 0xFF,
            (gateway >> 8) & 0xFF,
            gateway & 0xFF,
            (netmask >> 24) & 0xFF,
            (netmask >> 16) & 0xFF,
            (netmask >> 8) & 0xFF,
            netmask & 0xFF,
        });

        // Execute command
        var child = std.process.Child.init(
            &[_][]const u8{ "sh", "-c", cmd },
            self.allocator,
        );
        _ = child.spawnAndWait() catch {
            return UtunError.InterfaceConfigFailed;
        };
    }

    /// Configure with temporary link-local IP for initial setup
    pub fn configureTemporary(self: *UtunDevice) !void {
        // Generate random link-local address: 169.254.x.x
        const rand_bytes = generateRandomBytes(2);
        const temp_ip: u32 = 0xA9FE0000 | (@as(u32, rand_bytes[0]) << 8) | rand_bytes[1];
        const temp_peer: u32 = 0xA9FE0001;
        const temp_mask: u32 = 0xFFFF0000;

        try self.configure(temp_ip, temp_mask, temp_peer);
    }

    /// Get file descriptor for polling
    pub fn getFd(self: *const UtunDevice) posix.fd_t {
        return self.fd;
    }

    /// Check if device is open
    pub fn isOpen(self: *const UtunDevice) bool {
        return self.is_open;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const UtunDevice) TunStats {
        return self.stats;
    }

    /// Get MAC address
    pub fn getMac(self: *const UtunDevice) [6]u8 {
        return self.mac_address;
    }
};

// ============================================
// Ethernet Packet Building Functions
// ============================================

/// Build a Gratuitous ARP packet to register MAC in bridge
pub fn buildGratuitousArp(mac: [6]u8, ip: u32, buffer: []u8) !usize {
    if (buffer.len < 42) return error.BufferTooSmall;

    var pos: usize = 0;

    // Ethernet header (14 bytes)
    // Destination: broadcast
    @memset(buffer[pos..][0..6], 0xFF);
    pos += 6;
    // Source: our MAC
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;
    // EtherType: ARP (0x0806)
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x06;
    pos += 2;

    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x01;
    pos += 2;
    // Protocol type: IPv4 (0x0800)
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x00;
    pos += 2;
    // Hardware size: 6
    buffer[pos] = 0x06;
    pos += 1;
    // Protocol size: 4
    buffer[pos] = 0x04;
    pos += 1;
    // Opcode: Request (1)
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x01;
    pos += 2;

    // Sender MAC
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;

    // Sender IP
    buffer[pos] = @intCast((ip >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((ip >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((ip >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(ip & 0xFF);
    pos += 4;

    // Target MAC: zeros (unknown)
    @memset(buffer[pos..][0..6], 0);
    pos += 6;

    // Target IP: same as sender (gratuitous)
    buffer[pos] = @intCast((ip >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((ip >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((ip >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(ip & 0xFF);
    pos += 4;

    return pos;
}

/// Build an ARP Reply packet
pub fn buildArpReply(
    my_mac: [6]u8,
    my_ip: u32,
    target_mac: [6]u8,
    target_ip: u32,
    buffer: []u8,
) !usize {
    if (buffer.len < 42) return error.BufferTooSmall;

    var pos: usize = 0;

    // Ethernet header
    @memcpy(buffer[pos..][0..6], &target_mac);
    pos += 6;
    @memcpy(buffer[pos..][0..6], &my_mac);
    pos += 6;
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x06;
    pos += 2;

    // ARP Reply
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x01;
    pos += 2;
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x00;
    pos += 2;
    buffer[pos] = 0x06;
    pos += 1;
    buffer[pos] = 0x04;
    pos += 1;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x02; // Reply
    pos += 2;

    @memcpy(buffer[pos..][0..6], &my_mac);
    pos += 6;
    buffer[pos] = @intCast((my_ip >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((my_ip >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((my_ip >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(my_ip & 0xFF);
    pos += 4;

    @memcpy(buffer[pos..][0..6], &target_mac);
    pos += 6;
    buffer[pos] = @intCast((target_ip >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((target_ip >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((target_ip >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(target_ip & 0xFF);
    pos += 4;

    return pos;
}

/// Build an ARP Request packet
pub fn buildArpRequest(my_mac: [6]u8, my_ip: u32, target_ip: u32, buffer: []u8) !usize {
    if (buffer.len < 42) return error.BufferTooSmall;

    var pos: usize = 0;

    // Ethernet header - broadcast
    @memset(buffer[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(buffer[pos..][0..6], &my_mac);
    pos += 6;
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x06;
    pos += 2;

    // ARP Request
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x01;
    pos += 2;
    buffer[pos] = 0x08;
    buffer[pos + 1] = 0x00;
    pos += 2;
    buffer[pos] = 0x06;
    pos += 1;
    buffer[pos] = 0x04;
    pos += 1;
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x01; // Request
    pos += 2;

    @memcpy(buffer[pos..][0..6], &my_mac);
    pos += 6;
    buffer[pos] = @intCast((my_ip >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((my_ip >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((my_ip >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(my_ip & 0xFF);
    pos += 4;

    @memset(buffer[pos..][0..6], 0); // Unknown target MAC
    pos += 6;
    buffer[pos] = @intCast((target_ip >> 24) & 0xFF);
    buffer[pos + 1] = @intCast((target_ip >> 16) & 0xFF);
    buffer[pos + 2] = @intCast((target_ip >> 8) & 0xFF);
    buffer[pos + 3] = @intCast(target_ip & 0xFF);
    pos += 4;

    return pos;
}

/// Build IPv6 Router Solicitation (ICMPv6 type 133)
pub fn buildRouterSolicitation(mac: [6]u8, buffer: []u8) !usize {
    if (buffer.len < 62) return error.BufferTooSmall;

    var pos: usize = 0;

    // Ethernet header
    // Destination: IPv6 all-routers multicast (33:33:00:00:00:02)
    buffer[pos] = 0x33;
    buffer[pos + 1] = 0x33;
    @memset(buffer[pos + 2 ..][0..3], 0);
    buffer[pos + 5] = 0x02;
    pos += 6;
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;
    // EtherType: IPv6 (0x86DD)
    buffer[pos] = 0x86;
    buffer[pos + 1] = 0xDD;
    pos += 2;

    // IPv6 header
    buffer[pos] = 0x60; // Version 6
    buffer[pos + 1] = 0x00;
    buffer[pos + 2] = 0x00;
    buffer[pos + 3] = 0x00;
    pos += 4;

    // Payload length: 8 (ICMPv6 RS)
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x08;
    pos += 2;

    // Next header: ICMPv6 (58)
    buffer[pos] = 58;
    pos += 1;
    // Hop limit
    buffer[pos] = 255;
    pos += 1;

    // Source: link-local from MAC (fe80::)
    buffer[pos] = 0xFE;
    buffer[pos + 1] = 0x80;
    @memset(buffer[pos + 2 ..][0..6], 0);
    pos += 8;
    // EUI-64 from MAC
    buffer[pos] = mac[0] ^ 0x02;
    buffer[pos + 1] = mac[1];
    buffer[pos + 2] = mac[2];
    buffer[pos + 3] = 0xFF;
    buffer[pos + 4] = 0xFE;
    buffer[pos + 5] = mac[3];
    buffer[pos + 6] = mac[4];
    buffer[pos + 7] = mac[5];
    pos += 8;

    // Destination: ff02::2 (all-routers)
    buffer[pos] = 0xFF;
    buffer[pos + 1] = 0x02;
    @memset(buffer[pos + 2 ..][0..13], 0);
    buffer[pos + 15] = 0x02;
    pos += 16;

    // ICMPv6 Router Solicitation
    buffer[pos] = 133; // Type
    buffer[pos + 1] = 0; // Code
    buffer[pos + 2] = 0x00;
    buffer[pos + 3] = 0x00; // Checksum placeholder
    @memset(buffer[pos + 4 ..][0..4], 0); // Reserved
    pos += 8;

    return pos;
}

/// Build IPv6 Neighbor Advertisement (ICMPv6 type 136)
pub fn buildNeighborAdvertisement(mac: [6]u8, buffer: []u8) !usize {
    if (buffer.len < 78) return error.BufferTooSmall;

    var pos: usize = 0;

    // Ethernet header
    // Destination: all-nodes multicast (33:33:00:00:00:01)
    buffer[pos] = 0x33;
    buffer[pos + 1] = 0x33;
    @memset(buffer[pos + 2 ..][0..3], 0);
    buffer[pos + 5] = 0x01;
    pos += 6;
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;
    buffer[pos] = 0x86;
    buffer[pos + 1] = 0xDD;
    pos += 2;

    // IPv6 header
    buffer[pos] = 0x60;
    buffer[pos + 1] = 0x00;
    buffer[pos + 2] = 0x00;
    buffer[pos + 3] = 0x00;
    pos += 4;

    // Payload length: 24
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x18;
    pos += 2;

    buffer[pos] = 58; // ICMPv6
    pos += 1;
    buffer[pos] = 255;
    pos += 1;

    // Source: link-local
    buffer[pos] = 0xFE;
    buffer[pos + 1] = 0x80;
    @memset(buffer[pos + 2 ..][0..6], 0);
    pos += 8;
    buffer[pos] = mac[0] ^ 0x02;
    buffer[pos + 1] = mac[1];
    buffer[pos + 2] = mac[2];
    buffer[pos + 3] = 0xFF;
    buffer[pos + 4] = 0xFE;
    buffer[pos + 5] = mac[3];
    buffer[pos + 6] = mac[4];
    buffer[pos + 7] = mac[5];
    pos += 8;

    // Destination: ff02::1
    buffer[pos] = 0xFF;
    buffer[pos + 1] = 0x02;
    @memset(buffer[pos + 2 ..][0..13], 0);
    buffer[pos + 15] = 0x01;
    pos += 16;

    // ICMPv6 Neighbor Advertisement
    buffer[pos] = 136; // Type
    buffer[pos + 1] = 0;
    buffer[pos + 2] = 0x00;
    buffer[pos + 3] = 0x00; // Checksum
    @memset(buffer[pos + 4 ..][0..4], 0); // Flags
    pos += 8;

    // Target address
    buffer[pos] = 0xFE;
    buffer[pos + 1] = 0x80;
    @memset(buffer[pos + 2 ..][0..6], 0);
    pos += 8;
    buffer[pos] = mac[0] ^ 0x02;
    buffer[pos + 1] = mac[1];
    buffer[pos + 2] = mac[2];
    buffer[pos + 3] = 0xFF;
    buffer[pos + 4] = 0xFE;
    buffer[pos + 5] = mac[3];
    buffer[pos + 6] = mac[4];
    buffer[pos + 7] = mac[5];
    pos += 8;

    return pos;
}

// ============================================
// Helper Functions
// ============================================

/// Generate MAC address matching SoftEther format (02:00:5E:xx:xx:xx)
fn generateMac() [6]u8 {
    const rand_bytes = generateRandomBytes(3);
    return .{
        0x02, // Locally administered
        0x00,
        0x5E, // SoftEther prefix
        rand_bytes[0],
        rand_bytes[1],
        rand_bytes[2],
    };
}

/// Generate random DHCP transaction ID
fn generateXid() u32 {
    const rand_bytes = generateRandomBytes(4);
    return (@as(u32, rand_bytes[0]) << 24) |
        (@as(u32, rand_bytes[1]) << 16) |
        (@as(u32, rand_bytes[2]) << 8) |
        rand_bytes[3];
}

/// Generate random bytes using system PRNG
fn generateRandomBytes(comptime n: usize) [n]u8 {
    var buf: [n]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return buf;
}

// ============================================
// Tests
// ============================================

test "MAC address generation" {
    const mac = generateMac();
    try std.testing.expectEqual(@as(u8, 0x02), mac[0]);
    try std.testing.expectEqual(@as(u8, 0x00), mac[1]);
    try std.testing.expectEqual(@as(u8, 0x5E), mac[2]);
}

test "XID generation is random" {
    const xid1 = generateXid();
    const xid2 = generateXid();
    // Statistically unlikely to be equal
    try std.testing.expect(xid1 != xid2);
}

test "Gratuitous ARP packet building" {
    var buffer: [64]u8 = undefined;
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const ip: u32 = 0xC0A80101; // 192.168.1.1

    const size = try buildGratuitousArp(mac, ip, &buffer);

    try std.testing.expectEqual(@as(usize, 42), size);
    // Check broadcast destination
    try std.testing.expectEqual(@as(u8, 0xFF), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), buffer[5]);
    // Check source MAC
    try std.testing.expectEqual(@as(u8, 0x02), buffer[6]);
    // Check EtherType (ARP)
    try std.testing.expectEqual(@as(u8, 0x08), buffer[12]);
    try std.testing.expectEqual(@as(u8, 0x06), buffer[13]);
}

test "ARP Reply packet building" {
    var buffer: [64]u8 = undefined;
    const my_mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const target_mac = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const my_ip: u32 = 0xC0A80101;
    const target_ip: u32 = 0xC0A80102;

    const size = try buildArpReply(my_mac, my_ip, target_mac, target_ip, &buffer);

    try std.testing.expectEqual(@as(usize, 42), size);
    // Check destination is target MAC
    try std.testing.expectEqual(@as(u8, 0xAA), buffer[0]);
    // Check opcode is Reply (2)
    try std.testing.expectEqual(@as(u8, 0x02), buffer[21]);
}

test "ARP Request packet building" {
    var buffer: [64]u8 = undefined;
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const my_ip: u32 = 0xC0A80101;
    const target_ip: u32 = 0xC0A80102;

    const size = try buildArpRequest(mac, my_ip, target_ip, &buffer);

    try std.testing.expectEqual(@as(usize, 42), size);
    // Check broadcast destination
    try std.testing.expectEqual(@as(u8, 0xFF), buffer[0]);
    // Check opcode is Request (1)
    try std.testing.expectEqual(@as(u8, 0x01), buffer[21]);
}

test "Router Solicitation building" {
    var buffer: [128]u8 = undefined;
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };

    const size = try buildRouterSolicitation(mac, &buffer);

    try std.testing.expectEqual(@as(usize, 62), size);
    // Check IPv6 all-routers multicast
    try std.testing.expectEqual(@as(u8, 0x33), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0x33), buffer[1]);
    // Check ICMPv6 type (133 = Router Solicitation)
    try std.testing.expectEqual(@as(u8, 133), buffer[54]);
}

test "Neighbor Advertisement building" {
    var buffer: [128]u8 = undefined;
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };

    const size = try buildNeighborAdvertisement(mac, &buffer);

    try std.testing.expectEqual(@as(usize, 78), size);
    // Check IPv6 all-nodes multicast
    try std.testing.expectEqual(@as(u8, 0x33), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0x01), buffer[5]);
    // Check ICMPv6 type (136 = Neighbor Advertisement)
    try std.testing.expectEqual(@as(u8, 136), buffer[54]);
}

test "IPv6 link-local generation from MAC" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const cfg = Ipv6Config.generateLinkLocal(mac);

    // Check fe80:: prefix
    try std.testing.expectEqual(@as(u8, 0xFE), cfg.address[0]);
    try std.testing.expectEqual(@as(u8, 0x80), cfg.address[1]);
    // Check EUI-64 interface ID
    try std.testing.expectEqual(@as(u8, 0x00), cfg.address[8]); // 0x02 ^ 0x02
    try std.testing.expectEqual(@as(u8, 0xFF), cfg.address[11]);
    try std.testing.expectEqual(@as(u8, 0xFE), cfg.address[12]);
    try std.testing.expect(cfg.configured);
}

test "IPv4 config format" {
    var cfg = Ipv4Config{
        .address = 0xC0A80101, // 192.168.1.1
    };
    const formatted = cfg.formatAddress();
    // Check that it starts with "192"
    try std.testing.expectEqual(@as(u8, '1'), formatted[0]);
    try std.testing.expectEqual(@as(u8, '9'), formatted[1]);
    try std.testing.expectEqual(@as(u8, '2'), formatted[2]);
}

test "Packet queue operations" {
    const allocator = std.testing.allocator;
    var queue = PacketQueue.init(allocator, 10);
    defer queue.deinit();

    // Create and push packet
    const pkt = try TunPacket.fromData(allocator, "test data");
    try queue.push(pkt);

    try std.testing.expectEqual(@as(usize, 1), queue.len());

    // Pop packet
    const popped = queue.pop();
    try std.testing.expect(popped != null);
    try std.testing.expectEqualStrings("test data", popped.?.data);
    popped.?.deinit();

    try std.testing.expectEqual(@as(usize, 0), queue.len());
}

test "TunPacket lifecycle" {
    const allocator = std.testing.allocator;

    // Test fromData
    const pkt = try TunPacket.fromData(allocator, "hello world");
    defer pkt.deinit();

    try std.testing.expectEqualStrings("hello world", pkt.data);
    try std.testing.expectEqual(@as(usize, 11), pkt.size);
}

test "TunStats default values" {
    const stats = TunStats{};
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.packets_received);
    try std.testing.expectEqual(@as(u64, 0), stats.errors);
}

test "DhcpState transitions" {
    var state = DhcpState.init;
    try std.testing.expectEqual(DhcpState.init, state);

    state = .discover_sent;
    try std.testing.expectEqual(DhcpState.discover_sent, state);

    state = .configured;
    try std.testing.expectEqual(DhcpState.configured, state);
}

// Platform-specific test (only runs on macOS)
test "UtunDevice constants" {
    try std.testing.expectEqual(@as(u8, 32), AF_SYSTEM);
    try std.testing.expectEqual(@as(u16, 2), AF_SYS_CONTROL);
    try std.testing.expectEqual(@as(u8, 2), SYSPROTO_CONTROL);
    try std.testing.expectEqual(@as(u32, 0xC0644E03), CTLIOCGINFO);
}
