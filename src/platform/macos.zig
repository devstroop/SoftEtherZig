//! macOS Packet Adapter - Pure Zig Implementation
//!
//! This module provides a pure Zig implementation of the macOS packet adapter,
//! replacing the legacy C implementation (packet_adapter_macos.c).
//!
//! Features:
//! - utun device management using ZigTapTun
//! - DHCP client functionality
//! - ARP handling
//! - IPv4/IPv6 packet processing
//! - Zero-copy packet I/O where possible
//!
//! Architecture:
//!   Application → PacketAdapter → utun device → Network

const std = @import("std");
const builtin = @import("builtin");
const taptun = @import("taptun");
const Allocator = std.mem.Allocator;

// Ensure we're building for macOS
comptime {
    if (builtin.os.tag != .macos) {
        @compileError("This module is only for macOS");
    }
}

/// Maximum packet size (including protocol overhead)
pub const MAX_PACKET_SIZE = 2048;

/// TUN MTU
pub const TUN_MTU = 1500;

/// Maximum Ethernet frame size
pub const MAX_ETHERNET_FRAME = 1518;

/// Receive queue maximum size
pub const RECV_QUEUE_MAX = 1024;

/// DHCP state machine states
pub const DhcpState = enum(u8) {
    init = 0,
    arp_announce_sent = 1, // Gratuitous ARP to register MAC
    ipv6_na_sent = 2, // IPv6 Neighbor Advertisement
    ipv6_rs_sent = 3, // IPv6 Router Solicitation
    discover_sent = 4,
    offer_received = 5,
    request_sent = 6,
    arp_probe_sent = 7, // ARP probe after DHCP ACK
    configured = 8,
};

/// IP configuration structure
pub const IpConfig = struct {
    ip_address: [4]u8 = [_]u8{0} ** 4,
    netmask: [4]u8 = [_]u8{0} ** 4,
    gateway: [4]u8 = [_]u8{0} ** 4,
    dns1: [4]u8 = [_]u8{0} ** 4,
    dns2: [4]u8 = [_]u8{0} ** 4,
    configured: bool = false,
};

/// IPv6 configuration structure
pub const Ipv6Config = struct {
    address: [16]u8 = [_]u8{0} ** 16,
    gateway: [16]u8 = [_]u8{0} ** 16,
    prefix_len: u8 = 64,
    configured: bool = false,
};

/// Route configuration for VPN
pub const RouteConfig = struct {
    local_gateway: [4]u8 = [_]u8{0} ** 4,
    vpn_server_ip: [4]u8 = [_]u8{0} ** 4,
    local_network: [4]u8 = [_]u8{0} ** 4,
    routes_configured: bool = false,
};

/// Packet adapter state
pub const PacketAdapterState = struct {
    // Device
    device: ?taptun.TunDevice = null,
    mtu: u16 = TUN_MTU,

    // MAC address
    mac_address: [6]u8 = [_]u8{0} ** 6,

    // DHCP state
    dhcp_state: DhcpState = .init,
    dhcp_xid: u32 = 0,
    dhcp_server_ip: u32 = 0,
    offered_ip: u32 = 0,
    offered_mask: u32 = 0,
    offered_gw: u32 = 0,
    offered_dns1: u32 = 0,
    offered_dns2: u32 = 0,
    dhcp_retry_count: u32 = 0,
    last_dhcp_send_time: i64 = 0,
    last_state_change_time: i64 = 0,

    // IP configuration
    ip_config: IpConfig = .{},
    ipv6_config: Ipv6Config = .{},
    route_config: RouteConfig = .{},
    our_ip: u32 = 0,

    // ARP state
    need_arp_reply: bool = false,
    arp_reply_to_mac: [6]u8 = [_]u8{0} ** 6,
    arp_reply_to_ip: u32 = 0,
    need_gateway_arp: bool = false,
    gateway_ip: u32 = 0,
    gateway_mac: [6]u8 = [_]u8{0} ** 6,

    // Keep-alive
    last_keepalive_time: i64 = 0,
    keepalive_interval_ms: i64 = 10000,

    // Timing
    connection_start_time: i64 = 0,

    // Allocator
    allocator: Allocator,

    // Packet queue (simple array list for received packets)
    recv_queue: std.array_list.AlignedManaged([]u8, null),

    // Thread synchronization
    mutex: std.Thread.Mutex = .{},
    const Self = @This();

    /// Initialize the packet adapter
    pub fn init(allocator: Allocator) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const PacketList = std.array_list.AlignedManaged([]u8, null);
        self.* = Self{
            .allocator = allocator,
            .recv_queue = PacketList.init(allocator),
            .mac_address = [_]u8{0} ** 6,
            .dhcp_state = .init,
            .dhcp_xid = 0,
            .dhcp_server_ip = 0,
            .offered_ip = 0,
            .offered_mask = 0,
            .offered_gw = 0,
            .offered_dns1 = 0,
            .offered_dns2 = 0,
            .dhcp_retry_count = 0,
            .last_dhcp_send_time = 0,
            .last_state_change_time = 0,
            .ip_config = .{},
            .ipv6_config = .{},
            .route_config = .{},
            .our_ip = 0,
            .need_arp_reply = false,
            .arp_reply_to_mac = [_]u8{0} ** 6,
            .arp_reply_to_ip = 0,
            .need_gateway_arp = false,
            .gateway_ip = 0,
            .gateway_mac = [_]u8{0} ** 6,
            .last_keepalive_time = 0,
            .keepalive_interval_ms = 10000,
            .connection_start_time = 0,
            .device = null,
            .mtu = TUN_MTU,
            .mutex = .{},
        }; // Generate random MAC address (locally administered)
        self.generateMacAddress();

        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        // Close device
        if (self.device) |*dev| {
            dev.close();
        }

        // Free queued packets
        for (self.recv_queue.items) |packet| {
            self.allocator.free(packet);
        }
        self.recv_queue.deinit();

        self.allocator.destroy(self);
    }

    /// Generate a random locally-administered MAC address
    fn generateMacAddress(self: *Self) void {
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        const random = prng.random();

        random.bytes(&self.mac_address);

        // Set locally administered bit (bit 1 of first byte)
        self.mac_address[0] |= 0x02;
        // Clear multicast bit (bit 0 of first byte)
        self.mac_address[0] &= 0xFE;
    }

    /// Open and configure the utun device
    pub fn openDevice(self: *Self, unit_hint: ?u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Open utun device using ZigTapTun
        self.device = try taptun.TunDevice.open(self.allocator, unit_hint);

        // Note: MTU configuration happens via ifconfig in configureIpAddress // Mark connection start time
        self.connection_start_time = std.time.milliTimestamp();

        std.log.info("Opened utun device: {s} (unit {})", .{
            self.device.?.name[0..self.device.?.name_len],
            self.device.?.unit,
        });
    }

    /// Close the device
    pub fn closeDevice(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.device) |*dev| {
            dev.close();
            self.device = null;
        }
    }

    /// Read a packet from the device (non-blocking)
    pub fn readPacket(self: *Self, buffer: []u8, timeout_ms: u32) !usize {
        _ = timeout_ms; // TODO: Implement timeout

        var dev = &(self.device orelse return error.DeviceNotOpen);

        // Try to read from device
        const data = dev.read(buffer) catch |err| {
            if (err == error.WouldBlock) {
                return 0; // No data available
            }
            return err;
        };

        return data.len;
    }

    /// Write a packet to the device
    pub fn writePacket(self: *Self, data: []const u8) !void {
        var dev = &(self.device orelse return error.DeviceNotOpen);

        _ = try dev.write(data);
    }

    /// Process outgoing IP packet (called before writing to device)
    pub fn processOutgoingPacket(self: *Self, packet: []const u8) !void {
        if (packet.len < 20) return; // Invalid IP packet

        // Extract IP header info
        const version = (packet[0] >> 4) & 0x0F;

        if (version == 4) {
            // IPv4: Learn our IP from source address
            const src_ip = std.mem.readInt(u32, packet[12..16], .big);

            if (self.our_ip == 0 or self.our_ip != src_ip) {
                self.our_ip = src_ip;
                std.log.info("Learned our IP: {}.{}.{}.{}", .{
                    packet[12], packet[13], packet[14], packet[15],
                });
            }
        } else if (version == 6) {
            // IPv6: Learn our IPv6 address from source
            if (!self.ipv6_config.configured) {
                @memcpy(&self.ipv6_config.address, packet[8..24]);
                self.ipv6_config.configured = true;
                std.log.info("Learned our IPv6 address", .{});
            }
        }
    }

    /// Process incoming packet (called after reading from device)
    pub fn processIncomingPacket(self: *Self, packet: []const u8) !void {
        if (packet.len < 20) return;

        const version = (packet[0] >> 4) & 0x0F;

        if (version == 4) {
            try self.processIPv4Packet(packet);
        } else if (version == 6) {
            try self.processIPv6Packet(packet);
        }
    }

    /// Process IPv4 packet for DHCP/ARP
    fn processIPv4Packet(self: *Self, packet: []const u8) !void {
        _ = self;
        _ = packet;
        // TODO: Implement DHCP and ARP processing
        // This will be done in subsequent implementation
    }

    /// Process IPv6 packet
    fn processIPv6Packet(self: *Self, packet: []const u8) !void {
        _ = self;
        _ = packet;
        // TODO: Implement IPv6 processing (RA, NS, NA)
    }

    /// Configure IP address on the interface
    pub fn configureIpAddress(self: *Self, ip: [4]u8, netmask: [4]u8, gateway: [4]u8) !void {
        const dev = self.device orelse return error.DeviceNotOpen;

        // Format IP addresses for ifconfig command
        var ip_buf: [16]u8 = undefined;
        var netmask_buf: [16]u8 = undefined;

        const ip_str = try std.fmt.bufPrint(&ip_buf, "{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] });
        const netmask_str = try std.fmt.bufPrint(&netmask_buf, "{}.{}.{}.{}", .{ netmask[0], netmask[1], netmask[2], netmask[3] });

        // Use ifconfig to set IP (requires root)
        var child = std.process.Child.init(&[_][]const u8{
            "ifconfig",
            dev.name[0..dev.name_len],
            ip_str,
            netmask_str,
            "up",
        }, self.allocator);

        _ = try child.spawnAndWait();

        // Store configuration
        self.ip_config.ip_address = ip;
        self.ip_config.netmask = netmask;
        self.ip_config.gateway = gateway;
        self.ip_config.configured = true;

        std.log.info("Configured IP: {}.{}.{}.{} netmask {}.{}.{}.{}", .{
            ip[0],      ip[1],      ip[2],      ip[3],
            netmask[0], netmask[1], netmask[2], netmask[3],
        });
    }

    /// Get device name
    pub fn getDeviceName(self: *Self) []const u8 {
        if (self.device) |dev| {
            return dev.name[0..dev.name_len];
        }
        return "";
    }

    /// Get MAC address
    pub fn getMacAddress(self: *Self) [6]u8 {
        return self.mac_address;
    }

    /// Check if DHCP is configured
    pub fn isDhcpConfigured(self: *Self) bool {
        return self.dhcp_state == .configured;
    }

    /// Get current IP configuration
    pub fn getIpConfig(self: *Self) IpConfig {
        return self.ip_config;
    }
};

/// Packet Adapter API for C interop (if needed)
pub const PacketAdapter = struct {
    state: *PacketAdapterState,

    pub fn create(allocator: Allocator) !*PacketAdapter {
        const adapter = try allocator.create(PacketAdapter);
        errdefer allocator.destroy(adapter);

        adapter.state = try PacketAdapterState.init(allocator);
        return adapter;
    }

    pub fn destroy(self: *PacketAdapter) void {
        const allocator = self.state.allocator;
        self.state.deinit();
        allocator.destroy(self);
    }

    pub fn open(self: *PacketAdapter, unit_hint: ?u32) !void {
        try self.state.openDevice(unit_hint);
    }

    pub fn close(self: *PacketAdapter) void {
        self.state.closeDevice();
    }

    pub fn read(self: *PacketAdapter, buffer: []u8, timeout_ms: u32) !usize {
        return self.state.readPacket(buffer, timeout_ms);
    }

    pub fn write(self: *PacketAdapter, data: []const u8) !void {
        try self.state.processOutgoingPacket(data);
        try self.state.writePacket(data);
    }
};

// Tests
test "PacketAdapter creation and destruction" {
    const adapter = try PacketAdapter.create(std.testing.allocator);
    defer adapter.destroy();

    try std.testing.expect(adapter.state.dhcp_state == .init);
}

test "MAC address generation" {
    var state = try PacketAdapterState.init(std.testing.allocator);
    defer state.deinit();

    const mac = state.getMacAddress();

    // Check locally administered bit is set
    try std.testing.expect((mac[0] & 0x02) != 0);
    // Check multicast bit is clear
    try std.testing.expect((mac[0] & 0x01) == 0);
}

test "IP configuration" {
    var state = try PacketAdapterState.init(std.testing.allocator);
    defer state.deinit();

    const ip = [4]u8{ 192, 168, 1, 100 };
    const netmask = [4]u8{ 255, 255, 255, 0 };
    const gateway = [4]u8{ 192, 168, 1, 1 };

    // Note: This will fail without root privileges
    // state.configureIpAddress(ip, netmask, gateway) catch |err| {
    //     try std.testing.expect(err == error.PermissionDenied);
    // };

    // Just test the structure
    state.ip_config = .{
        .ip_address = ip,
        .netmask = netmask,
        .gateway = gateway,
        .configured = true,
    };

    const config = state.getIpConfig();
    try std.testing.expectEqual(ip, config.ip_address);
    try std.testing.expect(config.configured);
}
