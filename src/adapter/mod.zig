// SoftEther VPN Client - Virtual Adapter Module
// Network adapter management

const std = @import("std");
const log = std.log.scoped(.adapter_tun);
const builtin = @import("builtin");

// Android is detected as linux+android ABI; it uses an OS-provided fd from VpnService
// rather than opening /dev/net/tun directly (which is not permitted to apps).
const is_android = builtin.os.tag == .linux and (builtin.abi == .android or builtin.abi == .androideabi);

// Re-export submodules
pub const utun = @import("utun.zig");
pub const tun_linux = @import("tun_linux.zig");
pub const tap_windows = @import("tap_windows.zig");
pub const fd_adapter = @import("fd_adapter.zig");
pub const utun_escalate = @import("utun_escalate.zig");
pub const route = @import("route.zig");
pub const dhcp = @import("dhcp.zig");
pub const wrapper = @import("wrapper.zig");

// Wrapper
pub const AdapterWrapper = wrapper.AdapterWrapper;

// Platform-specific adapter types
pub const UtunDevice = utun.UtunDevice;
pub const TunLinuxDevice = tun_linux.TunLinuxDevice;
pub const TapWindowsDevice = tap_windows.TapWindowsDevice;
pub const FdAdapter = fd_adapter.FdAdapter;
pub const UtunError = utun.UtunError;
pub const TunLinuxError = tun_linux.TunLinuxError;
pub const TapWindowsError = tap_windows.TapWindowsError;
pub const FdAdapterError = fd_adapter.FdAdapterError;

// Common types (re-exported from platform-specific modules)
pub const TunPacket = utun.TunPacket;
pub const TunStats = if (is_android) fd_adapter.TunStats else if (builtin.os.tag == .linux) tun_linux.TunStats else if (builtin.os.tag == .windows) tap_windows.TunStats else utun.TunStats;
pub const DhcpState = utun.DhcpState;
pub const Ipv4Config = utun.Ipv4Config;
pub const Ipv6Config = utun.Ipv6Config;
pub const PacketQueue = utun.PacketQueue;

// Platform-agnostic device type alias
// iOS and Android use FdAdapter (OS-provided tunnel fd)
pub const PlatformDevice = if (is_android)
    FdAdapter
else if (builtin.os.tag == .linux)
    TunLinuxDevice
else if (builtin.os.tag == .windows)
    TapWindowsDevice
else if (builtin.os.tag == .ios)
    FdAdapter
else
    UtunDevice; // macOS

// Route types
pub const Route = route.Route;
pub const RouteError = route.RouteError;
pub const RouteFlags = route.RouteFlags;
pub const RouteManager = route.RouteManager;
pub const RoutingState = route.RoutingState;
pub const NetworkCidr = route.NetworkCidr;

// DHCP types
pub const DhcpMessageType = dhcp.DhcpMessageType;
pub const DhcpOption = dhcp.DhcpOption;
pub const DhcpConfig = dhcp.DhcpConfig;

// Constants - use platform-appropriate values
pub const TUN_MTU = if (is_android) fd_adapter.TUN_MTU else if (builtin.os.tag == .linux) tun_linux.TUN_MTU else if (builtin.os.tag == .windows) tap_windows.TUN_MTU else utun.TUN_MTU;
pub const MAX_PACKET_SIZE = if (is_android) fd_adapter.MAX_PACKET_SIZE else if (builtin.os.tag == .linux) tun_linux.MAX_PACKET_SIZE else if (builtin.os.tag == .windows) tap_windows.MAX_PACKET_SIZE else utun.MAX_PACKET_SIZE;
pub const RECV_QUEUE_MAX = if (is_android) fd_adapter.RECV_QUEUE_MAX else if (builtin.os.tag == .linux) tun_linux.RECV_QUEUE_MAX else if (builtin.os.tag == .windows) tap_windows.RECV_QUEUE_MAX else utun.RECV_QUEUE_MAX;

// Packet building functions
pub const buildGratuitousArp = utun.buildGratuitousArp;
pub const buildArpReply = utun.buildArpReply;
pub const buildArpRequest = utun.buildArpRequest;
pub const buildRouterSolicitation = utun.buildRouterSolicitation;
pub const buildNeighborAdvertisement = utun.buildNeighborAdvertisement;
pub const buildDhcpDiscover = dhcp.buildDhcpDiscover;
pub const buildDhcpRequest = dhcp.buildDhcpRequest;
pub const buildDhcpInform = dhcp.buildDhcpInform;
pub const parseDhcpResponse = dhcp.parseDhcpResponse;
pub const parseArpRequest = dhcp.parseArpRequest;
pub const parseArpReply = dhcp.parseArpReply;

// DHCPv6 ports
pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;

/// Build a DHCPv6 Ethernet frame by wrapping a raw DHCPv6 payload
/// in Ethernet + IPv6 + UDP headers.
/// mac: client MAC address
/// dhcpv6_payload: the raw DHCPv6 message (msg_type + xid + options)
/// buffer: output buffer (must be >= 14 + 40 + 8 + dhcpv6_payload.len)
/// Returns total frame length.
pub fn buildDhcpv6Frame(mac: [6]u8, dhcpv6_payload: []const u8, buffer: []u8) !usize {
    const total = 14 + 40 + 8 + dhcpv6_payload.len;
    if (buffer.len < total) return error.BufferTooSmall;

    var pos: usize = 0;

    // === Ethernet Header (14 bytes) ===
    // Destination: IPv6 multicast MAC for ff02::1:2
    buffer[pos] = 0x33;
    buffer[pos + 1] = 0x33;
    buffer[pos + 2] = 0x00;
    buffer[pos + 3] = 0x01;
    buffer[pos + 4] = 0x00;
    buffer[pos + 5] = 0x02;
    pos += 6;
    // Source: our MAC
    @memcpy(buffer[pos..][0..6], &mac);
    pos += 6;
    // EtherType: IPv6 (0x86DD)
    buffer[pos] = 0x86;
    buffer[pos + 1] = 0xDD;
    pos += 2;

    // === IPv6 Header (40 bytes) ===
    // Version (6), Traffic Class (0), Flow Label (0)
    buffer[pos] = 0x60;
    buffer[pos + 1] = 0x00;
    buffer[pos + 2] = 0x00;
    buffer[pos + 3] = 0x00;
    pos += 4;

    // Payload length: UDP header (8) + DHCPv6 payload
    const payload_len: u16 = @intCast(8 + dhcpv6_payload.len);
    buffer[pos] = @intCast((payload_len >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(payload_len & 0xFF);
    pos += 2;

    // Next Header: UDP (17)
    buffer[pos] = 17;
    pos += 1;

    // Hop Limit: 1 (link-local scope)
    buffer[pos] = 1;
    pos += 1;

    // Source Address: :: (unspecified — we don't have an IPv6 address yet)
    @memset(buffer[pos..][0..16], 0);
    pos += 16;

    // Destination Address: ff02::1:2 (All DHCPv6 Relay Agents and Servers)
    buffer[pos] = 0xFF;
    buffer[pos + 1] = 0x02;
    @memset(buffer[pos + 2 ..][0..13], 0);
    buffer[pos + 15] = 0x02;
    pos += 16;

    // === UDP Header (8 bytes) ===
    // Source port: 546 (DHCPv6 client)
    buffer[pos] = @intCast((DHCPV6_CLIENT_PORT >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(DHCPV6_CLIENT_PORT & 0xFF);
    pos += 2;
    // Destination port: 547 (DHCPv6 server)
    buffer[pos] = @intCast((DHCPV6_SERVER_PORT >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(DHCPV6_SERVER_PORT & 0xFF);
    pos += 2;
    // UDP length
    buffer[pos] = @intCast((payload_len >> 8) & 0xFF);
    buffer[pos + 1] = @intCast(payload_len & 0xFF);
    pos += 2;
    // UDP checksum (0 for now — SoftEther's L2 bridge doesn't validate)
    buffer[pos] = 0x00;
    buffer[pos + 1] = 0x00;
    pos += 2;

    // === DHCPv6 Payload ===
    @memcpy(buffer[pos..][0..dhcpv6_payload.len], dhcpv6_payload);
    pos += dhcpv6_payload.len;

    return pos;
}

/// Parse a DHCPv6 Reply from an Ethernet frame.
/// Returns the DHCPv6 message payload if the frame is a valid DHCPv6 Reply,
/// or null if not.
pub fn parseDhcpv6Reply(data: []const u8) ?[]const u8 {
    if (data.len < 14 + 40 + 8 + 4) return null; // min: eth + ipv6 + udp + dhcpv6 header

    // Check EtherType: IPv6 (0x86DD)
    if (data[12] != 0x86 or data[13] != 0xDD) return null;

    // Verify IPv6 next header is UDP (17)
    if (data[14 + 6] != 17) return null;

    // Verify UDP destination port is 546 (client)
    const udp_start = 14 + 40;
    const dst_port = (@as(u16, data[udp_start + 2]) << 8) | data[udp_start + 3];
    if (dst_port != DHCPV6_CLIENT_PORT) return null;

    // Extract DHCPv6 message type
    const dhcpv6_start = udp_start + 8;
    const msg_type = data[dhcpv6_start];

    // Only return Reply (7) messages
    if (msg_type != 7) return null;

    return data[dhcpv6_start..];
}

// Route functions
pub const parseIpv4 = route.parseIpv4;
pub const formatIpv4 = route.formatIpv4;
pub const netmaskToPrefix = route.netmaskToPrefix;
pub const prefixToNetmask = route.prefixToNetmask;
pub const getDefaultGateway = route.getDefaultGateway;
pub const addRoute = route.addRoute;
pub const addHostRoute = route.addHostRoute;
pub const deleteDefaultRoute = route.deleteDefaultRoute;
pub const deleteRoute = route.deleteRoute;
pub const configureDns = route.configureDns;
pub const clearDns = route.clearDns;

/// Virtual adapter state combining utun device with routing
pub const VirtualAdapter = struct {
    allocator: std.mem.Allocator,
    device: ?*PlatformDevice,
    routes: RouteManager,

    // DHCP state
    dhcp_xid: u32,
    dhcp_state: DhcpState,
    dhcp_config: DhcpConfig,
    dhcp_retry_count: u32,
    last_dhcp_time: i64,

    // ARP state
    gateway_mac: ?[6]u8,
    need_arp_reply: bool,
    arp_reply_target_mac: [6]u8,
    arp_reply_target_ip: u32,

    pub fn init(allocator: std.mem.Allocator) VirtualAdapter {
        var rand_buf: [4]u8 = undefined;
        std.crypto.random.bytes(&rand_buf);
        const xid = (@as(u32, rand_buf[0]) << 24) |
            (@as(u32, rand_buf[1]) << 16) |
            (@as(u32, rand_buf[2]) << 8) |
            rand_buf[3];

        return .{
            .allocator = allocator,
            .device = null,
            .routes = RouteManager.init(allocator),
            .dhcp_xid = xid,
            .dhcp_state = .init,
            .dhcp_config = .{},
            .dhcp_retry_count = 0,
            .last_dhcp_time = 0,
            .gateway_mac = null,
            .need_arp_reply = false,
            .arp_reply_target_mac = [_]u8{0} ** 6,
            .arp_reply_target_ip = 0,
        };
    }

    pub fn deinit(self: *VirtualAdapter) void {
        self.close();
    }

    /// Open the virtual adapter (platform-specific)
    pub fn open(self: *VirtualAdapter) !void {
        if (self.device != null) return;

        if (is_android) {
            return error.UnsupportedPlatform; // Android must use openWithFd()
        } else if (builtin.os.tag == .linux) {
            self.device = TunLinuxDevice.open(self.allocator) catch |err| {
                std.log.err("Failed to open Linux TUN device: {}", .{err});
                return err;
            };
            try self.device.?.configureTemporary();
        } else if (builtin.os.tag == .macos) {
            self.device = UtunDevice.open(self.allocator) catch |direct_err| {
                // Direct utun creation failed (likely EPERM) — try privilege escalation
                std.log.warn("Direct utun open failed ({}) — attempting privilege escalation...", .{direct_err});
                const escalated = utun_escalate.escalatedUtunOpen(self.allocator) catch |esc_err| {
                    std.log.err("Privilege escalation also failed: esc_err={}, returning direct_err={}", .{ esc_err, direct_err });
                    return direct_err;
                };
                self.device = UtunDevice.fromFd(self.allocator, escalated.fd, escalated.device_name, escalated.device_name_len) catch |fd_err| {
                    std.log.err("Failed to wrap escalated utun fd: {}", .{fd_err});
                    return fd_err;
                };
                // Already configured by helper — skip configureTemporary
                return;
            };
            // Direct utun open succeeded. Still need the privileged command channel
            // so that route add/delete commands run as root during tunnel setup.
            utun_escalate.ensurePrivilegedChannel(self.allocator);
            try self.device.?.configureTemporary();
        } else if (builtin.os.tag == .windows) {
            self.device = TapWindowsDevice.open(self.allocator) catch |err| {
                std.log.err("Failed to open Windows TUN adapter (Wintun): {}", .{err});
                return err;
            };
            try self.device.?.configureTemporary();
        } else if (builtin.os.tag == .ios) {
            return error.UnsupportedPlatform; // iOS must use openWithFd()
        } else {
            return error.UnsupportedPlatform;
        }
    }

    /// Open the virtual adapter with an externally-provided file descriptor.
    /// Used on mobile (iOS/Android) where the OS creates the TUN device.
    /// Only available when PlatformDevice is FdAdapter.
    pub fn openWithFd(self: *VirtualAdapter, fd: i32, name: []const u8) !void {
        if (PlatformDevice != FdAdapter) {
            return error.UnsupportedPlatform;
        }
        if (self.device != null) return;

        self.device = FdAdapter.initWithFd(self.allocator, fd, name) catch |err| {
            std.log.err("Failed to wrap external fd={d}: {}", .{ fd, err });
            return err;
        };
    }

    /// Close the virtual adapter and restore routing
    pub fn close(self: *VirtualAdapter) void {
        // Restore original routes
        self.routes.restore() catch {};

        // Close the privileged command channel (helper process exits)
        if (builtin.os.tag == .macos) {
            utun_escalate.closePrivilegedChannel();
        }

        if (self.device) |dev| {
            dev.close();
            self.device = null;
        }

        self.dhcp_state = .init;
    }

    /// Check if adapter is open
    pub fn isOpen(self: *const VirtualAdapter) bool {
        return self.device != null and self.device.?.isOpen();
    }

    /// Get device name
    pub fn getName(self: *const VirtualAdapter) ?[]const u8 {
        if (self.device) |dev| {
            return dev.getName();
        }
        return null;
    }

    /// Get MAC address
    pub fn getMac(self: *const VirtualAdapter) ?[6]u8 {
        if (self.device) |dev| {
            return dev.getMac();
        }
        return null;
    }

    /// Replace the wrapped file descriptor (mobile only). Used after DHCP
    /// completes and the platform has re-created the TUN with the assigned IP.
    pub fn replaceFd(self: *VirtualAdapter, new_fd: i32) !void {
        if (PlatformDevice != FdAdapter) return error.UnsupportedPlatform;
        const dev = self.device orelse return error.DeviceNotOpen;
        try dev.replaceFd(new_fd);
    }

    /// Read a packet from the adapter
    pub fn read(self: *VirtualAdapter, buffer: []u8) !?usize {
        if (self.device) |dev| {
            return dev.read(buffer);
        }
        if (builtin.os.tag == .linux) {
            return TunLinuxError.DeviceNotOpen;
        } else if (builtin.os.tag == .windows) {
            return TapWindowsError.DeviceNotOpen;
        } else {
            return UtunError.DeviceNotOpen;
        }
    }

    /// Write a packet to the adapter
    pub fn write(self: *VirtualAdapter, data: []const u8) !usize {
        if (self.device) |dev| {
            return dev.write(data);
        }
        if (builtin.os.tag == .linux) {
            return TunLinuxError.DeviceNotOpen;
        } else if (builtin.os.tag == .windows) {
            return TapWindowsError.DeviceNotOpen;
        } else {
            return UtunError.DeviceNotOpen;
        }
    }

    /// Configure full-tunnel VPN routing
    pub fn configureFullTunnel(self: *VirtualAdapter, vpn_gateway: u32, vpn_server: u32) !void {
        const dev = self.device orelse {
            if (builtin.os.tag == .linux) {
                return TunLinuxError.DeviceNotOpen;
            } else if (builtin.os.tag == .windows) {
                return TapWindowsError.DeviceNotOpen;
            } else {
                return UtunError.DeviceNotOpen;
            }
        };
        try self.routes.configureFullTunnel(vpn_gateway, vpn_server, dev.getName());
    }

    /// Configure split-tunnel VPN routing (only specified networks through VPN).
    /// `routes_str` is a newline-separated list of CIDR notations.
    pub fn configureSplitTunnel(self: *VirtualAdapter, vpn_gateway: u32, routes_str: []const u8) !void {
        _ = self.device orelse {
            if (builtin.os.tag == .linux) {
                return TunLinuxError.DeviceNotOpen;
            } else if (builtin.os.tag == .windows) {
                return TapWindowsError.DeviceNotOpen;
            } else {
                return UtunError.DeviceNotOpen;
            }
        };
        try self.routes.configureSplitTunnel(vpn_gateway, routes_str);
    }

    /// Add custom IPv6 split-tunnel routes through a gateway.
    /// `routes_str` is a newline-separated list of IPv6 CIDR notations.
    pub fn addIpv6Routes(self: *VirtualAdapter, gateway: []const u8, routes_str: []const u8) !void {
        _ = self.device orelse {
            if (builtin.os.tag == .linux) {
                return TunLinuxError.DeviceNotOpen;
            } else if (builtin.os.tag == .windows) {
                return TapWindowsError.DeviceNotOpen;
            } else {
                return UtunError.DeviceNotOpen;
            }
        };
        try route.addIpv6Routes(gateway, routes_str);
    }

    /// Configure IPv6 on the tunnel interface and add IPv6 routes.
    ///
    /// Platform support:
    ///   - macOS:    ✓ utun (ifconfig inet6)
    ///   - Linux:    ✓ TUN  (ip -6 addr add)
    ///   - Windows:  ✗ TAP  (netsh interface ipv6 or IP Helper API — not yet ported)
    pub fn configureIpv6(self: *VirtualAdapter, address: [16]u8, prefix_len: u8, gateway: []const u8) !void {
        const dev = self.device orelse return UtunError.DeviceNotOpen;

        // Delegate to device-specific IPv6 configuration (macOS utun, Linux TUN).
        // Windows TAP does not yet implement configureIpv6; IPv6 will be
        // unreachable on Windows until the IP Helper API is integrated.
        if (builtin.os.tag == .macos or builtin.os.tag == .linux) {
            if (@hasDecl(@TypeOf(dev.*), "configureIpv6")) {
                try dev.configureIpv6(address, prefix_len);
            } else {
                std.log.info("Device does not support IPv6 configuration (os={s})", .{@tagName(builtin.os.tag)});
            }
        } else {
            std.log.info("IPv6 interface configuration not implemented for {s}", .{@tagName(builtin.os.tag)});
        }

        // Add IPv6 default route through gateway
        const route_mod = @import("route.zig");
        if (gateway.len > 0) {
            route_mod.addIpv6DefaultRoute(gateway) catch |err| {
                std.log.warn("Failed to add IPv6 default route: {}", .{err});
            };
        }
    }

    /// Get traffic statistics
    pub fn getStats(self: *const VirtualAdapter) ?TunStats {
        if (self.device) |dev| {
            return dev.getStats();
        }
        return null;
    }

    /// Get total dropped packet count from the device's ring buffer.
    /// Returns 0 for non-FdAdapter devices (desktop utun/tun have no ring).
    pub fn getTxDrops(self: *const VirtualAdapter) u64 {
        const device = self.device orelse return 0;
        if (@hasDecl(@TypeOf(device.*), "getTxDrops")) {
            return device.getTxDrops();
        }
        return 0;
    }

    /// Get DHCP configuration
    pub fn getDhcpConfig(self: *const VirtualAdapter) ?DhcpConfig {
        if (self.dhcp_config.isValid()) {
            return self.dhcp_config;
        }
        return null;
    }

    /// Check if DHCP is complete
    pub fn isDhcpComplete(self: *const VirtualAdapter) bool {
        return self.dhcp_state == .configured;
    }

    /// Build initial packets for VPN connection (DHCP, ARP, IPv6)
    pub fn buildInitialPackets(self: *VirtualAdapter, packets: *std.ArrayList([]u8)) !void {
        const mac = self.getMac() orelse return;

        // 1. Gratuitous ARP
        var garp_buf: [64]u8 = undefined;
        const garp_size = try buildGratuitousArp(mac, 0, &garp_buf);
        const garp = try self.allocator.dupe(u8, garp_buf[0..garp_size]);
        try packets.append(garp);

        // 2. IPv6 Neighbor Advertisement
        var na_buf: [128]u8 = undefined;
        const na_size = try buildNeighborAdvertisement(mac, &na_buf);
        const na = try self.allocator.dupe(u8, na_buf[0..na_size]);
        try packets.append(na);

        // 3. IPv6 Router Solicitation
        var rs_buf: [128]u8 = undefined;
        const rs_size = try buildRouterSolicitation(mac, &rs_buf);
        const rs = try self.allocator.dupe(u8, rs_buf[0..rs_size]);
        try packets.append(rs);

        // 4. DHCP Discover
        var dhcp_buf: [512]u8 = undefined;
        const dhcp_size = try buildDhcpDiscover(mac, self.dhcp_xid, &dhcp_buf);
        const dhcp_pkt = try self.allocator.dupe(u8, dhcp_buf[0..dhcp_size]);
        try packets.append(dhcp_pkt);

        self.dhcp_state = .discover_sent;
        self.last_dhcp_time = std.time.milliTimestamp();
    }

    /// Process incoming packet and handle DHCP/ARP
    pub fn processIncomingPacket(self: *VirtualAdapter, data: []const u8) !?[]u8 {
        const mac = self.getMac() orelse return null;

        // Check for DHCP response
        if (self.dhcp_state != .configured) {
            if (try parseDhcpResponse(data, self.dhcp_xid)) |response| {
                if (response.msg_type == .offer and self.dhcp_state == .discover_sent) {
                    // Got offer, send request
                    self.dhcp_config = response.config;
                    self.dhcp_state = .offer_received;

                    var req_buf: [512]u8 = undefined;
                    const req_size = try buildDhcpRequest(
                        mac,
                        self.dhcp_xid,
                        response.config.ip_address,
                        response.config.server_id,
                        &req_buf,
                    );

                    self.dhcp_state = .request_sent;
                    return try self.allocator.dupe(u8, req_buf[0..req_size]);
                } else if (response.msg_type == .ack and self.dhcp_state == .request_sent) {
                    // Got ACK, configure interface
                    self.dhcp_config = response.config;
                    self.dhcp_state = .configured;

                    if (self.device) |dev| {
                        try dev.configure(
                            response.config.ip_address,
                            response.config.subnet_mask,
                            response.config.gateway,
                        );
                    }
                }
            }
        }

        // Check for ARP request for our IP
        if (self.dhcp_config.ip_address != 0) {
            if (parseArpRequest(data, self.dhcp_config.ip_address)) |arp_req| {
                // Build ARP reply
                var reply_buf: [64]u8 = undefined;
                const reply_size = try buildArpReply(
                    mac,
                    self.dhcp_config.ip_address,
                    arp_req.sender_mac,
                    arp_req.sender_ip,
                    &reply_buf,
                );
                return try self.allocator.dupe(u8, reply_buf[0..reply_size]);
            }
        }

        // Check for ARP reply from gateway
        if (self.gateway_mac == null and self.dhcp_config.gateway != 0) {
            if (parseArpReply(data, self.dhcp_config.gateway)) |gw_mac| {
                self.gateway_mac = gw_mac;
            }
        }

        return null;
    }
};

// ============================================
// Tests
// ============================================

test "VirtualAdapter initialization" {
    var adapter = VirtualAdapter.init(std.testing.allocator);
    defer adapter.deinit();

    try std.testing.expect(!adapter.isOpen());
    try std.testing.expectEqual(DhcpState.init, adapter.dhcp_state);
    try std.testing.expect(adapter.dhcp_xid != 0);
}

test "VirtualAdapter MAC before open" {
    var adapter = VirtualAdapter.init(std.testing.allocator);
    defer adapter.deinit();

    try std.testing.expect(adapter.getMac() == null);
}

test "VirtualAdapter name before open" {
    var adapter = VirtualAdapter.init(std.testing.allocator);
    defer adapter.deinit();

    try std.testing.expect(adapter.getName() == null);
}

test "VirtualAdapter stats before open" {
    var adapter = VirtualAdapter.init(std.testing.allocator);
    defer adapter.deinit();

    try std.testing.expect(adapter.getStats() == null);
}

test "VirtualAdapter DHCP config before completion" {
    var adapter = VirtualAdapter.init(std.testing.allocator);
    defer adapter.deinit();

    try std.testing.expect(adapter.getDhcpConfig() == null);
    try std.testing.expect(!adapter.isDhcpComplete());
}

test "Module exports" {
    // Test that all expected types are exported
    _ = UtunDevice;
    _ = TunPacket;
    _ = RouteManager;
    _ = DhcpConfig;
    _ = VirtualAdapter;
}
