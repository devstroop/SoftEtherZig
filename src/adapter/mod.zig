// SoftEther VPN Client - Virtual Adapter Module
// Network adapter management

const std = @import("std");

// Re-export submodules
pub const utun = @import("utun.zig");
pub const route = @import("route.zig");
pub const dhcp = @import("dhcp.zig");

// Main types
pub const UtunDevice = utun.UtunDevice;
pub const UtunError = utun.UtunError;
pub const TunPacket = utun.TunPacket;
pub const TunStats = utun.TunStats;
pub const DhcpState = utun.DhcpState;
pub const Ipv4Config = utun.Ipv4Config;
pub const Ipv6Config = utun.Ipv6Config;
pub const PacketQueue = utun.PacketQueue;

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

// Constants
pub const TUN_MTU = utun.TUN_MTU;
pub const MAX_PACKET_SIZE = utun.MAX_PACKET_SIZE;
pub const RECV_QUEUE_MAX = utun.RECV_QUEUE_MAX;

// Packet building functions
pub const buildGratuitousArp = utun.buildGratuitousArp;
pub const buildArpReply = utun.buildArpReply;
pub const buildArpRequest = utun.buildArpRequest;
pub const buildRouterSolicitation = utun.buildRouterSolicitation;
pub const buildNeighborAdvertisement = utun.buildNeighborAdvertisement;
pub const buildDhcpDiscover = dhcp.buildDhcpDiscover;
pub const buildDhcpRequest = dhcp.buildDhcpRequest;
pub const parseDhcpResponse = dhcp.parseDhcpResponse;
pub const parseArpRequest = dhcp.parseArpRequest;
pub const parseArpReply = dhcp.parseArpReply;

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
    device: ?*UtunDevice,
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

    /// Open the virtual adapter
    pub fn open(self: *VirtualAdapter) !void {
        if (self.device != null) return;

        self.device = try UtunDevice.open(self.allocator);

        // Configure with temporary IP for initial setup
        try self.device.?.configureTemporary();
    }

    /// Close the virtual adapter and restore routing
    pub fn close(self: *VirtualAdapter) void {
        // Restore original routes
        self.routes.restore() catch {};

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

    /// Read a packet from the adapter
    pub fn read(self: *VirtualAdapter, buffer: []u8) !?usize {
        if (self.device) |dev| {
            return dev.read(buffer);
        }
        return UtunError.DeviceNotOpen;
    }

    /// Write a packet to the adapter
    pub fn write(self: *VirtualAdapter, data: []const u8) !usize {
        if (self.device) |dev| {
            return dev.write(data);
        }
        return UtunError.DeviceNotOpen;
    }

    /// Configure full-tunnel VPN routing
    pub fn configureFullTunnel(self: *VirtualAdapter, vpn_gateway: u32, vpn_server: u32) !void {
        const dev = self.device orelse return UtunError.DeviceNotOpen;
        try self.routes.configureFullTunnel(vpn_gateway, vpn_server, dev.getName());
    }

    /// Get traffic statistics
    pub fn getStats(self: *const VirtualAdapter) ?TunStats {
        if (self.device) |dev| {
            return dev.getStats();
        }
        return null;
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
