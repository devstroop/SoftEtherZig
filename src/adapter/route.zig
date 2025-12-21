// SoftEther VPN Zig Client - Route Table Management
// Pure Zig implementation for macOS routing table manipulation

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Route management errors
pub const RouteError = error{
    CommandFailed,
    ParseError,
    NotMacOS,
    NoDefaultGateway,
    InvalidAddress,
    OutOfMemory,
};

/// IPv4 route entry
pub const Route = struct {
    destination: u32,
    netmask: u32,
    gateway: u32,
    interface: [32]u8,
    interface_len: usize,
    flags: RouteFlags,
    metric: u32,

    pub fn getDestinationStr(self: *const Route) [16]u8 {
        return formatIpv4(self.destination);
    }

    pub fn getGatewayStr(self: *const Route) [16]u8 {
        return formatIpv4(self.gateway);
    }

    pub fn getNetmaskStr(self: *const Route) [16]u8 {
        return formatIpv4(self.netmask);
    }

    pub fn getInterface(self: *const Route) []const u8 {
        return self.interface[0..self.interface_len];
    }
};

/// Route flags
pub const RouteFlags = packed struct {
    up: bool = false,
    gateway: bool = false,
    host: bool = false,
    static: bool = false,
    dynamic: bool = false,
    _padding: u3 = 0,
};

/// Routing table state for restoration
pub const RoutingState = struct {
    original_default_gateway: u32,
    vpn_server_ip: u32,
    local_network: u32,
    local_netmask: u32,
    routes_configured: bool,
    device_name: [64]u8,
    device_name_len: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RoutingState {
        return .{
            .original_default_gateway = 0,
            .vpn_server_ip = 0,
            .local_network = 0,
            .local_netmask = 0,
            .routes_configured = false,
            .device_name = [_]u8{0} ** 64,
            .device_name_len = 0,
            .allocator = allocator,
        };
    }

    /// Save current routing state before VPN connection
    pub fn save(self: *RoutingState, vpn_server: u32) !void {
        self.original_default_gateway = try getDefaultGateway(self.allocator);
        self.vpn_server_ip = vpn_server;

        // Calculate local network from gateway (assume /24)
        self.local_network = self.original_default_gateway & 0xFFFFFF00;
        self.local_netmask = 0xFFFFFF00;
    }

    /// Restore original routing state after VPN disconnect
    pub fn restore(self: *RoutingState) !void {
        if (!self.routes_configured) return;

        // Remove VPN routes
        try deleteDefaultRoute();

        // Restore original default route
        if (self.original_default_gateway != 0) {
            try addRoute(0, 0, self.original_default_gateway, null);
        }

        self.routes_configured = false;
    }
};

/// Route manager for VPN routing
pub const RouteManager = struct {
    allocator: std.mem.Allocator,
    state: RoutingState,

    pub fn init(allocator: std.mem.Allocator) RouteManager {
        return .{
            .allocator = allocator,
            .state = RoutingState.init(allocator),
        };
    }

    /// Configure full-tunnel VPN routing (all traffic through VPN)
    pub fn configureFullTunnel(
        self: *RouteManager,
        vpn_gateway: u32,
        vpn_server: u32,
        device_name: []const u8,
    ) !void {
        std.log.info("[ROUTING] Configuring full-tunnel...", .{});
        std.log.debug("[ROUTING] VPN gateway: {d}.{d}.{d}.{d}", .{
            @as(u8, @truncate(vpn_gateway >> 24)),
            @as(u8, @truncate(vpn_gateway >> 16)),
            @as(u8, @truncate(vpn_gateway >> 8)),
            @as(u8, @truncate(vpn_gateway)),
        });
        std.log.debug("[ROUTING] VPN server: {d}.{d}.{d}.{d}", .{
            @as(u8, @truncate(vpn_server >> 24)),
            @as(u8, @truncate(vpn_server >> 16)),
            @as(u8, @truncate(vpn_server >> 8)),
            @as(u8, @truncate(vpn_server)),
        });

        // Save original state
        self.state.save(vpn_server) catch |err| {
            std.log.err("[ROUTING] Failed to save original state: {}", .{err});
            return err;
        };

        // Copy device name
        const len = @min(device_name.len, 64);
        @memcpy(self.state.device_name[0..len], device_name[0..len]);
        self.state.device_name_len = len;

        std.log.debug("[ROUTING] Original default gateway: {d}.{d}.{d}.{d}", .{
            @as(u8, @truncate(self.state.original_default_gateway >> 24)),
            @as(u8, @truncate(self.state.original_default_gateway >> 16)),
            @as(u8, @truncate(self.state.original_default_gateway >> 8)),
            @as(u8, @truncate(self.state.original_default_gateway)),
        });

        // 1. Add route for local network through original gateway
        if (self.state.original_default_gateway != 0) {
            std.log.debug("[ROUTING] Step 1: Adding local network route...", .{});
            addRoute(
                self.state.local_network,
                self.state.local_netmask,
                self.state.original_default_gateway,
                null,
            ) catch |err| {
                std.log.warn("[ROUTING] Local network route failed (may already exist): {}", .{err});
            };
        }

        // 2. Add host route for VPN server through original gateway
        // CRITICAL: Prevents routing loop
        if (vpn_server != 0 and self.state.original_default_gateway != 0) {
            std.log.debug("[ROUTING] Step 2: Adding host route for VPN server...", .{});
            addHostRoute(vpn_server, self.state.original_default_gateway) catch |err| {
                std.log.warn("[ROUTING] Host route failed (may already exist): {}", .{err});
            };
        } else {
            std.log.warn("[ROUTING] SKIPPING host route - vpn_server={d}, orig_gw={d}", .{ vpn_server, self.state.original_default_gateway });
        }

        // 3. Delete existing default route
        std.log.debug("[ROUTING] Step 3: Deleting existing default route...", .{});
        _ = deleteDefaultRoute() catch {};

        // 4. Add default route through VPN gateway
        std.log.debug("[ROUTING] Step 4: Adding VPN default route through {d}.{d}.{d}.{d}...", .{
            @as(u8, @truncate(vpn_gateway >> 24)),
            @as(u8, @truncate(vpn_gateway >> 16)),
            @as(u8, @truncate(vpn_gateway >> 8)),
            @as(u8, @truncate(vpn_gateway)),
        });
        addRoute(0, 0, vpn_gateway, null) catch |err| {
            std.log.err("[ROUTING] Failed to add VPN default route: {}", .{err});
            return err;
        };

        std.log.info("[ROUTING] ✅ Full-tunnel routing configured successfully", .{});
        self.state.routes_configured = true;
    }

    /// Configure split-tunnel VPN routing (only specified networks through VPN)
    pub fn configureSplitTunnel(
        self: *RouteManager,
        vpn_gateway: u32,
        networks: []const NetworkCidr,
    ) !void {
        for (networks) |net| {
            try addRoute(net.network, net.netmask, vpn_gateway, null);
        }
        self.state.routes_configured = true;
    }

    /// Restore original routing configuration
    pub fn restore(self: *RouteManager) !void {
        try self.state.restore();
    }

    /// Check if routes are configured
    pub fn isConfigured(self: *const RouteManager) bool {
        return self.state.routes_configured;
    }
};

/// Network CIDR representation
pub const NetworkCidr = struct {
    network: u32,
    netmask: u32,

    /// Create from CIDR notation (e.g., "192.168.1.0/24")
    pub fn fromString(cidr: []const u8) !NetworkCidr {
        // Find slash
        var slash_pos: ?usize = null;
        for (cidr, 0..) |c, i| {
            if (c == '/') {
                slash_pos = i;
                break;
            }
        }

        const slash = slash_pos orelse return RouteError.ParseError;

        const ip_str = cidr[0..slash];
        const prefix_str = cidr[slash + 1 ..];

        const ip = try parseIpv4(ip_str);
        const prefix = std.fmt.parseInt(u8, prefix_str, 10) catch return RouteError.ParseError;

        if (prefix > 32) return RouteError.ParseError;

        const mask = prefixToNetmask(prefix);

        return .{
            .network = ip & mask,
            .netmask = mask,
        };
    }

    /// Convert to string representation
    pub fn toString(self: NetworkCidr, buffer: []u8) ![]const u8 {
        const net_str = formatIpv4(self.network);

        // Count prefix bits
        const prefix = netmaskToPrefix(self.netmask);

        return std.fmt.bufPrint(buffer, "{s}/{d}", .{ trimNull(&net_str), prefix }) catch return RouteError.ParseError;
    }
};

// ============================================
// Route Table Operations (macOS specific)
// ============================================

/// Get the current default gateway
pub fn getDefaultGateway(allocator: std.mem.Allocator) !u32 {
    if (builtin.os.tag != .macos) {
        return RouteError.NotMacOS;
    }

    // Run netstat to get routing table
    var child = std.process.Child.init(
        &[_][]const u8{ "sh", "-c", "netstat -rn | grep '^default' | grep -v 'utun' | head -1 | awk '{print $2}'" },
        allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Close;

    try child.spawn();

    // Read output
    var output_buf: [128]u8 = undefined;
    const stdout = child.stdout.?;
    const bytes_read = try stdout.read(&output_buf);

    _ = try child.wait();

    if (bytes_read == 0) {
        return RouteError.NoDefaultGateway;
    }

    // Trim newline and parse
    var end = bytes_read;
    while (end > 0 and (output_buf[end - 1] == '\n' or output_buf[end - 1] == '\r')) {
        end -= 1;
    }

    if (end == 0) {
        return RouteError.NoDefaultGateway;
    }

    return parseIpv4(output_buf[0..end]);
}

/// Add a route to the routing table
pub fn addRoute(destination: u32, netmask: u32, gateway: u32, interface: ?[]const u8) !void {
    var cmd_buf: [256]u8 = undefined;

    const dest_str = formatIpv4(destination);
    const gw_str = formatIpv4(gateway);

    // Calculate prefix length from netmask
    var prefix: u8 = 0;
    var mask = netmask;
    while (mask & 0x80000000 != 0) : (mask <<= 1) {
        prefix += 1;
    }

    const cmd = if (destination == 0 and netmask == 0)
        std.fmt.bufPrint(&cmd_buf, "route add default {s}", .{trimNull(&gw_str)}) catch return RouteError.CommandFailed
    else if (interface) |iface|
        std.fmt.bufPrint(&cmd_buf, "route add -net {s}/{d} -interface {s}", .{
            trimNull(&dest_str), prefix, iface,
        }) catch return RouteError.CommandFailed
    else
        std.fmt.bufPrint(&cmd_buf, "route add -net {s}/{d} {s}", .{
            trimNull(&dest_str), prefix, trimNull(&gw_str),
        }) catch return RouteError.CommandFailed;

    _ = runCommand(cmd);
}

/// Add a host route (for specific IP)
pub fn addHostRoute(host: u32, gateway: u32) !void {
    var cmd_buf: [256]u8 = undefined;

    const host_str = formatIpv4(host);
    const gw_str = formatIpv4(gateway);

    const cmd = std.fmt.bufPrint(&cmd_buf, "route add -host {s} {s}", .{
        trimNull(&host_str), trimNull(&gw_str),
    }) catch return RouteError.CommandFailed;

    _ = runCommand(cmd);
}

/// Delete the default route
pub fn deleteDefaultRoute() !void {
    _ = runCommand("route delete default");
}

/// Delete a specific route
pub fn deleteRoute(destination: u32, netmask: u32) !void {
    var cmd_buf: [256]u8 = undefined;

    const dest_str = formatIpv4(destination);

    var prefix: u8 = 0;
    var mask = netmask;
    while (mask & 0x80000000 != 0) : (mask <<= 1) {
        prefix += 1;
    }

    const cmd = std.fmt.bufPrint(&cmd_buf, "route delete -net {s}/{d}", .{
        trimNull(&dest_str), prefix,
    }) catch return RouteError.CommandFailed;

    _ = runCommand(cmd);
}

// ============================================
// DNS Configuration (macOS specific)
// ============================================

/// Configure DNS servers for the VPN interface
pub fn configureDns(interface: []const u8, dns_servers: []const u32) !void {
    if (dns_servers.len == 0) return;

    var cmd_buf: [512]u8 = undefined;
    var pos: usize = 0;

    // Build networksetup command
    const prefix_str = "networksetup -setdnsservers Wi-Fi";
    @memcpy(cmd_buf[pos..][0..prefix_str.len], prefix_str);
    pos += prefix_str.len;

    for (dns_servers) |dns| {
        const dns_str = formatIpv4(dns);
        cmd_buf[pos] = ' ';
        pos += 1;
        const dns_trimmed = trimNull(&dns_str);
        @memcpy(cmd_buf[pos..][0..dns_trimmed.len], dns_trimmed);
        pos += dns_trimmed.len;
    }

    _ = runCommand(cmd_buf[0..pos]);
    _ = interface;
}

/// Clear DNS configuration
pub fn clearDns() !void {
    _ = runCommand("networksetup -setdnsservers Wi-Fi Empty");
}

/// Run a shell command (helper function)
fn runCommand(cmd: []const u8) bool {
    var child = std.process.Child.init(
        &[_][]const u8{ "/bin/sh", "-c", cmd },
        std.heap.page_allocator,
    );
    child.stderr_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    _ = child.spawnAndWait() catch return false;
    return true;
}

/// Parse IPv4 address string to u32
/// Returns IP in network byte order (big-endian)
pub fn parseIpv4(str: []const u8) !u32 {
    var octets: [4]u8 = [_]u8{ 0, 0, 0, 0 };
    var octet: u32 = 0;
    var octet_idx: usize = 0;

    for (str) |c| {
        if (c == '.') {
            if (octet > 255) return RouteError.InvalidAddress;
            if (octet_idx >= 4) return RouteError.InvalidAddress;
            octets[octet_idx] = @truncate(octet);
            octet_idx += 1;
            octet = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
        } else {
            return RouteError.InvalidAddress;
        }
    }

    if (octet > 255 or octet_idx != 3) return RouteError.InvalidAddress;
    octets[3] = @truncate(octet);

    // Return in network byte order (big-endian)
    return (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        octets[3];
}

/// Format u32 IPv4 address to string
/// IPs are stored in network byte order (big-endian)
pub fn formatIpv4(ip: u32) [16]u8 {
    var buf: [16]u8 = [_]u8{0} ** 16;
    _ = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
        @as(u8, @truncate(ip >> 24)),
        @as(u8, @truncate(ip >> 16)),
        @as(u8, @truncate(ip >> 8)),
        @as(u8, @truncate(ip)),
    }) catch {};
    return buf;
}

/// Trim null bytes from fixed buffer
fn trimNull(buf: []const u8) []const u8 {
    var len: usize = 0;
    while (len < buf.len and buf[len] != 0) : (len += 1) {}
    return buf[0..len];
}

/// Convert netmask to CIDR prefix length
/// Netmask is in network byte order (big-endian)
pub fn netmaskToPrefix(netmask: u32) u8 {
    // Count leading 1 bits in big-endian format
    var prefix: u8 = 0;
    var mask = netmask;
    while (mask & 0x80000000 != 0) : (mask <<= 1) {
        prefix += 1;
    }
    return prefix;
}

/// Convert CIDR prefix to netmask
/// Returns netmask in network byte order (big-endian)
pub fn prefixToNetmask(prefix: u8) u32 {
    if (prefix == 0) return 0;
    if (prefix >= 32) return 0xFFFFFFFF;

    // Create mask with 'prefix' leading 1 bits
    return ~(@as(u32, 0xFFFFFFFF) >> @intCast(prefix));
}

// ============================================
// Tests
// ============================================

test "IPv4 parsing" {
    // Network byte order (big-endian): 192.168.1.1 = 0xC0A80101
    const ip = try parseIpv4("192.168.1.1");
    try std.testing.expectEqual(@as(u32, 0xC0A80101), ip);

    // Network byte order: 127.0.0.1 = 0x7F000001
    const localhost = try parseIpv4("127.0.0.1");
    try std.testing.expectEqual(@as(u32, 0x7F000001), localhost);

    const broadcast = try parseIpv4("255.255.255.255");
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), broadcast);
}

test "IPv4 formatting" {
    // Network byte order (big-endian): 0xC0A80101 = "192.168.1.1"
    const str = formatIpv4(0xC0A80101);
    try std.testing.expectEqualStrings("192.168.1.1", trimNull(&str));

    // Network byte order: 0x7F000001 = "127.0.0.1"
    const localhost = formatIpv4(0x7F000001);
    try std.testing.expectEqualStrings("127.0.0.1", trimNull(&localhost));
}

test "IPv4 roundtrip" {
    // Network byte order: 10.0.0.1 = 0x0A000001
    const original: u32 = 0x0A000001;
    const str = formatIpv4(original);
    const parsed = try parseIpv4(trimNull(&str));
    try std.testing.expectEqual(original, parsed);
}

test "Netmask to prefix conversion" {
    // Netmasks in network byte order (big-endian)
    // /24 = 255.255.255.0 = 0xFFFFFF00
    try std.testing.expectEqual(@as(u8, 24), netmaskToPrefix(0xFFFFFF00));
    // /16 = 255.255.0.0 = 0xFFFF0000
    try std.testing.expectEqual(@as(u8, 16), netmaskToPrefix(0xFFFF0000));
    // /8 = 255.0.0.0 = 0xFF000000
    try std.testing.expectEqual(@as(u8, 8), netmaskToPrefix(0xFF000000));
    try std.testing.expectEqual(@as(u8, 32), netmaskToPrefix(0xFFFFFFFF));
    try std.testing.expectEqual(@as(u8, 0), netmaskToPrefix(0x00000000));
}

test "Prefix to netmask conversion" {
    // Network byte order (big-endian)
    // /24 = 255.255.255.0 = 0xFFFFFF00
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), prefixToNetmask(24));
    // /16 = 255.255.0.0 = 0xFFFF0000
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), prefixToNetmask(16));
    // /8 = 255.0.0.0 = 0xFF000000
    try std.testing.expectEqual(@as(u32, 0xFF000000), prefixToNetmask(8));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), prefixToNetmask(32));
    try std.testing.expectEqual(@as(u32, 0x00000000), prefixToNetmask(0));
}

test "NetworkCidr from string" {
    // Network byte order: 192.168.1.0/24 = 0xC0A80100
    const net = try NetworkCidr.fromString("192.168.1.0/24");
    try std.testing.expectEqual(@as(u32, 0xC0A80100), net.network);
    // /24 = 255.255.255.0 = 0xFFFFFF00
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), net.netmask);

    // Network byte order: 10.0.0.0/8 = 0x0A000000
    const net16 = try NetworkCidr.fromString("10.0.0.0/8");
    try std.testing.expectEqual(@as(u32, 0x0A000000), net16.network);
    // /8 = 255.0.0.0 = 0xFF000000
    try std.testing.expectEqual(@as(u32, 0xFF000000), net16.netmask);
}

test "NetworkCidr to string" {
    // Network byte order: 192.168.1.0 = 0xC0A80100, /24 = 0xFFFFFF00
    const net = NetworkCidr{
        .network = 0xC0A80100,
        .netmask = 0xFFFFFF00,
    };
    var buf: [32]u8 = undefined;
    const str = try net.toString(&buf);
    try std.testing.expectEqualStrings("192.168.1.0/24", str);
}

test "Route structure" {
    var route = Route{
        // Little-endian IPs
        .destination = 0x0001A8C0, // 192.168.1.0
        .netmask = 0x00FFFFFF, // 255.255.255.0
        .gateway = 0x0101A8C0, // 192.168.1.1
        .interface = [_]u8{0} ** 32,
        .interface_len = 0,
        .flags = .{ .up = true, .gateway = true },
        .metric = 0,
    };

    @memcpy(route.interface[0..4], "en0\x00");
    route.interface_len = 3;

    const dest = route.getDestinationStr();
    try std.testing.expectEqualStrings("192.168.1.0", trimNull(&dest));

    const gw = route.getGatewayStr();
    try std.testing.expectEqualStrings("192.168.1.1", trimNull(&gw));

    try std.testing.expectEqualStrings("en0", route.getInterface());
}

test "RoutingState initialization" {
    const state = RoutingState.init(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 0), state.original_default_gateway);
    try std.testing.expectEqual(false, state.routes_configured);
}

test "RouteManager initialization" {
    const manager = RouteManager.init(std.testing.allocator);
    try std.testing.expect(!manager.isConfigured());
}

test "RouteFlags" {
    const flags = RouteFlags{
        .up = true,
        .gateway = true,
        .host = false,
        .static = true,
    };
    try std.testing.expect(flags.up);
    try std.testing.expect(flags.gateway);
    try std.testing.expect(!flags.host);
    try std.testing.expect(flags.static);
}

test "IPv4 parsing errors" {
    // Invalid octet
    try std.testing.expectError(RouteError.InvalidAddress, parseIpv4("256.0.0.1"));
    // Missing octets
    try std.testing.expectError(RouteError.InvalidAddress, parseIpv4("192.168.1"));
    // Invalid character
    try std.testing.expectError(RouteError.InvalidAddress, parseIpv4("192.168.x.1"));
}

test "NetworkCidr errors" {
    // Missing prefix
    try std.testing.expectError(RouteError.ParseError, NetworkCidr.fromString("192.168.1.0"));
    // Invalid prefix
    try std.testing.expectError(RouteError.ParseError, NetworkCidr.fromString("192.168.1.0/33"));
}
