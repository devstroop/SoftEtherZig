//! Configuration Builder
//!
//! Builds VPN client configuration from CLI arguments.

const std = @import("std");
const log = std.log.scoped(.app);

const cli = @import("../cli/mod.zig");
const client = @import("../cedar/client/mod.zig");
const tls = @import("../mayaqua/network/tls.zig");
const adapter_mod = @import("../adapter/mod.zig");
const iface_config = @import("../adapter/interface_config.zig");

pub const ConfigBuildError = error{
    MissingAddress,
    MissingHub,
    MissingPassword,
    InvalidProxyUrl,
    InvalidInterfaceType,
    MissingBridgeIngress,
    Overflow,
    InvalidCharacter,
    OutOfMemory,
};

/// Build a ClientConfig from CLI arguments
pub fn buildClientConfig(allocator: std.mem.Allocator, args: *const cli.CliArgs) ConfigBuildError!client.ClientConfig {
    // Validate required fields — address is mandatory
    const server_address = try allocator.dupe(u8, args.address orelse return error.MissingAddress);
    const hub = try allocator.dupe(u8, args.hub orelse return error.MissingHub);

    // Free allocations on any subsequent error
    errdefer allocator.free(server_address);
    errdefer allocator.free(hub);

    // Build auth method
    const auth: client.AuthMethod = blk: {
        if (args.password_hash) |hash| {
            break :blk .{ .password = .{
                .username = args.username orelse "anonymous",
                .password = hash,
                .is_hashed = true,
            } };
        } else if (args.password) |pass| {
            break :blk .{ .password = .{
                .username = args.username orelse "anonymous",
                .password = pass,
                .is_hashed = false,
            } };
        } else if (args.username) |_| {
            return error.MissingPassword;
        } else {
            break :blk .{ .anonymous = {} };
        }
    };

    // Build reconnect config
    const reconnect = client.ReconnectConfig{
        .enabled = args.reconnect,
        .max_attempts = args.max_retries,
        // Backoff timing is internal - 1s min, 60s max, 2x multiplier
    };

    // Build routing config
    const routing = client.RoutingConfig{
        .default_route = args.default_route,
        .accept_pushed_routes = args.accept_pushed_routes,
        .enable_custom_routes = args.enable_custom_routes,
        .ipv4_include = args.ipv4_include,
        .ipv4_exclude = args.ipv4_exclude,
        .ipv6_include = args.ipv6_include,
        .ipv6_exclude = args.ipv6_exclude,
    };

    // Build static IP config (if any static IP is configured)
    const static_ip: ?client.StaticIpConfig = if (args.static_ipv4 != null or args.static_ipv6 != null)
        .{
            .ipv4_address = args.static_ipv4,
            .ipv4_netmask = args.static_ipv4_netmask,
            .ipv4_gateway = args.static_ipv4_gateway,
            .ipv6_address = args.static_ipv6,
            .ipv6_prefix_len = args.static_ipv6_prefix,
            .ipv6_gateway = args.static_ipv6_gateway,
            .dns_servers = if (args.dns_servers.len > 0) args.dns_servers else null,
        }
    else
        null;

    return .{
        .server_address = server_address,
        .server_hostname = args.hostname,
        .server_port = args.port,
        .hub_name = hub,
        .auth = auth,
        .max_connections = @intCast(args.max_connections),
        .ip_version = if (args.ip_version) |iv| @as(client.IpVersion, @enumFromInt(@intFromEnum(iv))) else null,
        .use_compress = args.use_compress,
        .use_encrypt = args.use_encrypt,
        .half_connection = args.half_connection,
        .qos = args.qos,
        .udp_acceleration = args.udp_accel,
        .verbose = args.verbose,
        .verify_certificate = !args.skip_tls_verify,
        .mtu = args.mtu,
        .routing = routing,
        .reconnect = reconnect,
        .static_ip = static_ip,
        .connect_timeout_ms = args.connect_timeout_ms,
        .read_timeout_ms = args.read_timeout_ms,
        .keepalive_interval_ms = args.keepalive_interval_ms,
        .garp_interval_ms = args.garp_interval_ms,
        .tcp_nodelay = args.tcp_nodelay,
        .proxy = if (args.proxy) |proxy_str| try parseProxyUrl(proxy_str) else null,
        .interface = if (args.interface) |iface_str| blk: {
            break :blk try iface_config.parseInterfaceConfig(allocator, iface_str);
        } else null,
    };
}

/// Parse a proxy URL string into a ProxyConfig.
///
/// Supported formats:
///   http://user:pass@host:port
///   http://host:port
///   socks5://user:pass@host:1080
///   socks5://host:1080
///   socks4://host:1080
pub fn parseProxyUrl(url: []const u8) ConfigBuildError!tls.ProxyConfig {
    const ProxyType = tls.ProxyConfig.ProxyType;

    const prefix_http = "http://";
    const prefix_socks5 = "socks5://";
    const prefix_socks4 = "socks4://";
    const prefix_socks4a = "socks4a://";

    var remaining = url;
    var proxy_type: ProxyType = .http;

    if (std.mem.startsWith(u8, remaining, prefix_http)) {
        remaining = remaining[prefix_http.len..];
        proxy_type = .http;
    } else if (std.mem.startsWith(u8, remaining, prefix_socks5)) {
        remaining = remaining[prefix_socks5.len..];
        proxy_type = .socks5;
    } else if (std.mem.startsWith(u8, remaining, prefix_socks4)) {
        remaining = remaining[prefix_socks4.len..];
        proxy_type = .socks4;
    } else if (std.mem.startsWith(u8, remaining, prefix_socks4a)) {
        remaining = remaining[prefix_socks4a.len..];
        proxy_type = .socks4;
    }

    // Extract credentials if present: user:pass@host:port
    var username: ?[]const u8 = null;
    var password: ?[]const u8 = null;

    if (std.mem.indexOfScalar(u8, remaining, '@')) |at_index| {
        const userinfo = remaining[0..at_index];
        remaining = remaining[at_index + 1 ..];

        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon| {
            username = userinfo[0..colon];
            password = userinfo[colon + 1 ..];
        } else {
            username = userinfo;
        }
    }

    // Ensure non-empty remaining
    if (remaining.len == 0) return error.InvalidProxyUrl;

    // Extract host:port (keep colon in remaining for port parsing)
    const host: []const u8 = blk: {
        if (remaining[0] == '[') {
            // IPv6 literal: [::1]:1080
            const close = std.mem.indexOfScalar(u8, remaining, ']') orelse return error.InvalidProxyUrl;
            const addr = remaining[1..close];
            remaining = remaining[close + 1 ..]; // ":1080" or ""
            break :blk addr;
        } else if (std.mem.indexOfScalar(u8, remaining, ':')) |colon| {
            const addr = remaining[0..colon];
            remaining = remaining[colon..]; // keep colon
            break :blk addr;
        } else {
            return error.InvalidProxyUrl;
        }
    };

    const port: u16 = if (remaining.len > 0 and remaining[0] == ':') blk: {
        remaining = remaining[1..];
        break :blk std.fmt.parseInt(u16, remaining, 10) catch return error.InvalidProxyUrl;
    } else switch (proxy_type) {
        .http => 3128,
        .socks4, .socks5 => 1080,
    };

    return .{
        .host = host,
        .port = port,
        .username = username,
        .password = password,
        .proxy_type = proxy_type,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildClientConfig valid" {
    var args = cli.CliArgs{
        .address = "192.168.1.1",
        .hub = "VPN",
        .username = "user",
        .password = "pass",
        .port = 443,
    };
    const config = try buildClientConfig(std.testing.allocator, &args);

    try std.testing.expectEqualStrings("192.168.1.1", config.server_address);
    try std.testing.expectEqual(@as(u16, 443), config.server_port);
    try std.testing.expect(config.proxy == null);
}

test "parseProxyUrl http" {
    const pc = try parseProxyUrl("http://proxy.example.com:3128");
    try std.testing.expectEqualStrings("proxy.example.com", pc.host);
    try std.testing.expectEqual(@as(u16, 3128), pc.port);
    try std.testing.expect(pc.username == null);
    try std.testing.expectEqual(tls.ProxyConfig.ProxyType.http, pc.proxy_type);
}

test "parseProxyUrl http with auth" {
    const pc = try parseProxyUrl("http://user:pass@proxy.example.com:8080");
    try std.testing.expectEqualStrings("proxy.example.com", pc.host);
    try std.testing.expectEqual(@as(u16, 8080), pc.port);
    try std.testing.expectEqualStrings("user", pc.username.?);
    try std.testing.expectEqualStrings("pass", pc.password.?);
    try std.testing.expectEqual(tls.ProxyConfig.ProxyType.http, pc.proxy_type);
}

test "parseProxyUrl socks5" {
    const pc = try parseProxyUrl("socks5://192.168.1.1:1080");
    try std.testing.expectEqualStrings("192.168.1.1", pc.host);
    try std.testing.expectEqual(@as(u16, 1080), pc.port);
    try std.testing.expectEqual(tls.ProxyConfig.ProxyType.socks5, pc.proxy_type);
}

test "parseProxyUrl socks5 with auth" {
    const pc = try parseProxyUrl("socks5://alice:secret@socks.example.com:1080");
    try std.testing.expectEqualStrings("socks.example.com", pc.host);
    try std.testing.expectEqual(@as(u16, 1080), pc.port);
    try std.testing.expectEqualStrings("alice", pc.username.?);
    try std.testing.expectEqualStrings("secret", pc.password.?);
    try std.testing.expectEqual(tls.ProxyConfig.ProxyType.socks5, pc.proxy_type);
}

test "parseProxyUrl socks4" {
    const pc = try parseProxyUrl("socks4://socks.example.com:1080");
    try std.testing.expectEqualStrings("socks.example.com", pc.host);
    try std.testing.expectEqual(@as(u16, 1080), pc.port);
    try std.testing.expectEqual(tls.ProxyConfig.ProxyType.socks4, pc.proxy_type);
}

test "parseProxyUrl socks4a" {
    const pc = try parseProxyUrl("socks4a://socks.example.com:1080");
    try std.testing.expectEqualStrings("socks.example.com", pc.host);
    try std.testing.expectEqual(@as(u16, 1080), pc.port);
    try std.testing.expectEqual(tls.ProxyConfig.ProxyType.socks4, pc.proxy_type);
}

test "parseProxyUrl http default port" {
    const pc = try parseProxyUrl("http://proxy:3128");
    try std.testing.expectEqual(@as(u16, 3128), pc.port);
    try std.testing.expectEqualStrings("proxy", pc.host);
}

test "parseProxyUrl socks5 default port" {
    const pc = try parseProxyUrl("socks5://socks.example.com:1080");
    try std.testing.expectEqual(@as(u16, 1080), pc.port);
}

test "parseProxyUrl invalid" {
    try std.testing.expectError(error.InvalidProxyUrl, parseProxyUrl("not-a-proxy-url"));
}

test "parseProxyUrl empty" {
    try std.testing.expectError(error.InvalidProxyUrl, parseProxyUrl(""));
}

test "buildClientConfig missing address" {
    var args = cli.CliArgs{
        .hub = "VPN",
        .username = "user",
        .password = "pass",
    };
    defer args.deinit();

    try std.testing.expectError(error.MissingAddress, buildClientConfig(std.testing.allocator, &args));
}

test "buildClientConfig missing hub" {
    var args = cli.CliArgs{
        .address = "192.168.1.1",
        .username = "user",
        .password = "pass",
    };
    defer args.deinit();

    try std.testing.expectError(error.MissingHub, buildClientConfig(std.testing.allocator, &args));
}

test "buildClientConfig anonymous auth" {
    var args = cli.CliArgs{
        .address = "192.168.1.1",
        .hub = "VPN",
    };
    defer args.deinit();

    const config = try buildClientConfig(std.testing.allocator, &args);
    try std.testing.expect(config.auth == .anonymous);
}

test "buildClientConfig password hash" {
    var args = cli.CliArgs{
        .address = "192.168.1.1",
        .hub = "VPN",
        .username = "user",
        .password_hash = "base64hash==",
    };
    defer args.deinit();

    const config = try buildClientConfig(std.testing.allocator, &args);
    switch (config.auth) {
        .password => |p| {
            try std.testing.expect(p.is_hashed);
            try std.testing.expectEqualStrings("base64hash==", p.password);
        },
        else => try std.testing.expect(false),
    }
}
