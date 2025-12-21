//! Configuration Builder
//!
//! Builds VPN client configuration from CLI arguments.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const client = @import("../client/mod.zig");

pub const ConfigBuildError = error{
    MissingServer,
    MissingHub,
    MissingPassword,
};

/// Build a ClientConfig from CLI arguments
pub fn buildClientConfig(args: *const cli.CliArgs) ConfigBuildError!client.ClientConfig {
    // Validate required fields
    const server = args.server orelse return error.MissingServer;
    const hub = args.hub orelse return error.MissingHub;

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

    return .{
        .server_host = server,
        .server_port = args.port,
        .hub_name = hub,
        .auth = auth,
        .max_connections = @intCast(args.max_connection),
        .use_compression = args.use_compress,
        .use_encryption = true,
        .udp_acceleration = args.udp_accel,
        .verify_certificate = !args.skip_tls_verify,
        .mtu = args.mtu,
        .routing = routing,
        .reconnect = reconnect,
        .connect_timeout_ms = 30000,
        .read_timeout_ms = 60000,
        .keepalive_interval_ms = 10000,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "buildClientConfig valid" {
    var args = cli.CliArgs{
        .server = "test.example.com",
        .hub = "VPN",
        .username = "user",
        .password = "pass",
        .port = 443,
    };
    defer args.deinit();

    const config = try buildClientConfig(&args);
    try std.testing.expectEqualStrings("test.example.com", config.server_host);
    try std.testing.expectEqualStrings("VPN", config.hub_name);
    try std.testing.expectEqual(@as(u16, 443), config.server_port);
}

test "buildClientConfig missing server" {
    var args = cli.CliArgs{
        .hub = "VPN",
        .username = "user",
        .password = "pass",
    };
    defer args.deinit();

    try std.testing.expectError(error.MissingServer, buildClientConfig(&args));
}

test "buildClientConfig missing hub" {
    var args = cli.CliArgs{
        .server = "test.com",
        .username = "user",
        .password = "pass",
    };
    defer args.deinit();

    try std.testing.expectError(error.MissingHub, buildClientConfig(&args));
}

test "buildClientConfig anonymous auth" {
    var args = cli.CliArgs{
        .server = "test.com",
        .hub = "VPN",
    };
    defer args.deinit();

    const config = try buildClientConfig(&args);
    try std.testing.expect(config.auth == .anonymous);
}

test "buildClientConfig password hash" {
    var args = cli.CliArgs{
        .server = "test.com",
        .hub = "VPN",
        .username = "user",
        .password_hash = "base64hash==",
    };
    defer args.deinit();

    const config = try buildClientConfig(&args);
    switch (config.auth) {
        .password => |p| {
            try std.testing.expect(p.is_hashed);
            try std.testing.expectEqualStrings("base64hash==", p.password);
        },
        else => try std.testing.expect(false),
    }
}
