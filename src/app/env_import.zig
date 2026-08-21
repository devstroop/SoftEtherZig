//! Env import — vpncmd owns SOFTETHER_* env (M22 #279)
//!
//! Maps host env vars at vpncmd exec time into an Account for the XDG
//! vpn_client.config Cfg store. vpnclient no longer reads env (flags+store only).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const EnvAccount = struct {
    name: []const u8,
    server: []const u8,
    port: u16 = 443,
    port_explicit: bool = false,
    hub: []const u8,
    username: []const u8,
    password: ?[]const u8 = null,
    password_hash: ?[]const u8 = null,
};

/// Read SOFTETHER_* env into an EnvAccount. `account_name` is --account or SOFTETHER_ACCOUNT or "vpn1" default.
/// Caller must free returned strings via allocator.
pub fn fromEnv(allocator: Allocator, account_name: ?[]const u8) !?EnvAccount {
    const isTrue = struct {
        fn check(v: []const u8) bool {
            return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "yes");
        }
    }.check;
    _ = isTrue;

    const server = std.process.getEnvVarOwned(allocator, "SOFTETHER_ADDRESS") catch null;
    if (server == null) return null;

    const name = if (account_name) |n| try allocator.dupe(u8, n) else if (std.process.getEnvVarOwned(allocator, "SOFTETHER_ACCOUNT") catch null) |v| v else try allocator.dupe(u8, "env-import");

    const port_str = std.process.getEnvVarOwned(allocator, "SOFTETHER_PORT") catch null;
    var port: u16 = 443;
    var port_explicit = false;
    if (port_str) |ps| {
        defer allocator.free(ps);
        port = std.fmt.parseInt(u16, ps, 10) catch 443;
        port_explicit = true;
    }

    const hub = std.process.getEnvVarOwned(allocator, "SOFTETHER_HUB") catch null;
    const hub_val = if (hub) |h| h else try allocator.dupe(u8, "VPN");

    const user = std.process.getEnvVarOwned(allocator, "SOFTETHER_USER") catch null;
    if (user == null) {
        allocator.free(name);
        if (hub) |h| allocator.free(h) else allocator.free(hub_val);
        allocator.free(server.?);
        return error.MissingUsername;
    }

    const pass = std.process.getEnvVarOwned(allocator, "SOFTETHER_PASSWORD") catch null;
    const pass_hash = std.process.getEnvVarOwned(allocator, "SOFTETHER_PASSWORD_HASH") catch null;

    // At least one of password or hash should be present, but allow null for now (let caller validate)
    return EnvAccount{
        .name = name,
        .server = server.?,
        .port = port,
        .port_explicit = port_explicit,
        .hub = hub_val,
        .username = user.?,
        .password = pass,
        .password_hash = pass_hash,
    };
}

test "env_import fromEnv with tmp env" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // Use env vars in test
    try std.posix.setenv("SOFTETHER_ADDRESS", "203.0.113.10");
    try std.posix.setenv("SOFTETHER_HUB", "TEST");
    try std.posix.setenv("SOFTETHER_USER", "testuser");
    try std.posix.setenv("SOFTETHER_PASSWORD", "testpass");
    defer {
        std.posix.unsetenv("SOFTETHER_ADDRESS") catch {};
        std.posix.unsetenv("SOFTETHER_HUB") catch {};
        std.posix.unsetenv("SOFTETHER_USER") catch {};
        std.posix.unsetenv("SOFTETHER_PASSWORD") catch {};
        std.posix.unsetenv("SOFTETHER_PORT") catch {};
        std.posix.unsetenv("SOFTETHER_ACCOUNT") catch {};
    }
    const alloc = std.testing.allocator;
    const acc = try fromEnv(alloc, "testacct");
    try std.testing.expect(acc != null);
    if (acc) |a| {
        defer alloc.free(a.name);
        defer alloc.free(a.server);
        defer alloc.free(a.hub);
        defer alloc.free(a.username);
        if (a.password) |p| alloc.free(p);
        if (a.password_hash) |h| alloc.free(h);
        try std.testing.expectEqualStrings("203.0.113.10", a.server);
        try std.testing.expectEqualStrings("testuser", a.username);
    }
}
