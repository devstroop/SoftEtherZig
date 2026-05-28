const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const net = std.net;
const posix = std.posix;

const socket = @import("socket.zig");
const TcpSocket = socket.TcpSocket;

pub const SocksError = error{
    ConnectionFailed,
    RequestRejected,
    RequestFailed,
    IdentdFailed,
    InvalidResponse,
    AuthMethodRejected,
    AuthFailed,
    UnsupportedAddressType,
    UnsupportedVersion,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    NetworkUnreachable,
    NotAllowed,
    GeneralFailure,
};

pub const Socks4ResponseStatus = enum(u8) {
    granted = 0x5A,
    rejected = 0x5B,
    identd_failed = 0x5C,
    identd_mismatch = 0x5D,
};

pub const Socks5AuthMethod = enum(u8) {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable = 0xFF,
};

pub const Socks5Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

pub const AddressType = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

pub const ProxyConfig = struct {
    host: []const u8,
    port: u16,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

pub fn connectViaSocks4(
    allocator: Allocator,
    proxy: ProxyConfig,
    target_host: []const u8,
    target_port: u16,
) !TcpSocket {
    var tcp = try TcpSocket.connectHost(proxy.host, proxy.port, 30000);
    errdefer tcp.close();

    const target_ip = resolveToIpv4(target_host) catch {
        tcp.close();
        return SocksError.HostUnreachable;
    };

    var req: [9]u8 = undefined;
    req[0] = 4; // version
    req[1] = 1; // CONNECT
    req[2] = @as(u8, @intCast(target_port >> 8));
    req[3] = @as(u8, @intCast(target_port & 0xFF));
    req[4..8].* = target_ip;

    const user_id = proxy.username orelse "";
    const full_req = try std.mem.concat(allocator, u8, &[_][]const u8{ &req, user_id, &[_]u8{0} });
    defer allocator.free(full_req);

    try tcp.writeAll(full_req);

    var resp: [8]u8 = undefined;
    try tcp.readAll(resp[0..]);
    if (resp[0] != 0x00) return SocksError.InvalidResponse;

    switch (resp[1]) {
        0x5A => return tcp,
        0x5B => return SocksError.RequestRejected,
        0x5C => return SocksError.IdentdFailed,
        0x5D => return SocksError.IdentdFailed,
        else => return SocksError.RequestRejected,
    }
}

pub fn connectViaSocks5(
    allocator: Allocator,
    proxy: ProxyConfig,
    target_host: []const u8,
    target_port: u16,
) !TcpSocket {
    _ = allocator;
    var tcp = try TcpSocket.connectHost(proxy.host, proxy.port, 30000);
    errdefer tcp.close();

    try socks5Auth(&tcp, proxy);

    try socks5Connect(&tcp, target_host, target_port);

    return tcp;
}

fn socks5Auth(tcp: *TcpSocket, proxy: ProxyConfig) !void {
    const has_auth = proxy.username != null and proxy.password != null;

    var methods_buf: [4]u8 = undefined;
    methods_buf[0] = 5; // version
    if (has_auth) {
        methods_buf[1] = 2; // nmethods
        methods_buf[2] = 0x02; // username/password
        methods_buf[3] = 0x00; // no auth
        try tcp.writeAll(methods_buf[0..4]);
    } else {
        methods_buf[1] = 1; // nmethods
        methods_buf[2] = 0x00; // no auth
        try tcp.writeAll(methods_buf[0..3]);
    }

    var method_resp: [2]u8 = undefined;
    try tcp.readAll(method_resp[0..]);
    if (method_resp[0] != 5) return SocksError.UnsupportedVersion;

    if (method_resp[1] == 0xFF) return SocksError.AuthMethodRejected;

    if (method_resp[1] == 0x02 and has_auth) {
        try socks5UserPassAuth(tcp, proxy.username.?, proxy.password.?);
    }
}

fn socks5UserPassAuth(tcp: *TcpSocket, username: []const u8, password: []const u8) !void {
    if (username.len > 255 or password.len > 255) return SocksError.AuthFailed;

    var auth_buf: [513]u8 = undefined;
    var off: usize = 0;
    auth_buf[off] = 1; off += 1; // version
    auth_buf[off] = @as(u8, @intCast(username.len)); off += 1;
    for (username, 0..) |b, i| auth_buf[off + i] = b;
    off += username.len;
    auth_buf[off] = @as(u8, @intCast(password.len)); off += 1;
    for (password, 0..) |b, i| auth_buf[off + i] = b;
    off += password.len;

    try tcp.writeAll(auth_buf[0..off]);

    var resp: [2]u8 = undefined;
    try tcp.readAll(resp[0..]);
    if (resp[0] != 1) return SocksError.UnsupportedVersion;
    if (resp[1] != 0) return SocksError.AuthFailed;
}

fn socks5Connect(tcp: *TcpSocket, host: []const u8, port: u16) !void {
    var req_buf: [262]u8 = undefined;
    var off: usize = 0;

    req_buf[off] = 5; off += 1; // version
    req_buf[off] = 1; off += 1; // CONNECT
    req_buf[off] = 0; off += 1; // reserved

    if (net.Address.parseIp4(host, 0)) |addr| {
        req_buf[off] = @intFromEnum(AddressType.ipv4); off += 1;
        const ip4_bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
        for (ip4_bytes, 0..) |b, i| req_buf[off + i] = b;
        off += 4;
    } else |_| {
        if (net.Address.parseIp6(host, 0)) |addr| {
            req_buf[off] = @intFromEnum(AddressType.ipv6); off += 1;
            for (&addr.in6.sa.addr, 0..) |b, i| req_buf[off + i] = b;
            off += 16;
        } else |_| {
            if (host.len > 255) return SocksError.UnsupportedAddressType;
            req_buf[off] = @intFromEnum(AddressType.domain); off += 1;
            req_buf[off] = @as(u8, @intCast(host.len)); off += 1;
            for (host, 0..) |b, i| req_buf[off + i] = b;
            off += host.len;
        }
    }

    req_buf[off] = @as(u8, @intCast(port >> 8)); off += 1;
    req_buf[off] = @as(u8, @intCast(port & 0xFF)); off += 1;

    try tcp.writeAll(req_buf[0..off]);

    var resp: [4]u8 = undefined;
    try tcp.readAll(resp[0..]);
    if (resp[0] != 5) return SocksError.UnsupportedVersion;
    if (resp[1] != 0) {
        return switch (resp[1]) {
            0x01 => SocksError.GeneralFailure,
            0x02 => SocksError.NotAllowed,
            0x03 => SocksError.NetworkUnreachable,
            0x04 => SocksError.HostUnreachable,
            0x05 => SocksError.ConnectionRefused,
            0x06 => SocksError.TtlExpired,
            0x07 => SocksError.CommandNotSupported,
            0x08 => SocksError.AddressTypeNotSupported,
            else => SocksError.RequestRejected,
        };
    }

    switch (resp[3]) {
        @intFromEnum(AddressType.ipv4) => {
            var addr_buf: [4]u8 = undefined;
            try tcp.readAll(addr_buf[0..]);
            var port_buf: [2]u8 = undefined;
            try tcp.readAll(port_buf[0..]);
        },
        @intFromEnum(AddressType.domain) => {
            var len_buf: [1]u8 = undefined;
            try tcp.readAll(len_buf[0..]);
            const domain_buf = try std.heap.page_allocator.alloc(u8, len_buf[0]);
            defer std.heap.page_allocator.free(domain_buf);
            try tcp.readAll(domain_buf);
            var port_buf: [2]u8 = undefined;
            try tcp.readAll(port_buf[0..]);
        },
        @intFromEnum(AddressType.ipv6) => {
            var addr_buf: [16]u8 = undefined;
            try tcp.readAll(addr_buf[0..]);
            var port_buf: [2]u8 = undefined;
            try tcp.readAll(port_buf[0..]);
        },
        else => return SocksError.UnsupportedAddressType,
    }
}

fn resolveToIpv4(host: []const u8) ![4]u8 {
    // Parse dotted-decimal IPv4 string directly.
    // net.Address.parseIp4 exists but extracting raw bytes from it in a
    // platform-independent way is fragile (sockaddr layout differs per OS).
    var result: [4]u8 = .{0} ** 4;
    var octet_idx: usize = 0;
    var start: usize = 0;
    while (start < host.len and octet_idx < 4) {
        const end = std.mem.indexOfScalarPos(u8, host, start, '.') orelse host.len;
        const octet = std.fmt.parseInt(u8, host[start..end], 10) catch return SocksError.HostUnreachable;
        result[octet_idx] = octet;
        octet_idx += 1;
        start = end + 1;
    }
    if (octet_idx != 4) return SocksError.HostUnreachable;
    return result;
}

test "SOCKS4 request format" {
    var buf: [9]u8 = undefined;
    buf[0] = 4;
    buf[1] = 1;
    const port: u16 = 443;
    buf[2] = @as(u8, @intCast(port >> 8));
    buf[3] = @as(u8, @intCast(port & 0xFF));
    buf[4..8].* = .{ 10, 0, 0, 1 };
    buf[8] = 0;

    try testing.expectEqual(@as(u8, 4), buf[0]);
    try testing.expectEqual(@as(u8, 1), buf[1]);
    try testing.expectEqual(@as(u8, 0x01), buf[2]);
    try testing.expectEqual(@as(u8, 0xBB), buf[3]);
    try testing.expectEqual(@as(u8, 10), buf[4]);
}

test "SOCKS4 response status parsing" {
    try testing.expectEqual(@as(u8, 0x5A), @intFromEnum(Socks4ResponseStatus.granted));
    try testing.expectEqual(@as(u8, 0x5B), @intFromEnum(Socks4ResponseStatus.rejected));
}

test "SOCKS5 auth method values" {
    try testing.expectEqual(@as(u8, 0x00), @intFromEnum(Socks5AuthMethod.no_auth));
    try testing.expectEqual(@as(u8, 0x02), @intFromEnum(Socks5AuthMethod.username_password));
    try testing.expectEqual(@as(u8, 0xFF), @intFromEnum(Socks5AuthMethod.no_acceptable));
}

test "AddressType values" {
    try testing.expectEqual(@as(u8, 0x01), @intFromEnum(AddressType.ipv4));
    try testing.expectEqual(@as(u8, 0x03), @intFromEnum(AddressType.domain));
    try testing.expectEqual(@as(u8, 0x04), @intFromEnum(AddressType.ipv6));
}

test "resolveToIpv4 parses IP string" {
    const ip = try resolveToIpv4("10.0.0.1");
    try testing.expectEqual(@as(u8, 10), ip[0]);
    try testing.expectEqual(@as(u8, 0), ip[1]);
    try testing.expectEqual(@as(u8, 0), ip[2]);
    try testing.expectEqual(@as(u8, 1), ip[3]);
}

test "resolveToIpv4 returns error for hostname" {
    try testing.expectError(SocksError.HostUnreachable, resolveToIpv4("example.com"));
}
