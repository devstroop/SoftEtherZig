//! Socket Utilities Module
//!
//! Socket operations
//! Provides cross-platform TCP/UDP socket abstractions.
//!
//! Zig 0.16 migration: TcpSocket now uses raw posix.socket_t instead of
//! net.Stream which requires Io in Zig 0.16. A compatible TcpStream wrapper
//! is provided for the .stream field used by http.zig.

const std = @import("std");
const net = std.Io.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Random = std.Random;

const builtin = @import("builtin");

/// Socket error types
pub const SocketError = error{
    ConnectionRefused,
    ConnectionReset,
    ConnectionTimedOut,
    HostUnreachable,
    NetworkUnreachable,
    AddressInUse,
    AddressNotAvailable,
    BrokenPipe,
    WouldBlock,
    InvalidAddress,
    SocketNotConnected,
    NotSocket,
    Unexpected,
};

/// Address family
pub const AddressFamily = enum {
    ipv4,
    ipv6,
    unspec,
};

/// Socket address wrapper
pub const Address = struct {
    inner: net.IpAddress,

    pub fn parseIp(ip: []const u8, port: u16) !Address {
        return .{ .inner = try net.IpAddress.parse(ip, port) };
    }

    pub fn parseIp4(ip: []const u8, port: u16) !Address {
        return .{ .inner = try net.IpAddress.parseIp4(ip, port) };
    }

    pub fn parseIp6(ip: []const u8, port: u16) !Address {
        return .{ .inner = try net.IpAddress.parseIp6(ip, port) };
    }

    pub fn resolveIp(hostname: []const u8, port: u16) !Address {
        // Stub: DNS resolution for the Address wrapper. On iOS, real resolution
        // happens through vpn_client.zig's resolveDns using the Swift bridge.
        // This stub satisfies the type system and allows the non-iOS code paths
        // to compile.
        _ = hostname;
        _ = port;
        return error.DnsResolutionFailed;
    }

    pub fn getPort(self: *const Address) u16 {
        return self.inner.getPort();
    }

    pub fn format(self: Address, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try self.inner.format("{}", .{}, writer);
    }
};

/// Read-compatible wrapper around a raw fd for the .stream field compat.
pub const TcpStream = struct {
    fd: posix.socket_t,

    pub fn read(self: *const TcpStream, buf: []u8) !usize {
        return posix.read(self.fd, buf);
    }
};

/// TCP Socket wrapper with timeout support.
/// Zig 0.16: Uses raw posix.socket_t. The .stream field provides a reader
/// compatible interface for http.zig / socks.zig callers.
pub const TcpSocket = struct {
    fd: posix.socket_t,
    stream: TcpStream,

    /// Connect to a remote address with timeout
    pub fn connect(address: Address, timeout_ms: ?u32) !TcpSocket {
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (fd < 0) return error.ConnectionFailed;
        errdefer _ = std.c.close(fd);

        // Build sockaddr
        var sa: std.c.sockaddr.in = undefined;
        sa.len = @sizeOf(std.c.sockaddr.in);
        sa.family = std.c.AF.INET;
        switch (address.inner) {
            .ip4 => |ip4| {
                sa.port = std.mem.nativeToBig(u16, ip4.port);
                sa.addr = @bitCast(ip4.bytes);
            },
            .ip6 => return error.InvalidAddress,
        }
        @memset(&sa.zero, 0);

        const rc = std.c.connect(fd, @ptrCast(&sa), @sizeOf(std.c.sockaddr.in));
        if (rc != 0) {
            _ = std.c.close(fd);
            return error.ConnectionFailed;
        }

        if (timeout_ms) |timeout| {
            try setReadTimeout(fd, timeout);
            try setWriteTimeout(fd, timeout);
        }

        return .{ .fd = fd, .stream = .{ .fd = fd } };
    }

    /// Connect by hostname with DNS resolution
    pub fn connectHost(hostname: []const u8, port: u16, timeout_ms: ?u32) !TcpSocket {
        const address = try Address.resolveIp(hostname, port);
        return connect(address, timeout_ms);
    }

    /// Close the socket
    pub fn close(self: *TcpSocket) void {
        _ = std.c.close(self.fd);
        self.fd = -1;
    }

    /// Read data from socket
    pub fn read(self: *TcpSocket, buffer: []u8) !usize {
        return self.stream.read(buffer);
    }

    /// Read exactly n bytes
    pub fn readAll(self: *TcpSocket, buffer: []u8) !void {
        var index: usize = 0;
        while (index < buffer.len) {
            const n = try self.stream.read(buffer[index..]);
            if (n == 0) return error.EndOfStream;
            index += n;
        }
    }

    /// Write data to socket
    pub fn write(self: *TcpSocket, data: []const u8) !usize {
        const rc = std.c.write(self.fd, data.ptr, data.len);
        if (rc < 0) return error.ConnectionFailed;
        return @intCast(rc);
    }

    /// Write all data
    pub fn writeAll(self: *TcpSocket, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            const rc = std.c.write(self.fd, data[index..].ptr, data.len - index);
            if (rc < 0) return error.ConnectionFailed;
            index += @intCast(rc);
        }
    }

    /// Get socket for use with TLS and socket operations
    pub fn getFd(self: *const TcpSocket) posix.socket_t {
        return self.fd;
    }

    /// Get socket_t handle for socket operations
    fn sock(self: *const TcpSocket) posix.socket_t {
        return self.fd;
    }

    /// Set read timeout in milliseconds
    pub fn setReadTimeout(fd: posix.socket_t, ms: u32) !void {
        const timeout = posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    }

    /// Set write timeout in milliseconds
    pub fn setWriteTimeout(fd: posix.socket_t, ms: u32) !void {
        const timeout = posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
    }

    /// Enable TCP keepalive
    pub fn setKeepalive(self: *TcpSocket, enable: bool) !void {
        const val: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.sock(), posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&val));
    }

    /// Set TCP nodelay (disable Nagle's algorithm)
    pub fn setNoDelay(self: *TcpSocket, enable: bool) !void {
        const val: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.sock(), posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&val));
    }

    /// Check if socket has data available (non-blocking)
    pub fn poll(self: *TcpSocket, timeout_ms: i32) !bool {
        var pfd = [_]posix.pollfd{
            .{
                .fd = self.sock(),
                .events = posix.POLL.IN,
                .revents = 0,
            },
        };

        const result = try posix.poll(&pfd, timeout_ms);
        return result > 0 and (pfd[0].revents & posix.POLL.IN) != 0;
    }
};

/// TCP Server (listener)
pub const TcpListener = struct {
    fd: posix.socket_t,
    listen_addr: net.IpAddress,

    pub fn init(address: Address, backlog: u31) !TcpListener {
        const fd = try std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
        if (fd < 0) return error.InvalidAddress;
        errdefer _ = std.c.close(fd);

        // Set SO_REUSEADDR
        const one: u32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        // Build sockaddr and bind
        var sa: std.c.sockaddr.in = undefined;
        sa.len = @sizeOf(std.c.sockaddr.in);
        sa.family = std.c.AF.INET;
        switch (address.inner) {
            .ip4 => |ip4| {
                sa.port = std.mem.nativeToBig(u16, ip4.port);
                sa.addr = @bitCast(ip4.bytes);
            },
            .ip6 => return error.InvalidAddress,
        }
        @memset(&sa.zero, 0);

        _ = std.c.bind(fd, @ptrCast(&sa), @sizeOf(std.c.sockaddr.in));
        _ = std.c.listen(fd, @intCast(backlog));

        return .{ .fd = fd, .listen_addr = address.inner };
    }

    pub fn initPort(port: u16, backlog: u31) !TcpListener {
        const addr = net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
        return init(.{ .inner = addr }, backlog);
    }

    pub fn accept(self: *TcpListener) !TcpSocket {
        const fd = std.c.accept(self.fd, null, null);
        if (fd < 0) return error.ConnectionFailed;
        return .{ .fd = fd, .stream = .{ .fd = fd } };
    }

    pub fn close(self: *TcpListener) void {
        _ = std.c.close(self.fd);
        self.fd = -1;
    }

    pub fn getLocalAddress(self: *const TcpListener) Address {
        return .{ .inner = self.listen_addr };
    }
};

// ============================================================================
// UDP Socket
// ============================================================================

/// UDP Socket wrapper for datagram I/O
pub const UdpSocket = struct {
    fd: posix.socket_t,
    bound_port: u16 = 0,

    /// Create and bind a UDP socket to a local port (0 = system-assigned).
    pub fn bind(port: u16, family: AddressFamily) !UdpSocket {
        _ = family; // Use IPv4 for now

        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
        if (fd < 0) return error.AddressNotAvailable;
        errdefer _ = std.c.close(fd);

        // Allow address reuse
        const one: u32 = 1;
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one));

        // Bind to IPv4 0.0.0.0:port
        var sa: std.c.sockaddr.in = undefined;
        sa.len = @sizeOf(std.c.sockaddr.in);
        sa.family = std.c.AF.INET;
        sa.port = std.mem.nativeToBig(u16, port);
        sa.addr = 0;
        @memset(&sa.zero, 0);
        _ = std.c.bind(fd, @ptrCast(&sa), @sizeOf(std.c.sockaddr.in));

        // Retrieve actual bound port
        var sa_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        _ = std.c.getsockname(fd, @ptrCast(&sa), &sa_len);
        const real_port = std.mem.bigToNative(u16, sa.port);

        return .{ .fd = fd, .bound_port = real_port };
    }

    /// Close the socket.
    pub fn close(self: *UdpSocket) void {
        if (builtin.os.tag == .windows) {
            _ = std.os.windows.ws2_32.closesocket(self.fd);
            self.fd = @ptrFromInt(std.math.maxInt(usize));
        } else {
            _ = std.c.close(self.fd);
            self.fd = -1;
        }
    }

    /// Send a datagram to a specific address.
    pub fn sendTo(self: *const UdpSocket, data: []const u8, dest: Address) !usize {
        // Convert IpAddress to sockaddr.in
        const addr = dest.inner;
        const sa = switch (addr) {
            .ip4 => |ip4| blk: {
                var sa_in: std.c.sockaddr.in = undefined;
                sa_in.len = @sizeOf(std.c.sockaddr.in);
                sa_in.family = std.c.AF.INET;
                sa_in.port = std.mem.nativeToBig(u16, ip4.port);
                sa_in.addr = @bitCast(ip4.bytes);
                @memset(&sa_in.zero, 0);
                break :blk sa_in;
            },
            .ip6 => return error.InvalidAddress,
        };
        const n = std.c.sendto(self.fd, data.ptr, data.len, 0, @ptrCast(&sa), @sizeOf(std.c.sockaddr.in));
        if (n == -1) return 0;
        return @intCast(n);
    }

    /// Receive a datagram. Returns bytes read and sender address.
    pub fn recvFrom(self: *const UdpSocket, buf: []u8) !struct { len: usize, from: Address } {
        var src_addr: std.c.sockaddr.storage = undefined;
        var src_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
        const n = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(&src_addr), &src_len);
        if (n == -1) {
            return .{ .len = 0, .from = undefined };
        }
        // Convert storage to IpAddress
        const src_in: *const std.c.sockaddr.in = @ptrCast(&src_addr);
        const port: u16 = std.mem.bigToNative(u16, src_in.port);
        const ip_bytes: [4]u8 = @bitCast(src_in.addr);
        const ip = net.IpAddress{ .ip4 = .{ .bytes = ip_bytes, .port = port } };
        return .{ .len = @intCast(n), .from = .{ .inner = ip } };
    }

    /// Get the socket for use with poll().
    pub fn getFd(self: *const UdpSocket) posix.socket_t {
        return self.fd;
    }

    /// Set receive buffer size.
    pub fn setRecvBufSize(self: *const UdpSocket, size: u32) !void {
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&size));
    }

    /// Set send buffer size.
    pub fn setSendBufSize(self: *const UdpSocket, size: u32) !void {
        try posix.setsockopt(self.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, std.mem.asBytes(&size));
    }
};

// ============================================================================
// DNS resolution utilities
// ============================================================================

/// DNS resolver result
pub const ResolvedAddress = struct {
    addresses: []net.IpAddress,
    allocator: Allocator,

    pub fn deinit(self: *ResolvedAddress) void {
        self.allocator.free(self.addresses);
    }
};

/// Resolve hostname to IP addresses
pub fn resolve(allocator: Allocator, hostname: []const u8, port: u16) !ResolvedAddress {
    // Stub: net.getAddressList removed in Zig 0.16. Real resolution on iOS
    // goes through vpn_client.zig's resolveDns using the Swift bridge.
    _ = allocator;
    _ = hostname;
    _ = port;
    return error.DnsResolutionFailed;
}

// ============================================================================
// Connection state tracking
// ============================================================================

pub const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    tls_handshaking,
    tls_established,
    closing,
    closed,
    error_state,
};

/// Connection info for diagnostics
pub const ConnectionInfo = struct {
    local_address: ?Address = null,
    remote_address: ?Address = null,
    state: ConnectionState = .disconnected,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    connect_time_ms: ?u64 = null,
    last_activity_time: ?i64 = null,
};

// ============================================================================
// Tests
// ============================================================================

test "Address parsing" {
    const addr = try Address.parseIp4("127.0.0.1", 443);
    try testing.expectEqual(@as(u16, 443), addr.getPort());
}

test "Address IPv6 parsing" {
    const addr = try Address.parseIp6("::1", 8080);
    try testing.expectEqual(@as(u16, 8080), addr.getPort());
}
