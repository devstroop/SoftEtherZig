//! Socket Utilities Module
//!
//! Socket operations
//! Provides cross-platform TCP/UDP socket abstractions.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const testing = std.testing;

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
    inner: net.Address,

    pub fn parseIp(ip: []const u8, port: u16) !Address {
        return .{ .inner = try net.Address.parseIp(ip, port) };
    }

    pub fn parseIp4(ip: []const u8, port: u16) !Address {
        return .{ .inner = try net.Address.parseIp4(ip, port) };
    }

    pub fn parseIp6(ip: []const u8, port: u16) !Address {
        return .{ .inner = try net.Address.parseIp6(ip, port) };
    }

    pub fn resolveIp(hostname: []const u8, port: u16) !Address {
        return .{ .inner = try net.Address.resolveIp(hostname, port) };
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

/// TCP Socket wrapper with timeout support
pub const TcpSocket = struct {
    stream: net.Stream,

    /// Connect to a remote address with timeout
    pub fn connect(address: Address, timeout_ms: ?u32) !TcpSocket {
        const stream = try net.tcpConnectToAddress(address.inner);

        if (timeout_ms) |timeout| {
            try setReadTimeout(stream.handle, timeout);
            try setWriteTimeout(stream.handle, timeout);
        }

        return .{ .stream = stream };
    }

    /// Connect by hostname with DNS resolution
    pub fn connectHost(hostname: []const u8, port: u16, timeout_ms: ?u32) !TcpSocket {
        const address = try Address.resolveIp(hostname, port);
        return connect(address, timeout_ms);
    }

    /// Close the socket
    pub fn close(self: *TcpSocket) void {
        self.stream.close();
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
        return self.stream.write(data);
    }

    /// Write all data
    pub fn writeAll(self: *TcpSocket, data: []const u8) !void {
        try self.stream.writeAll(data);
    }

    /// Get file descriptor for use with TLS
    pub fn getFd(self: *const TcpSocket) posix.fd_t {
        return self.stream.handle;
    }

    /// Set read timeout in milliseconds
    pub fn setReadTimeout(fd: posix.fd_t, ms: u32) !void {
        const timeout = posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    }

    /// Set write timeout in milliseconds
    pub fn setWriteTimeout(fd: posix.fd_t, ms: u32) !void {
        const timeout = posix.timeval{
            .sec = @intCast(ms / 1000),
            .usec = @intCast((ms % 1000) * 1000),
        };
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
    }

    /// Enable TCP keepalive
    pub fn setKeepalive(self: *TcpSocket, enable: bool) !void {
        const val: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.stream.handle, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&val));
    }

    /// Set TCP nodelay (disable Nagle's algorithm)
    pub fn setNoDelay(self: *TcpSocket, enable: bool) !void {
        const val: u32 = if (enable) 1 else 0;
        try posix.setsockopt(self.stream.handle, posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&val));
    }

    /// Check if socket has data available (non-blocking)
    pub fn poll(self: *TcpSocket, timeout_ms: i32) !bool {
        var pfd = [_]posix.pollfd{
            .{
                .fd = self.stream.handle,
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
    listener: net.Server,

    pub fn init(address: Address, backlog: u31) !TcpListener {
        const listener = try address.inner.listen(.{
            .reuse_address = true,
            .kernel_backlog = backlog,
        });
        return .{ .listener = listener };
    }

    pub fn initPort(port: u16, backlog: u31) !TcpListener {
        const address = Address{ .inner = net.Address.initIp4(.{ 0, 0, 0, 0 }, port) };
        return init(address, backlog);
    }

    pub fn accept(self: *TcpListener) !TcpSocket {
        const conn = try self.listener.accept();
        return .{ .stream = conn };
    }

    pub fn close(self: *TcpListener) void {
        self.listener.deinit();
    }

    pub fn getLocalAddress(self: *const TcpListener) Address {
        return .{ .inner = self.listener.listen_address };
    }
};

// ============================================================================
// DNS resolution utilities
// ============================================================================

/// DNS resolver result
pub const ResolvedAddress = struct {
    addresses: []net.Address,
    allocator: Allocator,

    pub fn deinit(self: *ResolvedAddress) void {
        self.allocator.free(self.addresses);
    }
};

/// Resolve hostname to IP addresses
pub fn resolve(allocator: Allocator, hostname: []const u8, port: u16) !ResolvedAddress {
    var list = std.ArrayList(net.Address).init(allocator);
    errdefer list.deinit();

    const addrs = try net.getAddressList(allocator, hostname, port);
    defer addrs.deinit();

    for (addrs.addrs) |addr| {
        try list.append(addr);
    }

    return .{
        .addresses = try list.toOwnedSlice(),
        .allocator = allocator,
    };
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
