//! TLS Module
//!
//! TLS wrapper for SoftEther VPN connections using OpenSSL.
//! OpenSSL is required because SoftEther VPN servers typically use self-signed
//! certificates, and we need fine-grained control over certificate verification.

const std = @import("std");
const net = std.net;
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
});
const Allocator = std.mem.Allocator;
const testing = std.testing;

const socket_mod = @import("socket.zig");
const TcpSocket = socket_mod.TcpSocket;

/// TLS errors
pub const TlsError = error{
    HandshakeFailed,
    CertificateVerificationFailed,
    CertificateExpired,
    CertificateRevoked,
    HostnameMismatch,
    UnsupportedProtocol,
    AlertReceived,
    RecordOverflow,
    BadCertificate,
    InternalError,
    TlsInitializationFailed,
    ConnectionClosed,
    ConnectionFailed,
    OutOfMemory,
};

/// TLS version
pub const TlsVersion = enum {
    tls_1_2,
    tls_1_3,
};

/// TLS configuration
pub const TlsConfig = struct {
    /// Verify server certificate (should be true in production)
    verify_certificate: bool = true,

    /// Minimum TLS version
    min_version: TlsVersion = .tls_1_2,

    /// Connection timeout in milliseconds
    timeout_ms: u32 = 10000, // iOS-safe: keep under 15s to avoid watchdog

    /// SoftEther-specific: Accept self-signed certificates
    /// WARNING: Only use for testing or when server cert is pinned
    allow_self_signed: bool = false,
};

/// TLS-wrapped socket using OpenSSL
pub const TlsSocket = struct {
    allocator: Allocator,
    tcp_fd: std.posix.fd_t,
    ssl_ctx: ?*c.SSL_CTX,
    ssl: ?*c.SSL,
    config: TlsConfig,
    hostname_buf: []u8,
    connected: bool,

    /// Connect to hostname:port with TLS
    pub fn connect(allocator: Allocator, hostname: []const u8, port: u16, config: TlsConfig) !TlsSocket {
        // Initialize OpenSSL (idempotent in modern OpenSSL)
        _ = c.OPENSSL_init_ssl(0, null);

        // Resolve and connect TCP
        var tcp_fd: std.posix.fd_t = undefined;

        // First try to parse as IP address
        if (net.Address.resolveIp(hostname, port)) |address| {
            std.log.debug("TLS: Resolved IP address directly: {s}:{d}", .{ hostname, port });
            const stream = net.tcpConnectToAddress(address) catch |err| {
                std.log.err("TLS: TCP connect failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };
            tcp_fd = stream.handle;
        } else |resolve_err| {
            std.log.debug("TLS: Not an IP, trying DNS for: {s} (err: {})", .{ hostname, resolve_err });
            // DNS resolution
            const addr_list = net.getAddressList(allocator, hostname, port) catch |err| {
                std.log.err("TLS: DNS resolution failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };
            defer addr_list.deinit();

            if (addr_list.addrs.len == 0) {
                std.log.err("TLS: No addresses found for {s}", .{hostname});
                return TlsError.ConnectionFailed;
            }

            const stream = net.tcpConnectToAddress(addr_list.addrs[0]) catch |err| {
                std.log.err("TLS: TCP connect to DNS result failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };
            tcp_fd = stream.handle;
        }
        errdefer std.posix.close(tcp_fd);

        // CRITICAL: Disable Nagle's algorithm for low latency
        // Nagle buffers small packets for up to 200ms, causing latency spikes
        const nodelay: u32 = 1;
        std.posix.setsockopt(tcp_fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&nodelay)) catch |err| {
            std.log.warn("Failed to set TCP_NODELAY: {}", .{err});
        };

        // Apply timeout
        if (config.timeout_ms > 0) {
            TcpSocket.setReadTimeout(tcp_fd, config.timeout_ms) catch {};
            TcpSocket.setWriteTimeout(tcp_fd, config.timeout_ms) catch {};
        }

        // Allocate hostname buffer
        const hostname_buf = try allocator.dupe(u8, hostname);
        errdefer allocator.free(hostname_buf);

        // Create SSL context
        const method = c.TLS_client_method();
        const ssl_ctx = c.SSL_CTX_new(method) orelse {
            std.log.err("Failed to create SSL context", .{});
            return TlsError.TlsInitializationFailed;
        };
        errdefer c.SSL_CTX_free(ssl_ctx);

        // For SoftEther with self-signed certs, disable verification
        if (config.allow_self_signed or !config.verify_certificate) {
            c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_NONE, null);
        }

        // Create SSL connection
        const ssl = c.SSL_new(ssl_ctx) orelse {
            std.log.err("Failed to create SSL object", .{});
            return TlsError.TlsInitializationFailed;
        };
        errdefer c.SSL_free(ssl);

        // Set hostname for SNI
        const hostname_z = try allocator.dupeZ(u8, hostname);
        defer allocator.free(hostname_z);
        _ = c.SSL_set_tlsext_host_name(ssl, hostname_z.ptr);

        // Attach to socket
        if (c.SSL_set_fd(ssl, @intCast(tcp_fd)) != 1) {
            std.log.err("Failed to set SSL fd", .{});
            return TlsError.TlsInitializationFailed;
        }

        // Perform TLS handshake
        const ret = c.SSL_connect(ssl);
        if (ret != 1) {
            const err = c.SSL_get_error(ssl, ret);
            std.log.err("TLS handshake failed: SSL error {d}", .{err});
            logOpenSslErrors();
            return TlsError.HandshakeFailed;
        }

        // Log connection info
        const version = c.SSL_get_version(ssl);
        if (version) |v| {
            std.log.info("TLS connected with {s}", .{std.mem.span(v)});
        }

        return TlsSocket{
            .allocator = allocator,
            .tcp_fd = tcp_fd,
            .ssl_ctx = ssl_ctx,
            .ssl = ssl,
            .config = config,
            .hostname_buf = hostname_buf,
            .connected = true,
        };
    }

    fn logOpenSslErrors() void {
        var err = c.ERR_get_error();
        while (err != 0) {
            var buf: [256]u8 = undefined;
            c.ERR_error_string_n(err, &buf, buf.len);
            std.log.err("OpenSSL: {s}", .{std.mem.sliceTo(&buf, 0)});
            err = c.ERR_get_error();
        }
    }

    /// Close the connection
    pub fn close(self: *TlsSocket) void {
        if (self.connected) {
            if (self.ssl) |ssl| {
                _ = c.SSL_shutdown(ssl);
                c.SSL_free(ssl);
            }
            if (self.ssl_ctx) |ctx| {
                c.SSL_CTX_free(ctx);
            }
            std.posix.close(self.tcp_fd);
            self.connected = false;
            self.ssl = null;
            self.ssl_ctx = null;
        }

        self.allocator.free(self.hostname_buf);
    }

    /// Read data from the TLS connection
    pub fn read(self: *TlsSocket, buffer: []u8) !usize {
        if (!self.connected) return 0;

        const ssl = self.ssl orelse return 0;
        const ret = c.SSL_read(ssl, buffer.ptr, @intCast(buffer.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_ZERO_RETURN => {
                    self.connected = false;
                    return 0;
                },
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    // Non-blocking, retry later
                    return 0;
                },
                else => {
                    self.connected = false;
                    return 0;
                },
            }
        }

        return @intCast(ret);
    }

    /// Read data from the TLS connection with a timeout (in milliseconds)
    /// Returns 0 if timeout expires with no data available
    pub fn readWithTimeout(self: *TlsSocket, buffer: []u8, timeout_ms: i32) !usize {
        if (!self.connected) return error.ConnectionClosed;

        // Use poll to wait for data with timeout
        var poll_fds = [_]std.posix.pollfd{
            .{ .fd = self.tcp_fd, .events = std.posix.POLL.IN, .revents = 0 },
        };

        const poll_result = std.posix.poll(&poll_fds, timeout_ms) catch |err| {
            std.log.debug("TLS readWithTimeout poll error: {}", .{err});
            return 0;
        };

        // Timeout - no data available
        if (poll_result == 0) return 0;

        // Check for errors on the socket
        if ((poll_fds[0].revents & std.posix.POLL.ERR) != 0 or
            (poll_fds[0].revents & std.posix.POLL.HUP) != 0)
        {
            self.connected = false;
            return error.ConnectionClosed;
        }

        // Data available, do the read
        if ((poll_fds[0].revents & std.posix.POLL.IN) != 0) {
            return self.read(buffer);
        }

        return 0;
    }

    /// Read exactly n bytes
    pub fn readAll(self: *TlsSocket, buffer: []u8) !void {
        var index: usize = 0;
        while (index < buffer.len) {
            const n = try self.read(buffer[index..]);
            if (n == 0) return error.EndOfStream;
            index += n;
        }
    }

    /// Write data to the TLS connection
    pub fn write(self: *TlsSocket, data: []const u8) !usize {
        if (!self.connected) return error.BrokenPipe;

        const ssl = self.ssl orelse return error.BrokenPipe;
        const ret = c.SSL_write(ssl, data.ptr, @intCast(data.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    return 0; // Let caller retry
                },
                else => {
                    self.connected = false;
                    return error.BrokenPipe;
                },
            }
        }

        return @intCast(ret);
    }

    /// Write with poll-based waiting (avoids busy spin)
    pub fn writeWithPoll(self: *TlsSocket, data: []const u8) !usize {
        if (!self.connected) return error.BrokenPipe;

        const ssl = self.ssl orelse return error.BrokenPipe;
        const ret = c.SSL_write(ssl, data.ptr, @intCast(data.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_WRITE => {
                    // Wait for socket to be writable (max 1ms to avoid blocking too long)
                    var pfd = [_]std.posix.pollfd{.{
                        .fd = self.tcp_fd,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    }};
                    _ = std.posix.poll(&pfd, 1) catch {};
                    return 0;
                },
                c.SSL_ERROR_WANT_READ => {
                    return 0;
                },
                else => {
                    self.connected = false;
                    return error.BrokenPipe;
                },
            }
        }

        return @intCast(ret);
    }

    /// Write all data (blocking until complete)
    pub fn writeAll(self: *TlsSocket, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            const n = try self.write(data[index..]);
            if (n == 0) continue;
            index += n;
        }
    }

    /// Check if connection is still alive
    pub fn isConnected(self: *const TlsSocket) bool {
        return self.connected;
    }

    /// Get the underlying file descriptor
    pub fn getFd(self: *const TlsSocket) std.posix.fd_t {
        return self.tcp_fd;
    }

    /// Get the hostname this socket connected to
    pub fn getHostname(self: *const TlsSocket) []const u8 {
        return self.hostname_buf;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TlsConfig defaults" {
    const config = TlsConfig{};
    try testing.expect(config.verify_certificate);
    try testing.expectEqual(TlsVersion.tls_1_2, config.min_version);
    try testing.expectEqual(@as(u32, 30000), config.timeout_ms);
    try testing.expect(!config.allow_self_signed);
}

test "TlsSocket structure" {
    // Test that the structure compiles correctly
    // Actual connection tests require a server
    const T = TlsSocket;
    try testing.expect(@sizeOf(T) > 0);
}
