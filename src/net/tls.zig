//! TLS Module
//!
//! TLS wrapper for SoftEther VPN connections using OpenSSL.
//! OpenSSL is required because SoftEther VPN servers typically use self-signed
//! certificates, and we need fine-grained control over certificate verification.

const std = @import("std");
const builtin = @import("builtin");
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
const dns_cache_mod = @import("dns_cache.zig");

/// Global DNS cache instance for TLS connections
var global_dns_cache: ?dns_cache_mod.DnsCache = null;
var dns_cache_init_mutex: std.Thread.Mutex = .{};

/// Get or initialize the global DNS cache
fn getDnsCache(allocator: Allocator) *dns_cache_mod.DnsCache {
    dns_cache_init_mutex.lock();
    defer dns_cache_init_mutex.unlock();

    if (global_dns_cache == null) {
        global_dns_cache = dns_cache_mod.DnsCache.init(allocator, null);
    }
    return &global_dns_cache.?;
}

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
    timeout_ms: u32 = 30000,

    /// SoftEther-specific: Accept self-signed certificates
    /// WARNING: Only use for testing or when server cert is pinned
    allow_self_signed: bool = false,

    /// Client certificate PEM data (for certificate authentication)
    client_cert_pem: ?[]const u8 = null,

    /// Client private key PEM data (for certificate authentication)
    client_key_pem: ?[]const u8 = null,
};

/// TCP connect with configurable timeout using non-blocking socket + poll.
/// Avoids the OS default 75s SYN timeout that causes apparent freezes.
fn tcpConnectWithTimeout(address: net.Address, timeout_ms: u32) !std.posix.socket_t {
    const fd = try std.posix.socket(address.any.family, std.posix.SOCK.STREAM, 0);
    errdefer {
        if (builtin.os.tag == .windows) {
            _ = std.os.windows.ws2_32.closesocket(fd);
        } else {
            std.posix.close(fd);
        }
    }

    if (builtin.os.tag == .windows) {
        // Windows: use ioctlsocket for non-blocking mode
        const ws2 = std.os.windows.ws2_32;
        var nonblocking: c_ulong = 1;
        _ = ws2.ioctlsocket(fd, @as(i32, @bitCast(@as(u32, 0x8004667e))), &nonblocking); // FIONBIO

        // Initiate connect
        std.posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };

        // Poll for write-readiness
        var poll_fds = [1]std.posix.pollfd{
            .{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 },
        };
        const effective_timeout: i32 = if (timeout_ms > 0) @intCast(timeout_ms) else 30000;
        const poll_result = try std.posix.poll(&poll_fds, effective_timeout);
        if (poll_result == 0) {
            return error.ConnectionTimedOut;
        }

        // Check for connect error via revents
        if (poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0) {
            std.log.err("TLS: TCP connect failed (poll revents={x})", .{poll_fds[0].revents});
            return error.ConnectionRefused;
        }

        // Restore blocking mode
        nonblocking = 0;
        _ = ws2.ioctlsocket(fd, @as(i32, @bitCast(@as(u32, 0x8004667e))), &nonblocking); // FIONBIO
    } else {
        // POSIX: use fcntl for non-blocking mode
        // O_NONBLOCK differs per OS: macOS/BSD = 0x0004, Linux/Android = 0x0800
        const O_NONBLOCK: usize = if (builtin.os.tag == .linux) 0x0800 else 0x0004;
        const flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags | O_NONBLOCK);

        // Initiate connect — returns immediately with WouldBlock (EINPROGRESS)
        std.posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        };

        // Poll for write-readiness (connection completion)
        var poll_fds = [1]std.posix.pollfd{
            .{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 },
        };
        const effective_timeout: i32 = if (timeout_ms > 0) @intCast(timeout_ms) else 30000;
        const poll_result = try std.posix.poll(&poll_fds, effective_timeout);
        if (poll_result == 0) {
            return error.ConnectionTimedOut;
        }

        // Check for connect error via SO_ERROR
        var so_error: c_int = 0;
        var optlen: std.posix.socklen_t = @sizeOf(c_int);
        const rc = std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_error), &optlen);
        if (rc != 0) {
            return error.ConnectionRefused;
        }
        if (so_error != 0) {
            return error.ConnectionRefused;
        }

        // Restore blocking mode
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags);
    }

    return fd;
}

/// TLS-wrapped socket using OpenSSL
pub const TlsSocket = struct {
    allocator: Allocator,
    tcp_fd: std.posix.socket_t,
    ssl_ctx: ?*c.SSL_CTX,
    ssl: ?*c.SSL,
    config: TlsConfig,
    hostname_buf: []u8,
    connected: bool,
    /// Counter incremented every time writeAllNonBlocking polls POLLOUT (i.e.
    /// the underlying TCP sndbuf was full). Surfaced via DIAG to detect
    /// TX-bound bufferbloat.
    write_block_count: u64 = 0,

    /// Connect to hostname:port with TLS
    pub fn connect(allocator: Allocator, hostname: []const u8, port: u16, config: TlsConfig) !TlsSocket {
        // Initialize OpenSSL (idempotent in modern OpenSSL)
        _ = c.OPENSSL_init_ssl(0, null);

        // Resolve and connect TCP
        var tcp_fd: std.posix.socket_t = undefined;

        // First try to parse as IP address
        if (net.Address.resolveIp(hostname, port)) |address| {
            std.log.debug("TLS: Resolved IP address directly: {s}:{d}", .{ hostname, port });
            tcp_fd = tcpConnectWithTimeout(address, config.timeout_ms) catch |err| {
                std.log.err("TLS: TCP connect failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };
        } else |resolve_err| {
            std.log.debug("TLS: Not an IP, trying DNS for: {s} (err: {})", .{ hostname, resolve_err });

            // Try DNS cache first, fall back to OS resolution
            const cache = getDnsCache(allocator);
            const cached_addrs = cache.resolveWithCache(hostname, port) catch |err| {
                std.log.err("TLS: DNS resolution failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };

            if (cached_addrs.len == 0) {
                std.log.err("TLS: No addresses found for {s}", .{hostname});
                return TlsError.ConnectionFailed;
            }

            tcp_fd = tcpConnectWithTimeout(cached_addrs[0], config.timeout_ms) catch |err| {
                // Invalidate cache on connection failure — address may have changed
                cache.invalidate(hostname);
                std.log.err("TLS: TCP connect to DNS result failed: {}", .{err});
                return TlsError.ConnectionFailed;
            };
        }
        errdefer {
            if (builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(tcp_fd);
            } else {
                std.posix.close(tcp_fd);
            }
        }

        // CRITICAL: Disable Nagle's algorithm for low latency
        // Nagle buffers small packets for up to 200ms, causing latency spikes
        const nodelay: u32 = 1;
        const IPPROTO_TCP = 6;
        const TCP_NODELAY = 1;
        std.posix.setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, std.mem.asBytes(&nodelay)) catch |err| {
            std.log.warn("Failed to set TCP_NODELAY: {}", .{err});
        };

        // CYCLE 11 (TURN 16b): TCP_NOTSENT_LOWAT REMOVED — see clearTimeouts() comment.
        // Bufferbloat is bounded by SO_SNDBUF=512KB cap (set in clearTimeouts post-handshake).

        // On Windows, disable delayed ACKs — default 200ms ACK delay adds latency
        if (builtin.os.tag == .windows) {
            const SIO_TCP_SET_ACK_FREQUENCY = @as(u32, 0x98000017);
            var ack_freq: u32 = 1; // ACK every packet immediately
            var bytes_returned: u32 = 0;
            _ = std.os.windows.ws2_32.WSAIoctl(
                tcp_fd,
                SIO_TCP_SET_ACK_FREQUENCY,
                @ptrCast(&ack_freq),
                @sizeOf(u32),
                null,
                0,
                &bytes_returned,
                null,
                null,
            );
        }

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

        // Load client certificate for certificate authentication
        if (config.client_cert_pem) |cert_pem| {
            const cert_bio = c.BIO_new_mem_buf(cert_pem.ptr, @intCast(cert_pem.len)) orelse {
                std.log.err("TLS: Failed to create BIO for client certificate", .{});
                return TlsError.TlsInitializationFailed;
            };
            defer _ = c.BIO_free(cert_bio);
            const cert = c.PEM_read_bio_X509(cert_bio, null, null, null) orelse {
                std.log.err("TLS: Failed to parse client certificate PEM", .{});
                return TlsError.BadCertificate;
            };
            defer c.X509_free(cert);
            if (c.SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
                std.log.err("TLS: Failed to set client certificate", .{});
                logOpenSslErrors();
                return TlsError.BadCertificate;
            }
            std.log.info("TLS: Client certificate loaded", .{});
        }

        // Load client private key for certificate authentication
        if (config.client_key_pem) |key_pem| {
            const key_bio = c.BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse {
                std.log.err("TLS: Failed to create BIO for client key", .{});
                return TlsError.TlsInitializationFailed;
            };
            defer _ = c.BIO_free(key_bio);
            const pkey = c.PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse {
                std.log.err("TLS: Failed to parse client private key PEM", .{});
                return TlsError.BadCertificate;
            };
            defer c.EVP_PKEY_free(pkey);
            if (c.SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
                std.log.err("TLS: Failed to set client private key", .{});
                logOpenSslErrors();
                return TlsError.BadCertificate;
            }
            // Verify cert/key match
            if (c.SSL_CTX_check_private_key(ssl_ctx) != 1) {
                std.log.err("TLS: Client certificate and private key do not match", .{});
                logOpenSslErrors();
                return TlsError.BadCertificate;
            }
            std.log.info("TLS: Client private key loaded and verified", .{});
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
        const fd_int: c_int = if (builtin.os.tag == .windows) @intCast(@intFromPtr(tcp_fd)) else @intCast(tcp_fd);
        if (c.SSL_set_fd(ssl, fd_int) != 1) {
            std.log.err("Failed to set SSL fd", .{});
            return TlsError.TlsInitializationFailed;
        }

        // Perform TLS handshake with retry loop for WANT_READ/WANT_WRITE
        // (defensive: blocking sockets can still return these in edge cases on Android)
        const fd_for_poll: std.posix.socket_t = tcp_fd;
        var attempts: u32 = 0;
        const max_attempts: u32 = 100;
        while (true) : (attempts += 1) {
            if (attempts >= max_attempts) {
                std.log.err("TLS handshake failed: exceeded max retries", .{});
                return TlsError.HandshakeFailed;
            }
            const ret = c.SSL_connect(ssl);
            if (ret == 1) break;
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_READ => {
                    var pfd = [1]std.posix.pollfd{.{ .fd = fd_for_poll, .events = std.posix.POLL.IN, .revents = 0 }};
                    const pr = std.posix.poll(&pfd, 30000) catch 0;
                    if (pr == 0) {
                        std.log.err("TLS handshake failed: timeout waiting for read", .{});
                        return TlsError.HandshakeFailed;
                    }
                    continue;
                },
                c.SSL_ERROR_WANT_WRITE => {
                    var pfd = [1]std.posix.pollfd{.{ .fd = fd_for_poll, .events = std.posix.POLL.OUT, .revents = 0 }};
                    const pr = std.posix.poll(&pfd, 30000) catch 0;
                    if (pr == 0) {
                        std.log.err("TLS handshake failed: timeout waiting for write", .{});
                        return TlsError.HandshakeFailed;
                    }
                    continue;
                },
                else => {
                    std.log.err("TLS handshake failed: SSL error {d} (ret={d}, errno={d})", .{ err, ret, std.c._errno().* });
                    logOpenSslErrors();
                    return TlsError.HandshakeFailed;
                },
            }
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
            if (builtin.os.tag == .windows) {
                _ = std.os.windows.ws2_32.closesocket(self.tcp_fd);
            } else {
                std.posix.close(self.tcp_fd);
            }
            self.connected = false;
            self.ssl = null;
            self.ssl_ctx = null;
        }

        self.allocator.free(self.hostname_buf);
    }

    /// Read data from the TLS connection.
    ///
    /// Semantics:
    ///   N > 0          : received N bytes
    ///   0              : peer closed gracefully (TLS close_notify)
    ///   error.WouldBlock : non-blocking socket has no data right now (caller retry)
    ///   error.BrokenPipe : hard TLS / TCP error; connection lost
    ///
    /// On a blocking socket, WouldBlock should not occur. After calling
    /// setNonBlocking() (data plane), callers MUST handle WouldBlock as a
    /// normal "no data yet" signal, not an error.
    pub fn read(self: *TlsSocket, buffer: []u8) !usize {
        if (!self.connected) return error.BrokenPipe;

        const ssl = self.ssl orelse return error.BrokenPipe;
        const ret = c.SSL_read(ssl, buffer.ptr, @intCast(buffer.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_ZERO_RETURN => {
                    self.connected = false;
                    return 0;
                },
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    // Non-blocking socket: nothing available right now.
                    return error.WouldBlock;
                },
                else => {
                    std.log.err("TlsSocket.read: SSL_get_error={d} ret={d} errno={d}", .{ err, ret, std.c._errno().* });
                    logOpenSslErrors();
                    self.connected = false;
                    return error.BrokenPipe;
                },
            }
        }

        return @intCast(ret);
    }

    /// Read with built-in poll-on-WouldBlock retry, for control-plane use
    /// where the caller expects classical blocking semantics regardless of
    /// the underlying socket mode. Returns 0 only on graceful TLS close.
    pub fn readBlocking(self: *TlsSocket, buffer: []u8) !usize {
        while (true) {
            const n = self.read(buffer) catch |err| switch (err) {
                error.WouldBlock => {
                    var pfd = [_]std.posix.pollfd{.{
                        .fd = self.tcp_fd,
                        .events = std.posix.POLL.IN,
                        .revents = 0,
                    }};
                    const pr = std.posix.poll(&pfd, 30000) catch 0;
                    if (pr == 0) return error.BrokenPipe;
                    continue;
                },
                else => return err,
            };
            return n;
        }
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

    /// Check if OpenSSL has buffered decrypted application data invisible to poll().
    /// SSL records may contain multiple application messages; SSL_read can leave
    /// some buffered in the SSL object even when the kernel TCP buffer is empty
    /// (poll() will report POLL.IN unset). Without this check the data loop
    /// sleeps in poll while the next batch of bytes is already decrypted and
    /// waiting — a major source of stalls under bursty inbound traffic.
    pub fn hasPending(self: *TlsSocket) bool {
        const ssl = self.ssl orelse return false;
        return c.SSL_pending(ssl) > 0;
    }

    /// DIAGNOSTIC: Returns count of decrypted bytes buffered inside OpenSSL.
    pub fn pendingBytes(self: *const TlsSocket) u32 {
        const ssl = self.ssl orelse return 0;
        const p = c.SSL_pending(ssl);
        return if (p > 0) @intCast(p) else 0;
    }

    /// DIAGNOSTIC (macOS): Returns bytes currently sitting in the kernel TCP
    /// recv queue (i.e. arrived from network but not yet read by us). High
    /// values mean we're not draining fast enough → server's advertised
    /// window is shrinking → TCP backpressure.
    pub fn kernelRecvQueue(self: *const TlsSocket) u32 {
        if (builtin.os.tag != .macos) return 0;
        var n: c_int = 0;
        var len: u32 = @sizeOf(c_int);
        // SO_NREAD = 0x1020 on macOS/Darwin
        const SO_NREAD: u32 = 0x1020;
        const fd_int: c_int = @intCast(self.tcp_fd);
        const rc = std.c.getsockopt(fd_int, std.posix.SOL.SOCKET, SO_NREAD, &n, &len);
        if (rc != 0 or n < 0) return 0;
        return @intCast(n);
    }

    /// DIAGNOSTIC (macOS): Returns bytes currently sitting in the kernel TCP
    /// send queue (queued but not yet ACK'd / sent). High values mean we
    /// can't push outbound fast enough → our send window is full → upload
    /// backpressure / risk of SSL_write deadlock.
    pub fn kernelSendQueue(self: *const TlsSocket) u32 {
        if (builtin.os.tag != .macos) return 0;
        var n: c_int = 0;
        var len: u32 = @sizeOf(c_int);
        // SO_NWRITE = 0x1024 on macOS/Darwin
        const SO_NWRITE: u32 = 0x1024;
        const fd_int: c_int = @intCast(self.tcp_fd);
        const rc = std.c.getsockopt(fd_int, std.posix.SOL.SOCKET, SO_NWRITE, &n, &len);
        if (rc != 0 or n < 0) return 0;
        return @intCast(n);
    }

    /// Write data to the TLS connection.
    ///
    /// Semantics:
    ///   N > 0          : wrote N bytes
    ///   0              : caller-supplied empty buffer
    ///   error.WouldBlock : non-blocking socket cannot accept data right now
    ///   error.BrokenPipe : hard TLS / TCP error; connection lost
    pub fn write(self: *TlsSocket, data: []const u8) !usize {
        if (!self.connected) return error.BrokenPipe;

        const ssl = self.ssl orelse return error.BrokenPipe;
        const ret = c.SSL_write(ssl, data.ptr, @intCast(data.len));

        if (ret <= 0) {
            const err = c.SSL_get_error(ssl, ret);
            switch (err) {
                c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {
                    return error.WouldBlock;
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

    /// Write all data, polling for socket writability when the kernel
    /// send buffer is full. Safe on a non-blocking socket: WouldBlock from
    /// SSL_write triggers a short poll(POLLOUT) wait and retry with the
    /// SAME data pointer (required by OpenSSL non-blocking write semantics).
    ///
    /// Used by the data-plane writer adapter so the per-packet sendBlocks
    /// path remains effectively atomic from the caller's perspective even
    /// after the socket is switched to non-blocking mode.
    pub fn writeAllNonBlocking(self: *TlsSocket, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            const n = self.write(data[index..]) catch |err| switch (err) {
                error.WouldBlock => {
                    self.write_block_count +%= 1;
                    var pfd = [_]std.posix.pollfd{.{
                        .fd = self.tcp_fd,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    }};
                    _ = std.posix.poll(&pfd, 50) catch {};
                    continue;
                },
                else => return err,
            };
            if (n == 0) return error.BrokenPipe;
            index += n;
        }
    }

    /// Switch the underlying TCP socket to non-blocking mode.
    /// Call this AFTER the TLS handshake has completed and BEFORE entering
    /// the data-plane poll loop. Once non-blocking:
    ///   - read()  returns error.WouldBlock when no data is available
    ///   - write() returns error.WouldBlock when kernel sndbuf is full
    /// Use writeAllNonBlocking() for sends that must complete atomically.
    pub fn setNonBlocking(self: *TlsSocket) !void {
        if (builtin.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            var nonblocking: c_ulong = 1;
            _ = ws2.ioctlsocket(self.tcp_fd, @as(i32, @bitCast(@as(u32, 0x8004667e))), &nonblocking);
        } else {
            const O_NONBLOCK: usize = 0x0004;
            const flags = try std.posix.fcntl(self.tcp_fd, std.posix.F.GETFL, 0);
            _ = try std.posix.fcntl(self.tcp_fd, std.posix.F.SETFL, flags | O_NONBLOCK);
        }
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

    /// Get the underlying socket
    pub fn getFd(self: *const TlsSocket) std.posix.socket_t {
        return self.tcp_fd;
    }

    /// Remove read/write timeouts set during connect phase and configure
    /// socket for the poll-based data loop. Matches C SoftEther's
    /// SetTimeout(sock, INFINITE) after connect.
    ///
    /// SO_SNDBUF policy:
    ///   - NONE → macOS autotunes to multi-MB → DL ACKs queue behind UL data
    ///     in TLS egress for 800-1400ms → server sees ACK loss → DL collapses
    ///     to 5-7 Mbps with 1100ms RTT spikes (Cloudflare-confirmed).
    ///   - 512KB cap (Cycle 10) → still queues ~50ms of DL ACKs; UL capped.
    ///   - 128KB cap → bounds DL-ACK queueing latency to ~10ms at 100 Mbps
    ///     egress while still allowing autotune RWND headroom on receive.
    ///     This is the latency vs throughput tradeoff for single-thread
    ///     poll-driven encap loop. Long-term fix is split-thread I/O.
    /// SO_RCVBUF: never touched. Autotune (macOS autorcvbufmax=4MB) is fine.
    pub fn clearTimeouts(self: *TlsSocket) void {
        TcpSocket.setReadTimeout(self.tcp_fd, 0) catch {};
        TcpSocket.setWriteTimeout(self.tcp_fd, 0) catch {};

        // Enable TCP keepalive
        const keepalive: u32 = 1;
        std.posix.setsockopt(self.tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&keepalive)) catch {};

        // SO_SNDBUF sizing tradeoff at typical 180ms tunnel RTT:
        //   128KB → UL choked at 5 Mbps (BDP cap, single-flow)
        //   256KB → UL ~11 Mbps, ~22ms ACK queue
        //   512KB → UL ~22 Mbps, ~45ms ACK queue
        //   1MB   → UL ~45 Mbps, ~90ms ACK queue (ping spike +90ms)
        //   2MB+  → UL good, but DL ACKs bloat → 1100ms+ ping → DL collapse
        // 1MB is the best single-knob compromise: full UL via single OR
        // parallel flows, DL ping under load stays under ~300ms.
        const snd_cap: u32 = 1024 * 1024;
        std.posix.setsockopt(self.tcp_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&snd_cap)) catch {};
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
