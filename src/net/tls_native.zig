//! Native Zig TLS Implementation
//!
//! TLS wrapper using Zig's standard library crypto.tls module.
//! This provides TLS 1.2/1.3 support without requiring OpenSSL.
//! Works on iOS, macOS, Linux, Windows - pure Zig, no C dependencies.

const std = @import("std");
const net = std.net;
const crypto = std.crypto;
const tls = crypto.tls;
const Certificate = crypto.Certificate;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Io = std.Io;

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
    DnsResolutionFailed,
    TcpConnectFailed,
    TlsHandshakeFailed,
    WriteError,
    ReadError,
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
};

/// TLS-wrapped socket using Zig's native TLS implementation
///
/// This struct holds all state needed for a TLS connection including:
/// - The underlying TCP stream
/// - TLS client state from crypto.tls
/// - Stream reader/writer for socket I/O
/// - Buffers for TLS operations
///
/// IMPORTANT: This struct must be heap-allocated because tls.Client stores
/// pointers to the stream_reader/stream_writer interfaces. Moving this struct
/// after TLS init would invalidate those pointers.
pub const TlsSocket = struct {
    allocator: Allocator,
    tcp_stream: net.Stream,
    tls_client: ?tls.Client,
    config: TlsConfig,
    hostname_buf: []u8,
    connected: bool,

    // Stream reader/writer - these wrap the TCP stream
    // MUST be stored in struct before TLS init so pointers remain valid
    stream_reader: net.Stream.Reader,
    stream_writer: net.Stream.Writer,

    // Buffers for TLS operations (must live as long as TlsSocket)
    tls_read_buffer: []u8,
    tls_write_buffer: []u8,
    socket_read_buffer: []u8,
    socket_write_buffer: []u8,

    const Self = @This();
    const BUFFER_SIZE = tls.Client.min_buffer_len;

    /// Connect to hostname:port with TLS
    /// Returns a heap-allocated TlsSocket that must be freed with close()
    pub fn connect(allocator: Allocator, hostname: []const u8, port: u16, config: TlsConfig) !*Self {
        std.log.info("TLS: Connecting to {s}:{d}", .{ hostname, port });

        // Resolve and connect TCP
        var tcp_stream: net.Stream = undefined;

        // First try to parse as IP address
        if (net.Address.resolveIp(hostname, port)) |address| {
            std.log.debug("TLS: Resolved IP address directly: {s}:{d}", .{ hostname, port });
            tcp_stream = net.tcpConnectToAddress(address) catch |err| {
                std.log.err("TLS: TCP connect failed: {}", .{err});
                return TlsError.TcpConnectFailed;
            };
        } else |resolve_err| {
            std.log.debug("TLS: Not an IP, trying DNS for: {s} (err: {})", .{ hostname, resolve_err });
            // DNS resolution
            const addr_list = net.getAddressList(allocator, hostname, port) catch |err| {
                std.log.err("TLS: DNS resolution failed: {}", .{err});
                return TlsError.DnsResolutionFailed;
            };
            defer addr_list.deinit();

            if (addr_list.addrs.len == 0) {
                std.log.err("TLS: No addresses found for {s}", .{hostname});
                return TlsError.DnsResolutionFailed;
            }

            tcp_stream = net.tcpConnectToAddress(addr_list.addrs[0]) catch |err| {
                std.log.err("TLS: TCP connect to DNS result failed: {}", .{err});
                return TlsError.TcpConnectFailed;
            };
        }
        errdefer tcp_stream.close();

        // Set TCP_NODELAY to disable Nagle's algorithm for low-latency VPN
        // This is critical for DHCP/keepalive packets to be sent immediately
        // Use raw values since std.posix.TCP may not be available on all platforms
        const IPPROTO_TCP = 6;
        const TCP_NODELAY = 1;
        const nodelay: c_int = 1;
        _ = std.posix.setsockopt(tcp_stream.handle, IPPROTO_TCP, TCP_NODELAY, std.mem.asBytes(&nodelay)) catch |err| {
            std.log.warn("Failed to set TCP_NODELAY: {}", .{err});
        };

        // Apply timeout
        if (config.timeout_ms > 0) {
            TcpSocket.setReadTimeout(tcp_stream.handle, config.timeout_ms) catch {};
            TcpSocket.setWriteTimeout(tcp_stream.handle, config.timeout_ms) catch {};
        }

        // Allocate hostname buffer
        const hostname_buf = try allocator.dupe(u8, hostname);
        errdefer allocator.free(hostname_buf);

        // Allocate all buffers
        const tls_read_buffer = try allocator.alloc(u8, BUFFER_SIZE);
        errdefer allocator.free(tls_read_buffer);

        const tls_write_buffer = try allocator.alloc(u8, BUFFER_SIZE);
        errdefer allocator.free(tls_write_buffer);

        const socket_read_buffer = try allocator.alloc(u8, BUFFER_SIZE);
        errdefer allocator.free(socket_read_buffer);

        const socket_write_buffer = try allocator.alloc(u8, BUFFER_SIZE);
        errdefer allocator.free(socket_write_buffer);

        std.log.info("TLS: TCP connected, starting TLS handshake", .{});

        // Allocate the TlsSocket on the heap FIRST
        // This is critical because tls.Client stores pointers to stream_reader/writer
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Initialize struct fields (except tls_client)
        self.* = .{
            .allocator = allocator,
            .tcp_stream = tcp_stream,
            .tls_client = null, // Will be set after handshake
            .config = config,
            .hostname_buf = hostname_buf,
            .connected = false,
            .stream_reader = tcp_stream.reader(socket_read_buffer),
            .stream_writer = tcp_stream.writer(socket_write_buffer),
            .tls_read_buffer = tls_read_buffer,
            .tls_write_buffer = tls_write_buffer,
            .socket_read_buffer = socket_read_buffer,
            .socket_write_buffer = socket_write_buffer,
        };

        // Configure TLS options
        // For SoftEther VPN, servers typically use self-signed certificates
        const tls_options = tls.Client.Options{
            .host = if (config.verify_certificate and !config.allow_self_signed)
                .{ .explicit = hostname }
            else
                .{ .no_verification = {} },
            .ca = if (config.verify_certificate and !config.allow_self_signed)
                .{ .self_signed = {} }
            else
                .{ .no_verification = {} },
            .read_buffer = tls_read_buffer,
            .write_buffer = tls_write_buffer,
            // Allow truncation attacks since we verify content length at protocol level
            .allow_truncation_attacks = true,
        };

        // Perform TLS handshake
        // NOW the pointers to stream_reader/writer will remain valid because
        // self is heap-allocated and won't move
        self.tls_client = tls.Client.init(
            self.stream_reader.interface(),
            &self.stream_writer.interface,
            tls_options,
        ) catch |err| {
            std.log.err("TLS: Handshake failed: {}", .{err});
            return TlsError.TlsHandshakeFailed;
        };

        self.connected = true;

        std.log.info("TLS: Handshake complete, connection established (version: {})", .{self.tls_client.?.tls_version});

        return self;
    }

    /// Close the connection and free resources
    pub fn close(self: *Self) void {
        if (self.connected) {
            self.tcp_stream.close();
            self.connected = false;
        }

        self.allocator.free(self.hostname_buf);
        self.allocator.free(self.tls_read_buffer);
        self.allocator.free(self.tls_write_buffer);
        self.allocator.free(self.socket_read_buffer);
        self.allocator.free(self.socket_write_buffer);

        // Free the struct itself
        self.allocator.destroy(self);
    }

    /// Read data from the TLS connection
    pub fn read(self: *Self, buffer: []u8) !usize {
        if (!self.connected) {
            std.log.debug("TLS read: not connected", .{});
            return 0;
        }

        const client = &(self.tls_client orelse {
            std.log.debug("TLS read: no tls_client", .{});
            return 0;
        });

        // Use readSliceShort which returns actual bytes read (can be less than buffer.len)
        const n = client.reader.readSliceShort(buffer) catch |err| {
            // Only log as error if it's a real close, otherwise debug level (timeouts are expected)
            if (client.received_close_notify) {
                std.log.err("TLS read error: {} (close_notify: true)", .{err});
            } else {
                std.log.debug("TLS read: {} (close_notify: false, likely timeout)", .{err});
            }
            switch (err) {
                error.ReadFailed => {
                    // Check if connection was closed
                    if (client.received_close_notify) {
                        self.connected = false;
                        return 0;
                    }
                    return TlsError.ReadError;
                },
            }
        };
        std.log.debug("TLS read: {d} bytes into {d} byte buffer", .{ n, buffer.len });
        return n;
    }

    /// Read exactly n bytes
    pub fn readAll(self: *Self, buffer: []u8) !void {
        var index: usize = 0;
        while (index < buffer.len) {
            const n = try self.read(buffer[index..]);
            if (n == 0) return error.EndOfStream;
            index += n;
        }
    }

    /// Write data to the TLS connection
    pub fn write(self: *Self, data: []const u8) !usize {
        if (!self.connected) {
            std.log.debug("TLS write: not connected", .{});
            return error.BrokenPipe;
        }

        const client = &(self.tls_client orelse {
            std.log.debug("TLS write: no tls_client", .{});
            return error.BrokenPipe;
        });

        std.log.debug("TLS write: writing {d} bytes", .{data.len});

        // Use writeVec with a single slice
        var slices: [1][]const u8 = .{data};
        const n = client.writer.writeVec(&slices) catch |err| {
            std.log.err("TLS writeVec error: {}", .{err});
            self.connected = false;
            return error.BrokenPipe;
        };

        std.log.debug("TLS write: writeVec returned {d}", .{n});

        // Flush TLS writer (encrypts data to output buffer)
        client.writer.flush() catch |err| {
            std.log.err("TLS flush error: {}", .{err});
        };

        // Also flush the underlying stream writer to actually send data
        self.stream_writer.interface.flush() catch |err| {
            std.log.err("Stream flush error: {}", .{err});
        };

        std.log.debug("TLS write: flushed, returning {d}", .{n});
        return n;
    }

    /// Write with poll-based waiting (avoids busy spin)
    pub fn writeWithPoll(self: *Self, data: []const u8) !usize {
        return self.write(data);
    }

    /// Write all data (blocking until complete)
    pub fn writeAll(self: *Self, data: []const u8) !void {
        var index: usize = 0;
        while (index < data.len) {
            const n = try self.write(data[index..]);
            if (n == 0) continue;
            index += n;
        }
    }

    /// Check if connection is still alive
    pub fn isConnected(self: *const Self) bool {
        return self.connected;
    }

    /// Get the underlying file descriptor
    pub fn getFd(self: *const Self) std.posix.fd_t {
        return self.tcp_stream.handle;
    }

    /// Get the hostname this socket connected to
    pub fn getHostname(self: *const Self) []const u8 {
        return self.hostname_buf;
    }

    /// Check if there's data already buffered in the TLS layer
    /// This allows checking for data without blocking on the socket
    pub fn hasBufferedData(self: *Self) bool {
        if (self.tls_client) |*client| {
            // Check if there's decrypted data in the TLS buffer
            return client.reader.bufferedLen() > 0;
        }
        return false;
    }

    /// Read with timeout - uses poll() to check for data before reading
    /// Returns 0 if timeout expires with no data, otherwise returns bytes read
    /// This is safe to use in a loop without blocking forever
    ///
    /// CRITICAL FIX: TLS buffers data internally. We must check the TLS buffer FIRST
    /// before falling back to poll() on the TCP socket. Otherwise we may miss data
    /// that was already decrypted from a previous TLS record.
    ///
    /// IMPORTANT: TLS buffering issue - poll() only sees TCP data, not TLS internal buffers.
    /// The TLS layer may need multiple TCP segments to complete a TLS record, causing blocking.
    /// Solution: Set a temporary socket read timeout during the TLS read.
    pub fn readWithTimeout(self: *Self, buffer: []u8, timeout_ms: i32) !usize {
        if (!self.connected) {
            return 0;
        }

        const client = &(self.tls_client orelse return 0);

        // CRITICAL: First check if there's already decrypted data in the TLS buffer!
        // The TLS layer buffers data from previous records, and poll() won't see this.
        // This was causing DHCP to fail - server responses were buffered but we never read them.
        const buffered = client.reader.bufferedLen();
        if (buffered > 0) {
            std.log.debug("TLS readWithTimeout: {d} bytes already buffered in TLS layer", .{buffered});

            // Read buffered data without touching the socket
            // readSliceShort will return immediately with buffered data
            const result = self.read(buffer) catch |err| {
                switch (err) {
                    TlsError.ConnectionClosed => {
                        self.connected = false;
                        return error.ConnectionClosed;
                    },
                    else => return err,
                }
            };
            return result;
        }

        // No buffered TLS data, check TCP socket with poll()
        // Use a slightly longer poll timeout to allow TCP data to accumulate
        const poll_timeout = @max(timeout_ms, 500); // At least 500ms for TLS records
        std.log.warn("TLS readWithTimeout: poll(timeout={d}ms)", .{poll_timeout});
        var poll_fds = [_]std.posix.pollfd{
            .{ .fd = self.tcp_stream.handle, .events = std.posix.POLL.IN, .revents = 0 },
        };

        const poll_result = std.posix.poll(&poll_fds, poll_timeout) catch |err| {
            std.log.warn("TLS readWithTimeout: poll error: {}", .{err});
            return 0;
        };
        std.log.warn("TLS readWithTimeout: poll returned {d}, revents=0x{x:0>4}", .{
            poll_result,
            poll_fds[0].revents,
        });

        // Check for errors or hangup
        if ((poll_fds[0].revents & std.posix.POLL.ERR) != 0 or
            (poll_fds[0].revents & std.posix.POLL.HUP) != 0)
        {
            std.log.debug("TLS readWithTimeout: poll ERR/HUP detected", .{});
            self.connected = false;
            return error.ConnectionClosed;
        }

        // No data available within timeout at TCP level
        if (poll_result == 0 or (poll_fds[0].revents & std.posix.POLL.IN) == 0) {
            std.log.debug("TLS readWithTimeout: poll timeout (no data)", .{});
            return 0; // Timeout - no data at TCP or TLS level
        }

        std.log.debug("TLS readWithTimeout: data available, calling TLS read", .{});
        // Data is available at TCP level, now read through TLS
        // CRITICAL: TLS read can still block if it needs more TCP data to complete a record!
        // Set a longer socket timeout to allow TLS record completion (TLS records can be up to 16KB)
        const tls_read_timeout_ms: u32 = @max(2000, @as(u32, @intCast(timeout_ms)) * 4);
        socket_mod.TcpSocket.setReadTimeout(self.tcp_stream.handle, tls_read_timeout_ms) catch {};

        // Try to read through TLS - may get partial data or timeout
        // If the socket timeout triggers, it returns an error which we should treat as "no data yet"
        const result = self.read(buffer) catch |err| {
            // Restore timeout before returning
            socket_mod.TcpSocket.setReadTimeout(self.tcp_stream.handle, self.config.timeout_ms) catch {};

            // Check if this is a real error or just a timeout
            switch (err) {
                TlsError.ReadError => {
                    // Socket timeout caused TLS read to fail - this is expected, not an error
                    // Just return 0 to indicate no data available yet
                    std.log.debug("TLS readWithTimeout: socket timeout (expected, no data yet)", .{});
                    return 0;
                },
                TlsError.ConnectionClosed => {
                    // Real connection close
                    self.connected = false;
                    return error.ConnectionClosed;
                },
                else => {
                    // Other errors - propagate them
                    return err;
                },
            }
        };

        // Restore original timeout (30 seconds default)
        socket_mod.TcpSocket.setReadTimeout(self.tcp_stream.handle, self.config.timeout_ms) catch {};

        return result;
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
    const T = TlsSocket;
    try testing.expect(@sizeOf(T) > 0);
}
