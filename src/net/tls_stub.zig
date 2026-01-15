//! TLS Stub for iOS
//!
//! This is a stub implementation for iOS that doesn't use OpenSSL.
//! iOS apps should use Security.framework for TLS, but that requires
//! a different implementation approach.
//!
//! For now, this stub allows the library to compile on iOS.
//! TLS connections will return an error until a proper Security.framework
//! implementation is added.

const std = @import("std");
const net = std.net;
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
    NotImplemented,
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

/// TLS-wrapped socket (iOS stub - not implemented)
/// On iOS, TLS should be handled by the Swift layer using Security.framework
pub const TlsSocket = struct {
    allocator: Allocator,
    tcp_fd: std.posix.fd_t,
    config: TlsConfig,
    hostname_buf: []u8,
    connected: bool,

    /// Connect to hostname:port with TLS
    /// iOS stub: Returns error - use Swift Security.framework instead
    pub fn connect(allocator: Allocator, hostname: []const u8, port: u16, config: TlsConfig) !TlsSocket {
        _ = allocator;
        _ = hostname;
        _ = port;
        _ = config;

        std.log.err("TLS not implemented for iOS in Zig. Use Swift Security.framework.", .{});
        return TlsError.NotImplemented;
    }

    /// Close the connection
    pub fn close(self: *TlsSocket) void {
        if (self.connected) {
            std.posix.close(self.tcp_fd);
            self.connected = false;
        }
        self.allocator.free(self.hostname_buf);
    }

    /// Read data from the TLS connection
    pub fn read(self: *TlsSocket, buffer: []u8) !usize {
        _ = self;
        _ = buffer;
        return 0;
    }

    /// Read exactly n bytes
    pub fn readAll(self: *TlsSocket, buffer: []u8) !void {
        _ = self;
        _ = buffer;
        return error.NotImplemented;
    }

    /// Write data to the TLS connection
    pub fn write(self: *TlsSocket, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.NotImplemented;
    }

    /// Write with poll-based waiting
    pub fn writeWithPoll(self: *TlsSocket, data: []const u8) !usize {
        _ = self;
        _ = data;
        return error.NotImplemented;
    }

    /// Write all data (blocking until complete)
    pub fn writeAll(self: *TlsSocket, data: []const u8) !void {
        _ = self;
        _ = data;
        return error.NotImplemented;
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
    const T = TlsSocket;
    try testing.expect(@sizeOf(T) > 0);
}
