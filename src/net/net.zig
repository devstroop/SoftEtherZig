//! SoftEther VPN Networking Library
//!
//! This module provides Zig networking utilities.
//! Phase 2 of the C-to-Zig migration.

const builtin = @import("builtin");

pub const socket = @import("socket.zig");

// Use native Zig TLS on iOS (no OpenSSL), OpenSSL implementation elsewhere
pub const tls = if (builtin.os.tag == .ios)
    @import("tls_native.zig")
else
    @import("tls.zig");

pub const http = @import("http.zig");

// Re-export commonly used types
pub const TcpSocket = socket.TcpSocket;
pub const TcpListener = socket.TcpListener;
pub const Address = socket.Address;
pub const ConnectionState = socket.ConnectionState;
pub const ConnectionInfo = socket.ConnectionInfo;

pub const TlsSocket = tls.TlsSocket;
pub const TlsConfig = tls.TlsConfig;
pub const TlsVersion = tls.TlsVersion;

pub const HttpRequest = http.Request;
pub const HttpResponse = http.Response;
pub const HttpMethod = http.Method;
pub const StatusCode = http.StatusCode;
pub const ProxyConfig = http.ProxyConfig;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
