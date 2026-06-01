//! SoftEther VPN Networking Library
//!
//! This module provides Zig networking utilities.
//! Phase 2 of the C-to-Zig migration.

pub const socket = @import("socket.zig");
pub const tls = @import("tls.zig");
pub const http = @import("http.zig");
pub const dns_cache = @import("dns_cache.zig");
pub const socks = @import("socks.zig");
pub const dhcpv6 = @import("../tunnel/dhcpv6.zig");

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

pub const DnsCache = dns_cache.DnsCache;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
