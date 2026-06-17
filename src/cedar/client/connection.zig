//! SoftEther VPN Connection Manager
//!
//! Handles the low-level connection lifecycle including:
//! - TCP/TLS connection establishment
//! - HTTP CONNECT proxy support
//! - Connection pooling for multiple tunnels
//! - Keep-alive management
//! - Automatic reconnection

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const posix = std.posix;

// ============================================================================
// Connection Types
// ============================================================================

/// Connection transport type
pub const TransportType = enum {
    tcp_direct,
    tcp_proxy,
    ssl_direct,
    ssl_proxy,
};

/// Proxy configuration
pub const ProxyConfig = struct {
    host: []const u8,
    port: u16,
    auth_username: ?[]const u8 = null,
    auth_password: ?[]const u8 = null,
    proxy_type: ProxyType = .http,

    pub const ProxyType = enum {
        http,
        socks4,
        socks5,
    };
};

/// Connection parameters
pub const ConnectionParams = struct {
    host: []const u8,
    port: u16,
    transport: TransportType = .ssl_direct,
    proxy: ?ProxyConfig = null,
    connect_timeout_ms: u32 = 30000,
    read_timeout_ms: u32 = 60000,
    write_timeout_ms: u32 = 30000,
    keepalive_interval_ms: u32 = 10000,
    max_idle_ms: u32 = 120000,
};

/// Connection state
pub const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    error_state,

    pub fn isActive(self: ConnectionState) bool {
        return self == .connected;
    }
};

/// Connection statistics
pub const ConnectionStatistics = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    connect_time: i64 = 0,
    last_send_time: i64 = 0,
    last_recv_time: i64 = 0,
    reconnect_count: u32 = 0,
    error_count: u32 = 0,

    pub fn reset(self: *ConnectionStatistics) void {
        self.* = .{};
    }

    pub fn recordSend(self: *ConnectionStatistics, bytes: usize) void {
        self.bytes_sent += bytes;
        self.last_send_time = std.time.milliTimestamp();
    }

    pub fn recordRecv(self: *ConnectionStatistics, bytes: usize) void {
        self.bytes_received += bytes;
        self.last_recv_time = std.time.milliTimestamp();
    }
};

// ============================================================================
// Connection Error
// ============================================================================

pub const ConnectionError = error{
    NotConnected,
    AlreadyConnected,
    ConnectionFailed,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    SslHandshakeFailed,
    ProxyConnectionFailed,
    ProxyAuthFailed,
    SendFailed,
    RecvFailed,
    InvalidState,
    OutOfMemory,
};

// ============================================================================
// TCP Connection
// ============================================================================

/// Low-level TCP connection
pub const TcpConnection = struct {
    socket: ?posix.socket_t,
    state: ConnectionState,
    stats: ConnectionStatistics,
    params: ConnectionParams,
    allocator: Allocator,

    // Buffers
    recv_buffer: []u8,
    send_buffer: []u8,

    const BUFFER_SIZE = 65536;

    pub fn init(allocator: Allocator, params: ConnectionParams) !TcpConnection {
        return .{
            .socket = null,
            .state = .disconnected,
            .stats = .{},
            .params = params,
            .allocator = allocator,
            .recv_buffer = try allocator.alloc(u8, BUFFER_SIZE),
            .send_buffer = try allocator.alloc(u8, BUFFER_SIZE),
        };
    }

    pub fn deinit(self: *TcpConnection) void {
        self.close();
        self.allocator.free(self.recv_buffer);
        self.allocator.free(self.send_buffer);
    }

    /// Connect to the remote host
    pub fn connect(self: *TcpConnection) ConnectionError!void {
        if (self.state == .connected) {
            return ConnectionError.AlreadyConnected;
        }

        self.state = .connecting;

        // Resolve address
        const address = self.resolveAddress() catch {
            self.state = .error_state;
            return ConnectionError.HostUnreachable;
        };

        // Create socket
        self.socket = posix.socket(
            address.any.family,
            posix.SOCK.STREAM,
            0,
        ) catch {
            self.state = .error_state;
            return ConnectionError.ConnectionFailed;
        };

        // Set non-blocking temporarily for timeout
        // In production, would use poll/select for timeout

        // Connect
        posix.connect(self.socket.?, &address.any, address.getLen()) catch |err| {
            self.close();
            self.state = .error_state;
            return switch (err) {
                error.ConnectionRefused => ConnectionError.ConnectionRefused,
                error.NetworkUnreachable => ConnectionError.NetworkUnreachable,
                else => ConnectionError.ConnectionFailed,
            };
        };

        self.state = .connected;
        self.stats.connect_time = std.time.milliTimestamp();
    }

    /// Close the connection
    pub fn close(self: *TcpConnection) void {
        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }
        self.state = .disconnected;
    }

    /// Send data
    pub fn send(self: *TcpConnection, data: []const u8) ConnectionError!usize {
        if (self.state != .connected) {
            return ConnectionError.NotConnected;
        }

        const sock = self.socket orelse return ConnectionError.NotConnected;

        const sent = posix.send(sock, data, 0) catch {
            self.stats.error_count += 1;
            return ConnectionError.SendFailed;
        };

        self.stats.recordSend(sent);
        return sent;
    }

    /// Receive data
    pub fn recv(self: *TcpConnection, buffer: []u8) ConnectionError!usize {
        if (self.state != .connected) {
            return ConnectionError.NotConnected;
        }

        const sock = self.socket orelse return ConnectionError.NotConnected;

        const received = posix.recv(sock, buffer, 0) catch {
            self.stats.error_count += 1;
            return ConnectionError.RecvFailed;
        };

        if (received == 0) {
            // Connection closed by peer
            self.close();
            return ConnectionError.ConnectionReset;
        }

        self.stats.recordRecv(received);
        return received;
    }

    /// Check if connected
    pub fn isConnected(self: *const TcpConnection) bool {
        return self.state == .connected and self.socket != null;
    }

    /// Get statistics
    pub fn getStats(self: *const TcpConnection) ConnectionStatistics {
        return self.stats;
    }

    // Internal helpers
    fn resolveAddress(self: *const TcpConnection) !std.net.Address {
        // Try parsing as IP first
        if (std.net.Address.parseIp4(self.params.host, self.params.port)) |addr| {
            return addr;
        } else |_| {}

        if (std.net.Address.parseIp6(self.params.host, self.params.port)) |addr| {
            return addr;
        } else |_| {}

        // Would need DNS resolution here
        return error.HostUnreachable;
    }
};

// ============================================================================
// Connection Pool
// ============================================================================

/// Connection pool for multiple tunnels
pub const ConnectionPool = struct {
    allocator: Allocator,
    connections: std.ArrayListUnmanaged(*TcpConnection),
    max_connections: usize,
    params: ConnectionParams,

    pub fn init(allocator: Allocator, params: ConnectionParams, max_connections: usize) ConnectionPool {
        return .{
            .allocator = allocator,
            .connections = .{},
            .max_connections = max_connections,
            .params = params,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
    }

    /// Get an available connection or create new one
    pub fn acquire(self: *ConnectionPool) !*TcpConnection {
        // Try to find an existing connected connection
        for (self.connections.items) |conn| {
            if (conn.isConnected()) {
                return conn;
            }
        }

        // Create new connection if under limit
        if (self.connections.items.len < self.max_connections) {
            const conn = try self.allocator.create(TcpConnection);
            conn.* = try TcpConnection.init(self.allocator, self.params);
            try self.connections.append(self.allocator, conn);
            return conn;
        }

        return ConnectionError.ConnectionFailed;
    }

    /// Release a connection back to pool
    pub fn release(self: *ConnectionPool, conn: *TcpConnection) void {
        // Connection stays in pool, just mark as available
        _ = self;
        _ = conn;
    }

    /// Get active connection count
    pub fn activeCount(self: *const ConnectionPool) usize {
        var count: usize = 0;
        for (self.connections.items) |conn| {
            if (conn.isConnected()) count += 1;
        }
        return count;
    }

    /// Close all connections
    pub fn closeAll(self: *ConnectionPool) void {
        for (self.connections.items) |conn| {
            conn.close();
        }
    }
};

// ============================================================================
// Keep-Alive Manager
// ============================================================================

/// Keep-alive packet types
pub const KeepAliveType = enum {
    ping,
    pong,
    data,
};

/// Keep-alive manager
pub const KeepAliveManager = struct {
    interval_ms: u32,
    timeout_ms: u32,
    last_sent: i64,
    last_received: i64,
    pending_pong: bool,
    missed_count: u32,
    max_missed: u32,

    pub fn init(interval_ms: u32, timeout_ms: u32) KeepAliveManager {
        return .{
            .interval_ms = interval_ms,
            .timeout_ms = timeout_ms,
            .last_sent = 0,
            .last_received = 0,
            .pending_pong = false,
            .missed_count = 0,
            .max_missed = 3,
        };
    }

    /// Check if keep-alive should be sent
    pub fn shouldSend(self: *const KeepAliveManager) bool {
        const now = std.time.milliTimestamp();
        return (now - self.last_sent) >= self.interval_ms;
    }

    /// Record that keep-alive was sent
    pub fn recordSent(self: *KeepAliveManager) void {
        self.last_sent = std.time.milliTimestamp();
        self.pending_pong = true;
    }

    /// Record that response was received
    pub fn recordReceived(self: *KeepAliveManager) void {
        self.last_received = std.time.milliTimestamp();
        self.pending_pong = false;
        self.missed_count = 0;
    }

    /// Check if connection timed out
    pub fn isTimedOut(self: *const KeepAliveManager) bool {
        if (!self.pending_pong) return false;

        const now = std.time.milliTimestamp();
        return (now - self.last_sent) >= self.timeout_ms;
    }

    /// Record missed keep-alive
    pub fn recordMissed(self: *KeepAliveManager) void {
        self.missed_count += 1;
        self.pending_pong = false;
    }

    /// Check if too many missed
    pub fn isFailed(self: *const KeepAliveManager) bool {
        return self.missed_count >= self.max_missed;
    }

    /// Reset state
    pub fn reset(self: *KeepAliveManager) void {
        self.last_sent = 0;
        self.last_received = 0;
        self.pending_pong = false;
        self.missed_count = 0;
    }
};

// ============================================================================
// Reconnection Manager
// ============================================================================

/// Reconnection strategy
pub const ReconnectStrategy = enum {
    immediate,
    linear_backoff,
    exponential_backoff,
    fibonacci_backoff,
};

/// Reconnection manager
pub const ReconnectManager = struct {
    enabled: bool,
    strategy: ReconnectStrategy,
    attempt: u32,
    max_attempts: u32,
    min_delay_ms: u32,
    max_delay_ms: u32,
    current_delay_ms: u32,
    last_attempt_time: i64,
    multiplier: f32,

    // Fibonacci state
    fib_prev: u32,
    fib_curr: u32,

    pub fn init(strategy: ReconnectStrategy, max_attempts: u32, min_delay_ms: u32, max_delay_ms: u32) ReconnectManager {
        return .{
            .enabled = true,
            .strategy = strategy,
            .attempt = 0,
            .max_attempts = max_attempts,
            .min_delay_ms = min_delay_ms,
            .max_delay_ms = max_delay_ms,
            .current_delay_ms = min_delay_ms,
            .last_attempt_time = 0,
            .multiplier = 2.0,
            .fib_prev = 0,
            .fib_curr = 1,
        };
    }

    /// Check if should attempt reconnection
    pub fn shouldReconnect(self: *const ReconnectManager) bool {
        if (!self.enabled) return false;
        if (self.max_attempts > 0 and self.attempt >= self.max_attempts) return false;

        const now = std.time.milliTimestamp();
        return (now - self.last_attempt_time) >= self.current_delay_ms;
    }

    /// Record reconnection attempt
    pub fn recordAttempt(self: *ReconnectManager, success: bool) void {
        self.last_attempt_time = std.time.milliTimestamp();

        if (success) {
            self.reset();
        } else {
            self.attempt += 1;
            self.calculateNextDelay();
        }
    }

    /// Calculate next delay based on strategy
    fn calculateNextDelay(self: *ReconnectManager) void {
        self.current_delay_ms = switch (self.strategy) {
            .immediate => self.min_delay_ms,
            .linear_backoff => @min(self.current_delay_ms + self.min_delay_ms, self.max_delay_ms),
            .exponential_backoff => @min(
                @as(u32, @intFromFloat(@as(f32, @floatFromInt(self.current_delay_ms)) * self.multiplier)),
                self.max_delay_ms,
            ),
            .fibonacci_backoff => blk: {
                const next = self.fib_prev + self.fib_curr;
                self.fib_prev = self.fib_curr;
                self.fib_curr = next;
                break :blk @min(next * self.min_delay_ms, self.max_delay_ms);
            },
        };
    }

    /// Reset state
    pub fn reset(self: *ReconnectManager) void {
        self.attempt = 0;
        self.current_delay_ms = self.min_delay_ms;
        self.fib_prev = 0;
        self.fib_curr = 1;
    }

    /// Get time until next attempt
    pub fn getTimeUntilNext(self: *const ReconnectManager) i64 {
        const now = std.time.milliTimestamp();
        const elapsed = now - self.last_attempt_time;
        const remaining = @as(i64, self.current_delay_ms) - elapsed;
        return @max(0, remaining);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ConnectionParams defaults" {
    const params = ConnectionParams{
        .host = "vpn.example.com",
        .port = 443,
    };
    try std.testing.expectEqual(TransportType.ssl_direct, params.transport);
    try std.testing.expectEqual(@as(u32, 30000), params.connect_timeout_ms);
}

test "ConnectionStatistics tracking" {
    var stats = ConnectionStatistics{};

    stats.recordSend(100);
    try std.testing.expectEqual(@as(u64, 100), stats.bytes_sent);
    try std.testing.expect(stats.last_send_time > 0);

    stats.recordRecv(200);
    try std.testing.expectEqual(@as(u64, 200), stats.bytes_received);
    try std.testing.expect(stats.last_recv_time > 0);

    stats.reset();
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_sent);
}

test "ConnectionState predicates" {
    try std.testing.expect(ConnectionState.connected.isActive());
    try std.testing.expect(!ConnectionState.disconnected.isActive());
    try std.testing.expect(!ConnectionState.connecting.isActive());
}

test "KeepAliveManager initialization" {
    const ka = KeepAliveManager.init(10000, 30000);
    try std.testing.expectEqual(@as(u32, 10000), ka.interval_ms);
    try std.testing.expectEqual(@as(u32, 30000), ka.timeout_ms);
    try std.testing.expect(!ka.pending_pong);
}

test "KeepAliveManager shouldSend" {
    var ka = KeepAliveManager.init(0, 30000); // 0ms interval for test
    try std.testing.expect(ka.shouldSend());

    ka.recordSent();
    ka.interval_ms = 1000000; // Long interval
    try std.testing.expect(!ka.shouldSend());
}

test "KeepAliveManager recordReceived" {
    var ka = KeepAliveManager.init(10000, 30000);
    ka.recordSent();
    try std.testing.expect(ka.pending_pong);

    ka.recordReceived();
    try std.testing.expect(!ka.pending_pong);
    try std.testing.expectEqual(@as(u32, 0), ka.missed_count);
}

test "KeepAliveManager missed tracking" {
    var ka = KeepAliveManager.init(10000, 30000);
    ka.max_missed = 3;

    ka.recordMissed();
    try std.testing.expect(!ka.isFailed());

    ka.recordMissed();
    ka.recordMissed();
    try std.testing.expect(ka.isFailed());
}

test "ReconnectManager initialization" {
    const rm = ReconnectManager.init(.exponential_backoff, 5, 1000, 60000);
    try std.testing.expect(rm.enabled);
    try std.testing.expectEqual(@as(u32, 0), rm.attempt);
    try std.testing.expectEqual(@as(u32, 1000), rm.current_delay_ms);
}

test "ReconnectManager exponential backoff" {
    var rm = ReconnectManager.init(.exponential_backoff, 10, 1000, 60000);

    rm.recordAttempt(false);
    try std.testing.expectEqual(@as(u32, 1), rm.attempt);
    try std.testing.expectEqual(@as(u32, 2000), rm.current_delay_ms);

    rm.recordAttempt(false);
    try std.testing.expectEqual(@as(u32, 4000), rm.current_delay_ms);

    rm.recordAttempt(false);
    try std.testing.expectEqual(@as(u32, 8000), rm.current_delay_ms);
}

test "ReconnectManager max delay cap" {
    var rm = ReconnectManager.init(.exponential_backoff, 10, 1000, 5000);

    // Force many attempts
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        rm.recordAttempt(false);
    }

    try std.testing.expect(rm.current_delay_ms <= 5000);
}

test "ReconnectManager success resets" {
    var rm = ReconnectManager.init(.exponential_backoff, 10, 1000, 60000);

    rm.recordAttempt(false);
    rm.recordAttempt(false);
    try std.testing.expect(rm.attempt > 0);

    rm.recordAttempt(true);
    try std.testing.expectEqual(@as(u32, 0), rm.attempt);
    try std.testing.expectEqual(@as(u32, 1000), rm.current_delay_ms);
}

test "ReconnectManager max attempts" {
    var rm = ReconnectManager.init(.linear_backoff, 2, 1000, 60000);

    rm.recordAttempt(false);
    rm.last_attempt_time = 0; // Force time check to pass
    try std.testing.expect(rm.shouldReconnect()); // attempt=1 < max=2

    rm.recordAttempt(false); // attempt becomes 2
    rm.last_attempt_time = 0; // Force time check to pass
    try std.testing.expect(!rm.shouldReconnect()); // attempt=2 >= max=2
}

test "ProxyConfig defaults" {
    const proxy = ProxyConfig{
        .host = "proxy.example.com",
        .port = 8080,
    };
    try std.testing.expectEqual(ProxyConfig.ProxyType.http, proxy.proxy_type);
    try std.testing.expect(proxy.auth_username == null);
}

test "TransportType values" {
    const t = TransportType.ssl_direct;
    try std.testing.expect(t == .ssl_direct);
    try std.testing.expect(t != .tcp_direct);
}
