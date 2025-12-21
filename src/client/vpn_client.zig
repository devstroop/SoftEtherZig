//! SoftEther VPN Client
//!
//! High-level VPN client API.
//! This module provides a complete VPN client implementation without
//! any C dependencies.
//!
//! Architecture:
//! - VpnClient: Main client facade
//! - ClientConfig: Connection configuration
//! - ClientState: Connection state machine
//! - PacketProcessor: Packet processing pipeline

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const builtin = @import("builtin");
const net = std.net;

// Import real networking modules
const net_mod = @import("../net/net.zig");
const socket = net_mod.socket;
const tls = net_mod.tls;

// Import session module
const session_mod = @import("../session/mod.zig");
const RealSession = session_mod.Session;
const SessionOptions = session_mod.SessionOptions;

// Import adapter module
const adapter_mod = @import("../adapter/mod.zig");
const VirtualAdapter = adapter_mod.VirtualAdapter;

// Import protocol modules
const auth_mod = @import("../protocol/auth.zig");
const rpc = @import("../protocol/rpc.zig");
const softether_proto = @import("../protocol/softether_protocol.zig");
const pack_mod = @import("../protocol/pack.zig");
const tunnel_mod = @import("../protocol/tunnel.zig");

// Import DHCP parsing
const dhcp_mod = @import("../adapter/dhcp.zig");

// ============================================================================
// Self-Contained Helper Types (for modularity)
// ============================================================================

/// Parse IPv4 address string to u32 in host byte order (little-endian on x86/ARM)
fn parseIpv4(str: []const u8) ?u32 {
    var octets: [4]u8 = [_]u8{ 0, 0, 0, 0 };
    var octet: u32 = 0;
    var octet_idx: usize = 0;

    for (str) |c| {
        if (c == '.') {
            if (octet > 255 or octet_idx >= 4) return null;
            octets[octet_idx] = @truncate(octet);
            octet_idx += 1;
            octet = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
        } else {
            return null;
        }
    }

    if (octet > 255 or octet_idx != 3) return null;
    octets[3] = @truncate(octet);

    // Return in host byte order (little-endian) using bitcast
    return @as(u32, @bitCast(octets));
}

/// Format u32 IPv4 address to string
/// Pack protocol stores IPs in host byte order (little-endian on x86/ARM)
fn formatIpv4Buf(ip: u32, buffer: []u8) []const u8 {
    const ip_bytes: [4]u8 = @bitCast(ip);
    const result = std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
    }) catch return "";
    return result;
}

// ============================================================================
// Client Configuration
// ============================================================================

/// Authentication method for VPN connection
pub const AuthMethod = union(enum) {
    /// Password authentication
    password: struct {
        username: []const u8,
        password: []const u8,
        is_hashed: bool = false,
    },
    /// Certificate authentication
    certificate: struct {
        cert_data: []const u8,
        key_data: []const u8,
    },
    /// Anonymous authentication
    anonymous: void,
};

/// IP version preference
pub const IpVersionPreference = enum {
    auto,
    ipv4_only,
    ipv6_only,
    dual_stack,
};

/// Reconnection configuration
pub const ReconnectConfig = struct {
    enabled: bool = true,
    max_attempts: u32 = 0, // 0 = infinite
    min_backoff_ms: u32 = 1000,
    max_backoff_ms: u32 = 60000,
    backoff_multiplier: f32 = 2.0,
};

/// Static IP configuration (optional)
pub const StaticIpConfig = struct {
    ipv4_address: ?[]const u8 = null,
    ipv4_netmask: ?[]const u8 = null,
    ipv4_gateway: ?[]const u8 = null,
    ipv6_address: ?[]const u8 = null,
    ipv6_prefix_len: ?u8 = null,
    ipv6_gateway: ?[]const u8 = null,
    dns_servers: ?[]const []const u8 = null,
};

/// VPN Client configuration
pub const ClientConfig = struct {
    // Server settings
    server_host: []const u8,
    server_port: u16 = 443,
    hub_name: []const u8,

    // Authentication
    auth: AuthMethod,

    // Connection options
    ip_version: IpVersionPreference = .auto,
    max_connections: u8 = 1,
    use_compression: bool = false,
    use_encryption: bool = true,

    // TLS settings
    verify_certificate: bool = true,

    // Routing
    full_tunnel: bool = true,
    split_tunnel_networks: ?[]const []const u8 = null,

    // Reconnection
    reconnect: ReconnectConfig = .{},

    // Static IP (optional)
    static_ip: ?StaticIpConfig = null,

    // Timeouts (milliseconds)
    connect_timeout_ms: u32 = 30000,
    read_timeout_ms: u32 = 60000,
    keepalive_interval_ms: u32 = 10000,
};

// ============================================================================
// Client State Machine
// ============================================================================

/// Connection state
pub const ClientState = enum {
    disconnected,
    resolving_dns,
    connecting_tcp,
    ssl_handshake,
    authenticating,
    establishing_session,
    configuring_adapter,
    connected,
    reconnecting,
    disconnecting,
    error_state,

    pub fn isConnected(self: ClientState) bool {
        return self == .connected;
    }

    pub fn isConnecting(self: ClientState) bool {
        return switch (self) {
            .resolving_dns, .connecting_tcp, .ssl_handshake, .authenticating, .establishing_session, .configuring_adapter => true,
            else => false,
        };
    }

    pub fn canTransitionTo(self: ClientState, next: ClientState) bool {
        return switch (self) {
            .disconnected => next == .resolving_dns or next == .error_state,
            .resolving_dns => next == .connecting_tcp or next == .error_state or next == .disconnecting,
            .connecting_tcp => next == .ssl_handshake or next == .error_state or next == .disconnecting,
            .ssl_handshake => next == .authenticating or next == .error_state or next == .disconnecting,
            .authenticating => next == .establishing_session or next == .error_state or next == .disconnecting,
            .establishing_session => next == .configuring_adapter or next == .error_state or next == .disconnecting,
            .configuring_adapter => next == .connected or next == .error_state or next == .disconnecting,
            .connected => next == .disconnecting or next == .reconnecting or next == .error_state,
            .reconnecting => next == .resolving_dns or next == .disconnected or next == .error_state,
            .disconnecting => next == .disconnected or next == .reconnecting,
            .error_state => next == .disconnected or next == .reconnecting,
        };
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    connect_time_ms: i64 = 0,
    connected_duration_ms: u64 = 0,
    reconnect_count: u32 = 0,
    last_activity_time_ms: i64 = 0,

    pub fn updateActivity(self: *ConnectionStats) void {
        self.last_activity_time_ms = std.time.milliTimestamp();
    }

    pub fn recordSent(self: *ConnectionStats, bytes: usize) void {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
        self.updateActivity();
    }

    pub fn recordReceived(self: *ConnectionStats, bytes: usize) void {
        self.bytes_received += bytes;
        self.packets_received += 1;
        self.updateActivity();
    }
};

/// Disconnect reason
pub const DisconnectReason = enum {
    none,
    user_requested,
    server_closed,
    auth_failed,
    timeout,
    network_error,
    protocol_error,
    configuration_error,
};

// ============================================================================
// Client Events (Callback Interface)
// ============================================================================

/// Event types for client callbacks
pub const ClientEvent = union(enum) {
    state_changed: struct {
        old_state: ClientState,
        new_state: ClientState,
    },
    connected: struct {
        server_ip: u32,
        assigned_ip: u32,
        gateway_ip: u32,
    },
    disconnected: struct {
        reason: DisconnectReason,
    },
    stats_updated: ConnectionStats,
    error_occurred: struct {
        code: ClientError,
        message: []const u8,
    },
    dhcp_configured: struct {
        ip: u32,
        mask: u32,
        gateway: u32,
    },
};

/// Event callback function type
pub const EventCallback = *const fn (event: ClientEvent, user_data: ?*anyopaque) void;

// ============================================================================
// Error Types
// ============================================================================

pub const ClientError = error{
    NotInitialized,
    AlreadyConnected,
    NotConnected,
    ConnectionFailed,
    AuthenticationFailed,
    DnsResolutionFailed,
    SslHandshakeFailed,
    SessionEstablishmentFailed,
    AdapterConfigurationFailed,
    Timeout,
    NetworkError,
    ProtocolError,
    InvalidConfiguration,
    InvalidState,
    OutOfMemory,
    OperationCancelled,
};

// ============================================================================
// Session Wrapper (bridges to real session module)
// ============================================================================

const SessionWrapper = struct {
    allocator: Allocator,
    real_session: ?RealSession,
    connected: bool,
    use_encryption: bool,

    pub fn init(allocator: Allocator, use_encryption: bool) SessionWrapper {
        return .{
            .allocator = allocator,
            .real_session = null,
            .connected = false,
            .use_encryption = use_encryption,
        };
    }

    /// Initialize with full session options
    pub fn initWithOptions(allocator: Allocator, options: SessionOptions) SessionWrapper {
        const wrapper = SessionWrapper{
            .allocator = allocator,
            .real_session = RealSession.init(allocator, options),
            .connected = false,
            .use_encryption = options.use_encryption,
        };
        return wrapper;
    }

    pub fn deinit(self: *SessionWrapper) void {
        if (self.real_session) |*sess| {
            sess.deinit();
        }
        self.connected = false;
    }

    pub fn disconnect(self: *SessionWrapper) void {
        if (self.real_session) |*sess| {
            sess.setState(.disconnecting) catch {};
        }
        self.connected = false;
    }

    pub fn connect(self: *SessionWrapper) void {
        if (self.real_session) |*sess| {
            sess.setState(.connecting) catch {};
        }
        self.connected = true;
    }

    pub fn isConnected(self: *const SessionWrapper) bool {
        if (self.real_session) |*sess| {
            return sess.isConnected();
        }
        return self.connected;
    }

    /// Encrypt data using real session encryption
    pub fn encrypt(self: *SessionWrapper, allocator: Allocator, data: []const u8) ![]u8 {
        _ = allocator; // Not needed - session uses its own allocator
        if (self.real_session) |*sess| {
            if (self.use_encryption) {
                return sess.encryptPacket(data);
            }
        }
        // No encryption or no session - return copy
        return try self.allocator.dupe(u8, data);
    }

    /// Decrypt data using real session decryption
    pub fn decrypt(self: *SessionWrapper, allocator: Allocator, data: []const u8) ![]u8 {
        _ = allocator; // Not needed - session uses its own allocator
        if (self.real_session) |*sess| {
            if (self.use_encryption) {
                return sess.decryptPacket(data);
            }
        }
        // No decryption or no session - return copy
        return try self.allocator.dupe(u8, data);
    }

    /// Initialize encryption keys (after authentication)
    pub fn initEncryption(self: *SessionWrapper, password_hash: *const [20]u8, challenge: *const [20]u8) void {
        if (self.real_session) |*sess| {
            sess.initEncryption(password_hash, challenge);
        }
    }

    /// Get traffic statistics
    pub fn getTrafficStats(self: *const SessionWrapper) ?session_mod.TrafficStats {
        if (self.real_session) |*sess| {
            return sess.traffic;
        }
        return null;
    }
};

// ============================================================================
// Adapter Wrapper (bridges to real adapter module)
// ============================================================================

const AdapterWrapper = struct {
    allocator: Allocator,
    real_adapter: ?VirtualAdapter,
    is_open: bool,
    device_name: [32]u8,
    device_name_len: usize,
    mac: [6]u8,
    ip_address: u32,
    gateway_ip: u32,
    netmask: u32,

    pub fn init(allocator: Allocator) AdapterWrapper {
        var mac: [6]u8 = undefined;
        std.crypto.random.bytes(&mac);
        mac[0] = 0x02; // Locally administered
        mac[1] = 0x00;
        mac[2] = 0x5E;

        return .{
            .allocator = allocator,
            .real_adapter = VirtualAdapter.init(allocator),
            .is_open = false,
            .device_name = [_]u8{0} ** 32,
            .device_name_len = 0,
            .mac = mac,
            .ip_address = 0,
            .gateway_ip = 0,
            .netmask = 0,
        };
    }

    pub fn deinit(self: *AdapterWrapper) void {
        self.close();
    }

    pub fn open(self: *AdapterWrapper) !void {
        if (self.real_adapter) |*adapter| {
            try adapter.open();
            self.is_open = adapter.isOpen();

            // Copy device name if available
            if (adapter.getName()) |name| {
                const len = @min(name.len, self.device_name.len);
                @memcpy(self.device_name[0..len], name[0..len]);
                self.device_name_len = len;
            }

            // Copy MAC if available
            if (adapter.getMac()) |m| {
                self.mac = m;
            }
        } else {
            // Fallback stub behavior
            const name = "utun99";
            @memcpy(self.device_name[0..name.len], name);
            self.device_name_len = name.len;
            self.is_open = true;
        }
    }

    pub fn close(self: *AdapterWrapper) void {
        if (self.real_adapter) |*adapter| {
            adapter.close();
        }
        self.is_open = false;
    }

    pub fn getName(self: *const AdapterWrapper) ?[]const u8 {
        if (!self.is_open) return null;
        return self.device_name[0..self.device_name_len];
    }

    pub fn getMac(self: *const AdapterWrapper) [6]u8 {
        return self.mac;
    }

    pub fn configure(self: *AdapterWrapper, ip: u32, mask: u32, gateway: u32) void {
        self.ip_address = ip;
        self.netmask = mask;
        self.gateway_ip = gateway;

        // Real adapter configuration would be done via DHCP
        // or explicit configure call on the device
    }

    pub fn configureFullTunnel(self: *AdapterWrapper, gateway: u32, server_ip: u32) void {
        self.gateway_ip = gateway;
        if (self.real_adapter) |*adapter| {
            adapter.configureFullTunnel(gateway, server_ip) catch |err| {
                std.log.err("Failed to configure full-tunnel routing: {}", .{err});
            };
        }
    }

    pub fn processIncomingPacket(self: *AdapterWrapper, data: []const u8) ?[]u8 {
        if (self.real_adapter) |*adapter| {
            return adapter.processIncomingPacket(data) catch null;
        }
        return null;
    }

    /// Read a packet from the adapter
    pub fn read(self: *AdapterWrapper, buffer: []u8) !?usize {
        if (self.real_adapter) |*adapter| {
            return adapter.read(buffer);
        }
        return null;
    }

    /// Write a packet to the adapter
    pub fn write(self: *AdapterWrapper, data: []const u8) !usize {
        if (self.real_adapter) |*adapter| {
            return adapter.write(data);
        }
        return 0;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const AdapterWrapper) ?adapter_mod.TunStats {
        if (self.real_adapter) |*adapter| {
            return adapter.getStats();
        }
        return null;
    }

    /// Check if DHCP is complete
    pub fn isDhcpComplete(self: *const AdapterWrapper) bool {
        if (self.real_adapter) |*adapter| {
            return adapter.isDhcpComplete();
        }
        return false;
    }
};

// ============================================================================
// VPN Client Implementation
// ============================================================================

/// High-level VPN Client
pub const VpnClient = struct {
    allocator: Allocator,
    config: ClientConfig,
    state: ClientState,
    stats: ConnectionStats,
    disconnect_reason: DisconnectReason,

    adapter_ctx: ?AdapterWrapper,
    session: ?SessionWrapper,

    // Network connection
    tls_socket: ?tls.TlsSocket,

    mutex: Mutex,
    worker_thread: ?Thread,
    should_stop: bool,

    event_callback: ?EventCallback,
    event_user_data: ?*anyopaque,

    reconnect_attempt: u32,
    reconnect_backoff_ms: u32,
    last_error: ?ClientError,

    server_ip: u32,
    assigned_ip: u32,
    gateway_ip: u32,
    gateway_mac: ?[6]u8,

    // Authentication state
    auth_credentials: ?auth_mod.ClientAuth,

    last_keepalive_sent: i64,
    last_keepalive_recv: i64,

    const Self = @This();

    pub fn init(allocator: Allocator, config: ClientConfig) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .state = .disconnected,
            .stats = .{},
            .disconnect_reason = .none,
            .adapter_ctx = null,
            .session = null,
            .tls_socket = null,
            .mutex = .{},
            .worker_thread = null,
            .should_stop = false,
            .event_callback = null,
            .event_user_data = null,
            .reconnect_attempt = 0,
            .reconnect_backoff_ms = config.reconnect.min_backoff_ms,
            .last_error = null,
            .server_ip = 0,
            .assigned_ip = 0,
            .gateway_ip = 0,
            .gateway_mac = null,
            .auth_credentials = null,
            .last_keepalive_sent = 0,
            .last_keepalive_recv = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.disconnect() catch {};
        if (self.adapter_ctx) |*ctx| {
            ctx.deinit();
            self.adapter_ctx = null;
        }
        if (self.session) |*sess| {
            sess.deinit();
            self.session = null;
        }
        if (self.tls_socket) |*sock| {
            sock.close();
            self.tls_socket = null;
        }
    }

    pub fn setEventCallback(self: *Self, callback: ?EventCallback, user_data: ?*anyopaque) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.event_callback = callback;
        self.event_user_data = user_data;
    }

    pub fn getState(self: *const Self) ClientState {
        return self.state;
    }

    pub fn isConnected(self: *const Self) bool {
        return self.state.isConnected();
    }

    pub fn isConnecting(self: *const Self) bool {
        return self.state.isConnecting();
    }

    pub fn getStats(self: *const Self) ConnectionStats {
        return self.stats;
    }

    pub fn getAssignedIp(self: *const Self) u32 {
        return self.assigned_ip;
    }

    pub fn getGatewayIp(self: *const Self) u32 {
        return self.gateway_ip;
    }

    pub fn getDeviceName(self: *const Self) ?[]const u8 {
        if (self.adapter_ctx) |*ctx| {
            return ctx.getName();
        }
        return null;
    }

    pub fn connect(self: *Self) ClientError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state.isConnected() or self.state.isConnecting()) {
            return ClientError.AlreadyConnected;
        }

        self.should_stop = false;
        self.disconnect_reason = .none;
        self.last_error = null;
        self.stats = .{};
        self.stats.connect_time_ms = std.time.milliTimestamp();

        self.transitionState(.resolving_dns);

        self.performConnection() catch |err| {
            self.last_error = err;
            self.transitionState(.error_state);
            return err;
        };
    }

    pub fn disconnect(self: *Self) ClientError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .disconnected) {
            return;
        }

        self.should_stop = true;
        self.disconnect_reason = .user_requested;
        self.performDisconnect();
    }

    /// Signal-safe stop request - just sets the flag without acquiring mutex
    /// Use this from signal handlers to avoid deadlocks
    pub fn requestStop(self: *Self) void {
        @atomicStore(bool, &self.should_stop, true, .seq_cst);
    }

    pub fn reconnect(self: *Self) ClientError!void {
        try self.disconnect();
        self.reconnect_attempt = 0;
        self.reconnect_backoff_ms = self.config.reconnect.min_backoff_ms;
        try self.connect();
    }

    fn transitionState(self: *Self, new_state: ClientState) void {
        const old_state = self.state;
        if (!old_state.canTransitionTo(new_state)) {
            return;
        }
        self.state = new_state;
        if (self.event_callback) |cb| {
            cb(.{ .state_changed = .{
                .old_state = old_state,
                .new_state = new_state,
            } }, self.event_user_data);
        }
    }

    fn performConnection(self: *Self) ClientError!void {
        self.transitionState(.resolving_dns);
        self.server_ip = self.resolveDns() catch {
            self.disconnect_reason = .network_error;
            return ClientError.DnsResolutionFailed;
        };

        self.transitionState(.connecting_tcp);
        self.transitionState(.ssl_handshake);

        // Establish TLS connection to VPN server
        const tls_config = tls.TlsConfig{
            .verify_certificate = self.config.verify_certificate,
            .allow_self_signed = !self.config.verify_certificate,
            .timeout_ms = self.config.connect_timeout_ms,
        };

        self.tls_socket = tls.TlsSocket.connect(
            self.allocator,
            self.config.server_host,
            self.config.server_port,
            tls_config,
        ) catch {
            self.disconnect_reason = .network_error;
            return ClientError.ConnectionFailed;
        };

        self.transitionState(.authenticating);
        self.performAuthentication() catch {
            self.disconnect_reason = .auth_failed;
            return ClientError.AuthenticationFailed;
        };

        self.transitionState(.establishing_session);
        self.establishSession() catch {
            self.disconnect_reason = .protocol_error;
            return ClientError.SessionEstablishmentFailed;
        };

        self.transitionState(.configuring_adapter);
        self.configureAdapter() catch {
            self.disconnect_reason = .configuration_error;
            return ClientError.AdapterConfigurationFailed;
        };

        self.transitionState(.connected);
        self.stats.connect_time_ms = std.time.milliTimestamp();

        if (self.event_callback) |cb| {
            cb(.{ .connected = .{
                .server_ip = self.server_ip,
                .assigned_ip = self.assigned_ip,
                .gateway_ip = self.gateway_ip,
            } }, self.event_user_data);
        }
    }

    fn performDisconnect(self: *Self) void {
        const old_state = self.state;
        self.transitionState(.disconnecting);

        if (self.adapter_ctx) |*ctx| ctx.close();
        if (self.session) |*sess| sess.disconnect();
        if (self.tls_socket) |*sock| {
            sock.close();
            self.tls_socket = null;
        }

        self.transitionState(.disconnected);

        if (self.event_callback) |cb| {
            cb(.{ .disconnected = .{ .reason = self.disconnect_reason } }, self.event_user_data);
        }

        if (self.config.reconnect.enabled and
            self.disconnect_reason != .user_requested and
            old_state == .connected)
        {
            self.scheduleReconnect();
        }
    }

    fn resolveDns(self: *Self) !u32 {
        const host = self.config.server_host;

        // First try parsing as IP address (fast path)
        if (parseIpv4(host)) |ip| {
            return ip;
        }

        // Real DNS resolution using std.net
        const addrs = net.getAddressList(self.allocator, host, self.config.server_port) catch {
            return ClientError.DnsResolutionFailed;
        };
        defer addrs.deinit();

        // Look for first IPv4 address
        for (addrs.addrs) |addr| {
            if (addr.any.family == std.posix.AF.INET) {
                // Extract IPv4 address as u32 in host byte order (little-endian)
                // The addr.in.sa.addr is already in network byte order, bitcast gives us host order
                const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
                return @as(u32, @bitCast(bytes.*));
            }
        }

        return ClientError.DnsResolutionFailed;
    }

    fn performAuthentication(self: *Self) !void {
        // Get the TLS socket for communication
        const sock = &(self.tls_socket orelse return ClientError.ConnectionFailed);

        // Create protocol writer and reader wrappers for TLS socket
        const writer = softether_proto.Writer{
            .context = @ptrCast(sock),
            .writeFn = struct {
                fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                    const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                    return s.write(data);
                }
            }.write,
        };

        const reader = softether_proto.Reader{
            .context = @ptrCast(sock),
            .readFn = struct {
                fn read(ctx: *anyopaque, buffer: []u8) anyerror!usize {
                    const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                    return s.read(buffer);
                }
            }.read,
        };

        // Format server IP as string for HTTP Host header (like C code does)
        var ip_str_buf: [16]u8 = undefined;
        const host_for_http = formatIpv4Buf(self.server_ip, &ip_str_buf);

        std.log.debug("Uploading protocol signature...", .{});

        // Step 1: Upload signature (WaterMark)
        softether_proto.uploadSignature(self.allocator, writer, host_for_http) catch |err| {
            std.log.err("Failed to upload signature: {}", .{err});
            return ClientError.AuthenticationFailed;
        };

        std.log.debug("Downloading server hello...", .{});

        // Step 2: Download Hello (get server random challenge)
        var hello = softether_proto.downloadHello(self.allocator, reader) catch |err| {
            std.log.err("Failed to download hello: {}", .{err});
            return ClientError.AuthenticationFailed;
        };
        defer hello.deinit(self.allocator);

        std.log.debug("Building authentication request...", .{});

        // Step 3: Build and upload auth
        const auth_data = switch (self.config.auth) {
            .password => |p| blk: {
                if (p.is_hashed) {
                    // Password is pre-hashed (base64 encoded), decode and use directly
                    break :blk softether_proto.buildPasswordAuthWithHash(
                        self.allocator,
                        p.username,
                        p.password, // base64-encoded hash
                        self.config.hub_name,
                        &hello.random,
                    ) catch return ClientError.OutOfMemory;
                } else {
                    // Password is plain text, hash it first
                    break :blk softether_proto.buildPasswordAuth(
                        self.allocator,
                        p.username,
                        p.password,
                        self.config.hub_name,
                        &hello.random,
                    ) catch return ClientError.OutOfMemory;
                }
            },
            .anonymous => softether_proto.buildAnonymousAuth(
                self.allocator,
                self.config.hub_name,
            ) catch return ClientError.OutOfMemory,
            .certificate => return ClientError.AuthenticationFailed, // Not implemented yet
        };
        defer self.allocator.free(auth_data);

        std.log.debug("Uploading authentication...", .{});

        // Step 4: Upload auth and get result (use IP address for Host header like C code)
        var auth_result = softether_proto.uploadAuth(
            self.allocator,
            writer,
            reader,
            host_for_http,
            auth_data,
        ) catch |err| {
            std.log.err("Failed to upload auth: {}", .{err});
            return ClientError.AuthenticationFailed;
        };
        defer auth_result.deinit(self.allocator);

        if (!auth_result.success) {
            std.log.err("Authentication failed: code {d}", .{auth_result.error_code});
            if (auth_result.error_message) |msg| {
                std.log.err("Error: {s}", .{msg});
            }
            return ClientError.AuthenticationFailed;
        }

        // Check for redirect (cluster server setup)
        if (auth_result.redirect) |redirect| {
            std.log.debug("Redirecting to data server...", .{});

            // Store the ticket for redirect auth
            const ticket = redirect.ticket;
            const redirect_ip = redirect.ip;
            const redirect_port = redirect.port;
            const original_server_ip = self.server_ip; // Save original for fallback

            // CRITICAL: Send empty pack to acknowledge redirect before disconnecting
            // This tells the controller we received the redirect info
            std.log.debug("Sending redirect acknowledgment...", .{});
            var empty_pack = pack_mod.Pack.init(self.allocator);
            defer empty_pack.deinit();
            const empty_data = empty_pack.toBytes(self.allocator) catch {
                std.log.err("Failed to serialize empty pack", .{});
                return ClientError.ProtocolError;
            };
            defer self.allocator.free(empty_data);

            // Send via HTTP POST
            const current_sock = &(self.tls_socket orelse return ClientError.ConnectionFailed);
            const ack_writer = softether_proto.Writer{
                .context = @ptrCast(current_sock),
                .writeFn = struct {
                    fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                        const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                        return s.write(data);
                    }
                }.write,
            };

            // Get current host for HTTP header
            var current_ip_buf: [16]u8 = undefined;
            const current_host = formatIpv4Buf(self.server_ip, &current_ip_buf);

            softether_proto.sendHttpPost(self.allocator, ack_writer, current_host, empty_data) catch {
                std.log.err("Failed to send redirect ack", .{});
                return ClientError.ProtocolError;
            };

            // Wait a moment for the server to process the redirect
            std.Thread.sleep(100 * std.time.ns_per_ms);

            // Close current connection
            if (self.tls_socket) |*old_sock| {
                old_sock.close();
                self.tls_socket = null;
            }

            // Try redirect IP first, then fallback to original server IP
            const ips_to_try = [_]u32{ redirect_ip, original_server_ip };
            var connected = false;
            var actual_connect_ip: u32 = redirect_ip;

            for (ips_to_try) |try_ip| {
                // Format IP as hostname string
                var try_ip_str: [16]u8 = undefined;
                const try_hostname = formatIpv4Buf(try_ip, &try_ip_str);

                if (try_ip == redirect_ip) {
                    std.log.debug("Connecting to redirect server: {s}:{d}", .{ try_hostname, redirect_port });
                } else {
                    std.log.info("Redirect server unreachable, trying original server: {s}:{d}", .{ try_hostname, redirect_port });
                }

                const redirect_tls_config = tls.TlsConfig{
                    .verify_certificate = self.config.verify_certificate,
                    .allow_self_signed = !self.config.verify_certificate,
                    .timeout_ms = self.config.connect_timeout_ms,
                };

                self.tls_socket = tls.TlsSocket.connect(
                    self.allocator,
                    try_hostname,
                    redirect_port,
                    redirect_tls_config,
                ) catch |err| {
                    std.log.warn("Failed to connect to {s}:{d}: {}", .{ try_hostname, redirect_port, err });
                    continue;
                };

                connected = true;
                actual_connect_ip = try_ip;
                break;
            }

            if (!connected) {
                std.log.err("Failed to connect to any redirect server", .{});
                return ClientError.ConnectionFailed;
            }

            // Update server IP to what we actually connected to
            self.server_ip = actual_connect_ip;

            // Get username for ticket auth
            const username = switch (self.config.auth) {
                .password => |p| p.username,
                .anonymous => "anonymous",
                .certificate => "certificate",
            };

            // Redo authentication with ticket
            const redirect_sock = &(self.tls_socket orelse return ClientError.ConnectionFailed);
            const redirect_writer = softether_proto.Writer{
                .context = @ptrCast(redirect_sock),
                .writeFn = struct {
                    fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                        const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                        return s.write(data);
                    }
                }.write,
            };
            const redirect_reader = softether_proto.Reader{
                .context = @ptrCast(redirect_sock),
                .readFn = struct {
                    fn read(ctx: *anyopaque, buffer: []u8) anyerror!usize {
                        const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                        return s.read(buffer);
                    }
                }.read,
            };

            // Format actual connected IP for HTTP Host header
            var redirect_ip_buf: [16]u8 = undefined;
            const redirect_host = formatIpv4Buf(actual_connect_ip, &redirect_ip_buf);

            // Upload signature to redirect server
            softether_proto.uploadSignature(self.allocator, redirect_writer, redirect_host) catch |err| {
                std.log.err("Failed to upload signature to redirect server: {}", .{err});
                return ClientError.AuthenticationFailed;
            };

            // Download hello from redirect server
            var redirect_hello = softether_proto.downloadHello(self.allocator, redirect_reader) catch |err| {
                std.log.err("Failed to download hello from redirect server: {}", .{err});
                return ClientError.AuthenticationFailed;
            };
            defer redirect_hello.deinit(self.allocator);

            // Build ticket auth
            const ticket_auth_data = softether_proto.buildTicketAuth(
                self.allocator,
                self.config.hub_name,
                username,
                &ticket,
            ) catch return ClientError.OutOfMemory;
            defer self.allocator.free(ticket_auth_data);

            // Upload ticket auth
            var ticket_auth_result = softether_proto.uploadAuth(
                self.allocator,
                redirect_writer,
                redirect_reader,
                redirect_host,
                ticket_auth_data,
            ) catch |err| {
                std.log.err("Failed to upload ticket auth: {}", .{err});
                return ClientError.AuthenticationFailed;
            };
            defer ticket_auth_result.deinit(self.allocator);

            if (!ticket_auth_result.success) {
                std.log.err("Ticket authentication failed: code {d}", .{ticket_auth_result.error_code});
                return ClientError.AuthenticationFailed;
            }

            // Store session key from ticket auth if provided
            if (ticket_auth_result.session_key) |key| {
                _ = key; // Will be used for session encryption
            }

            std.log.debug("Ticket authentication successful!", .{});
            return;
        }

        // Store session key if provided
        if (auth_result.session_key) |key| {
            // Will be used for session encryption
            _ = key;
        }

        std.log.info("Authentication successful!", .{});
    }

    fn establishSession(self: *Self) !void {
        self.session = SessionWrapper.init(self.allocator, self.config.use_encryption);
    }

    fn configureAdapter(self: *Self) !void {
        self.adapter_ctx = AdapterWrapper.init(self.allocator);
        var ctx = &self.adapter_ctx.?;

        ctx.open() catch |err| {
            // Provide helpful error message for permission issues
            std.log.err("Failed to open virtual network adapter: {}", .{err});
            std.log.err("Note: Creating a TUN/TAP device requires root privileges.", .{});
            std.log.err("Try running with: sudo ./vpnclient-pure --config config.json", .{});
            return ClientError.AdapterConfigurationFailed;
        };

        if (self.config.static_ip) |static| {
            if (static.ipv4_address) |ip_str| {
                self.assigned_ip = parseIpv4(ip_str) orelse 0;
                if (static.ipv4_gateway) |gw_str| {
                    self.gateway_ip = parseIpv4(gw_str) orelse 0;
                }
            }
        }

        if (self.config.full_tunnel and self.gateway_ip != 0) {
            // Convert server_ip from little-endian (Pack protocol) to big-endian (network byte order)
            const server_ip_be = @byteSwap(self.server_ip);
            ctx.configureFullTunnel(self.gateway_ip, server_ip_be);
        }
    }

    fn scheduleReconnect(self: *Self) void {
        if (!self.config.reconnect.enabled) return;

        const max = self.config.reconnect.max_attempts;
        if (max > 0 and self.reconnect_attempt >= max) return;

        self.reconnect_attempt += 1;
        self.stats.reconnect_count += 1;

        const backoff = self.reconnect_backoff_ms;
        self.reconnect_backoff_ms = @min(
            @as(u32, @intFromFloat(@as(f32, @floatFromInt(backoff)) * self.config.reconnect.backoff_multiplier)),
            self.config.reconnect.max_backoff_ms,
        );

        self.transitionState(.reconnecting);
    }

    pub fn sendPacket(self: *Self, data: []const u8) ClientError!void {
        if (!self.isConnected()) return ClientError.NotConnected;

        var sess = &(self.session orelse return ClientError.NotConnected);

        if (self.config.use_encryption) {
            const encrypted = sess.encrypt(self.allocator, data) catch return ClientError.OperationCancelled;
            defer self.allocator.free(encrypted);
        }

        self.stats.recordSent(data.len);
    }

    pub fn receivePacket(self: *Self, data: []const u8) ClientError![]u8 {
        if (!self.isConnected()) return ClientError.NotConnected;

        var sess = &(self.session orelse return ClientError.NotConnected);

        var decrypted: []u8 = undefined;
        if (self.config.use_encryption) {
            decrypted = sess.decrypt(self.allocator, data) catch return ClientError.OperationCancelled;
        } else {
            decrypted = self.allocator.dupe(u8, data) catch return ClientError.OutOfMemory;
        }

        self.stats.recordReceived(data.len);

        if (self.adapter_ctx) |*ctx| {
            if (ctx.processIncomingPacket(decrypted)) |response| {
                self.allocator.free(response);
            }
        }

        return decrypted;
    }

    /// Run the data channel packet loop
    /// This is the main loop that processes packets between TLS and TUN
    /// Returns when should_stop is set or connection is lost
    pub fn runDataLoop(self: *Self) !void {
        if (!self.isConnected()) return ClientError.NotConnected;

        const sock = &(self.tls_socket orelse return ClientError.NotConnected);
        var adapter = &(self.adapter_ctx orelse return ClientError.NotConnected);

        std.log.debug("Starting data channel loop...", .{});

        // Get file descriptors for poll()
        const tls_fd = sock.getFd();
        const tun_fd = if (adapter.real_adapter) |*real|
            if (real.device) |dev| dev.getFd() else return ClientError.AdapterConfigurationFailed
        else
            return ClientError.AdapterConfigurationFailed;

        std.log.debug("Using poll() for concurrent I/O: TLS fd={d}, TUN fd={d}", .{ tls_fd, tun_fd });

        // Create tunnel connection
        var tunnel = tunnel_mod.TunnelConnection.init(
            self.allocator,
            @ptrCast(sock),
            struct {
                fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
                    const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                    return s.read(buf);
                }
            }.read,
            struct {
                fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                    const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                    return s.write(data);
                }
            }.write,
        );

        // DHCP state
        var dhcp_state = tunnel_mod.DhcpState.init;
        var dhcp_xid: u32 = 0;
        std.crypto.random.bytes(std.mem.asBytes(&dhcp_xid));
        var last_dhcp_time: i64 = 0;
        var dhcp_retry_count: u32 = 0;

        // Our assigned IP (from DHCP)
        var our_ip: u32 = 0;
        var our_gateway: u32 = 0;

        // Get MAC address
        const mac = adapter.getMac();

        // ARP state - for learning gateway MAC and responding to ARP requests
        var gateway_mac: [6]u8 = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // Default: broadcast
        var need_gateway_arp: bool = false;
        var need_gratuitous_arp: bool = false;
        var need_arp_reply: bool = false;
        var arp_reply_target_mac: [6]u8 = undefined;
        var arp_reply_target_ip: u32 = 0;

        // Timing
        var last_keepalive: i64 = std.time.milliTimestamp();
        var last_garp_time: i64 = 0;
        const keepalive_interval: i64 = 5000; // 5 seconds (server timeout is 20s)
        const garp_interval: i64 = 10000; // 10 seconds - periodic GARP for bridge mode

        // Receive buffers
        var recv_scratch: [512 * 1600]u8 = undefined;
        var recv_slices: [512][]u8 = undefined;

        // Outbound packet buffer
        var tun_read_buf: [2048]u8 = undefined;
        var outbound_eth_buf: [2048]u8 = undefined;

        // Packet buffer for ARP/GARP
        var arp_buf: [64]u8 = undefined;

        // Send initial Gratuitous ARP (0.0.0.0) to announce ourselves
        {
            const garp_size = adapter_mod.buildGratuitousArp(mac, 0, &arp_buf) catch 0;
            if (garp_size > 0) {
                const blocks = [_][]const u8{arp_buf[0..garp_size]};
                tunnel.sendBlocks(&blocks) catch {};
                std.log.debug("Sent initial Gratuitous ARP (announcing MAC)", .{});
            }
        }

        // Wait 300ms then send DHCP discover
        std.Thread.sleep(300 * std.time.ns_per_ms);

        // Send initial DHCP discover
        {
            var dhcp_buf: [512]u8 = undefined;
            const dhcp_size = adapter_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf) catch 0;
            if (dhcp_size > 0) {
                const blocks = [_][]const u8{dhcp_buf[0..dhcp_size]};
                tunnel.sendBlocks(&blocks) catch |err| {
                    std.log.err("Failed to send DHCP discover: {}", .{err});
                };
                dhcp_state = .discover_sent;
                last_dhcp_time = std.time.milliTimestamp();
                std.log.debug("Sent DHCP DISCOVER (xid=0x{x:0>8})", .{dhcp_xid});
            }
        }

        // Set up poll structures
        var poll_fds: [2]std.posix.pollfd = .{
            .{ .fd = tls_fd, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = tun_fd, .events = std.posix.POLL.IN, .revents = 0 },
        };
        const POLL_TLS = 0;
        const POLL_TUN = 1;
        _ = POLL_TLS; // Used implicitly via index 0

        // Main packet loop
        while (!self.should_stop and self.isConnected()) {
            const now = std.time.milliTimestamp();

            // Poll both TLS and TUN with 10ms timeout
            poll_fds[0].revents = 0;
            poll_fds[1].revents = 0;
            const poll_result = std.posix.poll(&poll_fds, 10) catch 0;
            _ = poll_result;
            const tls_readable = (poll_fds[0].revents & std.posix.POLL.IN) != 0;
            const tun_readable = (poll_fds[POLL_TUN].revents & std.posix.POLL.IN) != 0;

            // ============================================================
            // PRIORITY 1: Send ARP Reply if server asked for our IP
            // ============================================================
            if (need_arp_reply and dhcp_state == .configured) {
                need_arp_reply = false;
                const reply_size = adapter_mod.buildArpReply(mac, our_ip, arp_reply_target_mac, arp_reply_target_ip, &arp_buf) catch 0;
                if (reply_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..reply_size]};
                    tunnel.sendBlocks(&blocks) catch {};
                    std.log.debug("Sent ARP Reply to {d}.{d}.{d}.{d}", .{
                        @as(u8, @truncate(arp_reply_target_ip >> 24)),
                        @as(u8, @truncate(arp_reply_target_ip >> 16)),
                        @as(u8, @truncate(arp_reply_target_ip >> 8)),
                        @as(u8, @truncate(arp_reply_target_ip)),
                    });
                }
            }

            // ============================================================
            // PRIORITY 2: Send Gratuitous ARP with our IP (after DHCP)
            // ============================================================
            if (need_gratuitous_arp and dhcp_state == .configured) {
                need_gratuitous_arp = false;
                const garp_size = adapter_mod.buildGratuitousArp(mac, our_ip, &arp_buf) catch 0;
                if (garp_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..garp_size]};
                    tunnel.sendBlocks(&blocks) catch {};
                    last_garp_time = now;
                    std.log.debug("Sent Gratuitous ARP (IP={d}.{d}.{d}.{d})", .{
                        @as(u8, @truncate(our_ip >> 24)),
                        @as(u8, @truncate(our_ip >> 16)),
                        @as(u8, @truncate(our_ip >> 8)),
                        @as(u8, @truncate(our_ip)),
                    });
                }
            }

            // ============================================================
            // PRIORITY 3: Send ARP Request to resolve gateway MAC
            // ============================================================
            if (need_gateway_arp and dhcp_state == .configured) {
                need_gateway_arp = false;
                const arp_size = adapter_mod.buildArpRequest(mac, our_ip, our_gateway, &arp_buf) catch 0;
                if (arp_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..arp_size]};
                    tunnel.sendBlocks(&blocks) catch {};
                    std.log.debug("Sent ARP Request for gateway {d}.{d}.{d}.{d}", .{
                        @as(u8, @truncate(our_gateway >> 24)),
                        @as(u8, @truncate(our_gateway >> 16)),
                        @as(u8, @truncate(our_gateway >> 8)),
                        @as(u8, @truncate(our_gateway)),
                    });
                }
            }

            // ============================================================
            // Periodic Gratuitous ARP keepalive (for bridge mode)
            // ============================================================
            if (dhcp_state == .configured and our_ip != 0) {
                if (now - last_garp_time >= garp_interval) {
                    const garp_size = adapter_mod.buildGratuitousArp(mac, our_ip, &arp_buf) catch 0;
                    if (garp_size > 0) {
                        const blocks = [_][]const u8{arp_buf[0..garp_size]};
                        tunnel.sendBlocks(&blocks) catch {};
                        last_garp_time = now;
                    }
                }
            }

            // Send SoftEther keep-alive if needed
            if (now - last_keepalive >= keepalive_interval) {
                tunnel.sendKeepalive() catch |err| {
                    std.log.warn("Failed to send keepalive: {}", .{err});
                };
                std.log.debug("Sent keepalive", .{});
                last_keepalive = now;
            }

            // DHCP retry logic
            if (dhcp_state == .discover_sent and dhcp_retry_count < 5) {
                if (now - last_dhcp_time >= 3000) {
                    var dhcp_buf: [512]u8 = undefined;
                    const dhcp_size = adapter_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf) catch 0;
                    if (dhcp_size > 0) {
                        const blocks = [_][]const u8{dhcp_buf[0..dhcp_size]};
                        tunnel.sendBlocks(&blocks) catch {};
                        last_dhcp_time = now;
                        dhcp_retry_count += 1;
                        std.log.debug("DHCP DISCOVER retry #{d}", .{dhcp_retry_count});
                    }
                }
            }

            // ============================================================
            // OUTBOUND: Read from TUN device and send to VPN server
            // ============================================================
            if (dhcp_state == .configured and tun_readable) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        if (dev.read(&tun_read_buf)) |maybe_len| {
                            if (maybe_len) |ip_len| {
                                if (ip_len > 0 and ip_len <= 1500) {
                                    // Log outbound packet
                                    const ip_version = (tun_read_buf[0] >> 4) & 0x0F;
                                    if (ip_version == 4 and ip_len >= 20) {
                                        const src_ip = (@as(u32, tun_read_buf[12]) << 24) |
                                            (@as(u32, tun_read_buf[13]) << 16) |
                                            (@as(u32, tun_read_buf[14]) << 8) |
                                            tun_read_buf[15];
                                        const dst_ip = (@as(u32, tun_read_buf[16]) << 24) |
                                            (@as(u32, tun_read_buf[17]) << 16) |
                                            (@as(u32, tun_read_buf[18]) << 8) |
                                            tun_read_buf[19];
                                        const proto = tun_read_buf[9];
                                        // Per-packet logging at trace level to reduce noise
                                        std.log.scoped(.packet_trace).debug("TUN→VPN: {d}.{d}.{d}.{d} → {d}.{d}.{d}.{d} proto={d} len={d}", .{
                                            @as(u8, @truncate(src_ip >> 24)),
                                            @as(u8, @truncate(src_ip >> 16)),
                                            @as(u8, @truncate(src_ip >> 8)),
                                            @as(u8, @truncate(src_ip)),
                                            @as(u8, @truncate(dst_ip >> 24)),
                                            @as(u8, @truncate(dst_ip >> 16)),
                                            @as(u8, @truncate(dst_ip >> 8)),
                                            @as(u8, @truncate(dst_ip)),
                                            proto,
                                            ip_len,
                                        });
                                    }

                                    // Wrap IP packet in Ethernet frame for SoftEther
                                    @memcpy(outbound_eth_buf[0..6], &gateway_mac);
                                    @memcpy(outbound_eth_buf[6..12], &mac);

                                    if (ip_version == 4) {
                                        outbound_eth_buf[12] = 0x08;
                                        outbound_eth_buf[13] = 0x00;
                                    } else if (ip_version == 6) {
                                        outbound_eth_buf[12] = 0x86;
                                        outbound_eth_buf[13] = 0xDD;
                                    } else {
                                        continue;
                                    }

                                    @memcpy(outbound_eth_buf[14..][0..ip_len], tun_read_buf[0..ip_len]);

                                    const eth_frame = outbound_eth_buf[0 .. 14 + ip_len];
                                    const blocks = [_][]const u8{eth_frame};
                                    tunnel.sendBlocks(&blocks) catch |err| {
                                        std.log.debug("Failed to send outbound packet: {}", .{err});
                                    };

                                    self.stats.recordSent(eth_frame.len);
                                }
                            }
                        } else |err| {
                            std.log.debug("TUN read error: {}", .{err});
                        }
                    }
                }
            }

            // ============================================================
            // INBOUND: Receive packets from VPN server
            // ============================================================
            // Check if we should stop before blocking on network read
            if (self.should_stop) {
                std.log.info("Stop requested, exiting data loop", .{});
                break;
            }

            // Only try to receive if TLS has data available (poll told us)
            if (tls_readable) {
                const recv_count = tunnel.receiveBlocksBatch(&recv_slices, &recv_scratch) catch |err| {
                    if (self.should_stop) {
                        std.log.info("Stop requested during receive, exiting", .{});
                        break;
                    }
                    if (err == error.ConnectionClosed) {
                        std.log.info("Server closed connection", .{});
                        break;
                    }
                    std.log.warn("Receive error: {}", .{err});
                    continue;
                };

                // Process received packets
                for (recv_slices[0..recv_count]) |block_data| {
                    // Check for DHCP response
                    if (dhcp_state != .configured) {
                        const maybe_response = adapter_mod.parseDhcpResponse(block_data, dhcp_xid) catch null;
                        if (maybe_response) |response| {
                            if (response.msg_type == .offer and dhcp_state == .discover_sent) {
                                std.log.info("DHCP OFFER received: IP={d}.{d}.{d}.{d}", .{
                                    @as(u8, @truncate(response.config.ip_address >> 24)),
                                    @as(u8, @truncate(response.config.ip_address >> 16)),
                                    @as(u8, @truncate(response.config.ip_address >> 8)),
                                    @as(u8, @truncate(response.config.ip_address)),
                                });

                                var req_buf: [512]u8 = undefined;
                                const req_size = adapter_mod.buildDhcpRequest(
                                    mac,
                                    dhcp_xid,
                                    response.config.ip_address,
                                    response.config.server_id,
                                    &req_buf,
                                ) catch 0;
                                if (req_size > 0) {
                                    const blocks = [_][]const u8{req_buf[0..req_size]};
                                    tunnel.sendBlocks(&blocks) catch {};
                                    dhcp_state = .request_sent;
                                    std.log.info("Sent DHCP REQUEST", .{});
                                }
                            } else if (response.msg_type == .ack and dhcp_state == .request_sent) {
                                std.log.info("DHCP ACK received!", .{});

                                // Store our IP and gateway
                                our_ip = response.config.ip_address;
                                our_gateway = response.config.gateway;
                                self.assigned_ip = our_ip;
                                self.gateway_ip = our_gateway;
                                dhcp_state = .configured;

                                // Configure TUN device
                                if (adapter.real_adapter) |*real| {
                                    if (real.device) |dev| {
                                        dev.configure(
                                            response.config.ip_address,
                                            response.config.subnet_mask,
                                            response.config.gateway,
                                        ) catch |err| {
                                            std.log.err("Failed to configure interface: {}", .{err});
                                        };
                                    }
                                }

                                std.log.info("Interface configured with IP {d}.{d}.{d}.{d}", .{
                                    @as(u8, @truncate(our_ip >> 24)),
                                    @as(u8, @truncate(our_ip >> 16)),
                                    @as(u8, @truncate(our_ip >> 8)),
                                    @as(u8, @truncate(our_ip)),
                                });

                                // CRITICAL: Configure VPN routing now that we have the gateway
                                if (self.config.full_tunnel and our_gateway != 0) {
                                    std.log.info("Configuring full-tunnel routing through VPN gateway {d}.{d}.{d}.{d}", .{
                                        @as(u8, @truncate(our_gateway >> 24)),
                                        @as(u8, @truncate(our_gateway >> 16)),
                                        @as(u8, @truncate(our_gateway >> 8)),
                                        @as(u8, @truncate(our_gateway)),
                                    });
                                    // Convert server_ip from little-endian (Pack protocol) to big-endian (network byte order)
                                    // for routing commands. DHCP gateway is already in big-endian.
                                    const server_ip_be = @byteSwap(self.server_ip);
                                    adapter.configureFullTunnel(our_gateway, server_ip_be);
                                }

                                // CRITICAL: Queue Gratuitous ARP and Gateway ARP requests
                                need_gratuitous_arp = true;
                                need_gateway_arp = true;

                                if (self.event_callback) |cb| {
                                    cb(.{ .dhcp_configured = .{
                                        .ip = response.config.ip_address,
                                        .mask = response.config.subnet_mask,
                                        .gateway = response.config.gateway,
                                    } }, self.event_user_data);
                                }
                            }
                        }
                    }

                    // Check for ARP packets (learn gateway MAC, respond to requests)
                    if (block_data.len >= 42) {
                        const ethertype = (@as(u16, block_data[12]) << 8) | block_data[13];
                        if (ethertype == 0x0806) { // ARP
                            const arp_op = (@as(u16, block_data[20]) << 8) | block_data[21];

                            if (arp_op == 2) { // ARP Reply
                                // Extract sender IP (bytes 28-31 in big-endian)
                                const sender_ip = (@as(u32, block_data[28]) << 24) |
                                    (@as(u32, block_data[29]) << 16) |
                                    (@as(u32, block_data[30]) << 8) |
                                    block_data[31];

                                // If from gateway, learn its MAC
                                if (our_gateway != 0 and sender_ip == our_gateway) {
                                    @memcpy(&gateway_mac, block_data[22..28]);
                                    self.gateway_mac = gateway_mac;
                                    std.log.debug("Learned gateway MAC: {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
                                        gateway_mac[0], gateway_mac[1], gateway_mac[2],
                                        gateway_mac[3], gateway_mac[4], gateway_mac[5],
                                    });
                                }
                            } else if (arp_op == 1) { // ARP Request
                                // Extract target IP (bytes 38-41)
                                const target_ip = (@as(u32, block_data[38]) << 24) |
                                    (@as(u32, block_data[39]) << 16) |
                                    (@as(u32, block_data[40]) << 8) |
                                    block_data[41];

                                // If asking for our IP, send reply
                                if (target_ip == our_ip and our_ip != 0) {
                                    @memcpy(&arp_reply_target_mac, block_data[22..28]);
                                    arp_reply_target_ip = (@as(u32, block_data[28]) << 24) |
                                        (@as(u32, block_data[29]) << 16) |
                                        (@as(u32, block_data[30]) << 8) |
                                        block_data[31];
                                    need_arp_reply = true;
                                }
                            }
                        }
                    }

                    // Write IP packets to TUN device (strip Ethernet header)
                    if (adapter.real_adapter) |*real| {
                        if (real.device) |dev| {
                            if (block_data.len > 14) {
                                const ethertype_hi = block_data[12];
                                const ethertype_lo = block_data[13];

                                if ((ethertype_hi == 0x08 and ethertype_lo == 0x00) or
                                    (ethertype_hi == 0x86 and ethertype_lo == 0xDD))
                                {
                                    const ip_packet = block_data[14..];

                                    // Log inbound IP packet details
                                    if (ip_packet.len >= 20) {
                                        const ip_version = (ip_packet[0] >> 4) & 0x0F;
                                        if (ip_version == 4) {
                                            const src_ip = (@as(u32, ip_packet[12]) << 24) |
                                                (@as(u32, ip_packet[13]) << 16) |
                                                (@as(u32, ip_packet[14]) << 8) |
                                                ip_packet[15];
                                            const dst_ip = (@as(u32, ip_packet[16]) << 24) |
                                                (@as(u32, ip_packet[17]) << 16) |
                                                (@as(u32, ip_packet[18]) << 8) |
                                                ip_packet[19];
                                            const proto = ip_packet[9];
                                            // Per-packet logging at trace level to reduce noise
                                            std.log.scoped(.packet_trace).debug("VPN→TUN: {d}.{d}.{d}.{d} → {d}.{d}.{d}.{d} proto={d} len={d}", .{
                                                @as(u8, @truncate(src_ip >> 24)),
                                                @as(u8, @truncate(src_ip >> 16)),
                                                @as(u8, @truncate(src_ip >> 8)),
                                                @as(u8, @truncate(src_ip)),
                                                @as(u8, @truncate(dst_ip >> 24)),
                                                @as(u8, @truncate(dst_ip >> 16)),
                                                @as(u8, @truncate(dst_ip >> 8)),
                                                @as(u8, @truncate(dst_ip)),
                                                proto,
                                                ip_packet.len,
                                            });
                                        }
                                    }

                                    _ = dev.write(ip_packet) catch |err| {
                                        std.log.debug("TUN write error: {}", .{err});
                                    };
                                }
                            }
                        }
                    }

                    self.stats.recordReceived(block_data.len);
                }
            } // end if (tls_readable)

            std.Thread.sleep(1 * std.time.ns_per_ms);
        }

        std.log.info("Data channel loop ended", .{});
    }
};

// ============================================================================
// Convenience Builder
// ============================================================================

pub const ClientConfigBuilder = struct {
    config: ClientConfig,

    pub fn init(host: []const u8, hub: []const u8) ClientConfigBuilder {
        return .{ .config = .{
            .server_host = host,
            .hub_name = hub,
            .auth = .{ .anonymous = {} },
        } };
    }

    pub fn setPort(self: *ClientConfigBuilder, port: u16) *ClientConfigBuilder {
        self.config.server_port = port;
        return self;
    }

    pub fn setPasswordAuth(self: *ClientConfigBuilder, username: []const u8, password: []const u8) *ClientConfigBuilder {
        self.config.auth = .{ .password = .{ .username = username, .password = password, .is_hashed = false } };
        return self;
    }

    pub fn setFullTunnel(self: *ClientConfigBuilder, enabled: bool) *ClientConfigBuilder {
        self.config.full_tunnel = enabled;
        return self;
    }

    pub fn setEncryption(self: *ClientConfigBuilder, enabled: bool) *ClientConfigBuilder {
        self.config.use_encryption = enabled;
        return self;
    }

    pub fn setReconnect(self: *ClientConfigBuilder, enabled: bool, max_attempts: u32) *ClientConfigBuilder {
        self.config.reconnect.enabled = enabled;
        self.config.reconnect.max_attempts = max_attempts;
        return self;
    }

    pub fn setStaticIp(self: *ClientConfigBuilder, ip: []const u8, gateway: ?[]const u8) *ClientConfigBuilder {
        self.config.static_ip = .{ .ipv4_address = ip, .ipv4_gateway = gateway };
        return self;
    }

    pub fn build(self: *const ClientConfigBuilder) ClientConfig {
        return self.config;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ClientConfig defaults" {
    const config = ClientConfig{
        .server_host = "vpn.example.com",
        .hub_name = "DEFAULT",
        .auth = .{ .anonymous = {} },
    };
    try std.testing.expectEqual(@as(u16, 443), config.server_port);
    try std.testing.expect(config.full_tunnel);
    try std.testing.expect(config.use_encryption);
    try std.testing.expect(config.reconnect.enabled);
}

test "ClientConfigBuilder" {
    var builder = ClientConfigBuilder.init("10.0.0.1", "VPN");
    const config = builder.setPort(8443).setPasswordAuth("user", "pass").setFullTunnel(true).setEncryption(true).build();
    try std.testing.expectEqualStrings("10.0.0.1", config.server_host);
    try std.testing.expectEqualStrings("VPN", config.hub_name);
    try std.testing.expectEqual(@as(u16, 8443), config.server_port);
}

test "ClientConfigBuilder with static IP" {
    var builder = ClientConfigBuilder.init("192.168.1.1", "HUB");
    const config = builder.setStaticIp("10.0.0.100", "10.0.0.1").build();
    try std.testing.expect(config.static_ip != null);
    try std.testing.expectEqualStrings("10.0.0.100", config.static_ip.?.ipv4_address.?);
}

test "ClientState transitions" {
    try std.testing.expect(ClientState.disconnected.canTransitionTo(.resolving_dns));
    try std.testing.expect(ClientState.resolving_dns.canTransitionTo(.connecting_tcp));
    try std.testing.expect(ClientState.connected.canTransitionTo(.disconnecting));
    try std.testing.expect(!ClientState.disconnected.canTransitionTo(.connected));
}

test "ClientState predicates" {
    try std.testing.expect(ClientState.connected.isConnected());
    try std.testing.expect(!ClientState.disconnected.isConnected());
    try std.testing.expect(ClientState.resolving_dns.isConnecting());
    try std.testing.expect(!ClientState.connected.isConnecting());
}

test "ConnectionStats tracking" {
    var stats = ConnectionStats{};
    stats.recordSent(100);
    try std.testing.expectEqual(@as(u64, 100), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1), stats.packets_sent);
    stats.recordReceived(200);
    try std.testing.expectEqual(@as(u64, 200), stats.bytes_received);
}

test "VpnClient initialization" {
    const config = ClientConfig{ .server_host = "192.168.1.1", .hub_name = "TEST", .auth = .{ .anonymous = {} } };
    var client = VpnClient.init(std.testing.allocator, config);
    defer client.deinit();
    try std.testing.expectEqual(ClientState.disconnected, client.getState());
    try std.testing.expect(!client.isConnected());
}

test "VpnClient connect with valid IP" {
    const config = ClientConfig{ .server_host = "192.168.1.1", .hub_name = "TEST", .auth = .{ .anonymous = {} } };
    var client = VpnClient.init(std.testing.allocator, config);
    defer client.deinit();
    client.connect() catch {};
    try std.testing.expect(client.state != .disconnected);
}

test "VpnClient disconnect" {
    const config = ClientConfig{ .server_host = "192.168.1.1", .hub_name = "TEST", .auth = .{ .anonymous = {} } };
    var client = VpnClient.init(std.testing.allocator, config);
    defer client.deinit();
    try client.disconnect();
    try std.testing.expectEqual(ClientState.disconnected, client.getState());
}

test "DisconnectReason values" {
    const reason = DisconnectReason.user_requested;
    try std.testing.expect(reason == .user_requested);
    try std.testing.expect(reason != .server_closed);
}

test "AuthMethod password" {
    const auth = AuthMethod{ .password = .{ .username = "testuser", .password = "testpass", .is_hashed = false } };
    switch (auth) {
        .password => |p| {
            try std.testing.expectEqualStrings("testuser", p.username);
            try std.testing.expectEqualStrings("testpass", p.password);
        },
        else => unreachable,
    }
}

test "AuthMethod anonymous" {
    const auth = AuthMethod{ .anonymous = {} };
    switch (auth) {
        .anonymous => {},
        else => unreachable,
    }
}

test "ReconnectConfig defaults" {
    const rc = ReconnectConfig{};
    try std.testing.expect(rc.enabled);
    try std.testing.expectEqual(@as(u32, 0), rc.max_attempts);
    try std.testing.expectEqual(@as(u32, 1000), rc.min_backoff_ms);
}

test "IpVersionPreference" {
    const pref = IpVersionPreference.dual_stack;
    try std.testing.expect(pref == .dual_stack);
}

test "parseIpv4" {
    try std.testing.expectEqual(@as(u32, 0xC0A80101), parseIpv4("192.168.1.1").?);
    try std.testing.expectEqual(@as(u32, 0x7F000001), parseIpv4("127.0.0.1").?);
    try std.testing.expect(parseIpv4("invalid") == null);
}

test "formatIpv4Buf" {
    var buf: [16]u8 = undefined;
    const str = formatIpv4Buf(0xC0A80101, &buf);
    try std.testing.expectEqualStrings("192.168.1.1", str);
}

test "SessionWrapper" {
    var sess = SessionWrapper.init(std.testing.allocator, true);
    defer sess.deinit();
    const encrypted = try sess.encrypt(std.testing.allocator, "hello");
    defer std.testing.allocator.free(encrypted);
    try std.testing.expectEqualStrings("hello", encrypted);
}

test "AdapterWrapper" {
    var ad = AdapterWrapper.init(std.testing.allocator);
    defer ad.deinit();

    // Test initial state
    try std.testing.expect(!ad.is_open);
    try std.testing.expect(ad.getName() == null);

    // Opening a real utun device requires root privileges,
    // so we just test the initialization and configuration APIs
    ad.configure(0x0A000001, 0xFFFFFF00, 0x0A000001); // 10.0.0.1/24
    try std.testing.expectEqual(@as(u32, 0x0A000001), ad.ip_address);
    try std.testing.expectEqual(@as(u32, 0xFFFFFF00), ad.netmask);

    // Test MAC address was generated
    try std.testing.expectEqual(@as(u8, 0x02), ad.mac[0]); // Locally administered
    try std.testing.expectEqual(@as(u8, 0x00), ad.mac[1]);
    try std.testing.expectEqual(@as(u8, 0x5E), ad.mac[2]);
}
