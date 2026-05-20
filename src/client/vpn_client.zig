//! SoftEther VPN Client
//!
//! High-level VPN client API.
//! This module provides a complete VPN client implementation without
//! any C dependencies.
//!
//! Architecture:
//! - VpnClient: Main client facade
//! - ClientConfig: Connection configuration
//! - ClientState: Connection state machine (see state.zig)
//! - PacketProcessor: Packet processing pipeline

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const builtin = @import("builtin");
const net = std.net;

// Import core utilities
const core = @import("../core/mod.zig");
const parseIpv4 = core.parseIpv4;
const formatIpv4Buf = core.formatIpv4;

// Import extracted client modules
const state_mod = @import("state.zig");
const stats_mod = @import("stats.zig");
const events_mod = @import("events.zig");

pub const ClientState = state_mod.ClientState;
pub const ConnectionStats = stats_mod.ConnectionStats;
pub const DisconnectReason = stats_mod.DisconnectReason;
pub const ClientEvent = events_mod.ClientEvent;
pub const ClientError = events_mod.ClientError;
pub const EventCallback = events_mod.EventCallback;

// Import real networking modules
const net_mod = @import("../net/net.zig");
const socket = net_mod.socket;
const tls = net_mod.tls;

// Import session module
const session_mod = @import("../session/mod.zig");
const RealSession = session_mod.Session;
const SessionOptions = session_mod.SessionOptions;
const SessionWrapper = session_mod.SessionWrapper;

// Import adapter module
const adapter_mod = @import("../adapter/mod.zig");
const VirtualAdapter = adapter_mod.VirtualAdapter;
const AdapterWrapper = adapter_mod.AdapterWrapper;

// Import protocol modules
const auth_mod = @import("../protocol/auth.zig");
const rpc = @import("../protocol/rpc.zig");
const softether_proto = @import("../protocol/softether_protocol.zig");
const pack_mod = @import("../protocol/pack.zig");
const protocol_tunnel_mod = @import("../protocol/tunnel.zig");

// Import UDP acceleration
const udp_accel_mod = @import("../net/udp_accel.zig");

// Import tunnel module (data loop helpers)
const tunnel_mod = @import("../tunnel/mod.zig");

// Import DHCP parsing
const dhcp_mod = @import("../adapter/dhcp.zig");

// Import connection manager for multi-TCP
const connection_manager = @import("connection_manager.zig");
const ConnectionManager = connection_manager.ConnectionManager;
const TcpDirection = connection_manager.TcpDirection;

// Windows multimedia timer API (for high-resolution poll timeouts)
const winmm = if (builtin.os.tag == .windows) struct {
    extern "winmm" fn timeBeginPeriod(uPeriod: c_uint) callconv(.winapi) c_uint;
    extern "winmm" fn timeEndPeriod(uPeriod: c_uint) callconv(.winapi) c_uint;
} else struct {};

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

/// Routing configuration
pub const RoutingConfig = struct {
    /// Send ALL traffic through VPN (set VPN as default gateway)
    default_route: bool = true,
    /// Accept routes pushed by VPN server (DHCP option 121/249)
    accept_pushed_routes: bool = true,
    /// Enable custom route includes/excludes
    enable_custom_routes: bool = false,
    /// IPv4 routes to include (CIDR notation) - only these routes through VPN
    ipv4_include: ?[]const []const u8 = null,
    /// IPv4 routes to exclude (CIDR notation) - these routes NOT through VPN
    ipv4_exclude: ?[]const []const u8 = null,
    /// IPv6 routes to include (CIDR notation)
    ipv6_include: ?[]const []const u8 = null,
    /// IPv6 routes to exclude (CIDR notation)
    ipv6_exclude: ?[]const []const u8 = null,
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
    // LIBSE-93: enable multi-connection by default to fix UL→DL choke.
    // Single TCP socket carrying both directions causes server-side cwnd starvation
    // (delayed ACKs during heavy UL bursts). 8 connections + half-connection mode
    // splits TX and RX onto separate sockets, eliminating the choke completely.
    // Server can override via applyServerOverrides() if it caps lower.
    max_connections: u8 = 8,
    use_compression: bool = false,
    use_encryption: bool = true,
    udp_acceleration: bool = false,
    half_connection: bool = false,
    qos: bool = true,
    mtu: u16 = 1400,

    // TLS settings
    verify_certificate: bool = true,

    // Routing
    routing: RoutingConfig = .{},

    // Reconnection
    reconnect: ReconnectConfig = .{},

    // Static IP (optional)
    static_ip: ?StaticIpConfig = null,

    // Timeouts (milliseconds)
    connect_timeout_ms: u32 = 30000,
    read_timeout_ms: u32 = 60000,
    keepalive_interval_ms: u32 = 10000,

    // Mobile: external tunnel fd provided by platform (iOS/Android)
    // When set, the VPN client uses this fd instead of opening its own adapter.
    tunnel_fd: ?i32 = null,
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

    // Multi-TCP connection manager (null when max_connections=1)
    conn_manager: ?ConnectionManager,

    // UDP acceleration
    udp_accel: ?udp_accel_mod.UdpAccelEngine,
    bulk_keys: ?softether_proto.UdpBulkKeys,

    mutex: Mutex,
    worker_thread: ?Thread,
    should_stop: bool,
    data_loop_running: bool,

    event_callback: ?EventCallback,
    event_user_data: ?*anyopaque,

    reconnect_attempt: u32,
    reconnect_backoff_ms: u32,
    last_error: ?ClientError,

    server_ip: u32,
    assigned_ip: u32,
    assigned_mask: u32,
    gateway_ip: u32,
    gateway_mac: ?[6]u8,

    // Effective server address for additional connections (updated after redirect)
    effective_server_ip: u32,
    effective_server_port: u16,

    // Authentication state
    auth_credentials: ?auth_mod.ClientAuth,
    auth_session_key: ?[20]u8,
    auth_hello_random: ?[20]u8,

    last_keepalive_sent: i64,
    last_keepalive_recv: i64,

    const Self = @This();

    /// Create a protocol Writer wrapping a TLS socket pointer.
    fn makeProtoWriter(sock: *tls.TlsSocket) softether_proto.Writer {
        return .{
            .context = @ptrCast(sock),
            .writeFn = struct {
                fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                    const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                    return s.write(data);
                }
            }.write,
        };
    }

    /// Create a protocol Reader wrapping a TLS socket pointer.
    fn makeProtoReader(sock: *tls.TlsSocket) softether_proto.Reader {
        return .{
            .context = @ptrCast(sock),
            .readFn = struct {
                fn read(ctx: *anyopaque, buffer: []u8) anyerror!usize {
                    const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                    return s.readBlocking(buffer);
                }
            }.read,
        };
    }

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
            .conn_manager = null,
            .udp_accel = null,
            .bulk_keys = null,
            .mutex = .{},
            .worker_thread = null,
            .should_stop = false,
            .data_loop_running = false,
            .event_callback = null,
            .event_user_data = null,
            .reconnect_attempt = 0,
            .reconnect_backoff_ms = config.reconnect.min_backoff_ms,
            .last_error = null,
            .server_ip = 0,
            .assigned_ip = 0,
            .assigned_mask = 0,
            .gateway_ip = 0,
            .gateway_mac = null,
            .effective_server_ip = 0,
            .effective_server_port = config.server_port,
            .auth_credentials = null,
            .auth_session_key = null,
            .auth_hello_random = null,
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
        if (self.conn_manager) |*cm| {
            cm.deinit();
            self.conn_manager = null;
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

    /// Replace the underlying TUN file descriptor at runtime. Used on Android
    /// after DHCP completes and the platform re-creates the VpnService tunnel
    /// with the assigned IP. The data loop refreshes the polled fd each iter.
    pub fn replaceTunFd(self: *Self, new_fd: i32) !void {
        if (self.adapter_ctx) |*ac| {
            try ac.replaceFd(new_fd);
        } else {
            return error.AdapterNotOpen;
        }
    }

    pub fn getAssignedIp(self: *const Self) u32 {
        return self.assigned_ip;
    }

    pub fn getGatewayIp(self: *const Self) u32 {
        return self.gateway_ip;
    }

    /// DHCP-supplied subnet mask (host byte order). 0 until DHCP completes.
    pub fn getAssignedMask(self: *const Self) u32 {
        return self.assigned_mask;
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
        self.effective_server_ip = self.server_ip;
        self.effective_server_port = self.config.server_port;

        if (@atomicLoad(bool, &self.should_stop, .acquire)) {
            self.disconnect_reason = .user_requested;
            return ClientError.OperationCancelled;
        }

        self.transitionState(.connecting_tcp);
        self.transitionState(.ssl_handshake);

        // Establish TLS connection to VPN server
        const tls_config = tls.TlsConfig{
            .verify_certificate = self.config.verify_certificate,
            .allow_self_signed = !self.config.verify_certificate,
            .timeout_ms = self.config.connect_timeout_ms,
            .client_cert_pem = switch (self.config.auth) {
                .certificate => |cert| cert.cert_data,
                else => null,
            },
            .client_key_pem = switch (self.config.auth) {
                .certificate => |cert| cert.key_data,
                else => null,
            },
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

        if (@atomicLoad(bool, &self.should_stop, .acquire)) {
            self.disconnect_reason = .user_requested;
            return ClientError.OperationCancelled;
        }

        self.transitionState(.authenticating);
        self.performAuthentication() catch {
            self.disconnect_reason = .auth_failed;
            return ClientError.AuthenticationFailed;
        };

        if (@atomicLoad(bool, &self.should_stop, .acquire)) {
            self.disconnect_reason = .user_requested;
            return ClientError.OperationCancelled;
        }

        self.transitionState(.establishing_session);
        self.establishSession() catch {
            self.disconnect_reason = .protocol_error;
            return ClientError.SessionEstablishmentFailed;
        };

        if (@atomicLoad(bool, &self.should_stop, .acquire)) {
            self.disconnect_reason = .user_requested;
            return ClientError.OperationCancelled;
        }

        // Establish additional TCP connections (multi-connection mode)
        // Non-fatal: if some fail, we continue with what we have
        self.establishAdditionalConnections();

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

        // Signal data loop to stop and wait for it to exit
        @atomicStore(bool, &self.should_stop, true, .release);
        var wait_count: u32 = 0;
        while (@atomicLoad(bool, &self.data_loop_running, .acquire) and wait_count < 200) : (wait_count += 1) {
            std.Thread.sleep(10 * std.time.ns_per_ms); // 10ms per check, max 2s
        }

        // Stop UDP acceleration
        if (self.udp_accel) |*ua| {
            ua.stop();
        }
        self.udp_accel = null;

        if (self.adapter_ctx) |*ctx| ctx.close();
        if (self.session) |*sess| sess.disconnect();

        // Close all connections (multi-connection manager or single socket)
        if (self.conn_manager) |*cm| {
            cm.deinit();
            self.conn_manager = null;
        }
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
        const writer = makeProtoWriter(sock);
        const reader = makeProtoReader(sock);

        // Format server IP as string for HTTP Host header (like C code does)
        var ip_str_buf: [16]u8 = undefined;
        const host_for_http = formatIpv4Buf(self.server_ip, &ip_str_buf);

        std.log.debug("Uploading protocol signature...", .{});

        // Step 1: Upload signature (WaterMark)
        softether_proto.uploadSignature(self.allocator, writer, host_for_http) catch |err| {
            std.log.err("Failed to upload signature: {}", .{err});
            return ClientError.ProtocolError;
        };

        std.log.debug("Downloading server hello...", .{});

        // Step 2: Download Hello (get server random challenge)
        var hello = softether_proto.downloadHello(self.allocator, reader) catch |err| {
            std.log.err("Failed to download hello: {}", .{err});
            return ClientError.ProtocolError;
        };
        defer hello.deinit(self.allocator);

        std.log.debug("Building authentication request...", .{});

        // Generate bulk encryption keys for UDP acceleration
        var bulk_keys_storage: softether_proto.UdpBulkKeys = if (self.config.udp_acceleration)
            softether_proto.UdpBulkKeys.generate()
        else
            undefined;
        const bulk_keys_ptr: ?*const softether_proto.UdpBulkKeys = if (self.config.udp_acceleration)
            &bulk_keys_storage
        else
            null;
        if (self.config.udp_acceleration) {
            self.bulk_keys = bulk_keys_storage;
        }

        // Step 3: Build and upload auth
        const session_opts = softether_proto.SessionOptions{
            .max_connection = self.config.max_connections,
            .half_connection = self.config.half_connection,
            .qos = self.config.qos,
            .use_encryption = self.config.use_encryption,
            .use_compression = self.config.use_compression,
        };
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
                        self.config.udp_acceleration,
                        bulk_keys_ptr,
                        session_opts,
                    ) catch return ClientError.OutOfMemory;
                } else {
                    // Password is plain text, hash it first
                    break :blk softether_proto.buildPasswordAuth(
                        self.allocator,
                        p.username,
                        p.password,
                        self.config.hub_name,
                        &hello.random,
                        self.config.udp_acceleration,
                        bulk_keys_ptr,
                        session_opts,
                    ) catch return ClientError.OutOfMemory;
                }
            },
            .anonymous => softether_proto.buildAnonymousAuth(
                self.allocator,
                self.config.hub_name,
                self.config.udp_acceleration,
                bulk_keys_ptr,
                session_opts,
            ) catch return ClientError.OutOfMemory,
            .certificate => |cert| softether_proto.buildCertificateAuth(
                self.allocator,
                cert.cert_data,
                cert.key_data,
                self.config.hub_name,
                &hello.random,
                self.config.udp_acceleration,
                bulk_keys_ptr,
                session_opts,
            ) catch return ClientError.AuthenticationFailed,
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
            const ack_writer = makeProtoWriter(current_sock);

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
                    .client_cert_pem = switch (self.config.auth) {
                        .certificate => |cert| cert.cert_data,
                        else => null,
                    },
                    .client_key_pem = switch (self.config.auth) {
                        .certificate => |cert| cert.key_data,
                        else => null,
                    },
                    // Use the original server hostname for SNI, not the
                    // redirect IP literal. Load balancers routing on SNI
                    // will drop connections with an IP as SNI.
                    .sni_hostname = self.config.server_host,
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
            self.effective_server_ip = actual_connect_ip;
            self.effective_server_port = redirect_port;

            // Get username for ticket auth
            const username = switch (self.config.auth) {
                .password => |p| p.username,
                .anonymous => "anonymous",
                .certificate => "certificate",
            };

            // Redo authentication with ticket
            const redirect_sock = &(self.tls_socket orelse return ClientError.ConnectionFailed);
            const redirect_writer = makeProtoWriter(redirect_sock);
            const redirect_reader = makeProtoReader(redirect_sock);

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
                self.config.udp_acceleration,
                bulk_keys_ptr,
                session_opts,
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

            // LIBSE-95 probe: verify session_key arrived at consumer site
            std.log.info("LIBSE-95 consumer probe: ticket_auth_result.session_key is_some={}", .{ticket_auth_result.session_key != null});

            // Store session key from ticket auth for session encryption
            if (ticket_auth_result.session_key) |key| {
                self.auth_session_key = key;
                self.auth_hello_random = redirect_hello.random;
                std.log.info("LIBSE-95 consumer: stored auth_session_key (20B) and auth_hello_random", .{});
            } else {
                std.log.warn("LIBSE-95 consumer: ticket_auth_result.session_key was null — skipping store", .{});
            }

            // Apply server overrides from redirect server too
            self.applyServerOverrides(ticket_auth_result);

            std.log.debug("Ticket authentication successful!", .{});
            return;
        }

        // Store session key and server challenge for session encryption
        if (auth_result.session_key) |key| {
            self.auth_session_key = key;
            self.auth_hello_random = hello.random;
        }

        // Apply server-overridden session parameters (C: Protocol.c:4720-4741)
        self.applyServerOverrides(auth_result);

        // Initialize UDP acceleration if server supports it
        if (auth_result.udp_accel_enabled and self.config.udp_acceleration) {
            if (self.bulk_keys) |bk| {
                // Server's send key is our recv key and vice versa
                const recv_key = auth_result.server_bulk_send_key orelse bk.recv_key;
                const send_key = auth_result.server_bulk_recv_key orelse bk.send_key;

                // Derive HMAC keys from bulk keys (SHA-1 of the key)
                var send_hmac: [20]u8 = undefined;
                var recv_hmac: [20]u8 = undefined;
                std.crypto.hash.Sha1.hash(&send_key, &send_hmac, .{});
                std.crypto.hash.Sha1.hash(&recv_key, &recv_hmac, .{});

                // Use server IP for UDP if no specific UDP IP provided
                var server_ip_buf: [16]u8 = undefined;
                const server_ip_str = formatIpv4Buf(self.server_ip, &server_ip_buf);

                const udp_config = udp_accel_mod.UdpAccelConfig{
                    .server_ip = server_ip_str,
                    .server_port = auth_result.udp_accel_port,
                    .use_encryption = auth_result.udp_accel_use_encryption,
                    .send_key = send_key,
                    .recv_key = recv_key,
                    .send_hmac_key = send_hmac,
                    .recv_hmac_key = recv_hmac,
                };

                self.udp_accel = udp_accel_mod.UdpAccelEngine.init(self.allocator, udp_config);
                self.udp_accel.?.start() catch |err| {
                    std.log.warn("Failed to start UDP acceleration: {}", .{err});
                    self.udp_accel = null;
                };
            }
        }

        std.log.info("Authentication successful!", .{});
    }

    /// Apply server-overridden session parameters (C: Protocol.c:4720-4741).
    /// The server is authoritative and may cap or change what the client requested.
    fn applyServerOverrides(self: *Self, result: softether_proto.AuthResult) void {
        var effective_max = result.server_max_connection;
        effective_max = @min(effective_max, self.config.max_connections);
        effective_max = @min(effective_max, 32); // MAX_TCP_CONNECTION
        effective_max = @max(effective_max, 1);

        const effective_half = result.server_half_connection;

        // QoS requires minimum connections (C: Protocol.c:4737-4740)
        if (result.server_qos) {
            const qos_min: u32 = if (effective_half) 4 else 2;
            effective_max = @max(effective_max, qos_min);
        }

        if (effective_max != self.config.max_connections) {
            std.log.info("Server overrode max_connections: {d} -> {d}", .{ self.config.max_connections, effective_max });
        }
        if (effective_half != self.config.half_connection) {
            std.log.info("Server overrode half_connection: {} -> {}", .{ self.config.half_connection, effective_half });
        }

        self.config.max_connections = @intCast(effective_max);
        self.config.half_connection = effective_half;
        self.config.use_compression = result.server_use_compress;
        self.config.use_encryption = result.server_use_encrypt;
    }

    fn establishSession(self: *Self) !void {
        std.log.info("LIBSE-95 establishSession entry: use_encryption={} auth_session_key_some={} auth_hello_random_some={}", .{
            self.config.use_encryption,
            self.auth_session_key != null,
            self.auth_hello_random != null,
        });
        if (self.config.use_encryption and self.auth_session_key != null and self.auth_hello_random != null) {
            // Create a full session with encryption using auth-derived keys
            const username = switch (self.config.auth) {
                .password => |p| p.username,
                .anonymous => "anonymous",
                .certificate => "certificate",
            };
            const options = SessionOptions{
                .host = self.config.server_host,
                .port = self.config.server_port,
                .hub = self.config.hub_name,
                .username = username,
                .use_encryption = true,
                .use_compression = self.config.use_compression,
            };
            self.session = SessionWrapper.initWithOptions(self.allocator, options);

            // Derive encryption keys from session key + server challenge
            if (self.session) |*sess| {
                sess.initEncryption(&self.auth_session_key.?, &self.auth_hello_random.?);
            }
            std.log.info("Session established with AES-256-CBC encryption", .{});
        } else {
            // No encryption (server didn't provide session key or encryption disabled)
            self.session = SessionWrapper.init(self.allocator, false);
            std.log.info("Session established without encryption", .{});
        }
    }

    /// Establish additional TCP connections for multi-connection mode.
    /// When max_connections > 1, opens N-1 additional TCP connections,
    /// each performing the additional_connect handshake.
    /// Non-fatal: continues with fewer connections if some fail.
    fn establishAdditionalConnections(self: *Self) void {
        if (self.config.max_connections <= 1) return;

        const session_key = self.auth_session_key orelse {
            std.log.warn("No session key available, skipping additional connections", .{});
            return;
        };

        // Initialize conn_manager directly on self (NOT a local variable) so that
        // TunnelConnection context pointers inside ManagedConnections reference the
        // stable heap location. Using a local var + value-copy would leave dangling
        // pointers after the stack frame is reclaimed.
        self.conn_manager = ConnectionManager.init(
            self.allocator,
            self.config.max_connections,
            self.config.half_connection,
            self.config.use_compression,
        );

        // Transfer primary socket to the manager
        const primary_sock = self.tls_socket orelse {
            std.log.warn("No primary socket, skipping additional connections", .{});
            self.conn_manager = null;
            return;
        };

        // Primary direction: C2S in half-connection mode, bidirectional otherwise
        const primary_direction: TcpDirection = if (self.config.half_connection)
            .client_to_server
        else
            .bidirectional;

        _ = self.conn_manager.?.addConnection(primary_sock, primary_direction, true) catch |err| {
            std.log.err("Failed to add primary connection to manager: {}", .{err});
            self.conn_manager = null;
            return;
        };

        // Primary is now owned by the manager; clear self.tls_socket
        self.tls_socket = null;

        // Build TLS config (reuse from primary). After a cluster redirect
        // self.effective_server_ip is an IP literal; use the original server
        // hostname for SNI so load balancers can route the TLS handshake.
        const tls_config = tls.TlsConfig{
            .verify_certificate = self.config.verify_certificate,
            .allow_self_signed = !self.config.verify_certificate,
            .timeout_ms = self.config.connect_timeout_ms,
            .client_cert_pem = switch (self.config.auth) {
                .certificate => |cert| cert.cert_data,
                else => null,
            },
            .client_key_pem = switch (self.config.auth) {
                .certificate => |cert| cert.key_data,
                else => null,
            },
            .sni_hostname = self.config.server_host,
        };

        // Format effective server IP for HTTP Host header and TLS connect
        var ip_str_buf: [16]u8 = undefined;
        const host_for_http = formatIpv4Buf(self.effective_server_ip, &ip_str_buf);

        // Establish N-1 additional connections
        var established: u8 = 1; // counting primary
        var i: u8 = 1;
        while (i < self.config.max_connections) : (i += 1) {
            if (@atomicLoad(bool, &self.should_stop, .acquire)) break;

            self.establishOneAdditionalConnection(
                &self.conn_manager.?,
                &session_key,
                tls_config,
                host_for_http,
                i,
            );
            established = self.conn_manager.?.count;
        }

        std.log.info("Established {d}/{d} TCP connections (half_connection={})", .{
            established,
            self.config.max_connections,
            self.config.half_connection,
        });
    }

    /// Establish a single additional TCP connection to the server.
    fn establishOneAdditionalConnection(
        self: *Self,
        cm: *ConnectionManager,
        session_key: *const [20]u8,
        tls_config: tls.TlsConfig,
        host_for_http: []const u8,
        conn_index: u8,
    ) void {
        // Open new TLS connection to the effective server (may differ from
        // config.server_host after a cluster redirect).
        var new_sock = tls.TlsSocket.connect(
            self.allocator,
            host_for_http, // IP string of effective server
            self.effective_server_port,
            tls_config,
        ) catch |err| {
            std.log.warn("Additional connection {d} TLS failed: {}", .{ conn_index, err });
            return;
        };

        // Create writer/reader for the new socket
        const writer = makeProtoWriter(&new_sock);
        const reader = makeProtoReader(&new_sock);

        // Upload signature
        softether_proto.uploadSignature(self.allocator, writer, host_for_http) catch |err| {
            std.log.warn("Additional connection {d} signature failed: {}", .{ conn_index, err });
            new_sock.close();
            return;
        };

        // Download hello
        var hello = softether_proto.downloadHello(self.allocator, reader) catch |err| {
            std.log.warn("Additional connection {d} hello failed: {}", .{ conn_index, err });
            new_sock.close();
            return;
        };
        hello.deinit(self.allocator);

        // Send additional_connect with session key
        const result = softether_proto.uploadAdditionalConnect(
            self.allocator,
            writer,
            reader,
            host_for_http,
            session_key,
        ) catch |err| {
            std.log.warn("Additional connection {d} handshake failed: {}", .{ conn_index, err });
            new_sock.close();
            return;
        };

        if (!result.success) {
            std.log.warn("Additional connection {d} rejected: error_code={d}", .{ conn_index, result.error_code });
            new_sock.close();
            return;
        }

        // Map server direction value to TcpDirection
        const direction: TcpDirection = switch (result.direction) {
            1 => .server_to_client,
            2 => .client_to_server,
            else => .bidirectional,
        };

        _ = cm.addConnection(new_sock, direction, false) catch |err| {
            std.log.warn("Additional connection {d} add failed: {}", .{ conn_index, err });
            new_sock.close();
            return;
        };
    }

    fn configureAdapter(self: *Self) !void {
        self.adapter_ctx = AdapterWrapper.init(self.allocator);
        var ctx = &self.adapter_ctx.?;

        if (self.config.tunnel_fd) |fd| {
            // Mobile: use the OS-provided tunnel fd
            ctx.openWithFd(fd, "tun-mobile") catch |err| {
                std.log.err("Failed to open tunnel with external fd={d}: {}", .{ fd, err });
                return ClientError.AdapterConfigurationFailed;
            };
        } else {
            // Desktop: open native TUN/TAP device
            ctx.open() catch |err| {
                std.log.err("Failed to open virtual network adapter: {}", .{err});
                std.log.err("Note: Creating a TUN/TAP device requires root privileges.", .{});
                std.log.err("Try running with: sudo ./vpnclient-pure --config config.json", .{});
                return ClientError.AdapterConfigurationFailed;
            };
        }

        if (self.config.static_ip) |static| {
            if (static.ipv4_address) |ip_str| {
                self.assigned_ip = parseIpv4(ip_str) orelse 0;
                if (static.ipv4_gateway) |gw_str| {
                    self.gateway_ip = parseIpv4(gw_str) orelse 0;
                }
            }
        }

        if (self.config.routing.default_route and self.gateway_ip != 0) {
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

    /// Process a single inbound Ethernet block from the VPN server.
    /// Handles IP dispatch, ARP, and DHCP state machine.
    fn processInboundBlock(
        self: *Self,
        block_data: []u8,
        adapter: *AdapterWrapper,
        loop_state: *tunnel_mod.DataLoopState,
        send_helper: *SendTunnelHelper,
        dhcp_xid: *u32,
        mac: [6]u8,
        is_configured: *bool,
    ) void {
        if (block_data.len <= 14) return;

        const ethertype = (@as(u16, block_data[12]) << 8) | block_data[13];

        if (is_configured.*) {
            // Configured: fast path for IP packets
            if (ethertype == 0x0800 or ethertype == 0x86DD) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        _ = dev.write(block_data[14..]) catch {};
                    }
                }
            } else if (ethertype == 0x0806) {
                if (tunnel_mod.getArpOperation(block_data)) |arp_op| {
                    if (arp_op == 2) {
                        loop_state.processArpReply(block_data);
                        self.gateway_mac = loop_state.gateway_mac;
                    } else if (arp_op == 1) {
                        loop_state.processArpRequest(block_data);
                    }
                }
            }
        } else {
            // Not configured: check for DHCP
            const maybe_response = adapter_mod.parseDhcpResponse(block_data, dhcp_xid.*) catch null;
            if (maybe_response) |response| {
                if (response.msg_type == .offer and loop_state.dhcp.state == .discover_sent) {
                    const ip = tunnel_mod.formatIpForLog(response.config.ip_address);
                    std.log.info("DHCP OFFER received: IP={d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });

                    var req_buf: [512]u8 = undefined;
                    const req_size = adapter_mod.buildDhcpRequest(mac, dhcp_xid.*, response.config.ip_address, response.config.server_id, &req_buf) catch 0;
                    if (req_size > 0) {
                        const blocks = [_][]const u8{req_buf[0..req_size]};
                        send_helper.get().sendBlocks(&blocks) catch {};
                        loop_state.dhcp.state = .request_sent;
                        // Stash REQUEST params on the handler's config for retry path
                        // (no ACK in 3s → resend REQUEST using same offered IP/server_id).
                        // Note: tunnel.dhcp.DhcpConfig != adapter.dhcp.DhcpConfig, copy fields.
                        loop_state.dhcp.config.ip_address = response.config.ip_address;
                        loop_state.dhcp.config.subnet_mask = response.config.subnet_mask;
                        loop_state.dhcp.config.gateway = response.config.gateway;
                        loop_state.dhcp.config.server_id = response.config.server_id;
                        loop_state.dhcp.config.lease_time = response.config.lease_time;
                        loop_state.timing.last_dhcp_time = std.time.milliTimestamp();
                        std.log.info("Sent DHCP REQUEST", .{});
                    }
                } else if (response.msg_type == .ack and loop_state.dhcp.state == .request_sent) {
                    std.log.info("DHCP ACK received!", .{});
                    loop_state.configure(response.config.ip_address, response.config.gateway);
                    loop_state.dhcp.state = .configured;
                    is_configured.* = true;
                    self.assigned_ip = loop_state.our_ip;
                    self.gateway_ip = loop_state.our_gateway;
                    self.assigned_mask = response.config.subnet_mask;

                    if (adapter.real_adapter) |*real| {
                        if (real.device) |dev| {
                            dev.configure(response.config.ip_address, response.config.subnet_mask, response.config.gateway) catch |err| {
                                std.log.err("Failed to configure interface: {}", .{err});
                            };
                        }
                    }

                    const ip = tunnel_mod.formatIpForLog(loop_state.our_ip);
                    std.log.info("Interface configured with IP {d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });

                    if (self.config.routing.default_route and loop_state.our_gateway != 0) {
                        const gw = tunnel_mod.formatIpForLog(loop_state.our_gateway);
                        std.log.info("Configuring full-tunnel routing through VPN gateway {d}.{d}.{d}.{d}", .{ gw.a, gw.b, gw.c, gw.d });
                        const server_ip_be = @byteSwap(self.server_ip);
                        adapter.configureFullTunnel(loop_state.our_gateway, server_ip_be);
                    }

                    // Restore half-connection directions after DHCP completes
                    if (self.conn_manager) |*cm| {
                        cm.restoreDhcpDirections();
                    }

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
        self.stats.recordReceived(block_data.len);
    }

    // Forward declare SendTunnelHelper type for use in processInboundBlock signature
    const SendTunnelHelper = struct {
        cm_ptr: ?*ConnectionManager,
        single_ptr: *protocol_tunnel_mod.TunnelConnection,

        fn get(ctx: @This()) *protocol_tunnel_mod.TunnelConnection {
            if (ctx.cm_ptr) |m| {
                if (m.selectSendConnection()) |conn| return &conn.tunnel;
                if (m.getPrimary()) |primary| return &primary.tunnel;
            }
            return ctx.single_ptr;
        }
    };

    /// Run the data channel packet loop
    /// This is the main loop that processes packets between TLS and TUN
    /// Returns when should_stop is set or connection is lost
    pub fn runDataLoop(self: *Self) !void {
        if (!self.isConnected()) return ClientError.NotConnected;

        @atomicStore(bool, &self.data_loop_running, true, .release);
        defer @atomicStore(bool, &self.data_loop_running, false, .release);

        // Multi-connection mode: enable bidirectional on primary for DHCP phase
        const multi_conn = self.conn_manager != null;
        if (self.conn_manager) |*cm| {
            cm.prepareForDataLoop();
            cm.enableDhcpBidirectional();
        }

        // Get single-socket pointer (null if multi-connection mode owns it)
        const single_sock: ?*tls.TlsSocket = if (!multi_conn) blk: {
            var ss = &(self.tls_socket orelse return ClientError.NotConnected);
            ss.clearTimeouts(); // Remove connect-phase timeouts for data loop
            break :blk ss;
        } else null;
        var adapter = &(self.adapter_ctx orelse return ClientError.NotConnected);

        std.log.debug("Starting data channel loop...", .{});

        // Get file descriptors / handles for polling
        const tun_fd = if (builtin.os.tag == .windows) win_blk: {
            // Windows: Wintun uses event handles, not file descriptors.
            // We'll poll TUN separately with WaitForSingleObject.
            break :win_blk @as(std.posix.fd_t, std.os.windows.INVALID_HANDLE_VALUE);
        } else blk: {
            if (adapter.real_adapter) |*real| {
                if (real.device) |dev| {
                    const fd = dev.getFd();
                    if (fd < 0) return ClientError.AdapterConfigurationFailed;
                    break :blk fd;
                }
            }
            return ClientError.AdapterConfigurationFailed;
        };

        const tun_fd_int: usize = if (builtin.os.tag == .windows) @intFromPtr(tun_fd) else @as(usize, @intCast(tun_fd));
        if (builtin.os.tag != .windows) {
            if (multi_conn) {
                std.log.debug("Using poll() for multi-connection I/O: {d} TCP connections, TUN fd={d}", .{ self.conn_manager.?.count, tun_fd_int });
            } else {
                std.log.debug("Using poll() for concurrent I/O: TLS fd={d}, TUN fd={d}", .{ single_sock.?.getFd(), tun_fd_int });
            }
        } else {
            std.log.debug("Using Windows event-based I/O for data loop", .{});
        }

        // Create single tunnel connection (only used in single-connection mode)
        var single_tunnel: protocol_tunnel_mod.TunnelConnection = if (single_sock) |ss| blk: {
            var t = protocol_tunnel_mod.TunnelConnection.init(
                self.allocator,
                @ptrCast(ss),
                struct {
                    fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
                        const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                        return s.read(buf);
                    }
                }.read,
                struct {
                    fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
                        const s = @as(*tls.TlsSocket, @ptrCast(@alignCast(ctx)));
                        // Use writeAllNonBlocking so that even with the data
                        // socket switched to non-blocking mode, sendBlocks
                        // sees an atomic "all bytes written" return. WANT_WRITE
                        // is handled internally via a short poll(POLLOUT).
                        try s.writeAllNonBlocking(data);
                        return data.len;
                    }
                }.write,
            );
            t.use_compression = self.config.use_compression;
            break :blk t;
        } else undefined;

        // Get MAC address
        const mac = adapter.getMac();

        // Initialize data loop state (from tunnel module)
        var loop_state = tunnel_mod.DataLoopState.init(mac);

        // DHCP transaction ID
        var dhcp_xid: u32 = 0;
        std.crypto.random.bytes(std.mem.asBytes(&dhcp_xid));

        // Configuration constants
        const keepalive_interval: i64 = 5000; // 5 seconds (server timeout is 20s)
        const garp_interval: i64 = 10000; // 10 seconds - periodic GARP for bridge mode

        // Receive buffers — heap-allocated to avoid stack overflow
        // (Dart Isolate.run() threads have ~1MB stack; these buffers are 800KB+)
        const recv_scratch = try self.allocator.alloc(u8, 512 * 1600);
        defer self.allocator.free(recv_scratch);
        var recv_slices: [512][]u8 = undefined;

        // Outbound packet buffers — heap-allocated to allow larger batch (64)
        // without blowing the Dart isolate's ~512KB stack. 64x2048 + 64x1600 =
        // 230KB, kept on heap for safety in ReleaseFast mode.
        //
        // On iOS the TUN fd is a socketpair bridged to Swift pump; the bottleneck
        // is Swift pump throughput, not data-loop iterations. A larger batch reduces
        // per-packet overhead (fewer data-loop iters for same packet count).
        const OUTBOUND_BATCH: usize = 64;
        const tun_read_bufs = try self.allocator.alloc([2048]u8, OUTBOUND_BATCH);
        defer self.allocator.free(tun_read_bufs);
        const outbound_eth_bufs = try self.allocator.alloc([1600]u8, OUTBOUND_BATCH);
        defer self.allocator.free(outbound_eth_bufs);

        // Packet buffer for ARP/GARP (small, reused)
        var arp_buf: [64]u8 = undefined;

        // Heap-allocated send buffer for zero-copy outbound path.
        // Sized for 64-packet batch (worst case ~64 * ~1518B = ~97KB compressed)
        // plus SoftEther block headers. 256KB headroom for maximum batch + overhead.
        const send_buffer = try self.allocator.alloc(u8, 262_144);
        defer self.allocator.free(send_buffer);

        var send_helper = SendTunnelHelper{
            .cm_ptr = if (self.conn_manager != null) &self.conn_manager.? else null,
            .single_ptr = &single_tunnel,
        };

        // ============================================================
        // DIAGNOSTIC STATS — logged once per second when active.
        // Investigating: T1 of every connection achieves full DL, but
        // T2/T3 onwards starve to ~10-16 Mbps while UL stays healthy.
        // Hypotheses: TLS RX backpressure, kernel queue accumulation,
        // drain cap bottleneck, or TUN write blocking.
        // ============================================================
        const DiagStats = struct {
            bytes_in: u64 = 0,
            bytes_out: u64 = 0,
            pkts_in: u64 = 0,
            pkts_out: u64 = 0,
            drain_total: u64 = 0,
            drain_max: u32 = 0,
            drain_cap_hits: u64 = 0,
            ssl_pending_max: u32 = 0,
            nread_max: u32 = 0,
            nwrite_max: u32 = 0,
            pollout_skipped: u64 = 0,
            tcp_drops_pkts: u64 = 0,
            tun_eagain: u64 = 0,
            tx_drops_delta: u64 = 0,  // FdAdapter ring buffer drops (this second)
            tx_drops_last: u64 = 0,   // cumulative tx_drops at last flush
            poll_iters: u64 = 0,
            // Latency tracking (microseconds): per-iteration wall time.
            // iter_us_max captures the worst single-iter spike — useful to
            // detect when one iteration starves the rest (e.g. blocking I/O,
            // GC pause, kernel scheduler hiccup, large drain burst).
            iter_us_max: u64 = 0,
            iter_us_total: u64 = 0,
            iter_slow_10ms: u32 = 0,
            iter_slow_50ms: u32 = 0,
            iter_slow_100ms: u32 = 0,
            // poll() wait time (microseconds) — captures kernel-blocked time.
            // High poll_us_max with low iter_us_max means we're idle-waiting;
            // high values on both means a stall.
            poll_us_max: u32 = 0,
            poll_us_total: u64 = 0,
            // Bufferbloat detection: kernel TCP sendq depth, sampled at end
            // of every iter. Growing sendq while throughput drops = TX-side
            // queue building (server can't pull, or TCP cwnd shrunk). This
            // is the smoking gun for the latency-grows / throughput-collapses
            // pattern that the in-loop iter_us metric cannot see.
            sendq_max: u32 = 0,
            sendq_sum: u64 = 0,
            sendq_samples: u32 = 0,
            // Count of write_fn calls that hit WANT_WRITE (POLLOUT poll)
            // since last DIAG. High = TX bound. Diff'd from per-conn
            // TlsSocket.write_block_count snapshots.
            write_blocked: u64 = 0,
        };
        var diag = DiagStats{};
        var diag_last_ms: i64 = std.time.milliTimestamp();
        // Cycle 6 adaptive poll: track if last iter did work
        var last_iter_had_work: bool = false;

        // Send initial Gratuitous ARP (0.0.0.0) to announce ourselves
        {
            const garp_size = adapter_mod.buildGratuitousArp(mac, 0, &arp_buf) catch 0;
            if (garp_size > 0) {
                const blocks = [_][]const u8{arp_buf[0..garp_size]};
                send_helper.get().sendBlocks(&blocks) catch {};
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
                send_helper.get().sendBlocks(&blocks) catch |err| {
                    std.log.err("Failed to send DHCP discover: {}", .{err});
                };
                loop_state.dhcp.state = .discover_sent;
                loop_state.timing.last_dhcp_time = std.time.milliTimestamp();
                std.log.debug("Sent DHCP DISCOVER (xid=0x{x:0>8})", .{dhcp_xid});
            }
        }

        // Set up poll structures — all socket fds use socket_t for Windows compatibility
        const invalid_sock: std.posix.socket_t = if (builtin.os.tag == .windows) @ptrFromInt(std.math.maxInt(usize)) else -1;
        const udp_fd: std.posix.socket_t = if (self.udp_accel) |*ua| ua.getFd() orelse invalid_sock else invalid_sock;
        const has_udp = if (builtin.os.tag == .windows) (udp_fd != invalid_sock) else (udp_fd >= 0);

        // tun_fd is fd_t (not a socket on Windows). NOTE: this is mutable
        // because on Android we may swap the TUN fd at runtime after DHCP
        // completes (see replaceTunFd). Refreshed at the top of every loop iter.
        var poll_tun_sock: std.posix.socket_t = if (builtin.os.tag == .windows) @ptrCast(tun_fd) else tun_fd;

        // Dynamic poll_fds: up to 32 TLS connections + TUN + UDP = 34
        var poll_fds: [34]std.posix.pollfd = undefined;
        var tls_fd_count: usize = 0;

        // Cache the configured state check
        var is_configured = false;

        // Main packet loop
        // On Windows, set timer resolution to 1ms for accurate poll() timeouts.
        // Default Windows timer resolution is 15.6ms, making 1ms poll wait up to 15.6ms.
        if (builtin.os.tag == .windows) {
            _ = winmm.timeBeginPeriod(1);
        }
        defer if (builtin.os.tag == .windows) {
            _ = winmm.timeEndPeriod(1);
        };

        // Switch all data-plane TLS sockets to non-blocking mode now that
        // the handshake/auth/RPC phases are complete. This is the core of
        // Option A: SSL_read no longer blocks on mid-record stalls (~RTT
        // freezes) — instead it returns error.WouldBlock which the
        // tunnel state machine handles by stashing partial-read state and
        // letting the poll loop come back around. Sends use
        // writeAllNonBlocking which polls(POLLOUT) on WANT_WRITE.
        if (single_sock) |ss| {
            ss.setNonBlocking() catch |e| std.log.warn("setNonBlocking (single) failed: {}", .{e});
        }
        if (self.conn_manager) |*cm| {
            var ci: usize = 0;
            while (ci < cm.connections.len) : (ci += 1) {
                if (cm.connections[ci]) |*conn| {
                    conn.tls_socket.setNonBlocking() catch |e|
                        std.log.warn("setNonBlocking (conn {d}) failed: {}", .{ ci, e });
                }
            }
        }

        while (!@atomicLoad(bool, &self.should_stop, .acquire) and self.isConnected()) {
            // Refresh TUN fd each iter so a runtime fd swap (replaceTunFd) is
            // picked up by poll(). On non-Windows the FdAdapter exposes the
            // current fd via getFd(); we reuse the cached value otherwise.
            if (builtin.os.tag != .windows) {
                if (self.adapter_ctx) |*ac| {
                    if (ac.real_adapter) |*ra| {
                        if (ra.device) |dev| {
                            poll_tun_sock = dev.getFd();
                        }
                    }
                }
            }
            // Latency tracking: capture wall-clock at the very start of every
            // iteration so we can detect single-iter spikes vs steady state.
            const iter_start_us = std.time.microTimestamp();
            // Snapshot per-conn write_block_count so we can diff at end of iter
            // to count POLLOUT stalls (TCP sndbuf full) attributable to this iter.
            var iter_wb_start: u64 = 0;
            if (single_sock) |ss| iter_wb_start += ss.write_block_count;
            if (self.conn_manager) |cm| {
                for (cm.connections[0..cm.count]) |maybe_conn| {
                    if (maybe_conn) |conn| iter_wb_start += conn.tls_socket.write_block_count;
                }
            }

            // Build poll fd array
            tls_fd_count = 0;
            if (self.conn_manager) |*cm| {
                // Multi-connection: build poll fds from all recv-capable connections
                tls_fd_count = cm.buildPollFds(&poll_fds);
            } else if (single_sock) |ss| {
                // Single-connection: just the one TLS socket
                poll_fds[0] = .{ .fd = ss.getFd(), .events = std.posix.POLL.IN, .revents = 0 };
                tls_fd_count = 1;
            }

            // TUN fd at index tls_fd_count
            const poll_tun_idx = tls_fd_count;
            poll_fds[poll_tun_idx] = .{
                .fd = poll_tun_sock,
                .events = if (builtin.os.tag == .windows) 0 else std.posix.POLL.IN,
                .revents = 0,
            };

            // UDP fd at index tls_fd_count + 1
            const poll_udp_idx = tls_fd_count + 1;
            poll_fds[poll_udp_idx] = .{
                .fd = udp_fd,
                .events = if (has_udp) std.posix.POLL.IN else 0,
                .revents = 0,
            };

            const total_poll_count: std.posix.nfds_t = @intCast(tls_fd_count + (if (has_udp) @as(usize, 2) else if (builtin.os.tag == .windows) @as(usize, 0) else @as(usize, 1)));
            // Adaptive poll timeout: timeout=0 (immediate return) when last
            // iter did productive I/O so we keep up with bursts; timeout=10ms
            // when idle so the CPU can sleep.
            //
            // CRITICAL: last_iter_had_work MUST be cleared at the start of each
            // iter (see below) so it represents "this iter did work" rather than
            // "any iter ever did work". A previous version left it sticky-true,
            // which on iOS caused a 50k iters/sec busy-spin during what should
            // have been idle periods → CPU-wakeup-limit kill (45001 wakes/18s).
            // With proper clearing, productive iters drive timeout=0 (real I/O
            // wakes are not idle wakes) and idle iters drop back to 10ms sleep,
            // so an iOS-only floor is no longer needed and DL is not throttled.
            const poll_timeout_ms: i32 = if (last_iter_had_work) @as(i32, 0) else @as(i32, 10);
            // Reset for this iter — inbound/outbound sections will set it true
            // again if they observe real work (any_conn_had_data, tls_readable,
            // or tun_readable at end-of-iter).
            last_iter_had_work = false;
            const poll_t0 = std.time.microTimestamp();
            _ = std.posix.poll(poll_fds[0..total_poll_count], poll_timeout_ms) catch 0;
            const poll_us: u32 = @intCast(@max(0, std.time.microTimestamp() - poll_t0));
            if (poll_us > diag.poll_us_max) diag.poll_us_max = poll_us;
            diag.poll_us_total += poll_us;

            const tun_readable = if (builtin.os.tag == .windows) is_configured else (poll_fds[poll_tun_idx].revents & std.posix.POLL.IN) != 0;
            const udp_readable = has_udp and (poll_fds[poll_udp_idx].revents & std.posix.POLL.IN) != 0;

            // Decay pending bytes for load balancing (multi-connection)
            if (self.conn_manager) |*cm| cm.decayPendingBytes();

            // Drive UDP acceleration timers (probing, keepalive, timeout)
            if (self.udp_accel) |*ua| ua.tick();

            // ============================================================
            // FAST PATH: Data plane (process packets first for low latency)
            // ============================================================

            // INBOUND: Receive packets from VPN server (highest priority)
            if (self.conn_manager) |*cm| {
                // Multi-connection: iterate all recv-capable connections.
                // For each readable connection, drain up to MAX_INBOUND_DRAIN
                // batches while OpenSSL has buffered data — identical to the
                // single-conn drain loop. Without this, DL is capped at ~1
                // batch per poll iteration per connection (~7 Mbps).
                const MAX_INBOUND_DRAIN: u32 = 64;
                var any_conn_had_data = false;
                var iter = cm.forEachReadable(poll_fds[0..tls_fd_count]);
                while (iter.next()) |conn| {
                    var drain_iter: u32 = 0;
                    while (drain_iter < MAX_INBOUND_DRAIN) : (drain_iter += 1) {
                        const recv_count = conn.tunnel.receiveBlocksBatch(&recv_slices, recv_scratch) catch |err| {
                            if (self.should_stop) break;
                            if (err == error.ConnectionClosed or err == error.BrokenPipe) {
                                conn.established = false;
                                std.log.warn("Connection lost (multi-conn): {s}", .{@errorName(err)});
                                break;
                            }
                            break;
                        };

                        if (recv_count > 0) {
                            any_conn_had_data = true;
                            for (recv_slices[0..recv_count]) |block_data| {
                                diag.bytes_in += block_data.len;
                                diag.pkts_in += 1;
                                self.processInboundBlock(block_data, adapter, &loop_state, &send_helper, &dhcp_xid, mac, &is_configured);
                            }
                        }

                        // Stop draining when SSL has no more buffered data.
                        // Continuing would block on readU32() for up to RTT.
                        if (!conn.tls_socket.hasPending()) break;
                    }
                    // DIAG: drain stats per connection (sum across conns this iter)
                    diag.drain_total += drain_iter;
                    if (drain_iter > diag.drain_max) diag.drain_max = drain_iter;
                    if (drain_iter == MAX_INBOUND_DRAIN) diag.drain_cap_hits += 1;
                    // SSL pending / kernel queue stats for this conn
                    const pend = conn.tls_socket.pendingBytes();
                    if (pend > diag.ssl_pending_max) diag.ssl_pending_max = pend;
                    const nrd = conn.tls_socket.kernelRecvQueue();
                    if (nrd > diag.nread_max) diag.nread_max = nrd;
                    const nwr = conn.tls_socket.kernelSendQueue();
                    if (nwr > diag.nwrite_max) diag.nwrite_max = nwr;
                }
                if (any_conn_had_data) last_iter_had_work = true;

                // Cleanup dead connections
                if (cm.cleanupDead()) {
                    // Primary died — break data loop to trigger reconnect
                    std.log.err("Primary connection died, exiting data loop", .{});
                    break;
                }
            } else {
                // Single-connection mode
                // SSL_pending() check: OpenSSL may have decrypted application
                // data buffered internally that poll() can't see. Without this
                // OR, the data loop sleeps waiting for kernel readability while
                // bytes are already decrypted and waiting in the SSL object.
                //
                // INBOUND DRAIN LOOP: receiveBlocksBatch reads exactly ONE
                // SoftEther packet per call. Under heavy DL the server sends
                // packets back-to-back and many sit decrypted in OpenSSL's
                // internal buffer. Without a drain loop we'd read 1 packet
                // per outer-loop iteration → DL bounded by loop iteration
                // rate (~5000/s = ~7 Mbps for typical packet sizes).
                //
                // Drain up to MAX_INBOUND_DRAIN packets per iteration as long
                // as more TLS data is pending. Cap prevents complete outbound
                // starvation: even on heavy DL, after 8 drained packets we
                // yield to the outbound path so ACKs flow and TUN drains.
                const tls_readable = tls_fd_count > 0 and ((poll_fds[0].revents & std.posix.POLL.IN) != 0 or (self.tls_socket != null and self.tls_socket.?.hasPending()));
                if (tls_readable) {
                    // Cycle 6 adaptive poll: signal work to outer loop
                    last_iter_had_work = true;
                    // Cycle 6: raise cap 8→64. DIAG showed cap=8 was being
                    // hit EVERY iteration with ssl_pend_max=15KB still buffered
                    // — we were forfeiting decrypted data, kernel rcvbuf would
                    // fill, server's TCP RWND would collapse and never recover.
                    // hasPending() is the natural terminator; the cap is just a
                    // safety net to ensure outbound can run occasionally.
                    // Cycle 5 regression came from batch=32, NOT drain=32.
                    const MAX_INBOUND_DRAIN: u32 = 64;
                    var drain_iter: u32 = 0;
                    var inbound_dead = false;
                    while (drain_iter < MAX_INBOUND_DRAIN) : (drain_iter += 1) {
                        const recv_count = single_tunnel.receiveBlocksBatch(&recv_slices, recv_scratch) catch |err| {
                            if (self.should_stop) {
                                inbound_dead = true;
                                break;
                            }
                            // BrokenPipe == TLS dead. Must break, not continue — otherwise we
                            // spin forever polling a dead fd and silently drop all outbound.
                            if (err == error.ConnectionClosed or err == error.BrokenPipe) {
                                std.log.info("Server closed connection: {s}", .{@errorName(err)});
                                inbound_dead = true;
                                break;
                            }
                            // Non-fatal error — stop draining this iteration, retry next.
                            break;
                        };

                        for (recv_slices[0..recv_count]) |block_data| {
                            diag.bytes_in += block_data.len;
                            diag.pkts_in += 1;
                            self.processInboundBlock(block_data, adapter, &loop_state, &send_helper, &dhcp_xid, mac, &is_configured);
                        }

                        // Stop draining if TLS has no more buffered/decrypted data.
                        // Without this we'd block on the next readU32() waiting for
                        // bytes that haven't arrived yet → starves outbound for the
                        // RTT (~200ms) of waiting for the next packet.
                        if (self.tls_socket == null or !self.tls_socket.?.hasPending()) break;
                    }
                    // DIAG: capture drain metrics + queue depths
                    diag.drain_total += drain_iter;
                    if (drain_iter > diag.drain_max) diag.drain_max = drain_iter;
                    if (drain_iter == MAX_INBOUND_DRAIN) diag.drain_cap_hits += 1;
                    if (self.tls_socket) |ts| {
                        const pend = ts.pendingBytes();
                        if (pend > diag.ssl_pending_max) diag.ssl_pending_max = pend;
                        const nrd = ts.kernelRecvQueue();
                        if (nrd > diag.nread_max) diag.nread_max = nrd;
                        const nwr = ts.kernelSendQueue();
                        if (nwr > diag.nwrite_max) diag.nwrite_max = nwr;
                    }
                    if (inbound_dead) break;
                }
            }

            // INBOUND: Receive packets via UDP acceleration (if established)
            if (udp_readable) {
                if (self.udp_accel) |*ua| {
                    if (ua.processIncoming() catch null) |udp_data| {
                        // UDP data is an Ethernet frame — same dispatch as TCP
                        if (udp_data.len > 14 and is_configured) {
                            const ethertype_udp = (@as(u16, udp_data[12]) << 8) | udp_data[13];
                            if (ethertype_udp == 0x0800 or ethertype_udp == 0x86DD) {
                                if (adapter.real_adapter) |*real| {
                                    if (real.device) |dev| {
                                        _ = dev.write(udp_data[14..]) catch {};
                                    }
                                }
                            }
                            self.stats.recordReceived(udp_data.len);
                        }
                    }
                }
            }

            // OUTBOUND: Read from TUN and send to VPN (batched for throughput)
            // Prefer UDP if established, fall back to TCP
            //
            // BACKPRESSURE PROBE: Check whether the TLS socket can accept a
            // write (POLLOUT with 0 timeout). If kernel sndbuf is full,
            // blocking SSL_write would HANG indefinitely because the data
            // loop is single-threaded — and inbound ACKs (which would drain
            // sndbuf) are processed in the same loop. Result: deadlock,
            // upload stuck at 0 Mbps. Symptom: T1 great, T2/T3 upload=0.
            //
            // CRITICAL: We must STILL drain TUN even when tls_can_send=false.
            // If we skip the TUN read, packets pile up in the kernel TUN
            // queue, eventually overflow, and user-space TCP sockets see
            // EAGAIN/socket errors (e.g. "UPLOAD TEST ERROR" in speedtest).
            //
            // Behavior when sndbuf is full:
            //   - UDP path: send via UDP (its own buffer)
            //   - TCP path: DROP the batch. TCP-layer retransmit at the
            //     user app handles recovery. Better to drop than to block.
            //
            // Skip the probe in multi-connection mode (each conn has its own
            // sndbuf and we'd need to probe all; deferred).
            // CYCLE 11 (TURN 16c): Probe + drop logic REMOVED.
            // Was: poll(POLLOUT, timeout=0) on tls socket; drop batch if !writable.
            // Real-world result: 100% silent outbound drops (0 bytes sent in 2m41s).
            // Root cause: poll(timeout=0) returns POLL.OUT only when an EDGE event
            // happened, not when the socket is currently writable. So even with
            // NOTSENT_LOWAT removed, the probe returned false on idle/normal sockets,
            // and 100% of TCP outbound was dropped. Bufferbloat fix is provided by
            // SO_SNDBUF=512KB cap in tls.zig::clearTimeouts().
            const tls_can_send: bool = true;

            // CYCLE 11 REVERT (TURN 16b): The previous "gate TUN read on tls_can_send"
            // attempt killed throughput entirely (0 bytes sent). poll(POLLOUT,timeout=0)
            // returns false too aggressively at high RTT with NOTSENT_LOWAT=16384, so
            // we'd never drain TUN. NOTSENT_LOWAT is also being removed in tls.zig —
            // the SO_SNDBUF=512KB cap alone bounds bufferbloat. Without NOTSENT_LOWAT,
            // POLLOUT only goes false when kernel sndbuf actually fills, which is rare.
            if (is_configured and tun_readable) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        // Read up to OUTBOUND_BATCH packets from TUN in one batch
                        var outbound_blocks: [64][]const u8 = undefined;
                        var outbound_count: usize = 0;
                        var outbound_bytes: usize = 0;

                        while (outbound_count < OUTBOUND_BATCH) {
                            if (dev.read(&tun_read_bufs[outbound_count])) |maybe_len| {
                                if (maybe_len) |ip_len| {
                                    if (ip_len > 0 and ip_len <= 1500) {
                                        if (tunnel_mod.wrapIpInEthernet(tun_read_bufs[outbound_count][0..ip_len], loop_state.gateway_mac, mac, &outbound_eth_bufs[outbound_count])) |eth_frame| {
                                            outbound_blocks[outbound_count] = eth_frame;
                                            outbound_bytes += eth_frame.len;
                                            outbound_count += 1;
                                        }
                                    }
                                } else break; // No more packets available
                            } else |_| break;
                        }

                        if (outbound_count > 0) {
                            // Try UDP first, track how many succeeded
                            var udp_sent_count: usize = 0;
                            if (self.udp_accel) |*ua| {
                                for (outbound_blocks[0..outbound_count]) |frame| {
                                    if (!(ua.sendData(frame) catch false)) break;
                                    udp_sent_count += 1;
                                }
                            }
                            // Send remaining packets (not sent via UDP) over TCP.
                            // If the TCP path is dead (BrokenPipe / ConnectionClosed) we
                            // MUST exit the data loop — otherwise upload silently stalls
                            // at 0 Mbps while the loop spins forever swallowing errors.
                            //
                            // Also gated on tls_can_send: if sndbuf is full, drop the
                            // remaining batch this iteration (TUN buffers them, we'll
                            // retry next iteration after ACKs drain sndbuf). This is
                            // what prevents the SSL_write deadlock.
                            if (udp_sent_count < outbound_count and tls_can_send) {
                                var tls_send_ok = true;
                                send_helper.get().sendBlocksZeroCopy(outbound_blocks[udp_sent_count..outbound_count], send_buffer) catch |err| switch (err) {
                                    error.ConnectionClosed, error.BrokenPipe => {
                                        std.log.err("Outbound send failed, exiting data loop: {s}", .{@errorName(err)});
                                        return;
                                    },
                                    else => {
                                        // Non-fatal: likely WANT_WRITE (TLS sndbuf full).
                                        tls_send_ok = false;
                                    },
                                };
                                if (tls_send_ok) {
                                    // DIAG: count what we actually sent over TCP
                                    diag.pkts_out += outbound_count - udp_sent_count;
                                    for (outbound_blocks[udp_sent_count..outbound_count]) |b| diag.bytes_out += b.len;
                                } else {
                                    // DIAG: send failed — count as dropped
                                    diag.tcp_drops_pkts += outbound_count - udp_sent_count;
                                }
                            } else if (udp_sent_count < outbound_count and !tls_can_send) {
                                // DIAG: TCP path was blocked, batch dropped (TCP layer will retransmit)
                                diag.pollout_skipped += 1;
                                diag.tcp_drops_pkts += outbound_count - udp_sent_count;
                            }
                            // DIAG: count UDP-sent too
                            if (udp_sent_count > 0) {
                                diag.pkts_out += udp_sent_count;
                                for (outbound_blocks[0..udp_sent_count]) |b| diag.bytes_out += b.len;
                            }
                            self.stats.recordSent(outbound_bytes);
                        }
                    }
                }
            }

            // ============================================================
            // SLOW PATH: Control plane (ARP/DHCP/keepalive - less frequent)
            // ============================================================
            const now = std.time.milliTimestamp();

            // ARP Reply (urgent - server is waiting)
            if (loop_state.need_arp_reply and is_configured) {
                loop_state.need_arp_reply = false;
                const reply_size = adapter_mod.buildArpReply(mac, loop_state.our_ip, loop_state.arp_reply_target_mac, loop_state.arp_reply_target_ip, &arp_buf) catch 0;
                if (reply_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..reply_size]};
                    send_helper.get().sendBlocks(&blocks) catch {};
                    const ip = tunnel_mod.formatIpForLog(loop_state.arp_reply_target_ip);
                    std.log.debug("Sent ARP Reply to {d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });
                }
            }

            // Gratuitous ARP (post-DHCP)
            if (loop_state.need_gratuitous_arp and is_configured) {
                loop_state.need_gratuitous_arp = false;
                const garp_size = adapter_mod.buildGratuitousArp(mac, loop_state.our_ip, &arp_buf) catch 0;
                if (garp_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..garp_size]};
                    send_helper.get().sendBlocks(&blocks) catch {};
                    loop_state.timing.last_garp_time = now;
                    const ip = tunnel_mod.formatIpForLog(loop_state.our_ip);
                    std.log.debug("Sent Gratuitous ARP (IP={d}.{d}.{d}.{d})", .{ ip.a, ip.b, ip.c, ip.d });
                }
            }

            // Gateway ARP request
            if (loop_state.need_gateway_arp and is_configured) {
                loop_state.need_gateway_arp = false;
                const arp_size = adapter_mod.buildArpRequest(mac, loop_state.our_ip, loop_state.our_gateway, &arp_buf) catch 0;
                if (arp_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..arp_size]};
                    send_helper.get().sendBlocks(&blocks) catch {};
                    const ip = tunnel_mod.formatIpForLog(loop_state.our_gateway);
                    std.log.debug("Sent ARP Request for gateway {d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });
                }
            }

            // Periodic GARP (every 10s)
            if (is_configured and loop_state.timing.shouldSendGarp(now, garp_interval)) {
                const garp_size = adapter_mod.buildGratuitousArp(mac, loop_state.our_ip, &arp_buf) catch 0;
                if (garp_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..garp_size]};
                    send_helper.get().sendBlocks(&blocks) catch {};
                    loop_state.timing.last_garp_time = now;
                }
            }

            // SoftEther keepalive (every 5s)
            if (loop_state.timing.shouldSendKeepalive(now, keepalive_interval)) {
                if (self.conn_manager) |*cm| {
                    cm.sendKeepaliveAll();
                } else {
                    single_tunnel.sendKeepalive() catch |err| {
                        std.log.warn("Failed to send keepalive: {}", .{err});
                    };
                }
                std.log.debug("Sent keepalive", .{});
                loop_state.timing.last_keepalive = now;
            }

            // DHCP retry — covers both no-OFFER (resend DISCOVER) and no-ACK
            // (resend REQUEST using stashed OFFER params). Without REQUEST retry,
            // a single dropped ACK would hang the tunnel until Swift's poll timed
            // out, even though the only blocker is one lost ACK frame.
            if (loop_state.dhcp_retry_count < 5 and loop_state.timing.shouldRetryDhcp(now, 3000)) {
                if (loop_state.dhcp.state == .discover_sent) {
                    var dhcp_buf: [512]u8 = undefined;
                    const dhcp_size = adapter_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf) catch 0;
                    if (dhcp_size > 0) {
                        const blocks = [_][]const u8{dhcp_buf[0..dhcp_size]};
                        send_helper.get().sendBlocks(&blocks) catch {};
                        loop_state.timing.last_dhcp_time = now;
                        loop_state.dhcp_retry_count += 1;
                        std.log.debug("DHCP DISCOVER retry #{d}", .{loop_state.dhcp_retry_count});
                    }
                } else if (loop_state.dhcp.state == .request_sent and loop_state.dhcp.config.ip_address != 0) {
                    var req_buf: [512]u8 = undefined;
                    const req_size = adapter_mod.buildDhcpRequest(mac, dhcp_xid, loop_state.dhcp.config.ip_address, loop_state.dhcp.config.server_id, &req_buf) catch 0;
                    if (req_size > 0) {
                        const blocks = [_][]const u8{req_buf[0..req_size]};
                        send_helper.get().sendBlocks(&blocks) catch {};
                        loop_state.timing.last_dhcp_time = now;
                        loop_state.dhcp_retry_count += 1;
                        std.log.info("DHCP REQUEST retry #{d}", .{loop_state.dhcp_retry_count});
                    }
                }
            }

            // ============================================================
            // DIAG: 1Hz throughput / queue / drain stats
            // ============================================================
            diag.poll_iters += 1;
            // Cycle 6 adaptive poll: snapshot byte counts to detect work this iter.
            // Done at end of iteration: if bytes changed since iter start, had work.
            // Reset flag at top of next iter via simple comparison \u2014 we store
            // last byte total and compare to current.
            // (Implementation: we set last_iter_had_work based on whether tun_readable
            //  fired this iteration, since it's in scope here.)
            // NOTE: must NOT overwrite (`= tun_readable`) — that would clobber a
            // true value set earlier this iter by the inbound section (causing the
            // historic multi-conn DL collapse from 67→3 Mbps when DL had no UL).
            // Use OR-set so any work source keeps the flag true. The flag is
            // cleared at the TOP of each iter (just before poll), so this only
            // preserves work observed during THIS iter, not all prior iters.
            if (tun_readable) last_iter_had_work = true;

            // Bufferbloat sampling — snapshot kernel TCP sendq depth across
            // all conns and accumulate write-blocked deltas.
            var sendq_now: u32 = 0;
            var iter_wb_end: u64 = 0;
            if (single_sock) |ss| {
                const sq: u32 = @intCast(@min(ss.kernelSendQueue(), std.math.maxInt(u32)));
                if (sq > sendq_now) sendq_now = sq;
                iter_wb_end += ss.write_block_count;
            }
            if (self.conn_manager) |cm| {
                for (cm.connections[0..cm.count]) |maybe_conn| {
                    if (maybe_conn) |conn| {
                        const sq: u32 = @intCast(@min(conn.tls_socket.kernelSendQueue(), std.math.maxInt(u32)));
                        if (sq > sendq_now) sendq_now = sq;
                        iter_wb_end += conn.tls_socket.write_block_count;
                    }
                }
            }
            if (sendq_now > diag.sendq_max) diag.sendq_max = sendq_now;
            diag.sendq_sum += sendq_now;
            diag.sendq_samples += 1;
            diag.write_blocked += iter_wb_end - iter_wb_start;

            // Latency tracking: compute iter wall time and update spike counters.
            // This is the LAST thing in the loop body so it captures everything
            // including poll(), inbound drain, outbound drain, keepalives, DHCP.
            const iter_us: u64 = @intCast(@max(0, std.time.microTimestamp() - iter_start_us));
            if (iter_us > diag.iter_us_max) diag.iter_us_max = iter_us;
            diag.iter_us_total += iter_us;
            if (iter_us >= 10_000) diag.iter_slow_10ms += 1;
            if (iter_us >= 50_000) diag.iter_slow_50ms += 1;
            if (iter_us >= 100_000) diag.iter_slow_100ms += 1;

            if (now - diag_last_ms >= 1000) {
                if (diag.bytes_in > 0 or diag.bytes_out > 0 or diag.tcp_drops_pkts > 0 or diag.nread_max > 0) {
                    const mbps_in = @as(f64, @floatFromInt(diag.bytes_in)) * 8.0 / 1_000_000.0;
                    const mbps_out = @as(f64, @floatFromInt(diag.bytes_out)) * 8.0 / 1_000_000.0;
                    const drain_avg: f64 = if (diag.poll_iters > 0)
                        @as(f64, @floatFromInt(diag.drain_total)) / @as(f64, @floatFromInt(diag.poll_iters))
                    else
                        0.0;
                    const iter_avg_us: f64 = if (diag.poll_iters > 0)
                        @as(f64, @floatFromInt(diag.iter_us_total)) / @as(f64, @floatFromInt(diag.poll_iters))
                    else
                        0.0;
                    // Sample tx_drops from the adapter (FdAdapter ring buffer drops).
                    // On desktop (utun/tun) this always returns 0; on mobile it reveals
                    // how many packets were dropped because the ring was full — the
                    // smoking gun for TCP retrans storms and bufferbloat.
                    const tx_drops_now: u64 = if (adapter.real_adapter) |*ra|
                        ra.getTxDrops()
                    else
                        0;
                    diag.tx_drops_delta = tx_drops_now -| diag.tx_drops_last;
                    diag.tx_drops_last = tx_drops_now;

                    const sendq_avg: f64 = if (diag.sendq_samples > 0)
                        @as(f64, @floatFromInt(diag.sendq_sum)) / @as(f64, @floatFromInt(diag.sendq_samples))
                    else
                        0.0;
                    std.log.info("DIAG dl={d:.1}Mbps({d}p) ul={d:.1}Mbps({d}p) drain[avg={d:.2} max={d} caps={d}] ssl_pend_max={d}B nread_max={d}B nwrite_max={d}B pollout_skip={d} tcp_drop={d}p fda_drop={d}p iters={d} iter_us[avg={d:.0} max={d}] slow[10ms={d} 50ms={d} 100ms={d}] poll_us[max={d}] sendq[max={d} avg={d:.0}] write_blocked={d}", .{
                        mbps_in,             diag.pkts_in,         mbps_out,             diag.pkts_out,
                        drain_avg,           diag.drain_max,       diag.drain_cap_hits,  diag.ssl_pending_max,
                        diag.nread_max,      diag.nwrite_max,      diag.pollout_skipped, diag.tcp_drops_pkts,
                        diag.tx_drops_delta, diag.poll_iters,      iter_avg_us,          diag.iter_us_max,
                        diag.iter_slow_10ms, diag.iter_slow_50ms,  diag.iter_slow_100ms, diag.poll_us_max,
                        diag.sendq_max,      sendq_avg,            diag.write_blocked,
                    });
                }
                diag = DiagStats{};
                diag_last_ms = now;
            }
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
        self.config.routing.default_route = enabled;
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
    try std.testing.expect(config.default_route);
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
