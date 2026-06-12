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
const builtin = @import("builtin");
const net = std.Io.net;

// Minimal Mutex — Thread.Mutex was removed in Zig 0.16.
// Uses pthread on POSIX, SRWLOCK on Windows.
const Mutex = if (builtin.os.tag == .windows)
    std.os.windows.SRWLOCK
else
    extern struct {
        handle: std.c.pthread_mutex_t = .{},
        pub fn lock(self: *@This()) void {
            _ = std.c.pthread_mutex_lock(&self.handle);
        }
        pub fn unlock(self: *@This()) void {
            _ = std.c.pthread_mutex_unlock(&self.handle);
        }
    };

// Import core utilities
const core = @import("../core/mod.zig");
const parseIpv4 = core.parseIpv4;
const compat_timestamp = @import("../compat/timestamp.zig");

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

const tls = net_mod.tls;

// Import session module
const session_mod = @import("../session/mod.zig");

pub const SessionOptions = session_mod.SessionOptions;
pub const SessionWrapper = session_mod.SessionWrapper;

// Import adapter module
const adapter_mod = @import("../adapter/mod.zig");

const AdapterWrapper = adapter_mod.AdapterWrapper;

// Import protocol modules
const auth_mod = @import("../protocol/auth.zig");
const softether_proto = @import("../protocol/softether_protocol.zig");
const protocol_tunnel_mod = @import("../protocol/tunnel.zig");

// Import UDP acceleration
const udp_accel_mod = @import("../net/udp_accel.zig");

// Import tunnel module (data loop helpers)
const tunnel_mod = @import("../tunnel/mod.zig");

// Import route healing (#9, #10)
const route_heal = @import("../adapter/route_heal.zig");

// Import DHCPv6
const dhcpv6_mod = @import("../tunnel/dhcpv6.zig");
const Dhcpv6Client = dhcpv6_mod.Dhcpv6Client;

// Import connection manager for multi-TCP
const connection_manager = @import("connection_manager.zig");
const ConnectionManager = connection_manager.ConnectionManager;
const TcpDirection = connection_manager.TcpDirection;

// Auth handler — full SoftEther handshake (signature → hello → auth →
// optional cluster redirect → ticket re-auth) lives in a sibling file to
// keep this orchestration file focused on lifecycle + state machine.
const auth_handler = @import("auth_handler.zig");

// Session setup — session creation + multi-connection establishment.
const session_setup = @import("session_setup.zig");

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
    /// IPv4 routes to include (newline-separated CIDR notation) — only these through VPN
    ipv4_include: ?[]const u8 = null,
    /// IPv4 routes to exclude (newline-separated CIDR notation) — these NOT through VPN
    ipv4_exclude: ?[]const u8 = null,
    /// IPv6 routes to include (newline-separated CIDR notation)
    ipv6_include: ?[]const u8 = null,
    /// IPv6 routes to exclude (newline-separated CIDR notation)
    ipv6_exclude: ?[]const u8 = null,
};

/// VPN Client configuration
pub const ClientConfig = struct {
    // Server settings
    server_host: []const u8,
    server_port: u16 = 443,
    hub_name: []const u8,

    // Authentication
    auth: AuthMethod,
    max_connections: u8 = 1,
    use_compress: bool = false,
    use_encrypt: bool = true,
    udp_acceleration: bool = false,
    half_connection: bool = false,
    qos: bool = true,
    mtu: u16 = 1400,

    /// Emit non-standard diagnostic logs (per-second DIAG throughput/queue
    /// stats and per-connection RX state). Off by default; enabled via
    /// --verbose or "verbose": true in the JSON config.
    verbose: bool = false,

    // TLS settings
    verify_certificate: bool = true,

    // Routing
    routing: RoutingConfig = .{},

    // Reconnection
    reconnect: ReconnectConfig = .{},

    // Static IP (optional)
    static_ip: ?StaticIpConfig = null,

    // IP version preference
    ip_version: ?IpVersion = null,

    // Timeouts (milliseconds)
    connect_timeout_ms: u32 = 30000,
    read_timeout_ms: u32 = 60000,
    keepalive_interval_ms: u32 = 10000,

    // Proxy (optional)
    proxy: ?tls.ProxyConfig = null,

    // Mobile: external tunnel fd provided by platform (iOS/Android)
    // When set, the VPN client uses this fd instead of opening its own adapter.
    tunnel_fd: ?i32 = null,
};

/// IP version preference: null = try both, v4 = IPv4 only, v6 = IPv6 only
pub const IpVersion = enum(u8) {
    v4 = 4,
    v6 = 6,
};

// ============================================================================
// Transport helpers
// ============================================================================

/// Create a protocol Writer wrapping a TLS socket pointer.
/// File-scope (not a method) so sibling modules — currently auth_handler.zig —
/// can build readers/writers from a `*VpnClient`'s socket.
pub fn makeProtoWriter(sock: *tls.TlsSocket) softether_proto.Writer {
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
pub fn makeProtoReader(sock: *tls.TlsSocket) softether_proto.Reader {
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
    data_loop_thread: ?Thread = null,
    should_stop: bool,
    data_loop_running: bool,

    event_callback: ?EventCallback,
    event_user_data: ?*anyopaque,

    reconnect_attempt: u32,
    reconnect_backoff_ms: u32,
    last_error: ?ClientError,

    server_ip: ?net.IpAddress = null,
    assigned_ip: u32,
    assigned_mask: u32,
    gateway_ip: u32,
    gateway_mac: ?[6]u8,

    // IPv6 state
    dhcpv6_client: ?Dhcpv6Client = null,
    ipv6_assigned_addr: [16]u8 = [_]u8{0} ** 16,
    ipv6_configured: bool = false,
    ipv6_dhcp_sent: bool = false,
    ipv6_dhcp_retry_count: u32 = 0,
    last_dhcpv6_time: i64 = 0,

    /// Server IP that we actually connected to (may differ from server_ip after redirect)
    effective_server_ip: ?net.IpAddress = null,
    effective_server_port: u16,

    // Authentication state
    auth_credentials: ?auth_mod.ClientAuth,
    auth_session_key: ?[20]u8,
    auth_hello_random: ?[20]u8,

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
            .conn_manager = null,
            .udp_accel = null,
            .bulk_keys = null,
            .mutex = .{},
            .should_stop = false,
            .data_loop_running = false,
            .event_callback = null,
            .event_user_data = null,
            .reconnect_attempt = 0,
            .reconnect_backoff_ms = config.reconnect.min_backoff_ms,
            .last_error = null,
            .server_ip = null,
            .assigned_ip = 0,
            .assigned_mask = 0,
            .gateway_ip = 0,
            .gateway_mac = null,
            .dhcpv6_client = null,
            .ipv6_assigned_addr = [_]u8{0} ** 16,
            .ipv6_configured = false,
            .ipv6_dhcp_sent = false,
            .ipv6_dhcp_retry_count = 0,
            .last_dhcpv6_time = 0,
            .effective_server_ip = null,
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
        // Ensure the data loop thread is joined (should already be done by
        // performDisconnect, but be safe in case connect spawned it without
        // a subsequent disconnect).
        if (self.data_loop_thread) |thread| {
            thread.join();
            self.data_loop_thread = null;
        }
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

        // use_encrypt=false is not supported: SoftEther drops TLS on the data
        // channel and continues raw over the same TCP socket when encryption is
        // disabled, but this client keeps doing SSL_read/SSL_write on the data
        // path. The result is an immediate "bad record type" / record-layer
        // failure right after auth (the server's first raw block isn't a valid
        // TLS record), so the tunnel dies before DHCP. Until a raw data-channel
        // mode is implemented, coerce to encrypted — we never silently downgrade
        // security, and the transport is TLS regardless, so this is a no-op for
        // confidentiality and simply keeps the tunnel working.
        if (!self.config.use_encrypt) {
            std.log.warn("use_encrypt=false is not supported (raw data channel unimplemented); forcing encryption ON to avoid a broken tunnel", .{});
            self.config.use_encrypt = true;
        }

        self.should_stop = false;
        self.disconnect_reason = .none;
        self.last_error = null;
        self.stats = .{};
        self.stats.connect_time_ms = blk: {
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
            break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
        };

        self.transitionState(.resolving_dns);

        self.performConnection() catch |err| {
            self.last_error = err;
            self.transitionState(.error_state);
            return err;
        };

        // Mark data_loop_running BEFORE spawning the thread so that
        // softether_run_data_loop (which polls this flag) doesn't race
        // with thread startup and incorrectly return immediately.
        @atomicStore(bool, &self.data_loop_running, true, .release);

        // Spawn the data loop on a native pthread with its own stack.
        // The data loop runs decoupled from any Dart Isolate.run() thread,
        // avoiding the ARM 32-bit FFI trampoline corruption bug that
        // occurs when calling native functions from a second temp isolate.
        self.data_loop_thread = std.Thread.spawn(.{}, runDataLoopThread, .{self}) catch |err| blk: {
            std.log.err("Failed to spawn data loop thread: {}", .{err});
            @atomicStore(bool, &self.data_loop_running, false, .release);
            break :blk null;
        };
    }

    fn runDataLoopThread(self: *Self) void {
        self.runDataLoop() catch |err| {
            std.log.err("Data loop thread exited with error: {}", .{err});
        };
    }

    pub fn disconnect(self: *Self) ClientError!void {
        // Check/transition state under the mutex to prevent double-disconnect
        // when two threads call disconnect() simultaneously.
        self.mutex.lock();
        const old_state = self.state;
        if (old_state == .disconnected or old_state == .disconnecting) {
            self.mutex.unlock();
            return;
        }
        self.state = .disconnecting;
        self.mutex.unlock();

        // Fire .disconnecting event OUTSIDE the mutex so the Dart callback
        // can safely call FFI functions (e.g. softether_get_state) without
        // deadlocking on VpnClient.mutex.
        if (self.event_callback) |cb| {
            cb(.{ .state_changed = .{
                .old_state = old_state,
                .new_state = .disconnecting,
            } }, self.event_user_data);
        }

        self.mutex.lock();
        self.should_stop = true;
        self.disconnect_reason = .user_requested;
        self.performDisconnect();
        self.mutex.unlock();

        // Fire .disconnected event and reconnect check OUTSIDE the mutex
        // so Dart callbacks can safely query fresh VpnClient state.
        self.finishDisconnect(old_state);
    }

    /// Complete the disconnect with event notification and reconnection
    /// check. Called by disconnect() after the mutex is released.
    fn finishDisconnect(self: *Self, old_state: ClientState) void {
        // .disconnected state_changed event
        if (self.event_callback) |cb| {
            cb(.{ .state_changed = .{
                .old_state = .disconnecting,
                .new_state = .disconnected,
            } }, self.event_user_data);
        }
        // Disconnected reason event
        if (self.event_callback) |cb| {
            cb(.{ .disconnected = .{ .reason = self.disconnect_reason } }, self.event_user_data);
        }
        // Reconnection check
        if (self.config.reconnect.enabled and
            self.disconnect_reason != .user_requested and
            old_state == .connected)
        {
            self.scheduleReconnect();
        }
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
        // #10: Startup self-check — purge routes through vanished utun interfaces
        if (builtin.os.tag == .macos or builtin.os.tag == .linux) {
            const purged = route_heal.purgeStaleRoutes(self.allocator);
            if (purged > 0) {
                std.log.info("[STARTUP] Repaired {} stale route(s) from previous session", .{purged});
            }
        }

        self.transitionState(.resolving_dns);
        self.server_ip = self.resolveDns() catch {
            self.disconnect_reason = .network_error;
            return ClientError.DnsResolutionFailed;
        };
        self.effective_server_ip = self.server_ip;
        self.effective_server_port = self.config.server_port;

        // Clean up stale host route to the VPN server IP left from a
        // previous crashed/killed session. The purgeStaleRoutes scan above
        // only finds routes through dead utun interfaces — it can't see
        // the host bypass route because that goes through the physical NIC.
        // This call is idempotent; route delete -host is a no-op if the
        // route doesn't exist.
        if (self.server_ip) |srv| {
            if (srv.any.family == std.posix.AF.INET) {
                var ip_buf: [16]u8 = undefined;
                const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                    @as(u8, @truncate(srv.in.sa.addr >> 24)),
                    @as(u8, @truncate(srv.in.sa.addr >> 16)),
                    @as(u8, @truncate(srv.in.sa.addr >> 8)),
                    @as(u8, @truncate(srv.in.sa.addr)),
                }) catch unreachable;
                route_heal.cleanupStaleHostRoute(self.allocator, ip_str);
            }
        }

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
            .proxy = self.config.proxy,
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
        auth_handler.run(self) catch |err| {
            // Preserve the error type from auth_handler. When runRedirect
            // returns ConnectionFailed (redirect backend unreachable), we
            // must NOT map it to AuthenticationFailed — the retry loop and
            // UI both need to distinguish "infrastructure down" from
            // "wrong password".
            if (err == ClientError.ConnectionFailed) {
                std.log.err("Connection failed for hub '{s}' (redirect backend unreachable): {}", .{ self.config.hub_name, err });
                self.disconnect_reason = .network_error;
                return ClientError.ConnectionFailed;
            }
            // Application-level err so operators grepping `(err)` still see auth
            // failures even though the protocol layer logs server-side rejections
            // at warn (those are normal protocol outcomes, not library bugs).
            std.log.err("Authentication failed for hub '{s}': {}", .{ self.config.hub_name, err });
            self.disconnect_reason = .auth_failed;
            return ClientError.AuthenticationFailed;
        };

        if (@atomicLoad(bool, &self.should_stop, .acquire)) {
            self.disconnect_reason = .user_requested;
            return ClientError.OperationCancelled;
        }

        self.transitionState(.establishing_session);
        session_setup.run(self);

        if (@atomicLoad(bool, &self.should_stop, .acquire)) {
            self.disconnect_reason = .user_requested;
            return ClientError.OperationCancelled;
        }

        self.transitionState(.configuring_adapter);
        self.configureAdapter() catch {
            self.disconnect_reason = .configuration_error;
            return ClientError.AdapterConfigurationFailed;
        };

        self.transitionState(.connected);
        self.stats.connect_time_ms = blk: {
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
            break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
        };

        if (self.event_callback) |cb| {
            const server_ip_u32 = if (self.server_ip) |srv| switch (srv) {
                .ip4 => |v4| @as(u32, @bitCast(v4.bytes)),
                .ip6 => @as(u32, 0),
            } else 0;
            cb(.{ .connected = .{
                .server_ip = server_ip_u32,
                .assigned_ip = self.assigned_ip,
                .gateway_ip = self.gateway_ip,
            } }, self.event_user_data);
        }
    }

    pub fn performDisconnect(self: *Self) void {
        // NOTE: event callbacks (.disconnecting / .disconnected / state_changed)
        // are now fired by disconnect() outside the mutex-locked section.
        // performDisconnect does ONLY synchronous cleanup — no callbacks, no
        // blocking privileged I/O while holding the mutex.

        // Signal data loop to stop and wait for it to exit
        @atomicStore(bool, &self.should_stop, true, .release);
        var wait_count: u32 = 0;
        while (@atomicLoad(bool, &self.data_loop_running, .acquire) and wait_count < 200) : (wait_count += 1) {
            {
                var ts: std.c.timespec = .{ .sec = @intCast(@divFloor(10 * std.time.ns_per_ms, std.time.ns_per_s)), .nsec = @intCast(@mod(10 * std.time.ns_per_ms, std.time.ns_per_s)) };
                _ = std.c.nanosleep(&ts, null);
            } // 10ms per check, max 2s
        }

        // Join the native data loop thread (if any) — this releases its resources
        if (self.data_loop_thread) |thread| {
            thread.join();
            self.data_loop_thread = null;
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

        self.state = .disconnected;

        // Fire disconnected event and reconnection check OUTSIDE the mutex.
        // disconnect() calls us with the mutex held, then fires these after
        // releasing it. deinit() calls us directly (no event needed).
    }

    fn resolveDns(self: *Self) !net.IpAddress {
        const host = self.config.server_host;

        // First try parsing as IP address (fast path)
        if (net.IpAddress.parseIp4(host, self.config.server_port)) |addr| {
            return addr;
        } else |_| {}

        if (net.IpAddress.parseIp6(host, self.config.server_port)) |addr| {
            return addr;
        } else |_| {}

        // DNS resolution using libc getaddrinfo (std.Io.net.getAddressList removed in Zig 0.16)
        const c = std.c;
        var hints: c.addrinfo = undefined;
        @memset(std.mem.asBytes(&hints), 0);
        hints.family = c.AF.INET;
        hints.socktype = c.SOCK.STREAM;

        var result: ?*c.addrinfo = null;
        const port_z = try std.fmt.allocPrintSentinel(self.allocator, "{d}", .{self.config.server_port}, 0);
        defer self.allocator.free(port_z);
        const host_z = try self.allocator.dupeZ(u8, host);
        defer self.allocator.free(host_z);

        const rc = c.getaddrinfo(host_z.ptr, port_z.ptr, &hints, &result);
        if (@intFromEnum(rc) != 0) {
            return ClientError.DnsResolutionFailed;
        }
        defer c.freeaddrinfo(result.?);

        // Extract first IPv4 address
        var ai = result.?;
        while (true) {
            if (ai.family == c.AF.INET and ai.addrlen >= @sizeOf(c.sockaddr.in)) {
                const sa: *const c.sockaddr.in = @ptrCast(@alignCast(ai.addr.?));
                return net.IpAddress{ .ip4 = .{
                    .bytes = @bitCast(sa.addr),
                    .port = self.config.server_port,
                } };
            }
            ai = ai.next orelse break;
        }

        return ClientError.DnsResolutionFailed;
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
                // parseIpv4 returns HOST byte order, but assigned_ip/gateway_ip
                // are stored in NETWORK byte order (big-endian) everywhere else
                // — that's the convention the DHCP path uses and what
                // configureFullTunnel and formatIpForLog (which reads >>24
                // first) expect. Without the swap the octets come out reversed
                // (10.21.0.155 -> 155.0.21.10, gw 10.21.0.1 -> 1.0.21.10),
                // pointing the default route at a bogus gateway and breaking the
                // host's internet.
                self.assigned_ip = if (parseIpv4(ip_str)) |v| @byteSwap(v) else 0;
                if (static.ipv4_gateway) |gw_str| {
                    self.gateway_ip = if (parseIpv4(gw_str)) |v| @byteSwap(v) else 0;
                }
                const netmask: u32 = if (static.ipv4_netmask) |nm_str|
                    if (parseIpv4(nm_str)) |v| @byteSwap(v) else 0xFFFFFF00
                else
                    0xFFFFFF00;
                ctx.configure(self.assigned_ip, netmask, self.gateway_ip);
            }
            if (static.ipv6_address) |ip6_str| {
                var addr: [16]u8 = undefined;
                if (parseIpv6Address(ip6_str, &addr)) {
                    const prefix = static.ipv6_prefix_len orelse 64;
                    const gateway = static.ipv6_gateway orelse "";
                    ctx.configureIpv6(addr, prefix, gateway);
                    @memcpy(&self.ipv6_assigned_addr, &addr);
                    self.ipv6_configured = true;
                    std.log.info("Configured static IPv6 address", .{});
                } else {
                    std.log.err("Failed to parse static IPv6 address: {s}", .{ip6_str});
                }
            }
        }

        // Defer routing configuration until AFTER DHCP completes, because
        // routing set up now (with the static IP on the TUN) breaks when
        // DHCP later reconfigures the TUN with a pool IP — the kernel's route
        // cache invalidation during IP reassignment doesn't restore the
        // default-route gateway resolution, leaving the route dead.
        // The DHCP ACK handler below will call configureFullTunnel or
        // configureSplitTunnel once the TUN has its final IP from the pool.
        if (self.config.static_ip == null and self.gateway_ip != 0) {
            if (self.server_ip) |srv| {
                switch (srv) {
                    .ip4 => |v4| {
                        const server_ip_be = @as(u32, @bitCast(v4.bytes));
                        // Default Route (Full Tunnel) — base routing
                        if (self.config.routing.default_route) {
                            ctx.configureFullTunnel(self.gateway_ip, server_ip_be);
                        }
                        // Advanced Routing — stacks on top
                        if (self.config.routing.enable_custom_routes) {
                            if (self.config.routing.ipv4_include) |routes| {
                                ctx.configureSplitTunnel(self.gateway_ip, routes);
                            }
                        }
                    },
                    .ip6 => {},
                }
            }
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

        if (self.config.use_encrypt) {
            const encrypted = sess.encrypt(self.allocator, data) catch return ClientError.OperationCancelled;
            defer self.allocator.free(encrypted);
        }

        self.stats.recordSent(data.len);
    }

    pub fn receivePacket(self: *Self, data: []const u8) ClientError![]u8 {
        if (!self.isConnected()) return ClientError.NotConnected;

        var sess = &(self.session orelse return ClientError.NotConnected);

        var decrypted: []u8 = undefined;
        if (self.config.use_encrypt) {
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
                // TEMPORARY ICMP DIAG: log every ICMP packet written to TUN
                // if (ethertype == 0x0800 and block_data.len > 23) {
                //     const ip_proto = block_data[23]; // byte 9 of IP header
                //     if (ip_proto == 1) {
                //         const src = tunnel_mod.formatIpForLog((@as(u32, block_data[26]) << 24) | (@as(u32, block_data[27]) << 16) | (@as(u32, block_data[28]) << 8) | block_data[29]);
                //         const dst = tunnel_mod.formatIpForLog((@as(u32, block_data[30]) << 24) | (@as(u32, block_data[31]) << 16) | (@as(u32, block_data[32]) << 8) | block_data[33]);
                //         const icmp_type = block_data[34];
                //         const icmp_code = block_data[35];
                //         std.log.info("[ICMP-IN] {d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} type={d} code={d} len={d}", .{ src.a, src.b, src.c, src.d, dst.a, dst.b, dst.c, dst.d, icmp_type, icmp_code, block_data.len - 14 });
                //     }
                // }
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
                    std.log.info("Received DHCP Offer", .{});
                    {
                        const ip = tunnel_mod.formatIpForLog(response.config.ip_address);
                        std.log.info("DHCP: Your IP {d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });
                    }
                    {
                        const gw = tunnel_mod.formatIpForLog(response.config.gateway);
                        std.log.info("DHCP: Router {d}.{d}.{d}.{d}", .{ gw.a, gw.b, gw.c, gw.d });
                    }
                    {
                        const m = tunnel_mod.formatIpForLog(response.config.subnet_mask);
                        std.log.info("DHCP: Subnet mask {d}.{d}.{d}.{d}", .{ m.a, m.b, m.c, m.d });
                    }
                    {
                        const d1 = tunnel_mod.formatIpForLog(response.config.dns1);
                        if (response.config.dns2 != 0) {
                            const d2 = tunnel_mod.formatIpForLog(response.config.dns2);
                            std.log.info("DHCP: DNS {d}.{d}.{d}.{d}, {d}.{d}.{d}.{d}", .{ d1.a, d1.b, d1.c, d1.d, d2.a, d2.b, d2.c, d2.d });
                        } else {
                            std.log.info("DHCP: DNS {d}.{d}.{d}.{d}", .{ d1.a, d1.b, d1.c, d1.d });
                        }
                    }
                    {
                        const si = tunnel_mod.formatIpForLog(response.config.server_id);
                        std.log.info("DHCP: Server ID {d}.{d}.{d}.{d}", .{ si.a, si.b, si.c, si.d });
                    }
                    std.log.info("DHCP: Lease time {d}s", .{response.config.lease_time});

                    var req_buf: [512]u8 = undefined;
                    // Request the offered IP — do NOT override with a static IP
                    // via option 50. The server's DHCP server OFFERs an
                    // available IP; if we ask for a different one the server
                    // will NAK, breaking DHCP (no ACK ever arrives). This is
                    // required because the server's DHCPForce=1 policy
                    // discards packets from un-leased IPs — the DHCP ACK is
                    // what sets DhcpAllocated=1 on the server side.
                    const requested_ip = response.config.ip_address;
                    const req_size = adapter_mod.buildDhcpRequest(mac, dhcp_xid.*, requested_ip, response.config.server_id, &req_buf) catch 0;
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
                        loop_state.timing.last_dhcp_time = blk: {
                            var ts: std.c.timespec = undefined;
                            _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
                            break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
                        };
                        std.log.info("Send DHCP Request", .{});
                    }
                } else if (response.msg_type == .ack and loop_state.dhcp.state == .request_sent) {
                    std.log.info("Received DHCP Ack", .{});
                    loop_state.configure(response.config.ip_address, response.config.gateway);
                    loop_state.dhcp.state = .configured;
                    is_configured.* = true;
                    self.assigned_ip = loop_state.our_ip;
                    self.gateway_ip = loop_state.our_gateway;
                    self.assigned_mask = response.config.subnet_mask;

                    {
                        const m = tunnel_mod.formatIpForLog(response.config.subnet_mask);
                        std.log.info("DHCP: Subnet mask {d}.{d}.{d}.{d}", .{ m.a, m.b, m.c, m.d });
                    }
                    {
                        const gw = tunnel_mod.formatIpForLog(response.config.gateway);
                        std.log.info("DHCP: Router {d}.{d}.{d}.{d}", .{ gw.a, gw.b, gw.c, gw.d });
                    }
                    {
                        const d1 = tunnel_mod.formatIpForLog(response.config.dns1);
                        std.log.info("DHCP: DNS {d}.{d}.{d}.{d}", .{ d1.a, d1.b, d1.c, d1.d });
                    }
                    {
                        const si = tunnel_mod.formatIpForLog(response.config.server_id);
                        std.log.info("DHCP: Server ID {d}.{d}.{d}.{d}", .{ si.a, si.b, si.c, si.d });
                    }
                    std.log.info("DHCP: Lease time {d}s", .{response.config.lease_time});

                    if (adapter.real_adapter) |*real| {
                        if (real.device) |dev| {
                            dev.configure(response.config.ip_address, response.config.subnet_mask, response.config.gateway) catch |err| {
                                std.log.err("Failed to configure interface: {}", .{err});
                            };
                        }
                    }

                    {
                        const ip = tunnel_mod.formatIpForLog(response.config.ip_address);
                        std.log.info("IP Address {d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });
                    }
                    {
                        const gw = tunnel_mod.formatIpForLog(response.config.gateway);
                        std.log.info("Router {d}.{d}.{d}.{d}", .{ gw.a, gw.b, gw.c, gw.d });
                    }
                    {
                        const d1 = tunnel_mod.formatIpForLog(response.config.dns1);
                        if (response.config.dns2 != 0) {
                            const d2 = tunnel_mod.formatIpForLog(response.config.dns2);
                            std.log.info("DNS {d}.{d}.{d}.{d}, {d}.{d}.{d}.{d}", .{ d1.a, d1.b, d1.c, d1.d, d2.a, d2.b, d2.c, d2.d });
                        } else {
                            std.log.info("DNS {d}.{d}.{d}.{d}", .{ d1.a, d1.b, d1.c, d1.d });
                        }
                    }

                    if (self.gateway_ip != 0) {
                        // Default Route (Full Tunnel) — only controls whether VPN
                        // becomes the default gateway. Independent of Advanced Routing.
                        if (self.config.routing.default_route) {
                            const gw = tunnel_mod.formatIpForLog(loop_state.our_gateway);
                            std.log.info("Add IPv4 default route via {d}.{d}.{d}.{d}", .{ gw.a, gw.b, gw.c, gw.d });
                            if (self.server_ip) |srv| {
                                if (srv == .ip4) {
                                    const server_ip_be = @byteSwap(@as(u32, @bitCast(srv.ip4.bytes)));
                                    adapter.configureFullTunnel(loop_state.our_gateway, server_ip_be);
                                }
                            }
                        }
                        // Advanced Routing — stacks on top of base routing
                        if (self.config.routing.enable_custom_routes) {
                            if (self.config.routing.ipv4_include) |routes| {
                                std.log.info("Configuring split-tunnel with custom IPv4 routes", .{});
                                adapter.configureSplitTunnel(loop_state.our_gateway, routes);
                            }
                        }
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
                } else if (response.msg_type == .ack and loop_state.dhcp.state == .inform_sent) {
                    std.log.debug("DHCP INFORM ACK received (gateway learned static IP via ciaddr)", .{});
                }
            }
        }

        // DHCPv6 Reply parsing — runs regardless of IPv4 DHCP state
        if (!self.ipv6_configured and self.ipv6_dhcp_sent) {
            const dv6_payload = adapter_mod.parseDhcpv6Reply(block_data);
            if (dv6_payload) |payload| {
                if (self.dhcpv6_client) |*client| {
                    const parse_result = client.parseResponse(payload) catch null;
                    if (parse_result) |parsed| {
                        if (parsed.msg_type == .reply and client.config.isValid()) {
                            std.log.info("DHCPv6 REPLY received — configuring IPv6 address", .{});
                            @memcpy(&self.ipv6_assigned_addr, &client.config.address);
                            self.ipv6_configured = true;

                            // Configure IPv6 on the adapter
                            if (adapter.getName()) |ifname| {
                                var gw_buf: [64]u8 = undefined;
                                const gw = std.fmt.bufPrint(&gw_buf, "fe80::1%{s}", .{ifname}) catch "fe80::1";
                                adapter.configureIpv6(
                                    client.config.address,
                                    client.config.prefix_len,
                                    gw,
                                );

                                // Add IPv6 default route if full-tunnel is enabled
                                if (self.config.routing.default_route) {
                                    adapter_mod.route.addIpv6DefaultRoute(gw) catch |err| {
                                        std.log.warn("Failed to add IPv6 default route: {}", .{err});
                                    };
                                }
                                // Layer custom IPv6 split-tunnel routes on top
                                if (self.config.routing.enable_custom_routes) {
                                    if (self.config.routing.ipv6_include) |routes| {
                                        adapter.addIpv6Routes(gw, routes);
                                    }
                                }
                            } else {
                                adapter.configureIpv6(
                                    client.config.address,
                                    client.config.prefix_len,
                                    "fe80::1",
                                );
                                if (self.config.routing.default_route) {
                                    adapter_mod.route.addIpv6DefaultRoute("fe80::1%utun") catch |err| {
                                        std.log.warn("Failed to add IPv6 default route: {}", .{err});
                                    };
                                }
                                if (self.config.routing.enable_custom_routes) {
                                    if (self.config.routing.ipv6_include) |routes| {
                                        adapter.addIpv6Routes("fe80::1%utun", routes);
                                    }
                                }
                            }

                            if (self.event_callback) |cb| {
                                cb(.{ .state_changed = .{
                                    .old_state = self.state,
                                    .new_state = self.state,
                                } }, self.event_user_data);
                            }
                        }
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

        // Create single tunnel connection on heap (avoids stack overflow on Dart isolate threads)
        const single_tunnel = try self.allocator.create(protocol_tunnel_mod.TunnelConnection);
        defer {
            single_tunnel.deinit();
            self.allocator.destroy(single_tunnel);
        }
        var noop_ctx: u8 = 0; // hoisted: &noop_ctx stored in single_tunnel.context for multi-conn fallback
        if (single_sock) |ss| {
            single_tunnel.* = protocol_tunnel_mod.TunnelConnection.init(
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
                        try s.writeAllNonBlocking(data);
                        return data.len;
                    }
                }.write,
            );
            single_tunnel.use_compress = self.config.use_compress;
            single_tunnel.initCompression();
        } else {
            // Multi-connection mode: initialize with error-returning callbacks.
            // This path is never used during normal operation (send_helper.get()
            // returns connection-manager connections instead), but provides a safe
            // fallback should get() ever fall through to single_ptr.
            single_tunnel.* = protocol_tunnel_mod.TunnelConnection.init(
                self.allocator,
                &noop_ctx,
                struct {
                    fn read(_: *anyopaque, _: []u8) anyerror!usize {
                        return error.ConnectionClosed;
                    }
                }.read,
                struct {
                    fn write(_: *anyopaque, _: []const u8) anyerror!usize {
                        return error.ConnectionClosed;
                    }
                }.write,
            );
        }

        // Get MAC address
        const mac = adapter.getMac();

        // Initialize data loop state (from tunnel module)
        var loop_state = tunnel_mod.DataLoopState.init(mac);

        // DHCP transaction ID
        var dhcp_xid: u32 = 0;
        const random = @import("../compat/random.zig");
        random.bytes(std.mem.asBytes(&dhcp_xid));

        // Configuration constants
        const keepalive_interval: i64 = 5000; // 5 seconds (server timeout is 20s)
        const garp_interval: i64 = 10000; // 10 seconds - periodic GARP for bridge mode

        // Cache the configured state check (must be before DHCP discover)
        var is_configured = false;

        // Receive buffers — heap-allocated to avoid stack overflow
        // (Dart Isolate.run() threads have ~1MB stack; these buffers are 800KB+)
        const recv_scratch = try self.allocator.alloc(u8, 512 * 1600);
        defer self.allocator.free(recv_scratch);
        var recv_slices = try self.allocator.alloc([]u8, 512);
        defer self.allocator.free(recv_slices);

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
            .single_ptr = single_tunnel,
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
            tx_drops_delta: u64 = 0, // FdAdapter ring buffer drops (this second)
            tx_drops_last: u64 = 0, // cumulative tx_drops at last flush
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
        var diag_last_ms: i64 = blk: {
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
            break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
        };
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

        // Wait 300ms then send DHCP discover/inform
        {
            var ts: std.c.timespec = .{ .sec = @intCast(@divFloor(300 * std.time.ns_per_ms, std.time.ns_per_s)), .nsec = @intCast(@mod(300 * std.time.ns_per_ms, std.time.ns_per_s)) };
            _ = std.c.nanosleep(&ts, null);
        }

        var dhcp_buf_arr: [512]u8 = undefined;

        if (self.config.static_ip) |sip| {
            // Static IP: send DHCP INFORM so gateway learns our IP via ciaddr,
            // then DISCOVER to get a pool IP with DhcpAllocated=1 from the ACK.
            // The pool IP satisfies DHCPForce; gateway knows our static IP from
            // the INFORM's ciaddr field.
            const static_ip_be: u32 = if (sip.ipv4_address) |s|
                if (parseIpv4(s)) |v| @byteSwap(v) else 0
            else
                0;
            const dhcp_inform_size = adapter_mod.buildDhcpInform(mac, dhcp_xid, static_ip_be, &dhcp_buf_arr) catch 0;
            if (dhcp_inform_size > 0) {
                const blocks = [_][]const u8{dhcp_buf_arr[0..dhcp_inform_size]};
                send_helper.get().sendBlocks(&blocks) catch {};
                std.log.debug("Sent DHCP INFORM (xid=0x{x:0>8}) for static IP", .{dhcp_xid});
            }
            // Brief pause so INFORM is sent before DISCOVER
            // (ensures proper ordering even on fast connections).
            {
                var ts: std.c.timespec = .{ .sec = @intCast(@divFloor(50 * std.time.ns_per_ms, std.time.ns_per_s)), .nsec = @intCast(@mod(50 * std.time.ns_per_ms, std.time.ns_per_s)) };
                _ = std.c.nanosleep(&ts, null);
            }
        }

        // Always send DISCOVER for DhcpAllocated registration
        {
            const dhcp_disc_size = adapter_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf_arr) catch 0;
            if (dhcp_disc_size > 0) {
                const blocks = [_][]const u8{dhcp_buf_arr[0..dhcp_disc_size]};
                if (send_helper.get().sendBlocks(&blocks)) |_| {
                    loop_state.dhcp.state = .discover_sent;
                    loop_state.timing.last_dhcp_time = blk: {
                        var ts: std.c.timespec = undefined;
                        _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
                        break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
                    };
                    std.log.debug("Sent DHCP DISCOVER (xid=0x{x:0>8})", .{dhcp_xid});
                } else |err| {
                    std.log.err("Failed to send DHCP discover: {}", .{err});
                }
            }
        }

        // Reset IPv6 state (handles reconnect: old ipv6_configured/retry_count
        // must not carry over from a prior session)
        self.ipv6_configured = false;
        self.ipv6_dhcp_sent = false;
        self.ipv6_dhcp_retry_count = 0;
        self.last_dhcpv6_time = 0;

        // Send DHCPv6 Solicit. Skip if static IPv6 is configured in the config
        // (user-supplied IPv6 is authoritative, no need to solicit from server).
        const has_static_ipv6 = if (self.config.static_ip) |s| s.ipv6_address != null else false;
        if (!has_static_ipv6) {
            self.dhcpv6_client = Dhcpv6Client.init(self.allocator, mac);
            var dhcpv6_raw: [256]u8 = undefined;
            if (self.dhcpv6_client) |*client| {
                const dv6_len = client.buildSolicit(&dhcpv6_raw) catch 0;
                if (dv6_len > 0) {
                    var dv6_frame: [512]u8 = undefined;
                    const frame_len = adapter_mod.buildDhcpv6Frame(mac, dhcpv6_raw[0..dv6_len], &dv6_frame) catch 0;
                    if (frame_len > 0) {
                        const blocks = [_][]const u8{dv6_frame[0..frame_len]};
                        if (send_helper.get().sendBlocks(&blocks)) |_| {
                            self.ipv6_dhcp_sent = true;
                            self.last_dhcpv6_time = blk: {
                                var ts: std.c.timespec = undefined;
                                _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
                                break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
                            };
                            std.log.info("Send DHCPv6 Solicit", .{});
                        } else |err| {
                            std.log.err("Failed to send DHCPv6 Solicit: {}", .{err});
                        }
                    }
                }
            }
        } else {
            self.ipv6_configured = true;
            std.log.info("Static IPv6 configured — skipping DHCPv6", .{});
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

        // Persistent per-connection RX log state, used to suppress the
        // per-second "RX conn dir=... primary=... estab=... krecv=..."
        // log when nothing has changed since the last flush. Logged
        // unconditionally, this fires N times per second where N =
        // max_connections, ballooning the log and adding measurable CPU
        // (kernelRecvQueue is a syscall on every call). With state-change
        // gating, the log only fires when something actually changed.
        const ConnRxLogState = struct {
            dir: u8 = 255,
            primary: bool = false,
            estab: bool = false,
            krecv_nonzero: bool = false,
            pending: bool = false,
        };
        var conn_rx_log: [connection_manager.MAX_CONNECTIONS]ConnRxLogState = undefined;
        for (&conn_rx_log) |*s| s.* = .{};

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
            const iter_start_us = compat_timestamp.microTimestamp();
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

            // macOS poll(timeout=0) can sleep for 1 scheduler tick (~10ms)
            // unpredictably even with a zero timeout. During those 10ms the
            // kernel TCP recv buffer fills, the server's congestion window
            // collapses, and it takes seconds to recover — causing the
            // progressive DL/UL degradation we've been chasing.
            //
            // Fix: check if OpenSSL already has decrypted data buffered. If
            // yes, skip poll() entirely this iteration — drain the buffered
            // data immediately. Only fall through to poll() when genuinely
            // idle (no pending data), where the 10ms sleep is acceptable.
            var skip_poll = false;
            if (!multi_conn) {
                if (single_sock) |ss| {
                    if (ss.hasPending() or ss.kernelRecvQueue() > 0) skip_poll = true;
                }
            } else {
                if (self.conn_manager) |*cm| {
                    for (cm.connections[0..cm.count]) |*slot| {
                        if (slot.*) |*conn| {
                            if (conn.established and (conn.tls_socket.hasPending() or conn.tls_socket.kernelRecvQueue() > 0)) {
                                skip_poll = true;
                                break;
                            }
                        }
                    }
                }
            }

            const poll_t0 = compat_timestamp.microTimestamp();
            if (!skip_poll) {
                _ = std.posix.poll(poll_fds[0..total_poll_count], poll_timeout_ms) catch 0;
            } else {
                // Keep poll timeout=0 next iter — more data likely follows
                last_iter_had_work = true;
            }
            const poll_us: u32 = @intCast(@max(0, compat_timestamp.microTimestamp() - poll_t0));
            if (poll_us > diag.poll_us_max) diag.poll_us_max = poll_us;
            diag.poll_us_total += poll_us;

            const tun_readable = if (builtin.os.tag == .windows) is_configured else (poll_fds[poll_tun_idx].revents & std.posix.POLL.IN) != 0;
            const udp_readable = has_udp and (poll_fds[poll_udp_idx].revents & std.posix.POLL.IN) != 0;
            if (skip_poll) diag.pollout_skipped += 1;

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
                        const recv_count = conn.tunnel.receiveBlocksBatch(recv_slices, recv_scratch) catch |err| {
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

                        // Stop draining when SSL has no more buffered data
                        // AND kernel has nothing queued. Without the kernel
                        // check, data that arrived in the TCP recv buffer but
                        // hasn't been SSL_read() yet causes us to stop draining
                        // prematurely → back to poll → macOS 10ms stall.
                        if (!conn.tls_socket.hasPending() and conn.tls_socket.kernelRecvQueue() == 0) break;
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
                    // Primary died — exit data loop to trigger reconnect
                    std.log.err("Primary connection died, exiting data loop", .{});
                    self.disconnect_reason = .network_error;
                    return error.ConnectionLost;
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
                const tls_readable = tls_fd_count > 0 and ((poll_fds[0].revents & std.posix.POLL.IN) != 0 or (self.tls_socket != null and (self.tls_socket.?.hasPending() or self.tls_socket.?.kernelRecvQueue() > 0)));
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
                        const recv_count = single_tunnel.receiveBlocksBatch(recv_slices, recv_scratch) catch |err| {
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

                        // Stop draining if TLS has no more buffered/decrypted data
                        // AND kernel has nothing queued. Without the kernel check,
                        // data sitting in the TCP recv buffer (before SSL_read()
                        // pulls it in) causes us to stop draining early → back to
                        // poll → macOS 10ms stall.
                        if (self.tls_socket == null or (!self.tls_socket.?.hasPending() and self.tls_socket.?.kernelRecvQueue() == 0)) break;
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
                    if (inbound_dead) {
                        self.disconnect_reason = .network_error;
                        return error.ConnectionLost;
                    }
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
            // Prefer UDP if established, fall back to TCP.
            //
            // BACKPRESSURE: Sample kernel send queue depth and throttle the
            // outbound batch size. When sendq is high, halve the batch so the
            // kernel has time to drain before we pile on more. We do NOT cap
            // to a near-zero batch (1-4 packets) at any sendq level: the
            // outbound path carries both UL data AND DL ACKs, and starving
            // the ACKs at the 4 MB SO_SNDBUF ceiling collapses DL throughput
            // to <10 Mbps. The kernel's SO_SNDBUF is the real backpressure
            // — client-side we just smooth the slope.
            //
            // In multi-conn mode, sendq must be aggregated across every
            // established connection — not just the primary. Otherwise 8 conns
            // each at 1 MB queued = 8 MB of in-flight data with no throttle.
            //
            // We MUST NOT gate TUN reads entirely (as was tried with poll-level
            // gating) because in a VPN tunnel, outbound carries download ACKs
            // — blocking them causes the content server to stall, collapsing
            // download from 100+ Mbps to <1 Mbps.
            //
            // FIX: also try outbound when skip_poll = true. When TLS has
            // pending data the poll_fds are rebuilt with revents=0 and poll()
            // is skipped, so tun_readable is always false. Without this, the
            // outbound path (ACKs, new upload conns) is completely starved
            // during any continuous download burst. The TUN fd is non-blocking
            // so a read with no data returns WouldBlock instantly.
            const sendq_throttle_med: u32 = 256 * 1024; // 256 KB — halve batch
            const sendq_throttle_high: u32 = 512 * 1024; // 512 KB — minimum batch (single-conn only)
            if (is_configured and (tun_readable or skip_poll)) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        var sendq: u32 = 0;
                        const is_multi = self.conn_manager != null;
                        if (single_sock) |ss| {
                            sendq = @intCast(@min(ss.kernelSendQueue(), std.math.maxInt(u32)));
                        } else if (self.conn_manager) |*cm| {
                            // In multi-conn mode there's no head-of-line blocking
                            // across connections — if one is slow, others can drain.
                            // Use AVG to avoid throttling ALL connections because
                            // ONE connection's buffer is full. Single-conn uses MAX
                            // (the only connection IS the bottleneck).
                            var sq_sum: u64 = 0;
                            var sq_count: u32 = 0;
                            for (cm.connections[0..cm.count]) |*slot| {
                                if (slot.*) |*conn| {
                                    if (conn.established) {
                                        const sq: u32 = @intCast(@min(conn.tls_socket.kernelSendQueue(), std.math.maxInt(u32)));
                                        sq_sum += sq;
                                        sq_count += 1;
                                    }
                                }
                            }
                            if (sq_count > 0) sendq = @intCast(@min(sq_sum / sq_count, std.math.maxInt(u32)));
                        }
                        const batch_limit: usize = if (!is_multi and sendq >= sendq_throttle_high)
                            @min(OUTBOUND_BATCH, 4)
                        else if (sendq >= sendq_throttle_med)
                            OUTBOUND_BATCH / 2
                        else
                            OUTBOUND_BATCH;

                        var outbound_blocks: [64][]const u8 = undefined;
                        var outbound_count: usize = 0;
                        var outbound_bytes: usize = 0;

                        while (outbound_count < batch_limit) {
                            if (dev.read(&tun_read_bufs[outbound_count])) |maybe_len| {
                                if (maybe_len) |ip_len| {
                                    if (ip_len > 0 and ip_len <= 1500) {
                                        // TEMPORARY ICMP DIAG: log every ICMP packet read from TUN
                                        // if (ip_len > 9) {
                                        // const ip_proto = tun_read_bufs[outbound_count][9];
                                        // if (ip_proto == 1) {
                                        // const src = tunnel_mod.formatIpForLog((@as(u32, tun_read_bufs[outbound_count][12]) << 24) | (@as(u32, tun_read_bufs[outbound_count][13]) << 16) | (@as(u32, tun_read_bufs[outbound_count][14]) << 8) | tun_read_bufs[outbound_count][15]);
                                        // const dst = tunnel_mod.formatIpForLog((@as(u32, tun_read_bufs[outbound_count][16]) << 24) | (@as(u32, tun_read_bufs[outbound_count][17]) << 16) | (@as(u32, tun_read_bufs[outbound_count][18]) << 8) | tun_read_bufs[outbound_count][19]);
                                        // const icmp_type = tun_read_bufs[outbound_count][20];
                                        // const icmp_code = tun_read_bufs[outbound_count][21];
                                        // std.log.info("[ICMP-OUT] {d}.{d}.{d}.{d} -> {d}.{d}.{d}.{d} type={d} code={d} len={d}", .{ src.a, src.b, src.c, src.d, dst.a, dst.b, dst.c, dst.d, icmp_type, icmp_code, ip_len });
                                        // }
                                        // }
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
                            // Safety net: if send fails (WouldBlock), count as dropped.
                            // The sendq-based throttle should prevent this edge case.
                            if (udp_sent_count < outbound_count) {
                                var tls_send_ok = true;
                                send_helper.get().sendBlocksZeroCopy(outbound_blocks[udp_sent_count..outbound_count], send_buffer) catch |err| switch (err) {
                                    error.ConnectionClosed, error.BrokenPipe => {
                                        std.log.err("Outbound send failed, exiting data loop: {s}", .{@errorName(err)});
                                        self.disconnect_reason = .network_error;
                                        return error.ConnectionLost;
                                    },
                                    else => {
                                        tls_send_ok = false;
                                    },
                                };
                                if (tls_send_ok) {
                                    diag.pkts_out += outbound_count - udp_sent_count;
                                    for (outbound_blocks[udp_sent_count..outbound_count]) |b| diag.bytes_out += b.len;
                                } else {
                                    diag.tcp_drops_pkts += outbound_count - udp_sent_count;
                                }
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
            const now = blk: {
                var ts: std.c.timespec = undefined;
                _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
                break :blk @as(i64, @intCast(ts.sec)) * std.time.ms_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
            };

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
                } else if (loop_state.dhcp.state == .inform_sent) {
                    if (self.config.static_ip) |sip| {
                        const static_ip_be: u32 = if (sip.ipv4_address) |s|
                            if (parseIpv4(s)) |v| @byteSwap(v) else 0
                        else
                            0;
                        var inform_buf: [512]u8 = undefined;
                        const inform_size = adapter_mod.buildDhcpInform(mac, dhcp_xid, static_ip_be, &inform_buf) catch 0;
                        if (inform_size > 0) {
                            const blocks = [_][]const u8{inform_buf[0..inform_size]};
                            send_helper.get().sendBlocks(&blocks) catch {};
                            loop_state.timing.last_dhcp_time = now;
                            loop_state.dhcp_retry_count += 1;
                            std.log.info("DHCP INFORM retry #{d}", .{loop_state.dhcp_retry_count});
                        }
                    }
                }
            }

            // DHCPv4: give up after max retries with no response
            if (loop_state.dhcp_retry_count >= 5 and (loop_state.dhcp.state == .discover_sent or loop_state.dhcp.state == .inform_sent)) {
                if (loop_state.timing.last_dhcp_warn == 0 or now - loop_state.timing.last_dhcp_warn >= 5000) {
                    std.log.warn("DHCP: no response after {d} retries — server does not respond", .{loop_state.dhcp_retry_count});
                    loop_state.timing.last_dhcp_warn = now;
                }
            }

            // DHCPv6 retry — server may drop IPv6 (FilterIPv6=1); retry 3x then give up
            if (!self.ipv6_configured and self.ipv6_dhcp_sent and self.ipv6_dhcp_retry_count < 3) {
                if (now - self.last_dhcpv6_time >= 5000) {
                    if (self.dhcpv6_client) |*client| {
                        var dhcpv6_raw: [256]u8 = undefined;
                        const dv6_len = client.buildSolicit(&dhcpv6_raw) catch 0;
                        if (dv6_len > 0) {
                            var dv6_frame: [512]u8 = undefined;
                            const frame_len = adapter_mod.buildDhcpv6Frame(mac, dhcpv6_raw[0..dv6_len], &dv6_frame) catch 0;
                            if (frame_len > 0) {
                                const blocks = [_][]const u8{dv6_frame[0..frame_len]};
                                send_helper.get().sendBlocks(&blocks) catch {};
                                self.last_dhcpv6_time = now;
                                self.ipv6_dhcp_retry_count += 1;
                            }
                        }
                    }
                }
            }
            // Give up on DHCPv6 after max retries — interface already has link-local
            if (!self.ipv6_configured and self.ipv6_dhcp_sent and self.ipv6_dhcp_retry_count >= 3) {
                if (now - self.last_dhcpv6_time >= 5000) {
                    std.log.warn("DHCPv6: no Reply — server does not support IPv6", .{});
                    self.ipv6_configured = true;
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
            const iter_us: u64 = @intCast(@max(0, compat_timestamp.microTimestamp() - iter_start_us));
            if (iter_us > diag.iter_us_max) diag.iter_us_max = iter_us;
            diag.iter_us_total += iter_us;
            if (iter_us >= 10_000) diag.iter_slow_10ms += 1;
            if (iter_us >= 50_000) diag.iter_slow_50ms += 1;
            if (iter_us >= 100_000) diag.iter_slow_100ms += 1;

            if (now - diag_last_ms >= 1000) {
                // DIAG + per-connection RX: always log when data is flowing so
                // users can see real-time throughput without needing --verbose.
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
                        mbps_in,             diag.pkts_in,        mbps_out,             diag.pkts_out,
                        drain_avg,           diag.drain_max,      diag.drain_cap_hits,  diag.ssl_pending_max,
                        diag.nread_max,      diag.nwrite_max,     diag.pollout_skipped, diag.tcp_drops_pkts,
                        diag.tx_drops_delta, diag.poll_iters,     iter_avg_us,          diag.iter_us_max,
                        diag.iter_slow_10ms, diag.iter_slow_50ms, diag.iter_slow_100ms, diag.poll_us_max,
                        diag.sendq_max,      sendq_avg,           diag.write_blocked,
                    });
                    // Routing diagnostic: when download works but upload is stuck,
                    // log the default route and TUN interface state.
                    if (mbps_in > 1.0 and mbps_out < 0.5) {
                        if (adapter.getName()) |ifname| {
                            self.logRoutingDiag(ifname);
                        }
                    }
                }

                // Per-connection RX diagnostic (multi-conn only). Only fires
                // on state change so a 16-conn stress test doesn't dump 16
                // log lines/sec forever. The conditions worth flagging are:
                //   - connection just became established (or dropped)
                //   - krecv went 0 → non-zero (server started sending, our
                //     read path will need to keep up)
                //   - krecv went non-zero → 0 (the connection went silent,
                //     common in half-connection mode and the smoking gun
                //     for "the server is using a different direction")
                //   - SSL pending cleared (FIFO fully drained)
                if (self.config.verbose) {
                    if (self.conn_manager) |*cm| {
                        var idx: usize = 0;
                        while (idx < cm.count) : (idx += 1) {
                            if (cm.connections[idx]) |*conn| {
                                const krecv: u32 = conn.tls_socket.kernelRecvQueue();
                                const pending = conn.tls_socket.hasPending();
                                const cur = ConnRxLogState{
                                    .dir = @intFromEnum(conn.direction),
                                    .primary = conn.is_primary,
                                    .estab = conn.established,
                                    .krecv_nonzero = krecv > 0,
                                    .pending = pending,
                                };
                                if (!std.meta.eql(cur, conn_rx_log[idx])) {
                                    std.log.info("RX conn[{d}] dir={s} primary={} estab={} krecv={d}B pending={}", .{
                                        idx,
                                        @tagName(conn.direction),
                                        conn.is_primary,
                                        conn.established,
                                        krecv,
                                        pending,
                                    });
                                    conn_rx_log[idx] = cur;
                                }
                            }
                        }
                    }
                }

                diag = DiagStats{};
                diag_last_ms = now;
            }
        }

        std.log.info("Data channel loop ended", .{});
    }

    fn logRoutingDiag(self: *Self, ifname: []const u8) void {
        _ = self;
        _ = ifname;
        // NOTE: process.Child.init() removed in Zig 0.16; routing diag disabled.
        // To re-enable, use std.process.spawn() with an std.Io interface.
        std.log.info("[ROUTE-ROGUE] routing diagnostic disabled (Zig 0.16 compat)", .{});
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

    pub fn setDefaultRoute(self: *ClientConfigBuilder, enabled: bool) *ClientConfigBuilder {
        self.config.routing.default_route = enabled;
        return self;
    }

    pub fn setEncryption(self: *ClientConfigBuilder, enabled: bool) *ClientConfigBuilder {
        self.config.use_encrypt = enabled;
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
    try std.testing.expect(config.routing.default_route);
    try std.testing.expect(config.use_encrypt);
    try std.testing.expect(config.reconnect.enabled);
}

test "ClientConfigBuilder" {
    var builder = ClientConfigBuilder.init("10.0.0.1", "VPN");
    const config = builder.setPort(8443).setPasswordAuth("user", "pass").setDefaultRoute(true).setEncryption(true).build();
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

/// Parse an IPv6 address string into 16-byte binary representation.
/// Supports full and compressed notation (e.g., "2001:db8::1").
fn parseIpv6Address(str: []const u8, out: *[16]u8) bool {
    @memset(out, 0);

    var colon_count: usize = 0;
    var double_colon = false;
    for (str, 0..) |c, i| {
        if (c == ':') {
            colon_count += 1;
            if (i > 0 and str[i - 1] == ':') double_colon = true;
        }
    }

    var parts: [8][]const u8 = undefined;
    var part_count: usize = 0;

    if (double_colon) {
        var left_end: usize = 0;
        if (std.mem.indexOfScalar(u8, str, ':')) |first| {
            if (first > 0) {
                const left = str[0..first];
                var iter = std.mem.splitScalar(u8, left, ':');
                while (iter.next()) |p| {
                    if (p.len == 0) continue;
                    if (part_count >= 8) return false;
                    parts[part_count] = p;
                    part_count += 1;
                }
            }
            left_end = first;
        }
        var right_start: usize = left_end + 2;
        if (right_start < str.len and str[right_start] == ':') right_start += 1;

        var right_parts: [8][]const u8 = undefined;
        var right_count: usize = 0;
        if (right_start < str.len) {
            const right = str[right_start..];
            var iter = std.mem.splitScalar(u8, right, ':');
            while (iter.next()) |p| {
                if (p.len == 0) continue;
                if (right_count >= 8) return false;
                right_parts[right_count] = p;
                right_count += 1;
            }
        }

        const zeros = 8 - part_count - right_count;
        var idx: usize = 0;
        for (parts[0..part_count]) |p| {
            const val = std.fmt.parseInt(u16, p, 16) catch return false;
            out[idx * 2] = @intCast((val >> 8) & 0xFF);
            out[idx * 2 + 1] = @intCast(val & 0xFF);
            idx += 1;
        }
        idx += zeros;
        for (right_parts[0..right_count]) |p| {
            const val = std.fmt.parseInt(u16, p, 16) catch return false;
            out[idx * 2] = @intCast((val >> 8) & 0xFF);
            out[idx * 2 + 1] = @intCast(val & 0xFF);
            idx += 1;
        }
        return true;
    } else {
        var iter = std.mem.splitScalar(u8, str, ':');
        while (iter.next()) |p| {
            if (p.len == 0) continue;
            if (part_count >= 8) return false;
            parts[part_count] = p;
            part_count += 1;
        }
        if (part_count != 8) return false;
        for (parts, 0..) |p, i| {
            const val = std.fmt.parseInt(u16, p, 16) catch return false;
            out[i * 2] = @intCast((val >> 8) & 0xFF);
            out[i * 2 + 1] = @intCast(val & 0xFF);
        }
        return true;
    }
}
