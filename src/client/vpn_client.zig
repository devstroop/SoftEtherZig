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
const Io = std.Io;
const flate = std.compress.flate;

// C zlib for compression (Zig 0.15 std.compress.flate only has decompression)
const c = @cImport({
    @cInclude("zlib.h");
});

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

// Import tunnel module (data loop helpers)
const tunnel_mod = @import("../tunnel/mod.zig");

// Import DHCP parsing
const dhcp_mod = @import("../adapter/dhcp.zig");

// Import RC4 cipher for tunnel encryption
const crypto_mod = @import("../crypto/crypto.zig");
const Rc4 = crypto_mod.Rc4;

// ============================================================================
// Client Configuration
// ============================================================================

/// Authentication method for VPN connection
pub const AuthMethod = union(enum) {
    /// Password authentication (SHA-0 hashed)
    password: struct {
        username: []const u8,
        password: []const u8,
        is_hashed: bool = false,
    },
    /// Plain password authentication (for RADIUS/NT Domain)
    /// Password is sent plaintext over TLS for server-side auth
    plain_password: struct {
        username: []const u8,
        password: []const u8,
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
    max_connections: u8 = 1,
    use_compression: bool = false,
    use_encryption: bool = true,
    udp_acceleration: bool = false,
    mtu: u16 = 1486, // 1500 - 14 byte Ethernet header

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

    // Network connection (heap-allocated for stable pointers)
    tls_socket: ?*tls.TlsSocket,

    // Raw TCP stream for raw mode (when RC4 keys are provided)
    // In raw mode, tunnel data is sent over raw TCP with RC4 encryption,
    // not wrapped in TLS. This matches SoftEther's "UseFastRC4" mode.
    raw_stream: ?std.net.Stream,
    use_raw_mode: bool,

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
    subnet_mask: u32,
    gateway_ip: u32,
    gateway_mac: ?[6]u8,

    // Authentication state
    auth_credentials: ?auth_mod.ClientAuth,

    last_keepalive_sent: i64,
    last_keepalive_recv: i64,

    // RC4 tunnel encryption (if server enables UseFastRC4)
    rc4_send: ?Rc4,
    rc4_recv: ?Rc4,

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
            .raw_stream = null,
            .use_raw_mode = false,
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
            .subnet_mask = 0,
            .gateway_ip = 0,
            .gateway_mac = null,
            .auth_credentials = null,
            .last_keepalive_sent = 0,
            .last_keepalive_recv = 0,
            .rc4_send = null,
            .rc4_recv = null,
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
        if (self.tls_socket) |sock| {
            sock.close();
            // Native TLS (iOS) destroys itself in close(), OpenSSL doesn't
            // Check at comptime which implementation we're using
            const ConnectReturnType = @typeInfo(@TypeOf(tls.TlsSocket.connect)).@"fn".return_type.?;
            const PayloadType = @typeInfo(ConnectReturnType).error_union.payload;
            const is_pointer = @typeInfo(PayloadType) == .pointer;
            if (!is_pointer) {
                // OpenSSL returns value, so we heap-allocated it
                self.allocator.destroy(sock);
            }
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

        // Connect returns either a pointer (native TLS) or value (OpenSSL).
        // Handle both cases at comptime.
        const ConnectReturnType = @typeInfo(@TypeOf(tls.TlsSocket.connect)).@"fn".return_type.?;
        const PayloadType = @typeInfo(ConnectReturnType).error_union.payload;
        const is_pointer = @typeInfo(PayloadType) == .pointer;

        const sock_result = tls.TlsSocket.connect(
            self.allocator,
            self.config.server_host,
            self.config.server_port,
            tls_config,
        ) catch {
            self.disconnect_reason = .network_error;
            return ClientError.ConnectionFailed;
        };

        if (is_pointer) {
            // Native TLS returns pointer directly
            self.tls_socket = sock_result;
        } else {
            // OpenSSL returns value, need to allocate on heap
            const sock_ptr = self.allocator.create(tls.TlsSocket) catch {
                var s = sock_result;
                s.close();
                return ClientError.OutOfMemory;
            };
            sock_ptr.* = sock_result;
            self.tls_socket = sock_ptr;
        }

        self.transitionState(.authenticating);
        self.performAuthentication() catch |err| {
            std.log.err("[AUTH] performAuthentication failed with: {}", .{err});
            // Send error event through callback so iOS can see it
            if (self.event_callback) |cb| {
                cb(.{ .error_occurred = .{
                    .code = ClientError.AuthenticationFailed,
                    .message = "Authentication failed - check server logs for details",
                } }, self.event_user_data);
            }
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
        if (self.tls_socket) |sock| {
            sock.close();
            // Native TLS (iOS) destroys itself in close(), OpenSSL doesn't
            const ConnectReturnType = @typeInfo(@TypeOf(tls.TlsSocket.connect)).@"fn".return_type.?;
            const PayloadType = @typeInfo(ConnectReturnType).error_union.payload;
            const is_pointer = @typeInfo(PayloadType) == .pointer;
            if (!is_pointer) {
                self.allocator.destroy(sock);
            }
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
        const sock = self.tls_socket orelse return ClientError.ConnectionFailed;

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

        std.log.warn("[AUTH] Step 1: Uploading protocol signature to {s}...", .{host_for_http});

        // Step 1: Upload signature (WaterMark)
        softether_proto.uploadSignature(self.allocator, writer, host_for_http) catch |err| {
            std.log.err("[AUTH] Failed to upload signature: {}", .{err});
            return ClientError.AuthenticationFailed;
        };
        std.log.warn("[AUTH] Signature uploaded OK", .{});

        std.log.warn("[AUTH] Step 2: Downloading server hello...", .{});

        // Step 2: Download Hello (get server random challenge)
        var hello = softether_proto.downloadHello(self.allocator, reader) catch |err| {
            std.log.err("[AUTH] Failed to download hello: {}", .{err});
            return ClientError.AuthenticationFailed;
        };
        defer hello.deinit(self.allocator);
        std.log.warn("[AUTH] Hello received - server v{d} build {d}", .{ hello.server_ver, hello.server_build });

        std.log.warn("[AUTH] Step 3: Building auth request...", .{});

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
                        self.config.udp_acceleration,
                        self.config.use_encryption,
                        self.config.use_compression,
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
                        self.config.use_encryption,
                        self.config.use_compression,
                    ) catch return ClientError.OutOfMemory;
                }
            },
            .plain_password => |p| softether_proto.buildPlainPasswordAuth(
                self.allocator,
                self.config.hub_name,
                p.username,
                p.password,
                self.config.udp_acceleration,
                self.config.use_encryption,
                self.config.use_compression,
            ) catch return ClientError.OutOfMemory,
            .anonymous => softether_proto.buildAnonymousAuth(
                self.allocator,
                self.config.hub_name,
                self.config.udp_acceleration,
                self.config.use_encryption,
                self.config.use_compression,
            ) catch return ClientError.OutOfMemory,
            .certificate => return ClientError.AuthenticationFailed, // Not implemented yet
        };
        defer self.allocator.free(auth_data);

        std.log.warn("[AUTH] Step 4: Uploading auth ({d} bytes)...", .{auth_data.len});

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
            const current_sock = self.tls_socket orelse return ClientError.ConnectionFailed;
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
            if (self.tls_socket) |old_sock| {
                old_sock.close();
                // Native TLS (iOS) destroys itself in close(), OpenSSL doesn't
                const ConnectReturnType = @typeInfo(@TypeOf(tls.TlsSocket.connect)).@"fn".return_type.?;
                const PayloadType = @typeInfo(ConnectReturnType).error_union.payload;
                const is_pointer = @typeInfo(PayloadType) == .pointer;
                if (!is_pointer) {
                    self.allocator.destroy(old_sock);
                }
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

                // Handle both pointer and value return types
                const ConnectReturnType = @typeInfo(@TypeOf(tls.TlsSocket.connect)).@"fn".return_type.?;
                const PayloadType = @typeInfo(ConnectReturnType).error_union.payload;
                const is_pointer = @typeInfo(PayloadType) == .pointer;

                const redirect_sock_result = tls.TlsSocket.connect(
                    self.allocator,
                    try_hostname,
                    redirect_port,
                    redirect_tls_config,
                ) catch |err| {
                    std.log.warn("Failed to connect to {s}:{d}: {}", .{ try_hostname, redirect_port, err });
                    continue;
                };

                if (is_pointer) {
                    self.tls_socket = redirect_sock_result;
                } else {
                    const redirect_sock_ptr = self.allocator.create(tls.TlsSocket) catch {
                        var s = redirect_sock_result;
                        s.close();
                        continue;
                    };
                    redirect_sock_ptr.* = redirect_sock_result;
                    self.tls_socket = redirect_sock_ptr;
                }

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
                .plain_password => |p| p.username,
                .anonymous => "anonymous",
                .certificate => "certificate",
            };

            // Redo authentication with ticket
            const redirect_sock = self.tls_socket orelse return ClientError.ConnectionFailed;
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
                self.config.udp_acceleration,
                self.config.use_encryption,
                self.config.use_compression,
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

            // Determine whether to use raw TCP mode for tunnel data
            // SoftEther protocol: use_ssl_data_encryption = (use_encrypt && !use_fast_rc4)
            // - When use_ssl_data_encryption=true: Keep TLS for data (use_raw_mode=false)
            // - When use_ssl_data_encryption=false: Switch to raw TCP (use_raw_mode=true)
            const use_raw_mode = !ticket_auth_result.use_ssl_data_encryption;

            // Initialize RC4 ciphers if server requires RC4 encryption
            if (ticket_auth_result.rc4_keys) |keys| {
                std.log.info("Initializing RC4 ciphers from ticket auth", .{});
                self.rc4_send = Rc4.init(&keys.client_to_server);
                self.rc4_recv = Rc4.init(&keys.server_to_client);
            }

            // Switch to raw TCP mode if needed
            if (use_raw_mode) {
                self.raw_stream = redirect_sock.getRawStream();
                self.use_raw_mode = true;
                if (ticket_auth_result.rc4_keys != null) {
                    std.log.warn("Switched to raw TCP mode (RC4 encryption layer active)", .{});
                } else {
                    std.log.warn("Switched to raw TCP mode (no encryption)", .{});
                }
            } else {
                std.log.info("Keeping TLS for tunnel data (use_ssl_data_encryption=true)", .{});
            }

            std.log.debug("Ticket authentication successful!", .{});
            return;
        }

        // Store session key if provided
        if (auth_result.session_key) |key| {
            // Will be used for session encryption
            _ = key;
        }

        // Determine whether to use raw TCP mode for tunnel data (non-redirect case)
        // SoftEther protocol: use_ssl_data_encryption = (use_encrypt && !use_fast_rc4)
        // - When use_ssl_data_encryption=true: Keep TLS for data (use_raw_mode=false)
        // - When use_ssl_data_encryption=false: Switch to raw TCP (use_raw_mode=true)
        const use_raw_mode_auth = !auth_result.use_ssl_data_encryption;

        // Initialize RC4 ciphers if server requires RC4 encryption
        if (auth_result.rc4_keys) |keys| {
            std.log.info("Initializing RC4 ciphers from auth result", .{});
            self.rc4_send = Rc4.init(&keys.client_to_server);
            self.rc4_recv = Rc4.init(&keys.server_to_client);
        }

        // Switch to raw TCP mode if needed
        if (use_raw_mode_auth) {
            if (self.tls_socket) |tls_sock| {
                self.raw_stream = tls_sock.getRawStream();
                self.use_raw_mode = true;
                if (auth_result.rc4_keys != null) {
                    std.log.warn("Switched to raw TCP mode (RC4 encryption layer active)", .{});
                } else {
                    std.log.warn("Switched to raw TCP mode (no encryption)", .{});
                }
            }
        } else {
            std.log.info("Keeping TLS for tunnel data (use_ssl_data_encryption=true)", .{});
        }

        std.log.info("Authentication successful!", .{});
    }

    fn establishSession(self: *Self) !void {
        self.session = SessionWrapper.init(self.allocator, self.config.use_encryption);
    }

    fn configureAdapter(self: *Self) !void {
        self.adapter_ctx = AdapterWrapper.init(self.allocator);
        var ctx = &self.adapter_ctx.?;

        // In FFI mode (iOS/Android), we don't open the TUN device ourselves.
        // The platform provides packet flow via callbacks (NEPacketTunnelProvider on iOS).
        // We detect FFI mode by checking if an event callback is set.
        const is_ffi_mode = self.event_callback != null;

        if (is_ffi_mode) {
            // FFI mode: Skip opening TUN device, iOS provides packetFlow
            std.log.info("FFI mode: skipping TUN device creation (platform provides packet flow)", .{});

            // Perform DHCP to get IP address before reporting connected
            std.log.info("FFI mode: performing DHCP to obtain IP address...", .{});
            const dhcp_config = self.performDhcp() catch |err| {
                std.log.err("DHCP failed: {}", .{err});
                return ClientError.AdapterConfigurationFailed;
            };

            self.assigned_ip = dhcp_config.ip_address;
            self.subnet_mask = dhcp_config.subnet_mask;
            self.gateway_ip = dhcp_config.gateway;

            const ip = tunnel_mod.formatIpForLog(self.assigned_ip);
            const gw = tunnel_mod.formatIpForLog(self.gateway_ip);
            std.log.info("DHCP complete: IP={d}.{d}.{d}.{d}, Gateway={d}.{d}.{d}.{d}", .{
                ip.a, ip.b, ip.c, ip.d,
                gw.a, gw.b, gw.c, gw.d,
            });
        } else {
            // Standalone mode: Open TUN device ourselves
            ctx.open() catch |err| {
                // Provide helpful error message for permission issues
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

        if (!is_ffi_mode and self.config.routing.default_route and self.gateway_ip != 0) {
            // Only configure routing in standalone mode
            // Convert server_ip from little-endian (Pack protocol) to big-endian (network byte order)
            const server_ip_be = @byteSwap(self.server_ip);
            ctx.configureFullTunnel(self.gateway_ip, server_ip_be);
        }
    }

    /// Perform DHCP over the TLS tunnel to obtain IP configuration
    /// This is used in FFI mode where we need to get IP before reporting connected
    ///
    /// Architecture (matches Swift/Rust):
    /// - Non-blocking reads with short timeout
    /// - Keep-alives every 5 seconds to prevent server timeout (server times out at ~20s)
    /// - DHCP retries every 3 seconds
    /// - Total timeout of 30 seconds
    fn performDhcp(self: *Self) !dhcp_mod.DhcpConfig {
        const sock = self.tls_socket orelse return ClientError.ConnectionFailed;

        // Generate a random transaction ID
        var dhcp_xid: u32 = 0;
        std.crypto.random.bytes(std.mem.asBytes(&dhcp_xid));

        // Get or generate MAC address
        const mac: [6]u8 = if (self.adapter_ctx) |*ctx| ctx.getMac() else blk: {
            var m: [6]u8 = undefined;
            std.crypto.random.bytes(&m);
            m[0] = (m[0] | 0x02) & 0xFE; // Locally administered unicast
            break :blk m;
        };

        std.log.info("Starting DHCP (xid=0x{x:0>8}, mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2})", .{
            dhcp_xid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        });

        // Buffers
        var dhcp_buf: [512]u8 = undefined;
        var send_buf: [1024]u8 = undefined;
        var recv_buf: [8192]u8 = undefined;
        var decompress_buf: [4096]u8 = undefined; // For zlib decompression

        // SKIP DRAIN PHASE - it was causing 15+ second delays that triggered server timeout
        // TLS 1.3 NewSessionTicket messages will be processed during normal read loop
        // The server has a 15-second keep-alive timeout, and the drain was taking too long
        // because partial TLS records require waiting for all fragments to arrive
        std.log.info("Skipping TLS drain (server has 15s keep-alive, drain can take 20s+)", .{});

        // DHCP state machine
        var dhcp_state: enum { discover_sent, request_sent, configured } = .discover_sent;
        var offered_ip: u32 = 0;
        var server_id: u32 = 0;
        var final_config: ?dhcp_mod.DhcpConfig = null;

        // Send initial DHCP DISCOVER
        // NOTE: DHCP happens BEFORE RC4 encryption is established (matching Rust behavior)
        // Use sendTunnelFrameRaw to bypass RC4 encryption
        const discover_size = dhcp_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf) catch {
            return ClientError.ProtocolError;
        };
        try self.sendTunnelFrameRaw(sock, dhcp_buf[0..discover_size], &send_buf);
        std.log.info("Sent DHCP DISCOVER ({d} bytes)", .{discover_size});

        // DHCP retry/timeout settings (matching Rust behavior)
        const max_retries: u32 = 10;
        const retry_interval_ms: i64 = 3000; // Retry every 3 seconds
        const read_timeout_ms: i32 = 3000; // 3 second read timeout (same as Rust's tokio timeout)
        var retry_count: u32 = 0;
        var last_send_time = std.time.milliTimestamp();
        const deadline = last_send_time + 30000; // 30 second total timeout

        std.log.info("Starting DHCP loop (deadline in 30s)", .{});

        // NOTE: Do NOT send keep-alives during DHCP phase (matching Rust behavior)
        // The server timeout is 20 seconds, and DHCP should complete within ~10 seconds
        // Sending extra packets during DHCP may interfere with the response

        // Main DHCP loop - poll-based like Swift's NIO and Rust's tokio
        var loop_count: u32 = 0;
        while (std.time.milliTimestamp() < deadline) {
            loop_count += 1;

            // WARN level so these appear in iOS logs
            if (loop_count == 1 or loop_count % 10 == 0) {
                std.log.warn("DHCP loop #{d}, elapsed={d}ms since last send", .{
                    loop_count,
                    std.time.milliTimestamp() - last_send_time,
                });
            }

            // Check if we should stop
            if (self.should_stop) {
                return ClientError.OperationCancelled;
            }

            const now = std.time.milliTimestamp();

            // Check if we need to retry DHCP (matching Rust's 3-second timeout behavior)
            // NOTE: DHCP uses sendTunnelFrameRaw to bypass RC4 encryption
            if (now - last_send_time >= retry_interval_ms and retry_count < max_retries) {
                retry_count += 1;
                last_send_time = now;
                if (dhcp_state == .discover_sent) {
                    const size = dhcp_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf) catch continue;
                    self.sendTunnelFrameRaw(sock, dhcp_buf[0..size], &send_buf) catch {};
                    std.log.warn("DHCP timeout, retrying DISCOVER (#{d})", .{retry_count});
                } else if (dhcp_state == .request_sent) {
                    const size = dhcp_mod.buildDhcpRequest(mac, dhcp_xid, offered_ip, server_id, &dhcp_buf) catch continue;
                    self.sendTunnelFrameRaw(sock, dhcp_buf[0..size], &send_buf) catch {};
                    std.log.warn("DHCP timeout, retrying REQUEST (#{d})", .{retry_count});
                }
            }

            // Non-blocking read with 3-second timeout (matching Rust behavior)
            // This mirrors Rust's tokio::time::timeout(Duration::from_secs(3), conn.read())
            // Uses tunnelRead which handles raw mode vs TLS mode transparently
            std.log.warn("DHCP: tunnelRead({d}ms), use_raw_mode={}", .{ read_timeout_ms, self.use_raw_mode });
            const bytes_read = self.tunnelRead(&recv_buf, read_timeout_ms) catch |err| {
                std.log.warn("DHCP: tunnelRead error: {}", .{err});
                // Connection errors are fatal
                if (err == error.ConnectionClosed) {
                    std.log.err("DHCP: Server closed connection", .{});
                    return ClientError.ConnectionFailed;
                }
                // Other errors (timeout, would block) are expected - continue loop
                continue;
            };
            std.log.warn("DHCP: tunnelRead returned {d} bytes", .{bytes_read});

            // No data within timeout - this is normal, just loop back to check keepalive/retry
            if (bytes_read == 0) continue;

            std.log.info("DHCP: Received {d} bytes from tunnel", .{bytes_read});

            // DEBUG: Log first 16 bytes of received data to trace crash
            if (bytes_read >= 16) {
                std.log.err("DHCP: First 16 bytes: {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}", .{
                    recv_buf[0],  recv_buf[1],  recv_buf[2],  recv_buf[3],
                    recv_buf[4],  recv_buf[5],  recv_buf[6],  recv_buf[7],
                    recv_buf[8],  recv_buf[9],  recv_buf[10], recv_buf[11],
                    recv_buf[12], recv_buf[13], recv_buf[14], recv_buf[15],
                });
            }

            std.log.err("DHCP: About to parse tunnel frames inline...", .{});

            // NOTE: Do NOT apply RC4 decryption during DHCP - server sends raw tunnel data
            // RC4 is only used after DHCP completes (matching Rust behavior)

            // Parse tunnel frames inline to avoid iOS static storage issues
            // Process each frame directly as we parse
            var parse_pos: usize = 0;
            const tunnel_data = recv_buf[0..bytes_read];

            while (parse_pos + 4 <= tunnel_data.len) {
                const header = mem.readInt(u32, tunnel_data[parse_pos..][0..4], .big);

                if (header == protocol_tunnel_mod.KEEP_ALIVE_MAGIC) {
                    // Keep-alive packet: skip past it
                    if (parse_pos + 8 > tunnel_data.len) break;
                    const keepalive_size = mem.readInt(u32, tunnel_data[parse_pos + 4 ..][0..4], .big);
                    const total_keepalive_len = 8 + keepalive_size;
                    std.log.warn("RX Keep-alive: size={d}", .{keepalive_size});
                    if (parse_pos + total_keepalive_len > tunnel_data.len) break;
                    parse_pos += total_keepalive_len;
                    continue;
                }

                // Data block packet: num_blocks followed by [size][data] pairs
                const num_blocks = header;
                if (num_blocks == 0 or num_blocks > 512) {
                    std.log.warn("RX: Invalid num_blocks={d} at offset {d}", .{ num_blocks, parse_pos });
                    break;
                }

                std.log.info("DHCP: Parsing data block with {d} frames", .{num_blocks});
                parse_pos += 4; // Skip num_blocks header

                var frame_idx: u32 = 0;
                while (frame_idx < num_blocks) : (frame_idx += 1) {
                    if (parse_pos + 4 > tunnel_data.len) break;
                    const block_size = mem.readInt(u32, tunnel_data[parse_pos..][0..4], .big);
                    parse_pos += 4;

                    if (block_size == 0) continue;
                    if (block_size > 2048 or parse_pos + block_size > tunnel_data.len) {
                        std.log.warn("RX: Invalid block_size={d} at offset {d}", .{ block_size, parse_pos });
                        break;
                    }

                    const frame = tunnel_data[parse_pos..][0..block_size];
                    parse_pos += block_size;

                    // Skip frames that are too small
                    if (frame.len < 14) {
                        std.log.debug("DHCP: Skipping small frame len={d}", .{frame.len});
                        continue;
                    }

                    // Check for zlib compressed data and decompress if needed
                    const frame_data: []const u8 = if (isZlibCompressed(frame)) blk: {
                        const decompressed_len = decompressZlib(frame, &decompress_buf) orelse {
                            std.log.warn("DHCP: Decompression failed for frame len={d}", .{frame.len});
                            continue;
                        };
                        std.log.info("DHCP: Decompressed {d} -> {d} bytes", .{ frame.len, decompressed_len });
                        break :blk decompress_buf[0..decompressed_len];
                    } else frame;

                    // Log frame info for debugging
                    const ethertype = (@as(u16, frame_data[12]) << 8) | frame_data[13];
                    std.log.info("DHCP: Frame len={d}, ethertype=0x{x:0>4}", .{ frame_data.len, ethertype });

                    // Check for DHCP response (IPv4 UDP port 68)
                    const response = dhcp_mod.parseDhcpResponse(frame_data, dhcp_xid) catch |err| {
                        std.log.debug("DHCP: Parse error: {}", .{err});
                        continue;
                    };
                    if (response) |resp| {
                        std.log.info("DHCP: Got response type={}", .{resp.msg_type});
                        if (resp.msg_type == .offer and dhcp_state == .discover_sent) {
                            // Got OFFER, send REQUEST
                            offered_ip = resp.config.ip_address;
                            server_id = resp.config.server_id;

                            const ip = tunnel_mod.formatIpForLog(offered_ip);
                            std.log.info("DHCP OFFER received: IP={d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });

                            const req_size = dhcp_mod.buildDhcpRequest(mac, dhcp_xid, offered_ip, server_id, &dhcp_buf) catch continue;
                            self.sendTunnelFrameRaw(sock, dhcp_buf[0..req_size], &send_buf) catch {};
                            dhcp_state = .request_sent;
                            retry_count = 0;
                            last_send_time = std.time.milliTimestamp();
                            std.log.info("Sent DHCP REQUEST", .{});
                        } else if (resp.msg_type == .ack and dhcp_state == .request_sent) {
                            // Got ACK - done!
                            std.log.info("DHCP ACK received - configuration complete", .{});
                            final_config = resp.config;
                            dhcp_state = .configured;
                            break;
                        }
                    }
                }

                if (dhcp_state == .configured) break;
            }

            // Check if DHCP completed - break from main loop
            if (dhcp_state == .configured) break;
        }

        if (final_config) |cfg| {
            return cfg;
        }

        std.log.err("DHCP timeout - no response received after {d} retries", .{retry_count});
        return ClientError.OperationCancelled;
    }

    /// Check if data is zlib compressed (starts with zlib magic header)
    /// Common zlib headers: 0x78 0x01 (no compression), 0x78 0x9C (default), 0x78 0xDA (best)
    fn isZlibCompressed(data: []const u8) bool {
        if (data.len < 2) return false;
        return data[0] == 0x78 and (data[1] == 0x01 or data[1] == 0x5E or data[1] == 0x9C or data[1] == 0xDA);
    }

    /// Decompress zlib data into output buffer using Zig 0.15 std.compress.flate
    /// Returns decompressed length, or null on error
    fn decompressZlib(compressed: []const u8, output: []u8) ?usize {
        // Create input reader from compressed data
        var input_reader: Io.Reader = .fixed(compressed);

        // Create output writer to fixed buffer
        var output_writer: Io.Writer = .fixed(output);

        // Create decompressor - need a window buffer for history
        var window_buf: [flate.max_window_len]u8 = undefined;
        var decompress: flate.Decompress = .init(&input_reader, .zlib, &window_buf);

        // Stream decompressed data to output
        const decompressed_len = decompress.reader.streamRemaining(&output_writer) catch |err| {
            std.log.debug("Zlib decompression error: {}", .{err});
            return null;
        };

        return decompressed_len;
    }

    /// Compress data using C zlib into output buffer
    /// Returns compressed length, or null on error
    /// Uses Z_DEFAULT_COMPRESSION (level 6) for good balance of speed/size
    fn compressZlib(input: []const u8, output: []u8) ?usize {
        // Use C zlib compress2() function
        // Zig 0.15 std.compress.flate only has decompression, so we use C zlib
        var dest_len: c.uLongf = @intCast(output.len);
        const src_ptr: [*c]const u8 = @ptrCast(input.ptr);
        const dest_ptr: [*c]u8 = @ptrCast(output.ptr);

        const result = c.compress2(
            dest_ptr,
            &dest_len,
            src_ptr,
            @intCast(input.len),
            c.Z_DEFAULT_COMPRESSION, // level 6 - good balance
        );

        if (result != c.Z_OK) {
            std.log.debug("Zlib compression error: {d}", .{result});
            return null;
        }

        return @intCast(dest_len);
    }

    /// Read from the tunnel (raw TCP in raw mode, TLS otherwise)
    /// This handles the mode switch transparently for DHCP and tunnel data.
    fn tunnelRead(self: *Self, buffer: []u8, timeout_ms: i32) !usize {
        if (self.use_raw_mode) {
            // Raw TCP mode - read directly from TCP stream
            const stream = self.raw_stream orelse return error.NotConnected;

            // Poll for data with timeout
            var poll_fds = [_]std.posix.pollfd{
                .{ .fd = stream.handle, .events = std.posix.POLL.IN, .revents = 0 },
            };

            const poll_timeout = @min(timeout_ms, 500);
            const poll_result = std.posix.poll(&poll_fds, @intCast(poll_timeout)) catch |err| {
                std.log.warn("Raw tunnelRead: poll error: {}", .{err});
                return 0;
            };

            if (poll_result == 0) {
                return 0; // Timeout, no data
            }

            // Check for connection close
            if ((poll_fds[0].revents & std.posix.POLL.HUP) != 0 and
                (poll_fds[0].revents & std.posix.POLL.IN) == 0)
            {
                return error.ConnectionClosed;
            }

            // Read data
            const n = stream.read(buffer) catch |err| {
                std.log.warn("Raw tunnelRead: read error: {}", .{err});
                return error.ReadError;
            };

            std.log.warn("Raw tunnelRead: {d} bytes", .{n});
            return n;
        } else {
            // TLS mode - use TLS socket with timeout
            const sock = self.tls_socket orelse return error.NotConnected;
            return sock.readWithTimeout(buffer, timeout_ms);
        }
    }

    /// Write to the tunnel (raw TCP in raw mode, TLS otherwise)
    fn tunnelWrite(self: *Self, data: []const u8) !usize {
        if (self.use_raw_mode) {
            // Raw TCP mode - write directly to TCP stream
            const stream = self.raw_stream orelse return error.NotConnected;
            const n = stream.write(data) catch |err| {
                std.log.warn("Raw tunnelWrite: write error: {}", .{err});
                return error.WriteError;
            };
            std.log.warn("Raw tunnelWrite: {d} bytes", .{n});
            return n;
        } else {
            // TLS mode - use TLS socket
            const sock = self.tls_socket orelse return error.NotConnected;
            return sock.write(data);
        }
    }

    /// Send a single Ethernet frame over the SoftEther tunnel
    /// NO compression or RC4 encryption (for DHCP phase)
    /// DHCP happens before the tunnel is fully established, matching Swift's approach
    /// which sends use_compress=false during auth.
    fn sendTunnelFrameRaw(self: *Self, sock: *tls.TlsSocket, frame: []const u8, buf: []u8) !void {
        _ = sock; // Using self.tunnelWrite instead
        // SoftEther tunnel format:
        // [4 bytes] num_blocks (big-endian) = 1
        // [4 bytes] block_size (big-endian)
        // [N bytes] block_data (raw Ethernet frame, no compression during DHCP)

        // Debug: Log outgoing frame details
        if (frame.len >= 14) {
            const dst_mac = frame[0..6];
            const src_mac = frame[6..12];
            const ethertype = (@as(u16, frame[12]) << 8) | frame[13];
            std.log.warn("TX Frame (raw DHCP): {d} bytes, dst={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, src={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, ethertype=0x{x:0>4}", .{
                frame.len,
                dst_mac[0],
                dst_mac[1],
                dst_mac[2],
                dst_mac[3],
                dst_mac[4],
                dst_mac[5],
                src_mac[0],
                src_mac[1],
                src_mac[2],
                src_mac[3],
                src_mac[4],
                src_mac[5],
                ethertype,
            });
        }

        // NO compression for DHCP phase - send raw frame like Swift does
        // (Swift hardcodes use_compress=false in auth, we match that behavior for DHCP)
        const total_len = 4 + 4 + frame.len;
        if (total_len > buf.len) return error.BufferTooSmall;

        mem.writeInt(u32, buf[0..4], 1, .big); // num_blocks = 1
        mem.writeInt(u32, buf[4..8], @intCast(frame.len), .big); // block_size
        @memcpy(buf[8..][0..frame.len], frame);

        // NOTE: No RC4 encryption or compression for DHCP phase
        std.log.warn("TX Tunnel (raw DHCP, no compress/RC4): {d} bytes", .{total_len});

        // Use tunnelWrite to handle raw mode vs TLS mode transparently
        _ = try self.tunnelWrite(buf[0..total_len]);
    }

    fn sendTunnelFrame(self: *Self, sock: *tls.TlsSocket, frame: []const u8, buf: []u8) !void {
        // SoftEther tunnel format:
        // [4 bytes] num_blocks (big-endian) = 1
        // [4 bytes] block_size (big-endian)
        // [N bytes] block_data (Ethernet frame, possibly zlib compressed)

        // Debug: Log outgoing frame details
        if (frame.len >= 14) {
            const dst_mac = frame[0..6];
            const src_mac = frame[6..12];
            const ethertype = (@as(u16, frame[12]) << 8) | frame[13];
            std.log.warn("TX Frame: {d} bytes, dst={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, src={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, ethertype=0x{x:0>4}", .{
                frame.len,
                dst_mac[0],
                dst_mac[1],
                dst_mac[2],
                dst_mac[3],
                dst_mac[4],
                dst_mac[5],
                src_mac[0],
                src_mac[1],
                src_mac[2],
                src_mac[3],
                src_mac[4],
                src_mac[5],
                ethertype,
            });
            // If IPv4, show more details
            if (ethertype == 0x0800 and frame.len >= 34) {
                const ip_proto = frame[23];
                const src_ip = frame[26..30];
                const dst_ip = frame[30..34];
                std.log.warn("  IPv4: proto={d}, src={d}.{d}.{d}.{d}, dst={d}.{d}.{d}.{d}", .{
                    ip_proto,
                    src_ip[0],
                    src_ip[1],
                    src_ip[2],
                    src_ip[3],
                    dst_ip[0],
                    dst_ip[1],
                    dst_ip[2],
                    dst_ip[3],
                });
                // If UDP, show ports
                if (ip_proto == 17 and frame.len >= 42) {
                    const src_port = (@as(u16, frame[34]) << 8) | frame[35];
                    const dst_port = (@as(u16, frame[36]) << 8) | frame[37];
                    std.log.warn("  UDP: src_port={d}, dst_port={d}", .{ src_port, dst_port });
                }
            }
        }

        // Compress the frame if compression is enabled
        // CRITICAL: When we send use_compress=1 in auth, server expects ALL data to be compressed
        const data_to_send: []const u8 = if (self.config.use_compression) blk: {
            // Compress into buffer starting at offset 8 (leaving room for headers)
            const max_compressed = buf.len - 8;
            if (max_compressed < frame.len) {
                // Buffer too small, send uncompressed
                std.log.warn("Compression buffer too small, sending uncompressed", .{});
                break :blk frame;
            }
            const compressed_len = compressZlib(frame, buf[8..][0..max_compressed]) orelse {
                std.log.warn("Compression failed, sending uncompressed", .{});
                break :blk frame;
            };
            std.log.debug("Compressed frame: {d} -> {d} bytes", .{ frame.len, compressed_len });
            break :blk buf[8..][0..compressed_len];
        } else frame;

        const total_len = 4 + 4 + data_to_send.len;
        if (total_len > buf.len) return error.BufferTooSmall;

        mem.writeInt(u32, buf[0..4], 1, .big); // num_blocks = 1
        mem.writeInt(u32, buf[4..8], @intCast(data_to_send.len), .big); // block_size

        // If we didn't compress, we need to copy the frame data
        // If we did compress, data is already in buf[8..] so no copy needed
        if (!self.config.use_compression or data_to_send.ptr != buf[8..].ptr) {
            @memcpy(buf[8..][0..data_to_send.len], data_to_send);
        }

        // Apply RC4 encryption if enabled (entire tunnel packet including headers)
        if (self.rc4_send) |*cipher| {
            cipher.process(buf[0..total_len]);
            std.log.debug("TX: Applied RC4 encryption to {d} bytes", .{total_len});
        }

        // Debug: Log tunnel header being sent
        std.log.warn("TX Tunnel: total={d} bytes, header=[{x:0>2} {x:0>2} {x:0>2} {x:0>2}][{x:0>2} {x:0>2} {x:0>2} {x:0>2}] (num_blocks=1, block_size={d})", .{
            total_len,
            buf[0],
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
            data_to_send.len,
        });

        // Use tunnelWrite to handle raw mode vs TLS mode transparently
        _ = sock; // Unused - using tunnelWrite instead
        _ = try self.tunnelWrite(buf[0..total_len]);
    }

    /// Send a keep-alive packet to keep the connection alive
    /// SoftEther servers timeout connections after ~20 seconds without activity
    fn sendKeepalive(self: *Self, sock: *tls.TlsSocket, buf: []u8) !void {
        _ = sock; // Unused - using tunnelWrite instead
        // SoftEther keep-alive format:
        // [4 bytes] KEEP_ALIVE_MAGIC (0xFFFFFFFF) big-endian
        // [4 bytes] size (32) big-endian
        // [32 bytes] random padding
        if (buf.len < 40) return error.BufferTooSmall;

        mem.writeInt(u32, buf[0..4], protocol_tunnel_mod.KEEP_ALIVE_MAGIC, .big);
        mem.writeInt(u32, buf[4..8], 32, .big);
        std.crypto.random.bytes(buf[8..40]);

        // Apply RC4 encryption if enabled
        if (self.rc4_send) |*cipher| {
            cipher.process(buf[0..40]);
        }

        _ = try self.tunnelWrite(buf[0..40]);
        std.log.debug("Sent keep-alive packet", .{});
    }

    /// Parse tunnel frames from raw data - handles multiple concatenated packets
    /// SoftEther can send keep-alives and data frames back-to-back in a single TLS read.
    /// Format: [packet1][packet2]... where each packet is either:
    ///   - Keep-alive: [4B magic=0xFFFFFFFF][4B size][N bytes padding]
    ///   - Data block: [4B num_blocks][4B size1][data1][4B size2][data2]...
    fn parseTunnelFramesMulti(self: *Self, data: []const u8) ![]const []const u8 {
        _ = self;

        // Debug: Log raw incoming data header
        if (data.len >= 8) {
            std.log.warn("RX Tunnel: {d} bytes, header=[{x:0>2} {x:0>2} {x:0>2} {x:0>2}][{x:0>2} {x:0>2} {x:0>2} {x:0>2}]", .{
                data.len,
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7],
            });
        }

        const max_frames = 64;
        // Use simple static storage - iOS doesn't support threadlocal in Network Extensions
        const S = struct {
            var frame_ptrs: [max_frames][]const u8 = .{&[_]u8{}} ** max_frames;
        };
        var frame_count: usize = 0;
        var pos: usize = 0;

        // Reset frame_ptrs to empty slices before use
        for (&S.frame_ptrs) |*ptr| {
            ptr.* = &[_]u8{};
        }

        std.log.warn("parseTunnelFramesMulti: entering loop, data.len={d}", .{data.len});

        while (pos + 8 <= data.len and frame_count < max_frames) {
            std.log.warn("parseTunnelFramesMulti: loop pos={d}, remaining={d}", .{ pos, data.len - pos });
            const header = mem.readInt(u32, data[pos..][0..4], .big);
            const second = mem.readInt(u32, data[pos + 4 ..][0..4], .big);
            std.log.warn("parseTunnelFramesMulti: header=0x{x:0>8}, second=0x{x:0>8}", .{ header, second });

            if (header == protocol_tunnel_mod.KEEP_ALIVE_MAGIC) {
                // Keep-alive packet: skip past it
                const keepalive_size = second;
                const total_keepalive_len = 8 + keepalive_size;
                std.log.warn("RX Keep-alive: size={d}", .{keepalive_size});
                if (pos + total_keepalive_len > data.len) break;
                pos += total_keepalive_len;
                continue;
            }

            // Data block packet: num_blocks followed by [size][data] pairs
            const num_blocks = header;
            if (num_blocks == 0 or num_blocks > 512) {
                std.log.warn("RX: Invalid num_blocks={d} at offset {d}", .{ num_blocks, pos });
                break;
            }

            std.log.warn("RX Data block: num_blocks={d}", .{num_blocks});
            pos += 4; // Skip num_blocks header
            var i: u32 = 0;
            while (i < num_blocks and frame_count < max_frames) : (i += 1) {
                if (pos + 4 > data.len) break;
                const block_size = mem.readInt(u32, data[pos..][0..4], .big);
                pos += 4;

                if (block_size == 0) continue;
                if (block_size > 2048 or pos + block_size > data.len) {
                    std.log.warn("RX: Invalid block_size={d} at offset {d}", .{ block_size, pos });
                    break;
                }

                // Debug: Log received frame details
                const frame = data[pos..][0..block_size];
                if (frame.len >= 14) {
                    const dst_mac = frame[0..6];
                    const src_mac = frame[6..12];
                    const ethertype = (@as(u16, frame[12]) << 8) | frame[13];
                    std.log.warn("RX Frame #{d}: {d} bytes, dst={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, src={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}, ethertype=0x{x:0>4}", .{
                        i,
                        frame.len,
                        dst_mac[0],
                        dst_mac[1],
                        dst_mac[2],
                        dst_mac[3],
                        dst_mac[4],
                        dst_mac[5],
                        src_mac[0],
                        src_mac[1],
                        src_mac[2],
                        src_mac[3],
                        src_mac[4],
                        src_mac[5],
                        ethertype,
                    });
                    // If IPv4, show more details
                    if (ethertype == 0x0800 and frame.len >= 34) {
                        const ip_proto = frame[23];
                        const src_ip = frame[26..30];
                        const dst_ip = frame[30..34];
                        std.log.warn("  IPv4: proto={d}, src={d}.{d}.{d}.{d}, dst={d}.{d}.{d}.{d}", .{
                            ip_proto,
                            src_ip[0],
                            src_ip[1],
                            src_ip[2],
                            src_ip[3],
                            dst_ip[0],
                            dst_ip[1],
                            dst_ip[2],
                            dst_ip[3],
                        });
                        // If UDP, show ports
                        if (ip_proto == 17 and frame.len >= 42) {
                            const src_port = (@as(u16, frame[34]) << 8) | frame[35];
                            const dst_port = (@as(u16, frame[36]) << 8) | frame[37];
                            std.log.warn("  UDP: src_port={d}, dst_port={d}", .{ src_port, dst_port });
                        }
                    }
                } else {
                    std.log.warn("RX Frame #{d}: {d} bytes (too small for ethernet)", .{ i, frame.len });
                }

                S.frame_ptrs[frame_count] = frame;
                frame_count += 1;
                pos += block_size;
            }
        }

        return S.frame_ptrs[0..frame_count];
    }

    /// Parse tunnel frames from raw data (single packet only - legacy)
    /// Returns slices into the input buffer for each frame
    fn parseTunnelFrames(self: *Self, data: []const u8) ![]const []const u8 {
        _ = self;
        if (data.len < 4) return &[_][]const u8{};

        const num_blocks = mem.readInt(u32, data[0..4], .big);

        // Handle keep-alive (magic number 0xFFFFFFFF)
        if (num_blocks == protocol_tunnel_mod.KEEP_ALIVE_MAGIC) {
            // Just skip keep-alive packets
            return &[_][]const u8{};
        }

        if (num_blocks == 0 or num_blocks > 512) return &[_][]const u8{};

        // Static buffer for frame pointers (max 64 frames per call)
        // Note: iOS doesn't support threadlocal in Network Extensions
        const max_frames = 64;
        const S = struct {
            var frame_ptrs: [max_frames][]const u8 = .{&[_]u8{}} ** max_frames;
        };

        // Reset frame_ptrs before use
        for (&S.frame_ptrs) |*ptr| {
            ptr.* = &[_]u8{};
        }

        var offset: usize = 4;
        var frame_count: usize = 0;

        var i: u32 = 0;
        while (i < num_blocks and frame_count < max_frames) : (i += 1) {
            if (offset + 4 > data.len) break;
            const block_size = mem.readInt(u32, data[offset..][0..4], .big);
            offset += 4;

            if (block_size == 0) continue;
            if (block_size > 2048 or offset + block_size > data.len) break;

            S.frame_ptrs[frame_count] = data[offset..][0..block_size];
            frame_count += 1;
            offset += block_size;
        }

        return S.frame_ptrs[0..frame_count];
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

    /// Send a packet to the VPN tunnel
    /// In FFI mode (iOS/Android), the packet is an Ethernet frame from the platform
    /// The frame is wrapped in SoftEther tunnel format and sent over the connection
    pub fn sendPacket(self: *Self, data: []const u8) ClientError!void {
        if (!self.isConnected()) return ClientError.NotConnected;

        // Validate packet has at least Ethernet header
        if (data.len < 14) return ClientError.InvalidParameter;

        // Use stack buffer for tunnel framing
        var buf: [2048]u8 = undefined;
        const sock = self.tls_socket orelse return ClientError.NotConnected;

        // Send as raw tunnel frame (DHCP mode) or compressed depending on config
        // Currently matching DHCP behavior (no compression) for simplicity
        self.sendTunnelFrameRaw(sock, data, &buf) catch |err| {
            std.log.warn("sendPacket failed: {}", .{err});
            return ClientError.OperationCancelled;
        };

        self.stats.recordSent(data.len);
    }

    /// Poll for incoming packets from the VPN tunnel
    /// Returns the number of Ethernet frames received (0 if none ready)
    /// Frames are written to frame_ptrs slice with lengths in frame_lens
    /// This is non-blocking with a short poll timeout
    pub fn pollReceive(
        self: *Self,
        frame_ptrs: [][*]u8,
        frame_lens: []usize,
        frame_buf: []u8,
    ) ClientError!usize {
        if (!self.isConnected()) return ClientError.NotConnected;

        // Read from tunnel with short timeout
        var recv_buf: [8192]u8 = undefined;
        const bytes_read = self.tunnelRead(&recv_buf, 10) catch |err| {
            if (err == error.ConnectionClosed) {
                return ClientError.ConnectionLost;
            }
            return 0; // Timeout or temporary error
        };

        if (bytes_read == 0) {
            return 0;
        }

        // Debug: log received data
        std.log.debug("pollReceive: got {d} bytes from tunnel", .{bytes_read});

        // Parse tunnel frames
        var pos: usize = 0;
        var frame_count: usize = 0;
        var buf_offset: usize = 0;
        const max_frames = @min(frame_ptrs.len, frame_lens.len);

        while (pos + 8 <= bytes_read and frame_count < max_frames) {
            const header = mem.readInt(u32, recv_buf[pos..][0..4], .big);
            const second = mem.readInt(u32, recv_buf[pos + 4 ..][0..4], .big);

            if (header == protocol_tunnel_mod.KEEP_ALIVE_MAGIC) {
                // Keep-alive packet - skip
                const keepalive_size = second;
                pos += 8 + keepalive_size;
                std.log.debug("pollReceive: skip keep-alive ({d} bytes)", .{keepalive_size});
                continue;
            }

            // Data block: header = num_blocks
            const num_blocks = header;
            pos += 4; // Skip num_blocks

            var block_idx: u32 = 0;
            while (block_idx < num_blocks and pos + 4 <= bytes_read and frame_count < max_frames) : (block_idx += 1) {
                const block_size = mem.readInt(u32, recv_buf[pos..][0..4], .big);
                pos += 4;

                if (pos + block_size > bytes_read) {
                    break; // Incomplete frame
                }

                const frame = recv_buf[pos..][0..block_size];
                pos += block_size;

                // Skip non-Ethernet or too-small frames
                if (block_size < 14) {
                    continue;
                }

                // Copy frame to output buffer
                if (buf_offset + block_size > frame_buf.len) {
                    break; // Buffer full
                }

                @memcpy(frame_buf[buf_offset..][0..block_size], frame);
                frame_ptrs[frame_count] = @ptrCast(&frame_buf[buf_offset]);
                frame_lens[frame_count] = block_size;
                frame_count += 1;
                buf_offset += block_size;

                // Log the received frame
                const ethertype = (@as(u16, frame[12]) << 8) | frame[13];
                std.log.debug("pollReceive: frame {d}: {d} bytes, ethertype=0x{x:0>4}", .{
                    frame_count,
                    block_size,
                    ethertype,
                });
            }
        }

        self.stats.recordReceived(bytes_read);
        return frame_count;
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

        const sock = self.tls_socket orelse return ClientError.NotConnected;
        var adapter = &(self.adapter_ctx orelse return ClientError.NotConnected);

        std.log.debug("Starting data channel loop...", .{});

        // Get file descriptors for poll()
        const tls_fd = sock.getFd();
        const tun_fd = blk: {
            if (adapter.real_adapter) |*real| {
                if (real.device) |dev| {
                    const fd = dev.getFd();
                    if (fd < 0) return ClientError.AdapterConfigurationFailed;
                    break :blk fd;
                }
            }
            return ClientError.AdapterConfigurationFailed;
        };

        std.log.debug("Using poll() for concurrent I/O: TLS fd={d}, TUN fd={d}", .{ tls_fd, tun_fd });

        // Create tunnel connection (from protocol module) with compression if enabled
        var tunnel = protocol_tunnel_mod.TunnelConnection.initWithCompression(
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
            self.config.use_compression,
        );

        std.log.info("Tunnel initialized with compression={}", .{self.config.use_compression});

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

        // Receive buffers (zero-copy: reused each iteration)
        var recv_scratch: [512 * 1600]u8 = undefined;
        var recv_slices: [512][]u8 = undefined;
        var decompress_buf: [4096]u8 = undefined; // For zlib decompression

        // Outbound packet buffer
        var tun_read_buf: [2048]u8 = undefined;
        var outbound_eth_buf: [1600]u8 = undefined;

        // Packet buffer for ARP/GARP (small, reused)
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
                loop_state.dhcp.state = .discover_sent;
                loop_state.timing.last_dhcp_time = std.time.milliTimestamp();
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

        // Cache the configured state check
        var is_configured = false;

        // Main packet loop
        while (!self.should_stop and self.isConnected()) {
            // Poll both TLS and TUN with 1ms timeout for low latency
            poll_fds[0].revents = 0;
            poll_fds[1].revents = 0;
            _ = std.posix.poll(&poll_fds, 1) catch 0;
            const tls_readable = (poll_fds[0].revents & std.posix.POLL.IN) != 0;
            const tun_readable = (poll_fds[POLL_TUN].revents & std.posix.POLL.IN) != 0;

            // ============================================================
            // FAST PATH: Data plane (process packets first for low latency)
            // ============================================================

            // INBOUND: Receive packets from VPN server (highest priority)
            if (tls_readable) {
                const recv_count = tunnel.receiveBlocksBatch(&recv_slices, &recv_scratch) catch |err| {
                    if (self.should_stop) break;
                    if (err == error.ConnectionClosed) {
                        std.log.info("Server closed connection", .{});
                        break;
                    }
                    continue;
                };

                for (recv_slices[0..recv_count]) |block_data| {
                    if (block_data.len < 2) continue;

                    // Check for zlib compressed data and decompress if needed
                    const frame_data: []const u8 = if (isZlibCompressed(block_data)) blk: {
                        const decompressed_len = decompressZlib(block_data, &decompress_buf) orelse continue;
                        break :blk decompress_buf[0..decompressed_len];
                    } else block_data;

                    if (frame_data.len <= 14) continue;

                    // Fast EtherType dispatch
                    const ethertype = (@as(u16, frame_data[12]) << 8) | frame_data[13];

                    if (is_configured) {
                        // Configured: fast path for IP packets
                        if (ethertype == 0x0800 or ethertype == 0x86DD) {
                            // IPv4/IPv6 - direct to TUN (zero-copy slice)
                            if (adapter.real_adapter) |*real| {
                                if (real.device) |dev| {
                                    _ = dev.write(frame_data[14..]) catch {};
                                }
                            }
                        } else if (ethertype == 0x0806) {
                            // ARP
                            if (tunnel_mod.getArpOperation(frame_data)) |arp_op| {
                                if (arp_op == 2) {
                                    loop_state.processArpReply(frame_data);
                                    self.gateway_mac = loop_state.gateway_mac;
                                } else if (arp_op == 1) {
                                    loop_state.processArpRequest(frame_data);
                                }
                            }
                        }
                    } else {
                        // Not configured: check for DHCP
                        const maybe_response = adapter_mod.parseDhcpResponse(frame_data, dhcp_xid) catch null;
                        if (maybe_response) |response| {
                            if (response.msg_type == .offer and loop_state.dhcp.state == .discover_sent) {
                                const ip = tunnel_mod.formatIpForLog(response.config.ip_address);
                                std.log.info("DHCP OFFER received: IP={d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });

                                var req_buf: [512]u8 = undefined;
                                const req_size = adapter_mod.buildDhcpRequest(mac, dhcp_xid, response.config.ip_address, response.config.server_id, &req_buf) catch 0;
                                if (req_size > 0) {
                                    const blocks = [_][]const u8{req_buf[0..req_size]};
                                    tunnel.sendBlocks(&blocks) catch {};
                                    loop_state.dhcp.state = .request_sent;
                                    std.log.info("Sent DHCP REQUEST", .{});
                                }
                            } else if (response.msg_type == .ack and loop_state.dhcp.state == .request_sent) {
                                std.log.info("DHCP ACK received!", .{});
                                loop_state.configure(response.config.ip_address, response.config.gateway);
                                loop_state.dhcp.state = .configured;
                                is_configured = true;
                                self.assigned_ip = loop_state.our_ip;
                                self.gateway_ip = loop_state.our_gateway;

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
            }

            // OUTBOUND: Read from TUN and send to VPN (simple path)
            if (is_configured and tun_readable) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        // Read one packet from TUN
                        if (dev.read(&tun_read_buf)) |maybe_len| {
                            if (maybe_len) |ip_len| {
                                if (ip_len > 0 and ip_len <= 1500) {
                                    // Wrap in Ethernet and send
                                    if (tunnel_mod.wrapIpInEthernet(tun_read_buf[0..ip_len], loop_state.gateway_mac, mac, &outbound_eth_buf)) |eth_frame| {
                                        const blocks = [_][]const u8{eth_frame};
                                        tunnel.sendBlocks(&blocks) catch {};
                                        self.stats.recordSent(eth_frame.len);
                                    }
                                }
                            }
                        } else |_| {}
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
                    tunnel.sendBlocks(&blocks) catch {};
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
                    tunnel.sendBlocks(&blocks) catch {};
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
                    tunnel.sendBlocks(&blocks) catch {};
                    const ip = tunnel_mod.formatIpForLog(loop_state.our_gateway);
                    std.log.debug("Sent ARP Request for gateway {d}.{d}.{d}.{d}", .{ ip.a, ip.b, ip.c, ip.d });
                }
            }

            // Periodic GARP (every 10s)
            if (is_configured and loop_state.timing.shouldSendGarp(now, garp_interval)) {
                const garp_size = adapter_mod.buildGratuitousArp(mac, loop_state.our_ip, &arp_buf) catch 0;
                if (garp_size > 0) {
                    const blocks = [_][]const u8{arp_buf[0..garp_size]};
                    tunnel.sendBlocks(&blocks) catch {};
                    loop_state.timing.last_garp_time = now;
                }
            }

            // SoftEther keepalive (every 5s)
            if (loop_state.timing.shouldSendKeepalive(now, keepalive_interval)) {
                tunnel.sendKeepalive() catch |err| {
                    std.log.warn("Failed to send keepalive: {}", .{err});
                };
                std.log.debug("Sent keepalive", .{});
                loop_state.timing.last_keepalive = now;
            }

            // DHCP retry
            if (loop_state.dhcp.state == .discover_sent and loop_state.dhcp_retry_count < 5) {
                if (loop_state.timing.shouldRetryDhcp(now, 3000)) {
                    var dhcp_buf: [512]u8 = undefined;
                    const dhcp_size = adapter_mod.buildDhcpDiscover(mac, dhcp_xid, &dhcp_buf) catch 0;
                    if (dhcp_size > 0) {
                        const blocks = [_][]const u8{dhcp_buf[0..dhcp_size]};
                        tunnel.sendBlocks(&blocks) catch {};
                        loop_state.timing.last_dhcp_time = now;
                        loop_state.dhcp_retry_count += 1;
                        std.log.debug("DHCP DISCOVER retry #{d}", .{loop_state.dhcp_retry_count});
                    }
                }
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
