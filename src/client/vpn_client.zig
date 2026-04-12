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
    gateway_ip: u32,
    gateway_mac: ?[6]u8,

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
            .gateway_ip = 0,
            .gateway_mac = null,
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
                    ) catch return ClientError.OutOfMemory;
                }
            },
            .anonymous => softether_proto.buildAnonymousAuth(
                self.allocator,
                self.config.hub_name,
                self.config.udp_acceleration,
                bulk_keys_ptr,
            ) catch return ClientError.OutOfMemory,
            .certificate => |cert| softether_proto.buildCertificateAuth(
                self.allocator,
                cert.cert_data,
                cert.key_data,
                self.config.hub_name,
                &hello.random,
                self.config.udp_acceleration,
                bulk_keys_ptr,
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
                self.config.udp_acceleration,
                bulk_keys_ptr,
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

            // Store session key from ticket auth for session encryption
            if (ticket_auth_result.session_key) |key| {
                self.auth_session_key = key;
                self.auth_hello_random = redirect_hello.random;
            }

            std.log.debug("Ticket authentication successful!", .{});
            return;
        }

        // Store session key and server challenge for session encryption
        if (auth_result.session_key) |key| {
            self.auth_session_key = key;
            self.auth_hello_random = hello.random;
        }

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

    fn establishSession(self: *Self) !void {
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

    /// Run the data channel packet loop
    /// This is the main loop that processes packets between TLS and TUN
    /// Returns when should_stop is set or connection is lost
    pub fn runDataLoop(self: *Self) !void {
        if (!self.isConnected()) return ClientError.NotConnected;

        @atomicStore(bool, &self.data_loop_running, true, .release);
        defer @atomicStore(bool, &self.data_loop_running, false, .release);

        const sock = &(self.tls_socket orelse return ClientError.NotConnected);
        var adapter = &(self.adapter_ctx orelse return ClientError.NotConnected);

        std.log.debug("Starting data channel loop...", .{});

        // Get file descriptors / handles for polling
        const tls_fd = sock.getFd();
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

        if (builtin.os.tag != .windows) {
            std.log.debug("Using poll() for concurrent I/O: TLS fd={d}, TUN fd={d}", .{ tls_fd, tun_fd });
        } else {
            std.log.debug("Using Windows event-based I/O for data loop", .{});
        }

        // Create tunnel connection (from protocol module)
        var tunnel = protocol_tunnel_mod.TunnelConnection.init(
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

        // Outbound packet buffers — multiple buffers for batching TUN reads
        var tun_read_bufs: [16][2048]u8 = undefined;
        var outbound_eth_bufs: [16][1600]u8 = undefined;

        // Packet buffer for ARP/GARP (small, reused)
        var arp_buf: [64]u8 = undefined;

        // Pre-allocated send buffer for zero-copy outbound path (avoids per-send heap alloc)
        // 16 packets * (4 + 1514) + 4 header ≈ 25KB
        var send_buffer: [25000]u8 = undefined;

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

        // Set up poll structures — all socket fds use socket_t for Windows compatibility
        const invalid_sock: std.posix.socket_t = if (builtin.os.tag == .windows) @ptrFromInt(std.math.maxInt(usize)) else -1;
        const udp_fd: std.posix.socket_t = if (self.udp_accel) |*ua| ua.getFd() orelse invalid_sock else invalid_sock;
        const has_udp = if (builtin.os.tag == .windows) (udp_fd != invalid_sock) else (udp_fd >= 0);

        // tls_fd is already socket_t; tun_fd is fd_t (not a socket on Windows)
        const poll_tun_sock: std.posix.socket_t = if (builtin.os.tag == .windows) @ptrCast(tun_fd) else tun_fd;

        var poll_fds: [3]std.posix.pollfd = .{
            .{ .fd = tls_fd, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = poll_tun_sock, .events = if (builtin.os.tag == .windows) 0 else std.posix.POLL.IN, .revents = 0 },
            .{ .fd = udp_fd, .events = if (has_udp) std.posix.POLL.IN else 0, .revents = 0 },
        };
        const POLL_TLS = 0;
        const POLL_TUN = 1;
        const POLL_UDP = 2;
        _ = POLL_TLS; // Used implicitly via index 0

        // Cache the configured state check
        var is_configured = false;

        // Main packet loop
        while (!@atomicLoad(bool, &self.should_stop, .acquire) and self.isConnected()) {
            // Poll TLS, TUN, and optionally UDP
            poll_fds[0].revents = 0;
            poll_fds[1].revents = 0;
            poll_fds[2].revents = 0;
            const poll_count: std.posix.nfds_t = if (has_udp) 3 else if (builtin.os.tag == .windows) 1 else 2;
            // On Windows, poll only TLS socket; TUN uses non-blocking receivePacket
            _ = std.posix.poll(poll_fds[0..poll_count], 1) catch 0;
            const tls_readable = (poll_fds[0].revents & std.posix.POLL.IN) != 0;
            // On Windows, Wintun receivePacket is non-blocking (returns null if no data).
            // We always attempt TUN read but the 1ms poll timeout prevents busy-spinning.
            const tun_readable = if (builtin.os.tag == .windows) is_configured else (poll_fds[POLL_TUN].revents & std.posix.POLL.IN) != 0;
            const udp_readable = has_udp and (poll_fds[POLL_UDP].revents & std.posix.POLL.IN) != 0;

            // Drive UDP acceleration timers (probing, keepalive, timeout)
            if (self.udp_accel) |*ua| ua.tick();

            // ============================================================
            // FAST PATH: Data plane (process packets first for low latency)
            // ============================================================

            // INBOUND: Receive packets from VPN server (highest priority)
            if (tls_readable) {
                const recv_count = tunnel.receiveBlocksBatch(&recv_slices, recv_scratch) catch |err| {
                    if (self.should_stop) break;
                    if (err == error.ConnectionClosed) {
                        std.log.info("Server closed connection", .{});
                        break;
                    }
                    continue;
                };

                for (recv_slices[0..recv_count]) |block_data| {
                    if (block_data.len <= 14) continue;

                    // Fast EtherType dispatch
                    const ethertype = (@as(u16, block_data[12]) << 8) | block_data[13];

                    if (is_configured) {
                        // Configured: fast path for IP packets
                        if (ethertype == 0x0800 or ethertype == 0x86DD) {
                            // IPv4/IPv6 - direct to TUN (zero-copy slice)
                            if (adapter.real_adapter) |*real| {
                                if (real.device) |dev| {
                                    _ = dev.write(block_data[14..]) catch {};
                                }
                            }
                        } else if (ethertype == 0x0806) {
                            // ARP
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
                        const maybe_response = adapter_mod.parseDhcpResponse(block_data, dhcp_xid) catch null;
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
            if (is_configured and tun_readable) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        // Read up to 32 packets from TUN in one batch
                        var outbound_blocks: [16][]const u8 = undefined;
                        var outbound_count: usize = 0;
                        var outbound_bytes: usize = 0;

                        while (outbound_count < 16) {
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
                            // Try UDP first for each packet
                            var sent_udp = false;
                            if (self.udp_accel) |*ua| {
                                for (outbound_blocks[0..outbound_count]) |frame| {
                                    sent_udp = ua.sendData(frame) catch false;
                                    if (!sent_udp) break;
                                }
                            }
                            if (!sent_udp) {
                                // Batch send all packets over TCP in one protocol frame (zero-copy)
                                tunnel.sendBlocksZeroCopy(outbound_blocks[0..outbound_count], &send_buffer) catch {};
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
