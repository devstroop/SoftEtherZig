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

        // Receive buffers (zero-copy: reused each iteration)
        var recv_scratch: [512 * 1600]u8 = undefined;
        var recv_slices: [512][]u8 = undefined;

        // Outbound packet buffer (zero-copy: build Ethernet frame in-place)
        var tun_read_buf: [2048]u8 = undefined;

        // Batch outbound: multiple packets per TLS write (reduces syscall overhead)
        const MAX_OUTBOUND_BATCH = 32;
        var outbound_batch_bufs: [MAX_OUTBOUND_BATCH][1600]u8 = undefined;
        var outbound_batch_slices: [MAX_OUTBOUND_BATCH][]const u8 = undefined;

        // Large send buffer for batched packets: 4 + (4+1514)*32 = ~48KB
        var send_buffer: [4 + (4 + 1514) * MAX_OUTBOUND_BATCH]u8 = undefined;

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

                                if (self.config.full_tunnel and loop_state.our_gateway != 0) {
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

            // OUTBOUND: Drain TUN and batch send to VPN (reduces syscalls)
            if (is_configured and tun_readable) {
                if (adapter.real_adapter) |*real| {
                    if (real.device) |dev| {
                        var batch_count: usize = 0;

                        // Drain up to MAX_OUTBOUND_BATCH packets from TUN
                        while (batch_count < MAX_OUTBOUND_BATCH) {
                            if (dev.read(&tun_read_buf)) |maybe_len| {
                                if (maybe_len) |ip_len| {
                                    if (ip_len > 0 and ip_len <= 1500) {
                                        // Build Ethernet frame directly into batch buffer
                                        if (tunnel_mod.wrapIpInEthernet(tun_read_buf[0..ip_len], loop_state.gateway_mac, mac, &outbound_batch_bufs[batch_count])) |eth_frame| {
                                            outbound_batch_slices[batch_count] = eth_frame;
                                            self.stats.recordSent(eth_frame.len);
                                            batch_count += 1;
                                        }
                                    }
                                } else {
                                    break; // No more packets
                                }
                            } else |_| {
                                break; // Read error or would block
                            }
                        }

                        // Send batch in single TLS write
                        if (batch_count > 0) {
                            tunnel.sendBlocksZeroCopy(outbound_batch_slices[0..batch_count], &send_buffer) catch {};
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

test "IpVersionPreference" {
    const pref = IpVersionPreference.dual_stack;
    try std.testing.expect(pref == .dual_stack);
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
