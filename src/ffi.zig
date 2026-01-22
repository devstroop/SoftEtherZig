//! SoftEther Zig FFI Implementation
//!
//! C-compatible interface for embedding the Zig VPN client in iOS/Android apps.
//! This module exports functions that can be called from Swift/Kotlin via C interop.

const std = @import("std");
const builtin = @import("builtin");
const client_mod = @import("client/mod.zig");

const VpnClient = client_mod.VpnClient;
const ClientConfig = client_mod.ClientConfig;
const ClientState = client_mod.ClientState;
const AuthMethod = client_mod.AuthMethod;

// ============================================================================
// Global Logging Override for iOS
// ============================================================================

/// Global log callback storage (set when connecting)
var g_log_callback: ZigLogCallback = null;
var g_log_user_data: ?*anyopaque = null;

/// Custom log function that routes to iOS callback
pub fn ffiLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;

    // If we have a callback, route logs there
    if (g_log_callback) |callback| {
        const zig_level: ZigLogLevel = switch (level) {
            .err => .@"error",
            .warn => .warn,
            .info => .info,
            .debug => .debug,
        };

        var buf: [2048]u8 = undefined;
        const msg = std.fmt.bufPrintZ(&buf, format, args) catch "[log truncated]";
        callback(g_log_user_data, zig_level, msg);
    }
}

/// Override std.log for FFI builds
pub const std_options: std.Options = .{
    .logFn = ffiLogFn,
    .log_level = .debug,
};

// ============================================================================
// Types (matching C header)
// ============================================================================

pub const ZigConnectionState = enum(c_int) {
    disconnected = 0,
    connecting = 1,
    handshaking = 2,
    authenticating = 3,
    establishing = 4,
    connected = 5,
    disconnecting = 6,
    @"error" = 7,
};

pub const ZigLogLevel = enum(c_int) {
    @"error" = 0,
    warn = 1,
    info = 2,
    debug = 3,
    trace = 4,
};

pub const ZigSessionInfo = extern struct {
    assigned_ip: u32,
    subnet_mask: u32,
    gateway_ip: u32,
    mac_address: [6]u8,
    gateway_mac: [6]u8,
    dns_servers: [4]u32,
    dns_count: u8,
    connected_server_ip: [64]u8,
};

/// Authentication method for VPN connection
pub const ZigAuthMethod = enum(c_int) {
    /// Standard password authentication (SHA-0 hashed)
    standard_password = 0,
    /// RADIUS or NT Domain authentication (plaintext over TLS)
    radius_or_nt_domain = 1,
    /// Certificate-based authentication (not yet implemented)
    certificate = 2,
    /// Anonymous authentication (no credentials)
    anonymous = 3,
};

pub const ZigVpnConfig = extern struct {
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password_hash: [*:0]const u8,
    /// Plain password for RADIUS/NT Domain auth (only used when auth_method = radius_or_nt_domain)
    plain_password: [*:0]const u8,

    /// Authentication method (default: standard_password)
    auth_method: ZigAuthMethod,

    use_encryption: bool,
    use_compression: bool,
    udp_acceleration: bool,
    verify_certificate: bool,

    max_connections: u8,
    timeout_ms: u32,
    mtu: u16,

    default_route: bool,
};

// Callback types
pub const ZigStateCallback = ?*const fn (?*anyopaque, ZigConnectionState) callconv(.c) void;
pub const ZigConnectedCallback = ?*const fn (?*anyopaque, *const ZigSessionInfo) callconv(.c) void;
pub const ZigDisconnectedCallback = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.c) void;
pub const ZigPacketsCallback = ?*const fn (?*anyopaque, [*]const [*]const u8, [*]const usize, usize) callconv(.c) void;
pub const ZigLogCallback = ?*const fn (?*anyopaque, ZigLogLevel, [*:0]const u8) callconv(.c) void;
pub const ZigExcludeIpCallback = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.c) bool;
pub const ZigProtectSocketCallback = ?*const fn (?*anyopaque, c_int) callconv(.c) bool;

pub const ZigCallbacks = extern struct {
    user_data: ?*anyopaque,
    on_state_changed: ZigStateCallback,
    on_connected: ZigConnectedCallback,
    on_disconnected: ZigDisconnectedCallback,
    on_packets_received: ZigPacketsCallback,
    on_log: ZigLogCallback,
    on_exclude_ip: ZigExcludeIpCallback,
    protect_socket: ZigProtectSocketCallback,
};

// ============================================================================
// Client Handle Wrapper
// ============================================================================

const ClientHandle = struct {
    allocator: std.mem.Allocator,
    client: ?VpnClient,
    callbacks: ZigCallbacks,
    session_info: ZigSessionInfo,
    last_error: [256]u8,

    fn init(allocator: std.mem.Allocator) ClientHandle {
        return ClientHandle{
            .allocator = allocator,
            .client = null,
            .callbacks = std.mem.zeroes(ZigCallbacks),
            .session_info = std.mem.zeroes(ZigSessionInfo),
            .last_error = std.mem.zeroes([256]u8),
        };
    }

    fn deinit(self: *ClientHandle) void {
        if (self.client) |*c| {
            c.deinit();
        }
    }

    fn log(self: *ClientHandle, level: ZigLogLevel, comptime fmt: []const u8, args: anytype) void {
        if (self.callbacks.on_log) |callback| {
            var buf: [1024]u8 = undefined;
            const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch "[log truncated]";
            callback(self.callbacks.user_data, level, msg);
        }
    }

    fn stateToZig(state: ClientState) ZigConnectionState {
        return switch (state) {
            .disconnected => .disconnected,
            .resolving_dns, .connecting_tcp => .connecting,
            .ssl_handshake => .handshaking,
            .authenticating => .authenticating,
            .establishing_session, .configuring_adapter => .establishing,
            .connected => .connected,
            .reconnecting, .disconnecting => .disconnecting,
            .error_state => .@"error",
        };
    }
};

// Global allocator for FFI (using page allocator for simplicity)
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

// ============================================================================
// Exported FFI Functions
// ============================================================================

/// Create a new VPN client instance
export fn zig_vpn_create() ?*ClientHandle {
    const allocator = gpa.allocator();
    const handle = allocator.create(ClientHandle) catch return null;
    handle.* = ClientHandle.init(allocator);
    return handle;
}

/// Destroy a VPN client instance
export fn zig_vpn_destroy(handle: ?*ClientHandle) void {
    if (handle) |h| {
        h.deinit();
        gpa.allocator().destroy(h);
    }
}

/// Set callbacks for the client
export fn zig_vpn_set_callbacks(handle: ?*ClientHandle, callbacks: ?*const ZigCallbacks) void {
    if (handle) |h| {
        if (callbacks) |cb| {
            h.callbacks = cb.*;
            // Update global log callback for std.log routing
            g_log_callback = cb.on_log;
            g_log_user_data = cb.user_data;
        }
    }
}

/// Connect to VPN server
export fn zig_vpn_connect(handle: ?*ClientHandle, config: ?*const ZigVpnConfig) i32 {
    const h = handle orelse return -1;
    const cfg = config orelse return -2;

    h.log(.info, "[ZIG] Connecting to {s}:{d}", .{ cfg.server, cfg.port });

    // Build auth method based on config
    const auth_method: AuthMethod = switch (cfg.auth_method) {
        .standard_password => .{
            .password = .{
                .username = std.mem.sliceTo(cfg.username, 0),
                .password = std.mem.sliceTo(cfg.password_hash, 0),
                .is_hashed = true,
            },
        },
        .radius_or_nt_domain => .{
            .plain_password = .{
                .username = std.mem.sliceTo(cfg.username, 0),
                .password = std.mem.sliceTo(cfg.plain_password, 0),
            },
        },
        .anonymous => .{ .anonymous = {} },
        .certificate => {
            setLastError(h, "Certificate authentication not yet implemented", .{});
            return -10;
        },
    };

    // Convert C config to Zig config
    const zig_config = ClientConfig{
        .server_host = std.mem.sliceTo(cfg.server, 0),
        .server_port = cfg.port,
        .hub_name = std.mem.sliceTo(cfg.hub, 0),
        .auth = auth_method,
        .max_connections = cfg.max_connections,
        .use_compression = cfg.use_compression,
        .use_encryption = cfg.use_encryption,
        .udp_acceleration = cfg.udp_acceleration,
        .verify_certificate = cfg.verify_certificate,
        .mtu = cfg.mtu,
        .connect_timeout_ms = cfg.timeout_ms,
        .routing = .{
            .default_route = cfg.default_route,
        },
    };

    // Create client
    h.client = VpnClient.init(h.allocator, zig_config);

    // Set event callback to forward to FFI callbacks
    if (h.client) |*client| {
        client.setEventCallback(ffiEventCallback, h);
    }

    // Connect (async in the client)
    if (h.client) |*client| {
        client.connect() catch |err| {
            h.log(.@"error", "[ZIG] Connect failed: {}", .{err});
            return -3;
        };
    }

    return 0;
}

/// Internal event callback that forwards to FFI callbacks
fn ffiEventCallback(event: client_mod.ClientEvent, user_data: ?*anyopaque) void {
    const h: *ClientHandle = @ptrCast(@alignCast(user_data orelse return));

    switch (event) {
        .state_changed => |state_info| {
            if (h.callbacks.on_state_changed) |cb| {
                cb(h.callbacks.user_data, ClientHandle.stateToZig(state_info.new_state));
            }
        },
        .connected => |info| {
            // Fill session info with available data
            h.session_info.assigned_ip = info.assigned_ip;
            h.session_info.gateway_ip = info.gateway_ip;
            // Get subnet mask from client if available, otherwise use /24 default
            if (h.client) |client| {
                h.session_info.subnet_mask = if (client.subnet_mask != 0) client.subnet_mask else 0xFFFFFF00;
            } else {
                h.session_info.subnet_mask = 0xFFFFFF00; // 255.255.255.0
            }

            // Copy DNS servers from connected event
            h.session_info.dns_servers = info.dns_servers;
            // Count non-zero DNS servers
            var dns_count: u8 = 0;
            for (info.dns_servers) |dns| {
                if (dns != 0) dns_count += 1;
            }
            h.session_info.dns_count = dns_count;

            // Format server IP as string for connected_server_ip
            // Convert from u32 (host byte order) to dotted decimal string
            const server_ip = info.server_ip;
            const formatted = std.fmt.bufPrint(
                &h.session_info.connected_server_ip,
                "{d}.{d}.{d}.{d}",
                .{
                    (server_ip >> 0) & 0xFF,
                    (server_ip >> 8) & 0xFF,
                    (server_ip >> 16) & 0xFF,
                    (server_ip >> 24) & 0xFF,
                },
            ) catch "0.0.0.0";
            // Null-terminate the string
            if (formatted.len < h.session_info.connected_server_ip.len) {
                h.session_info.connected_server_ip[formatted.len] = 0;
            }

            if (h.callbacks.on_connected) |cb| {
                cb(h.callbacks.user_data, &h.session_info);
            }
        },
        .disconnected => |disconnect_info| {
            if (h.callbacks.on_disconnected) |cb| {
                const msg: [*:0]const u8 = switch (disconnect_info.reason) {
                    .user_requested => "User requested disconnect",
                    .server_closed => "Server disconnected",
                    .network_error => "Connection lost",
                    .auth_failed => "Authentication failed",
                    .timeout => "Connection timeout",
                    else => "Unknown error",
                };
                cb(h.callbacks.user_data, msg);
            }
        },
        .error_occurred => |err| {
            h.log(.@"error", "[ZIG] Error: {s}", .{err.message});
        },
        // Handle remaining events
        .stats_updated, .dhcp_configured => {},
    }
}

/// Disconnect from VPN server
export fn zig_vpn_disconnect(handle: ?*ClientHandle) void {
    if (handle) |h| {
        if (h.client) |*client| {
            client.disconnect() catch {};
        }
    }
}

/// Get current connection state
export fn zig_vpn_get_state(handle: ?*ClientHandle) ZigConnectionState {
    if (handle) |h| {
        if (h.client) |client| {
            return ClientHandle.stateToZig(client.getState());
        }
    }
    return .disconnected;
}

/// Check if connected
export fn zig_vpn_is_connected(handle: ?*ClientHandle) bool {
    if (handle) |h| {
        if (h.client) |client| {
            return client.isConnected();
        }
    }
    return false;
}

/// Send packets to VPN server
export fn zig_vpn_send_packets(
    handle: ?*ClientHandle,
    packets: [*]const [*]const u8,
    lengths: [*]const usize,
    count: usize,
) i32 {
    const h = handle orelse return -1;
    const client = &(h.client orelse return -2);

    var sent: i32 = 0;
    for (0..count) |i| {
        const packet = packets[i][0..lengths[i]];
        client.sendPacket(packet) catch {
            break;
        };
        sent += 1;
    }
    return sent;
}

/// Send a single packet
export fn zig_vpn_send_packet(
    handle: ?*ClientHandle,
    packet: [*]const u8,
    length: usize,
) i32 {
    const h = handle orelse return -1;
    const client = &(h.client orelse return -2);

    client.sendPacket(packet[0..length]) catch return -3;
    return 1;
}

/// Poll for received packets from VPN tunnel
/// Returns number of frames received (0 if none ready, negative on error)
/// Frames are Ethernet frames that should be unwrapped to IP packets
export fn zig_vpn_poll_receive(
    handle: ?*ClientHandle,
    frame_ptrs_out: [*][*]u8,
    frame_lens_out: [*]usize,
    frame_buf: [*]u8,
    buf_size: usize,
    max_frames: usize,
) i32 {
    const h = handle orelse return -1;
    const client = &(h.client orelse return -2);

    // Call client's pollReceive with slices
    const count = client.pollReceive(
        frame_ptrs_out[0..max_frames],
        frame_lens_out[0..max_frames],
        frame_buf[0..buf_size],
    ) catch |err| {
        if (err == client_mod.ClientError.NotConnected) return -3;
        if (err == client_mod.ClientError.ConnectionLost) return -4;
        return 0; // Temporary error, try again
    };

    return @intCast(count);
}

/// Get bytes sent
export fn zig_vpn_get_bytes_sent(handle: ?*ClientHandle) u64 {
    if (handle) |h| {
        if (h.client) |client| {
            return client.getStats().bytes_sent;
        }
    }
    return 0;
}

/// Get bytes received
export fn zig_vpn_get_bytes_received(handle: ?*ClientHandle) u64 {
    if (handle) |h| {
        if (h.client) |client| {
            return client.getStats().bytes_received;
        }
    }
    return 0;
}

/// Get packets sent
export fn zig_vpn_get_packets_sent(handle: ?*ClientHandle) u64 {
    if (handle) |h| {
        if (h.client) |client| {
            return client.getStats().packets_sent;
        }
    }
    return 0;
}

/// Get packets received
export fn zig_vpn_get_packets_received(handle: ?*ClientHandle) u64 {
    if (handle) |h| {
        if (h.client) |client| {
            return client.getStats().packets_received;
        }
    }
    return 0;
}

/// Get library version
export fn zig_vpn_version() [*:0]const u8 {
    return "0.2.0-ffi";
}

/// Get last error message
export fn zig_vpn_get_last_error(handle: ?*ClientHandle) [*:0]const u8 {
    if (handle) |h| {
        // Return pointer to null-terminated error buffer
        const sentinel_ptr: [*:0]const u8 = @ptrCast(&h.last_error);
        return sentinel_ptr;
    }
    return "No handle";
}

/// Set last error message (internal helper)
fn setLastError(handle: *ClientHandle, comptime fmt: []const u8, args: anytype) void {
    _ = std.fmt.bufPrintZ(&handle.last_error, fmt, args) catch {};
}
