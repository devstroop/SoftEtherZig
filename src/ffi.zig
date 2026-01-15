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

pub const ZigVpnConfig = extern struct {
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password_hash: [*:0]const u8,

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
pub const ZigStateCallback = ?*const fn (?*anyopaque, ZigConnectionState) callconv(.C) void;
pub const ZigConnectedCallback = ?*const fn (?*anyopaque, *const ZigSessionInfo) callconv(.C) void;
pub const ZigDisconnectedCallback = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.C) void;
pub const ZigPacketsCallback = ?*const fn (?*anyopaque, [*]const [*]const u8, [*]const usize, usize) callconv(.C) void;
pub const ZigLogCallback = ?*const fn (?*anyopaque, ZigLogLevel, [*:0]const u8) callconv(.C) void;
pub const ZigExcludeIpCallback = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.C) bool;

pub const ZigCallbacks = extern struct {
    user_data: ?*anyopaque,
    on_state_changed: ZigStateCallback,
    on_connected: ZigConnectedCallback,
    on_disconnected: ZigDisconnectedCallback,
    on_packets_received: ZigPacketsCallback,
    on_log: ZigLogCallback,
    on_exclude_ip: ZigExcludeIpCallback,
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
            .connecting => .connecting,
            .handshaking => .handshaking,
            .authenticating => .authenticating,
            .connected => .connected,
            .disconnecting => .disconnecting,
            .error_state => .@"error",
            else => .disconnected,
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
        }
    }
}

/// Connect to VPN server
export fn zig_vpn_connect(handle: ?*ClientHandle, config: ?*const ZigVpnConfig) i32 {
    const h = handle orelse return -1;
    const cfg = config orelse return -2;

    h.log(.info, "[ZIG] Connecting to {s}:{d}", .{ cfg.server, cfg.port });

    // Convert C config to Zig config
    const zig_config = ClientConfig{
        .server_host = std.mem.sliceTo(cfg.server, 0),
        .server_port = cfg.port,
        .hub_name = std.mem.sliceTo(cfg.hub, 0),
        .auth = .{
            .password = .{
                .username = std.mem.sliceTo(cfg.username, 0),
                .password = std.mem.sliceTo(cfg.password_hash, 0),
                .is_hashed = true,
            },
        },
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
        .state_changed => |state| {
            if (h.callbacks.on_state_changed) |cb| {
                cb(h.callbacks.user_data, ClientHandle.stateToZig(state));
            }
        },
        .connected => |info| {
            // Fill session info
            h.session_info.assigned_ip = info.assigned_ip;
            h.session_info.subnet_mask = info.subnet_mask;
            h.session_info.gateway_ip = info.gateway_ip;
            if (info.mac_address) |mac| {
                @memcpy(&h.session_info.mac_address, &mac);
            }
            if (info.gateway_mac) |gmac| {
                @memcpy(&h.session_info.gateway_mac, &gmac);
            }

            if (h.callbacks.on_connected) |cb| {
                cb(h.callbacks.user_data, &h.session_info);
            }
        },
        .disconnected => |reason| {
            if (h.callbacks.on_disconnected) |cb| {
                const msg = switch (reason) {
                    .user_request => "User requested disconnect",
                    .server_disconnect => "Server disconnected",
                    .connection_lost => "Connection lost",
                    .authentication_failed => "Authentication failed",
                    .timeout => "Connection timeout",
                    else => "Unknown error",
                };
                cb(h.callbacks.user_data, msg);
            }
        },
        .packet_received => |packet| {
            if (h.callbacks.on_packets_received) |cb| {
                const packets = [_][*]const u8{packet.ptr};
                const lengths = [_]usize{packet.len};
                cb(h.callbacks.user_data, &packets, &lengths, 1);
            }
        },
        .error_occurred => |err| {
            h.log(.@"error", "[ZIG] Error: {}", .{err});
        },
        else => {},
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
