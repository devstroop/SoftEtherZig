//! SoftEther VPN Client — C ABI Export Layer
//!
//! Provides C-compatible function exports for FFI consumers:
//! - Flutter (dart:ffi)
//! - Python (ctypes)
//! - Any language with C FFI support
//!
//! Build: zig build shared-lib
//! Output: libsoftether.dylib (macOS), libsoftether.so (Linux), softether.dll (Windows)

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

// ============================================================================
// Android logging bridge (routes std.log -> __android_log_print)
// ============================================================================

const is_android_build = builtin.os.tag == .linux and
    (builtin.abi == .android or builtin.abi == .androideabi);

const is_ios_build = builtin.os.tag == .ios;

const android_log = if (is_android_build) struct {
    extern "log" fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;
    const PRIO_VERBOSE: c_int = 2;
    const PRIO_DEBUG: c_int = 3;
    const PRIO_INFO: c_int = 4;
    const PRIO_WARN: c_int = 5;
    const PRIO_ERROR: c_int = 6;
} else struct {};

// On iOS, write directly to stderr fd (which the Swift host has dup2'd to a pipe
// that forwards to os_log). std.log.defaultLog wraps in std.debug locks that may
// drop output in release-fast extensions; we go straight to write(2).
fn iosWriteStderr(text: []const u8) void {
    _ = std.posix.write(2, text) catch {};
}

/// External log sink (set by hosts that can't easily read stderr — e.g. iOS NE
/// extensions where pipe-based stderr capture races with extension teardown).
/// Called synchronously from logFn with a NUL-terminated UTF-8 message and the
/// numeric log level (0=err, 1=warn, 2=info, 3=debug).
const ExternalLogFn = *const fn (level: c_int, msg: [*:0]const u8) callconv(.c) void;
var external_log_fn: ?ExternalLogFn = null;

export fn softether_set_log_callback(cb: ?ExternalLogFn) void {
    external_log_fn = cb;
}

fn libsoftetherLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime fmt: []const u8,
    args: anytype,
) void {
    var buf: [2048]u8 = undefined;
    const scope_prefix = if (scope == .default) "" else "[" ++ @tagName(scope) ++ "] ";
    const level_prefix = switch (level) {
        .err => "ERR ",
        .warn => "WARN ",
        .info => "INFO ",
        .debug => "DBG ",
    };

    // External callback first (host-controlled, e.g. iOS os_log direct).
    if (external_log_fn) |cb| {
        const text = std.fmt.bufPrintZ(&buf, scope_prefix ++ fmt, args) catch blk: {
            buf[buf.len - 1] = 0;
            break :blk @as([:0]const u8, buf[0 .. buf.len - 1 :0]);
        };
        const lvl: c_int = switch (level) {
            .err => 0,
            .warn => 1,
            .info => 2,
            .debug => 3,
        };
        cb(lvl, text.ptr);
        return;
    }

    if (is_android_build) {
        const text = std.fmt.bufPrintZ(&buf, scope_prefix ++ fmt, args) catch blk: {
            buf[buf.len - 1] = 0;
            break :blk @as([:0]const u8, buf[0 .. buf.len - 1 :0]);
        };
        const prio: c_int = switch (level) {
            .err => android_log.PRIO_ERROR,
            .warn => android_log.PRIO_WARN,
            .info => android_log.PRIO_INFO,
            .debug => android_log.PRIO_DEBUG,
        };
        _ = android_log.__android_log_write(prio, "libsoftether", text.ptr);
        return;
    }

    if (is_ios_build) {
        const text = std.fmt.bufPrint(&buf, level_prefix ++ scope_prefix ++ fmt ++ "\n", args) catch blk: {
            break :blk buf[0 .. buf.len - 1];
        };
        iosWriteStderr(text);
        return;
    }

    std.log.defaultLog(level, scope, fmt, args);
}

pub const std_options: std.Options = .{
    .logFn = libsoftetherLogFn,
};

// Import library modules
const client_mod = @import("client/mod.zig");
const VpnClient = client_mod.VpnClient;
const ClientConfig = client_mod.ClientConfig;
const ClientState = client_mod.ClientState;
const ClientError = client_mod.ClientError;
const ConnectionStats = client_mod.ConnectionStats;
const AuthMethod = client_mod.AuthMethod;
const ReconnectConfig = client_mod.ReconnectConfig;

// ============================================================================
// Opaque Handle
// ============================================================================

/// Opaque client handle for FFI consumers
const ClientHandle = *VpnClient;

/// Allocator for FFI-created objects (uses page allocator for safety)
const ffi_allocator = std.heap.page_allocator;

// ============================================================================
// Error Codes
// ============================================================================

/// FFI error codes (C-compatible integers)
pub const SoftetherError = enum(c_int) {
    ok = 0,
    invalid_argument = -1,
    already_connected = -2,
    not_connected = -3,
    connection_failed = -4,
    auth_failed = -5,
    dns_failed = -6,
    timeout = -7,
    protocol_error = -8,
    adapter_failed = -9,
    session_failed = -10,
    out_of_memory = -11,
    operation_cancelled = -12,
    internal_error = -99,
};

fn mapClientError(err: ClientError) SoftetherError {
    return switch (err) {
        ClientError.AlreadyConnected => .already_connected,
        ClientError.NotConnected => .not_connected,
        ClientError.ConnectionFailed => .connection_failed,
        ClientError.AuthenticationFailed => .auth_failed,
        ClientError.DnsResolutionFailed => .dns_failed,
        ClientError.Timeout => .timeout,
        ClientError.ProtocolError => .protocol_error,
        ClientError.AdapterConfigurationFailed => .adapter_failed,
        ClientError.SessionEstablishmentFailed => .session_failed,
        ClientError.OutOfMemory => .out_of_memory,
        ClientError.OperationCancelled => .operation_cancelled,
        else => .internal_error,
    };
}

// ============================================================================
// C-Compatible Structs
// ============================================================================

/// Connection statistics (C layout)
pub const CStats = extern struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    connect_time_ms: i64,
    reconnect_count: u32,
    _padding: u32 = 0,
};

/// Connection state (C-compatible enum)
pub const CState = enum(c_int) {
    disconnected = 0,
    resolving_dns = 1,
    connecting_tcp = 2,
    ssl_handshake = 3,
    authenticating = 4,
    establishing_session = 5,
    configuring_adapter = 6,
    connected = 7,
    reconnecting = 8,
    disconnecting = 9,
    error_state = 10,
};

fn mapState(state: ClientState) CState {
    return switch (state) {
        .disconnected => .disconnected,
        .resolving_dns => .resolving_dns,
        .connecting_tcp => .connecting_tcp,
        .ssl_handshake => .ssl_handshake,
        .authenticating => .authenticating,
        .establishing_session => .establishing_session,
        .configuring_adapter => .configuring_adapter,
        .connected => .connected,
        .reconnecting => .reconnecting,
        .disconnecting => .disconnecting,
        .error_state => .error_state,
    };
}

// ============================================================================
// Event Callback
// ============================================================================

/// C-compatible event types
pub const CEventType = enum(c_int) {
    state_changed = 0,
    connected = 1,
    disconnected = 2,
    stats_updated = 3,
    error_occurred = 4,
};

/// C event callback function pointer
pub const CEventCallback = ?*const fn (event_type: CEventType, new_state: CState, user_data: ?*anyopaque) callconv(.c) void;

// ============================================================================
// Client Lifecycle
// ============================================================================

/// Create a new VPN client with password authentication.
/// Returns null on failure. Caller must call softether_destroy() when done.
///
/// The C strings are duped into FFI-owned memory immediately, so callers do
/// NOT need to keep their buffers alive (Swift's String → C-pointer bridging
/// only keeps the buffer alive for the duration of THIS call, so duping is
/// mandatory on iOS / macOS Swift hosts).
export fn softether_create(
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password: [*:0]const u8,
) ?*VpnClient {
    const server_in = std.mem.span(server);
    const hub_in = std.mem.span(hub);
    const username_in = std.mem.span(username);
    const password_in = std.mem.span(password);

    if (server_in.len == 0 or hub_in.len == 0 or username_in.len == 0) {
        return null;
    }

    // Dupe so we don't depend on the caller's buffers staying alive. (Tiny leak
    // on destroy — acceptable; per-connect lifetime, freed at process teardown.)
    const server_slice = ffi_allocator.dupe(u8, server_in) catch return null;
    const hub_slice = ffi_allocator.dupe(u8, hub_in) catch return null;
    const username_slice = ffi_allocator.dupe(u8, username_in) catch return null;
    const password_slice = ffi_allocator.dupe(u8, password_in) catch return null;

    const config = ClientConfig{
        .server_host = server_slice,
        .server_port = port,
        .hub_name = hub_slice,
        .auth = .{ .password = .{
            .username = username_slice,
            .password = password_slice,
        } },
        // Explicit defaults — don't rely on struct defaults (ReleaseFast may not apply them)
        .max_connections = 1,
        .use_compression = false,
        .use_encryption = true,
        .udp_acceleration = false,
        .half_connection = false,
        .qos = true,
        .mtu = 1400,
        .verify_certificate = true,
    };

    const ptr = ffi_allocator.create(VpnClient) catch return null;
    ptr.* = VpnClient.init(ffi_allocator, config);
    return ptr;
}

/// Create a new VPN client with anonymous authentication.
/// Strings are duped into FFI-owned memory (see softether_create for rationale).
export fn softether_create_anonymous(
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
) ?*VpnClient {
    const server_in = std.mem.span(server);
    const hub_in = std.mem.span(hub);

    if (server_in.len == 0 or hub_in.len == 0) {
        return null;
    }

    const server_slice = ffi_allocator.dupe(u8, server_in) catch return null;
    const hub_slice = ffi_allocator.dupe(u8, hub_in) catch return null;

    const config = ClientConfig{
        .server_host = server_slice,
        .server_port = port,
        .hub_name = hub_slice,
        .auth = .{ .anonymous = {} },
        .max_connections = 1,
        .use_compression = false,
        .use_encryption = true,
        .udp_acceleration = false,
        .half_connection = false,
        .qos = true,
        .mtu = 1400,
        .verify_certificate = true,
    };

    const ptr = ffi_allocator.create(VpnClient) catch return null;
    ptr.* = VpnClient.init(ffi_allocator, config);
    return ptr;
}

/// Create a new VPN client with X.509 certificate authentication.
/// PEM data is passed as pointer+length since PEM may contain embedded nulls.
/// All inputs are duped into FFI-owned memory (see softether_create).
export fn softether_create_certificate(
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    cert_pem: [*]const u8,
    cert_pem_len: u32,
    key_pem: [*]const u8,
    key_pem_len: u32,
) ?*VpnClient {
    const server_in = std.mem.span(server);
    const hub_in = std.mem.span(hub);

    if (server_in.len == 0 or hub_in.len == 0 or cert_pem_len == 0 or key_pem_len == 0) {
        return null;
    }

    const server_slice = ffi_allocator.dupe(u8, server_in) catch return null;
    const hub_slice = ffi_allocator.dupe(u8, hub_in) catch return null;
    const cert_slice = ffi_allocator.dupe(u8, cert_pem[0..cert_pem_len]) catch return null;
    const key_slice = ffi_allocator.dupe(u8, key_pem[0..key_pem_len]) catch return null;

    const config = ClientConfig{
        .server_host = server_slice,
        .server_port = port,
        .hub_name = hub_slice,
        .auth = .{ .certificate = .{
            .cert_data = cert_slice,
            .key_data = key_slice,
        } },
        .max_connections = 1,
        .use_compression = false,
        .use_encryption = true,
        .udp_acceleration = false,
        .half_connection = false,
        .qos = true,
        .mtu = 1400,
        .verify_certificate = true,
    };

    const ptr = ffi_allocator.create(VpnClient) catch return null;
    ptr.* = VpnClient.init(ffi_allocator, config);
    return ptr;
}

/// Destroy a VPN client and free all resources.
export fn softether_destroy(client: ?*VpnClient) void {
    const c = client orelse return;
    c.deinit();
    ffi_allocator.destroy(c);
}

// ============================================================================
// Connection Management
// ============================================================================

/// Connect to the VPN server. Blocks until connected or error.
export fn softether_connect(client: ?*VpnClient) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    c.connect() catch |err| {
        return @intFromEnum(mapClientError(err));
    };
    return 0;
}

/// Disconnect from the VPN server.
/// First signals cancellation (non-blocking), then waits for clean disconnect.
export fn softether_disconnect(client: ?*VpnClient) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    // Signal stop first so performConnection() can exit early
    c.requestStop();
    c.disconnect() catch |err| {
        return @intFromEnum(mapClientError(err));
    };
    return 0;
}

/// Run the data loop (blocks until disconnect). Call from a dedicated thread.
export fn softether_run_data_loop(client: ?*VpnClient) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    c.runDataLoop() catch {
        return @intFromEnum(SoftetherError.internal_error);
    };
    return 0;
}

/// Request a stop (signal-safe, non-blocking).
export fn softether_request_stop(client: ?*VpnClient) void {
    const c = client orelse return;
    c.requestStop();
}

// ============================================================================
// State & Stats Queries
// ============================================================================

/// Get current connection state.
export fn softether_get_state(client: ?*const VpnClient) c_int {
    const c = client orelse return @intFromEnum(CState.disconnected);
    return @intFromEnum(mapState(c.getState()));
}

/// Check if connected.
export fn softether_is_connected(client: ?*const VpnClient) bool {
    const c = client orelse return false;
    return c.isConnected();
}

/// Get connection statistics. Returns 0 on success.
export fn softether_get_stats(client: ?*const VpnClient, out: ?*CStats) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    const s = out orelse return @intFromEnum(SoftetherError.invalid_argument);
    const stats = c.getStats();
    s.* = .{
        .bytes_sent = stats.bytes_sent,
        .bytes_received = stats.bytes_received,
        .packets_sent = stats.packets_sent,
        .packets_received = stats.packets_received,
        .connect_time_ms = stats.connect_time_ms,
        .reconnect_count = stats.reconnect_count,
    };
    return 0;
}

/// Get assigned VPN IP address (host byte order u32, 0 if not assigned).
export fn softether_get_assigned_ip(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    return c.getAssignedIp();
}

/// Get gateway IP address (host byte order u32, 0 if not assigned).
export fn softether_get_gateway_ip(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    return c.getGatewayIp();
}

/// Get assigned subnet mask (host byte order u32, 0 if not assigned).
export fn softether_get_assigned_mask(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    return c.getAssignedMask();
}

// ============================================================================
// Configuration
// ============================================================================

/// Set encryption on/off. Must be called before connect().
export fn softether_set_encryption(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.use_encryption = enabled;
}

/// Set compression on/off. Must be called before connect().
export fn softether_set_compression(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.use_compression = enabled;
}

/// Set TLS certificate verification. Must be called before connect().
export fn softether_set_verify_certificate(client: ?*VpnClient, verify: bool) void {
    const c = client orelse return;
    c.config.verify_certificate = verify;
}

/// Bind outbound TLS sockets to a specific network interface (Darwin only;
/// no-op on other platforms). Required on iOS NEPacketTunnelProvider where
/// NECP would otherwise route the extension's own outbound socket through the
/// tunnel that's not yet established → instant ECONNREFUSED.
/// Pass NULL or "" to clear.
export fn softether_set_bind_interface(name: ?[*:0]const u8) void {
    const tls = @import("net/tls.zig");
    if (name == null) {
        tls.bind_interface_index = 0;
        return;
    }
    const slice = std.mem.span(name.?);
    if (slice.len == 0) {
        tls.bind_interface_index = 0;
        return;
    }
    // if_nametoindex(3) — POSIX. Returns 0 on failure.
    const if_nametoindex = struct {
        extern "c" fn if_nametoindex(ifname: [*:0]const u8) c_uint;
    }.if_nametoindex;
    const idx = if_nametoindex(name.?);
    tls.bind_interface_index = idx;
    if (idx == 0) {
        std.log.warn("softether_set_bind_interface: if_nametoindex({s}) returned 0", .{slice});
    } else {
        std.log.info("softether_set_bind_interface: bound to {s} (idx={d})", .{ slice, idx });
    }
}

/// Host-provided TCP dial. Receives hostname (NUL-terminated UTF-8) and port,
/// returns a connected, blocking socket fd, or -1 on failure. The returned fd
/// is owned by libsoftether and will be close()d when the TLS session ends.
///
/// Used on iOS NEPacketTunnelProvider where the extension's own POSIX
/// connect() is denied by NECP — Swift dials via NEProvider.createTCPConnection
/// (which goes outside the tunnel) and bridges bytes through a socketpair.
const tls_mod = @import("net/tls.zig");

export fn softether_set_tcp_dial_callback(cb: ?tls_mod.ExternalTcpDialFn) void {
    tls_mod.external_tcp_dial = cb;
    if (cb == null) {
        std.log.info("softether_set_tcp_dial_callback: cleared (using POSIX connect)", .{});
    } else {
        std.log.info("softether_set_tcp_dial_callback: registered (host will dial)", .{});
    }
}

/// Set full tunnel (route all traffic through VPN). Must be called before connect().
export fn softether_set_full_tunnel(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.routing.default_route = enabled;
}

/// Set MTU. Must be called before connect().
export fn softether_set_mtu(client: ?*VpnClient, mtu: u16) void {
    const c = client orelse return;
    if (mtu >= 576 and mtu <= 9000) {
        c.config.mtu = mtu;
    }
}

/// Enable/disable reconnection. Must be called before connect().
export fn softether_set_reconnect(client: ?*VpnClient, enabled: bool, max_attempts: u32) void {
    const c = client orelse return;
    c.config.reconnect.enabled = enabled;
    c.config.reconnect.max_attempts = max_attempts;
}

/// Set max TCP connections (1-32). Must be called before connect().
export fn softether_set_max_connections(client: ?*VpnClient, count: u8) void {
    const c = client orelse return;
    if (count >= 1 and count <= 32) {
        c.config.max_connections = count;
    }
}

/// Set half-connection mode. Must be called before connect().
export fn softether_set_half_connection(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.half_connection = enabled;
}

/// Set QoS (VoIP/QoS prioritization). Must be called before connect().
export fn softether_set_qos(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.qos = enabled;
}

/// Set an external tunnel file descriptor (for iOS/Android).
/// On mobile, the OS creates the TUN device and provides an fd.
/// Must be called before connect().
export fn softether_set_tunnel_fd(client: ?*VpnClient, fd: i32) void {
    const c = client orelse return;
    c.config.tunnel_fd = fd;
}

/// Replace the active TUN fd at runtime (mobile only). Used after DHCP
/// completes and the platform re-creates the VpnService tunnel with the
/// server-assigned IP/mask. Returns 0 on success, -1 on error.
export fn softether_replace_tun_fd(client: ?*VpnClient, fd: i32) c_int {
    const c = client orelse return -1;
    c.replaceTunFd(fd) catch |e| {
        std.log.err("softether_replace_tun_fd failed: {}", .{e});
        return -1;
    };
    return 0;
}

// ============================================================================
// Event Callback
// ============================================================================

/// Register an event callback. Pass null to unregister.
export fn softether_set_event_callback(
    client: ?*VpnClient,
    callback: CEventCallback,
    user_data: ?*anyopaque,
) void {
    const c = client orelse return;
    if (callback) |cb| {
        // Store the C callback info in a wrapper
        const wrapper = struct {
            var c_callback: *const fn (CEventType, CState, ?*anyopaque) callconv(.c) void = undefined;
            var c_user_data: ?*anyopaque = null;

            fn dispatch(event: client_mod.ClientEvent, ud: ?*anyopaque) void {
                _ = ud;
                const event_type: CEventType = switch (event) {
                    .state_changed => .state_changed,
                    .connected => .connected,
                    .disconnected => .disconnected,
                    .stats_updated => .stats_updated,
                    .error_occurred => .error_occurred,
                    else => return,
                };
                const state = switch (event) {
                    .state_changed => |sc| mapState(sc.new_state),
                    .connected => CState.connected,
                    .disconnected => CState.disconnected,
                    else => CState.disconnected,
                };
                c_callback(event_type, state, c_user_data);
            }
        };
        wrapper.c_callback = cb;
        wrapper.c_user_data = user_data;
        c.setEventCallback(wrapper.dispatch, null);
    } else {
        c.setEventCallback(null, null);
    }
}

// ============================================================================
// Version
// ============================================================================

/// Get library version string. Returns pointer to static string.
export fn softether_version() [*:0]const u8 {
    return "0.2.0";
}

// ============================================================================
// Tests
// ============================================================================

test "ffi error mapping" {
    const err = mapClientError(ClientError.ConnectionFailed);
    try std.testing.expectEqual(SoftetherError.connection_failed, err);
}

test "ffi state mapping" {
    try std.testing.expectEqual(CState.disconnected, mapState(.disconnected));
    try std.testing.expectEqual(CState.connected, mapState(.connected));
    try std.testing.expectEqual(CState.authenticating, mapState(.authenticating));
}
