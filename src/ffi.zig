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
const log = std.log.scoped(.ffi);
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const lib = @import("lib.zig");
// L2 bridge pump tests live in the whole-package test target; force
// analysis of lib.bridge.loop so its `bridge.loop.*` test blocks are
// compiled into that binary (fdb/engine run standalone in test_sources).
// Same for lib.monitor (`monitor.*` ring/PCAP tests).
comptime {
    _ = lib.bridge.loop;
    _ = lib.monitor;
}

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

/// Runtime log level override. 0=err, 1=warn, 2=info, 3=debug.
/// Values 4-5 from the old 0-5 API are mapped to 3 (debug).
/// When set to a value lower than the caller's level, the message is skipped
/// before any formatting. Initialized to 2 (info) by default; the Flutter
/// app can raise it to 3 (debug) when "Verbose Logging" is enabled.
var runtime_log_level: u3 = 2;

/// When true (default), the external log callback is the sole sink — the
/// function returns immediately after calling it. When false, the message is
/// also forwarded to platform sinks (Android logcat, iOS stderr, desktop
/// stdout) after the callback. This preserves the original exclusive-callback
/// contract for existing FFI consumers.
var external_log_fn_exclusive: bool = true;

export fn softether_set_log_callback(cb: ?ExternalLogFn) void {
    external_log_fn = cb;
}

/// Set whether the external log callback is exclusive (stops further output)
/// or allows fall-through to platform sinks. Default: true (exclusive).
export fn softether_set_log_callback_exclusive(exclusive: bool) void {
    external_log_fn_exclusive = exclusive;
}

/// Set the minimum log level at runtime. Messages below this level are
/// dropped before formatting. 0=err, 1=warn, 2=info, 3=debug, 4-5→3 (debug).
/// Values outside 0-5 are clamped. The old 0-5 range is accepted: levels 4
/// and 5 (previously no-ops) now map to 3 (debug).
export fn softether_set_log_level_global(level: c_int) void {
    runtime_log_level = @as(u3, @intCast(@min(@max(level, 0), 3)));
}

/// Compatibility shim — old two-arg API (client pointer is ignored).
/// Kept so FFI callers using `softether_set_log_level(client, level)` don't break.
export fn softether_set_log_level(client: ?*VpnClient, level: c_int) void {
    _ = client;
    softether_set_log_level_global(level);
}

fn libsoftetherLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime fmt: []const u8,
    args: anytype,
) void {
    // ── External callback: registered callbacks (e.g. iOS os_log via Swift)
    //    may want all levels regardless of runtime_log_level. Runs before the
    //    level gate so debug messages still reach the external sink.
    //    Uses the original scope_prefix ++ fmt format to preserve compatibility.
    if (external_log_fn) |cb| {
        var cb_buf: [2048]u8 = .{0} ** 2048;
        const scope_prefix = if (scope == .default) "" else "[" ++ @tagName(scope) ++ "] ";
        const cb_text = std.fmt.bufPrintZ(&cb_buf, scope_prefix ++ fmt, args) catch blk: {
            cb_buf[cb_buf.len - 1] = 0;
            break :blk @as([:0]const u8, cb_buf[0 .. cb_buf.len - 1 :0]);
        };
        const lvl: c_int = switch (level) {
            .err => 0,
            .warn => 1,
            .info => 2,
            .debug => 3,
        };
        cb(lvl, cb_text.ptr);
        // By default the external callback is exclusive (the FFI contract says
        // this sink is set by hosts that can't read stderr). When
        // external_log_fn_exclusive is true the log is consumed here; when
        // false we fall through to platform sinks (Android logcat, iOS stderr,
        // desktop stdout) for dual-routing.
        if (external_log_fn_exclusive) return;
    }

    // ── fast-path: skip formatting debug messages in release builds ──
    if (comptime level == .debug and builtin.mode != .Debug) {
        if (runtime_log_level < 3) return;
    }
    // ── runtime log level gate ──
    // Zig's Level enum is err=3, warn=2, info=1, debug=0 (reverse order),
    // but runtime_log_level uses the external mapping (err=0, warn=1,
    // info=2, debug=3). Map Zig level to external rank before comparing.
    if ((3 - @intFromEnum(level)) > runtime_log_level) return;

    // Use a 2049-byte buffer but format into the first 2048 bytes so there is
    // always room for a trailing NUL sentinel — this avoids false "overflow"
    // when bufPrint exactly fills the available space.
    var buf: [2049]u8 = .{0} ** 2049;
    const scope_prefix = if (scope == .default) "" else "[" ++ @tagName(scope) ++ "] ";
    const level_prefix = switch (level) {
        .err => "ERR ",
        .warn => "WARN ",
        .info => "INFO ",
        .debug => "DBG ",
    };

    // Format into buf[0..2048] — one byte reserved for sentinel.
    const format_prefix = (if (is_ios_build) level_prefix else "") ++ scope_prefix;
    const decorated_fmt = if (is_ios_build) fmt ++ "\n" else fmt;
    const text_slice = std.fmt.bufPrint(buf[0..2048], format_prefix ++ decorated_fmt, args) catch blk: {
        // Overflow: bufPrint ran out of space. The message was truncated at
        // buf[0..2048]; null-terminate the last byte and return a [:0] slice
        // of the first 2047 characters.
        buf[2047] = 0;
        break :blk buf[0..2047];
    };
    const text_z: [:0]const u8 = buf[0..text_slice.len :0];

    if (is_android_build) {
        const prio: c_int = switch (level) {
            .err => android_log.PRIO_ERROR,
            .warn => android_log.PRIO_WARN,
            .info => android_log.PRIO_INFO,
            .debug => android_log.PRIO_DEBUG,
        };
        _ = android_log.__android_log_write(prio, "libsoftether", text_z.ptr);
        return;
    }

    if (is_ios_build) {
        iosWriteStderr(text_z);
        return;
    }

    std.log.defaultLog(level, scope, fmt, args);
}

pub const std_options: std.Options = .{
    .logFn = libsoftetherLogFn,
    .log_level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
    .log_scope_levels = &.{
        // Per-packet I/O: only show in debug builds
        .{ .scope = .packet_trace, .level = .err },
        // Suppress noisy platform scopes to reduce logcat pressure
        .{ .scope = .mayaqua, .level = .info },
        .{ .scope = .adapter, .level = .info },
        .{ .scope = .cedar_client, .level = .info },
        .{ .scope = .cedar_conn, .level = .info },
        .{ .scope = .cedar_proto, .level = .info },
        .{ .scope = .cedar_tunnel, .level = .info },
        .{ .scope = .cedar_auth, .level = .info },
        .{ .scope = .cedar_pack, .level = .info },
        .{ .scope = .cedar_session, .level = .info },
    },
};

// Import library modules
const client_mod = @import("cedar/client/mod.zig");
const VpnClient = client_mod.VpnClient;
const ClientConfig = client_mod.ClientConfig;
const ClientState = client_mod.ClientState;
const ClientError = client_mod.ClientError;
const ConnectionStats = client_mod.ConnectionStats;
const AuthMethod = client_mod.AuthMethod;
const ReconnectConfig = client_mod.ReconnectConfig;

// Server-core modules (epic #71). Imported here so the whole-package test
// runner collects `server.session.*` tests (decls are lazily analyzed).
const server_mod = @import("cedar/server/mod.zig");

comptime {
    _ = server_mod;
}

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
        // SslHandshakeFailed → protocol_error: the Zig TLS layer aborted
        // the handshake (cert mismatch, version mismatch, cipher failure).
        // The UI's _classifyError will show "Protocol mismatch" advice
        // which is actionable — the "Internal error" fallback is not.
        ClientError.SslHandshakeFailed => .protocol_error,
        // NetworkError → connection_failed: the TCP socket or I/O
        // sub-system reported a non-timeout error (connection refused,
        // host unreachable, connection reset by peer).
        ClientError.NetworkError => .connection_failed,
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

/// Aggregate bridge-mode stats (C layout, mirrors `BridgeStats`).
pub const CBridgeStats = extern struct {
    fdb_entries: u32,
    _pad0: u32 = 0,
    forwarded: u64,
    flooded: u64,
    blocked: u64,
    lan_rx_pkts: u64,
    lan_tx_pkts: u64,
    lan_rx_bytes: u64,
    lan_tx_bytes: u64,
    drops: u64,
    session_rx: u64,
    session_tx: u64,
    session_tx_errors: u64,
};

/// Aggregate monitor-mode stats (C layout, mirrors `MonitorStats`).
pub const CMonitorStats = extern struct {
    frames_captured: u64,
    frames_dropped: u64,
    bytes_captured: u64,
    ring_used: u32,
    _pad0: u32 = 0,
    pcap_records: u64,
    pcap_bytes: u64,
    pcap_write_errors: u64,
};

/// Connection state (C-compatible enum)
pub const CState = enum(c_int) {
    disconnected = 0,
    connecting_tcp = 1,
    ssl_handshake = 2,
    authenticating = 3,
    establishing_session = 4,
    configuring_adapter = 5,
    connected = 6,
    reconnecting = 7,
    disconnecting = 8,
    error_state = 9,
};

fn mapState(state: ClientState) CState {
    return switch (state) {
        .disconnected => .disconnected,
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

/// Shared defaults for all FFI create paths.
/// Centralized to prevent drift between softether_create, softether_create_anonymous,
/// and softether_create_certificate.
fn defaultClientConfig() ClientConfig {
    return .{
        .server_address = "",
        .server_port = 443,
        .hub_name = "",
        .auth = .{ .anonymous = {} },
        .max_connections = 1,
        .use_compress = false,
        .use_encrypt = true,
        .udp_acceleration = false,
        .half_connection = false,
        .qos = true,
        .mtu = 1400,
        .verify_certificate = true,
        .ip_version = null,
        .routing = .{},
        .reconnect = .{},
        .static_ip = null,
        .connect_timeout_ms = 30000,
        .read_timeout_ms = 60000,
        .keepalive_interval_ms = 10000,
        .proxy = null,
        .tcp_nodelay = true,
        .verbose = false,
        .tunnel_fd = null,
    };
}

/// Create a new VPN client with password authentication.
/// Returns null on failure. Caller must call softether_destroy() when done.
///
/// The C strings are duped into FFI-owned memory immediately, so callers do
/// NOT need to keep their buffers alive (Swift's String → C-pointer bridging
/// only keeps the buffer alive for the duration of THIS call, so duping is
/// mandatory on iOS / macOS Swift hosts).
export fn softether_create(
    address: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password: [*:0]const u8,
) ?*VpnClient {
    const server_in = std.mem.span(address);
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

    var config = defaultClientConfig();
    config.server_address = server_slice;
    config.server_port = port;
    config.hub_name = hub_slice;
    config.auth = .{ .password = .{
        .username = username_slice,
        .password = password_slice,
    } };

    const ptr = ffi_allocator.create(VpnClient) catch return null;
    ptr.* = VpnClient.init(ffi_allocator, config);
    return ptr;
}

/// Create a new VPN client with anonymous authentication.
/// Strings are duped into FFI-owned memory (see softether_create for rationale).
export fn softether_create_anonymous(
    address: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
) ?*VpnClient {
    const server_in = std.mem.span(address);
    const hub_in = std.mem.span(hub);

    if (server_in.len == 0 or hub_in.len == 0) {
        return null;
    }

    const server_slice = ffi_allocator.dupe(u8, server_in) catch return null;
    const hub_slice = ffi_allocator.dupe(u8, hub_in) catch return null;

    var config = defaultClientConfig();
    config.server_address = server_slice;
    config.server_port = port;
    config.hub_name = hub_slice;
    config.auth = .{ .anonymous = {} };

    const ptr = ffi_allocator.create(VpnClient) catch return null;
    ptr.* = VpnClient.init(ffi_allocator, config);
    return ptr;
}

/// Create a new VPN client with X.509 certificate authentication.
/// PEM data is passed as pointer+length since PEM may contain embedded nulls.
/// All inputs are duped into FFI-owned memory (see softether_create).
export fn softether_create_certificate(
    address: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    cert_pem: [*]const u8,
    cert_pem_len: u32,
    key_pem: [*]const u8,
    key_pem_len: u32,
) ?*VpnClient {
    const server_in = std.mem.span(address);
    const hub_in = std.mem.span(hub);

    if (server_in.len == 0 or hub_in.len == 0 or cert_pem_len == 0 or key_pem_len == 0) {
        return null;
    }

    const server_slice = ffi_allocator.dupe(u8, server_in) catch return null;
    const hub_slice = ffi_allocator.dupe(u8, hub_in) catch return null;
    const cert_slice = ffi_allocator.dupe(u8, cert_pem[0..cert_pem_len]) catch return null;
    const key_slice = ffi_allocator.dupe(u8, key_pem[0..key_pem_len]) catch return null;

    var config = defaultClientConfig();
    config.server_address = server_slice;
    config.server_port = port;
    config.hub_name = hub_slice;
    config.auth = .{ .certificate = .{
        .cert_data = cert_slice,
        .key_data = key_slice,
    } };

    const ptr = ffi_allocator.create(VpnClient) catch return null;
    ptr.* = VpnClient.init(ffi_allocator, config);
    return ptr;
}

/// Destroy a VPN client and free all resources.
export fn softether_destroy(client: ?*VpnClient) void {
    const c = client orelse return;
    // Free FFI-owned callback context before deinit. Holding the lock guards
    // against a late event firing into a half-freed context, though deinit
    // also tears down the worker thread that would dispatch one.
    c.mutex.lock();
    clearFfiCallbackCtxLocked(c);
    c.mutex.unlock();
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

/// Poll until the native data-loop thread (spawned by `softether_connect`)
/// exits. Blocking — call from a background worker.
///
/// The actual data loop runs on a dedicated native pthread with its own
/// stack. This function only waits for it to finish, then returns.
export fn softether_run_data_loop(client: ?*VpnClient) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    // Quick check: was the data loop thread ever spawned?
    {
        c.mutex.lock();
        defer c.mutex.unlock();
        if (c.data_loop_thread == null) {
            return @intFromEnum(SoftetherError.not_connected);
        }
    }
    // Poll data_loop_running without holding the mutex (performDisconnect
    // needs the mutex to join the thread and close resources).
    while (@atomicLoad(bool, &c.data_loop_running, .acquire)) {
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
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

/// Get bridge-mode stats (zeroed when bridge mode is not active or the
/// pump is not running). Returns 0 on success.
export fn softether_get_bridge_stats(client: ?*const VpnClient, out: ?*CBridgeStats) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    const s = out orelse return @intFromEnum(SoftetherError.invalid_argument);
    // Contract: zeroed when bridge mode is not active or the pump is not
    // running (the pump also resets the cached snapshot at teardown, but
    // the flag guard covers the pre-start / post-stop windows too).
    const st = if (c.session_mode == .bridge and c.data_loop_running) c.bridge_stats else lib.bridge.loop.BridgeStats{};
    s.* = .{
        .fdb_entries = st.fdb_entries,
        .forwarded = st.forwarded,
        .flooded = st.flooded,
        .blocked = st.blocked,
        .lan_rx_pkts = st.lan_rx_pkts,
        .lan_tx_pkts = st.lan_tx_pkts,
        .lan_rx_bytes = st.lan_rx_bytes,
        .lan_tx_bytes = st.lan_tx_bytes,
        .drops = st.drops,
        .session_rx = st.session_rx,
        .session_tx = st.session_tx,
        .session_tx_errors = st.session_tx_errors,
    };
    return 0;
}

/// Get monitor-mode stats (zeroed when monitor mode is not active or the
/// pump is not running). Returns 0 on success.
export fn softether_get_monitor_stats(client: ?*const VpnClient, out: ?*CMonitorStats) c_int {
    const c = client orelse return @intFromEnum(SoftetherError.invalid_argument);
    const s = out orelse return @intFromEnum(SoftetherError.invalid_argument);
    // Contract: zeroed when monitor mode is not active or the pump is not
    // running (the pump also resets the cached snapshot at teardown, but
    // the flag guard covers the pre-start / post-stop windows too).
    const st = if (c.session_mode == .monitor and c.data_loop_running) c.monitor_stats else lib.monitor.MonitorStats{};
    s.* = .{
        .frames_captured = st.frames_captured,
        .frames_dropped = st.frames_dropped,
        .bytes_captured = st.bytes_captured,
        .ring_used = st.ring_used,
        .pcap_records = st.pcap_records,
        .pcap_bytes = st.pcap_bytes,
        .pcap_write_errors = st.pcap_write_errors,
    };
    return 0;
}

/// Frames currently held in the monitor ring; 0 means an empty ring.
/// Returns -1 when the client is invalid or the monitor pump is not
/// running.
export fn softether_monitor_frame_count(client: ?*VpnClient) i64 {
    const c = client orelse return -1;
    c.mutex.lock();
    defer c.mutex.unlock();
    const loop = c.monitor_loop orelse return -1;
    return loop.frameCount();
}

/// Copy one captured frame (index 0 = oldest) into `out`. Returns the
/// number of bytes copied (0 when index is out of range or `out_cap` is
/// 0), or -1 when the client is invalid or the monitor pump is not
/// running. The frame data is copied under the loop mutex, so it is a
/// stable snapshot even while the pump keeps capturing.
export fn softether_monitor_get_frame(client: ?*VpnClient, index: i64, out: ?[*]u8, out_cap: usize) i64 {
    const c = client orelse return -1;
    if (index < 0) return 0;
    const dst = (out orelse return 0)[0..out_cap];
    if (dst.len == 0) return 0;
    c.mutex.lock();
    defer c.mutex.unlock();
    const loop = c.monitor_loop orelse return -1;
    return @intCast(loop.readFrame(@intCast(index), dst) orelse 0);
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
/// Get first DHCP-assigned DNS server (host byte order u32, 0 if none).
export fn softether_get_assigned_dns1(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    return c.getAssignedDns1();
}

/// Get second DHCP-assigned DNS server (host byte order u32, 0 if none).
export fn softether_get_assigned_dns2(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    return c.getAssignedDns2();
}

export fn softether_get_assigned_mask(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    return c.getAssignedMask();
}

/// Get the IPv4 server address this client actually connected to (host byte
/// order u32, 0 if not yet connected or if redirected to an IPv6 target).
///
/// May differ from the configured server after a cluster-redirect — in that
/// case this returns the physical backend's IP, while the configured server
/// (a load-balancer hostname) is the entry point. Letting the host app log
/// this on every connect makes silent redirect-target rotations visible.
export fn softether_get_effective_server_ip(client: ?*const VpnClient) u32 {
    const c = client orelse return 0;
    const addr = c.effective_server_ip orelse return 0;
    if (addr.any.family != std.posix.AF.INET) return 0;
    return addr.in.sa.addr;
}

/// Get the last error code for a failed connection. Returns the SoftetherError
/// enum value (negative on error, 0 = no error recorded).
/// Callers should read this after a failed connect() to get an actionable
/// error code rather than relying on generic "connection failed" messages.
export fn softether_get_last_error(client: ?*const VpnClient) c_int {
    const c = client orelse return 0;
    return @intFromEnum(mapClientError(c.last_error orelse return 0));
}

// ============================================================================
// Configuration
// ============================================================================

/// Set encryption on/off. Must be called before connect().
export fn softether_set_encryption(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.use_encrypt = enabled;
}

/// Set compression on/off. Must be called before connect().
export fn softether_set_compression(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.use_compress = enabled;
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
    const tls = @import("mayaqua/network/tls.zig");
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
const tls_mod = @import("mayaqua/network/tls.zig");

export fn softether_set_tcp_dial_callback(cb: ?tls_mod.ExternalTcpDialFn) void {
    tls_mod.external_tcp_dial = cb;
    if (cb == null) {
        std.log.info("softether_set_tcp_dial_callback: cleared (using POSIX connect)", .{});
    } else {
        std.log.info("softether_set_tcp_dial_callback: registered (host will dial)", .{});
    }
}

/// Register an Android VpnService.protect() callback.
///
/// On Android, the VpnService creates a TUN device and routes ALL traffic
/// through it. The VPN client's own TLS connections to the server would be
/// caught in this routing loop — the TLS handshake goes through the TUN,
/// which isn't connected to anything yet → instant failure. VpnService.protect()
/// exempts a socket fd from the VPN routing so it goes through the physical
/// network interface instead.
///
/// The Kotlin host calls this with a JNI-upcall wrapper that invokes
/// VpnService.protect(fd). The callback returns the fd (unchanged) on success
/// or -1 if protect failed. Pass null to clear.
export fn softether_set_android_protect(cb: ?tls_mod.AndroidProtectFn) void {
    tls_mod.android_protect_fn = cb;
}

/// Set default route (route all traffic through VPN). Must be called before connect().
export fn softether_set_default_route(client: ?*VpnClient, enabled: bool) void {
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

/// Set UDP acceleration on/off. Must be called before connect().
export fn softether_set_udp_acceleration(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.udp_acceleration = enabled;
}

/// Set connection timeout in milliseconds. Must be called before connect().
export fn softether_set_connect_timeout(client: ?*VpnClient, ms: u32) void {
    const c = client orelse return;
    c.config.connect_timeout_ms = ms;
}

/// Set TCP_NODELAY (disable Nagle's algorithm for low latency).
/// Must be called before connect(). Default: true.
export fn softether_set_tcp_nodelay(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.tcp_nodelay = enabled;
}

/// Set read timeout in milliseconds. Must be called before connect().
export fn softether_set_read_timeout(client: ?*VpnClient, ms: u32) void {
    const c = client orelse return;
    c.config.read_timeout_ms = ms;
}

/// Set keepalive interval in milliseconds. Must be called before connect().
export fn softether_set_keepalive_interval(client: ?*VpnClient, ms: u32) void {
    const c = client orelse return;
    c.config.keepalive_interval_ms = ms;
}

/// Set the gratuitous ARP interval in milliseconds.
/// Must be called before connect().
export fn softether_set_garp_interval(client: ?*VpnClient, ms: u32) void {
    const c = client orelse return;
    c.config.garp_interval_ms = ms;
}

/// Set IP version preference. Must be called before connect().
/// version: 0=try both, 4=IPv4 only, 6=IPv6 only.
export fn softether_set_ip_version(client: ?*VpnClient, version: c_int) void {
    const c = client orelse return;
    c.config.ip_version = switch (version) {
        4 => .v4,
        6 => .v6,
        else => null,
    };
}

/// Switch to plain password auth (authtype=2) instead of hashed.
/// Must be called BEFORE connect(). If not called, the client uses
/// the default hashed-password auth (authtype=1) created at init.
export fn softether_set_plain_password(client: ?*VpnClient) void {
    const c = client orelse return;
    if (c.config.auth == .password) {
        const pw = c.config.auth.password;
        c.config.auth = .{ .plain_password = .{
            .username = pw.username,
            .password = pw.password,
        } };
    }
}

/// Set proxy configuration. Must be called before connect().
/// proxy_type: 0=none (clears), 1=HTTP, 2=SOCKS5.
/// host/port/username/password are ignored when proxy_type is 0.
/// Strings are duped into FFI-owned memory (see softether_create for rationale).
export fn softether_set_proxy(
    client: ?*VpnClient,
    proxy_type: c_int,
    host: [*:0]const u8,
    port: u16,
    username: [*:0]const u8,
    password: [*:0]const u8,
) void {
    const c = client orelse return;
    if (proxy_type == 0) {
        c.config.proxy = null;
        return;
    }
    const host_in = std.mem.span(host);
    if (host_in.len == 0) {
        c.config.proxy = null;
        return;
    }
    const proxy_type_enum: tls_mod.ProxyConfig.ProxyType = switch (proxy_type) {
        1 => .http,
        2 => .socks5,
        else => return,
    };
    const host_slice = ffi_allocator.dupe(u8, host_in) catch return;
    var username_slice: ?[]const u8 = null;
    var password_slice: ?[]const u8 = null;
    const username_str = std.mem.span(username);
    const password_str = std.mem.span(password);
    if (username_str.len > 0) {
        username_slice = ffi_allocator.dupe(u8, username_str) catch return;
    }
    if (password_str.len > 0) {
        password_slice = ffi_allocator.dupe(u8, password_str) catch return;
    }
    c.config.proxy = .{
        .host = host_slice,
        .port = port,
        .username = username_slice,
        .password = password_slice,
        .proxy_type = proxy_type_enum,
    };
}

// ============================================================================
// Routing configuration setters
// ============================================================================

/// Set whether to accept routes pushed by the VPN server (DHCP option 121/249).
/// Must be called before connect().
export fn softether_set_accept_pushed_routes(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.routing.accept_pushed_routes = enabled;
}

/// Set whether custom split-tunnel routes are enabled.
/// When enabled, only the networks listed in ipv4_include/ipv6_include
/// are routed through the VPN (instead of a full default-route tunnel).
/// Must be called before connect().
export fn softether_set_enable_custom_routes(client: ?*VpnClient, enabled: bool) void {
    const c = client orelse return;
    c.config.routing.enable_custom_routes = enabled;
}

/// Set IPv4 routes to INCLUDE (newline-separated CIDR notations).
/// Only used when enable_custom_routes is true. Pass NULL or "" to clear.
/// String is duped into FFI-owned memory.
export fn softether_set_ipv4_include(client: ?*VpnClient, routes: [*:0]const u8) void {
    const c = client orelse return;
    const routes_in = std.mem.span(routes);
    if (routes_in.len == 0) {
        c.config.routing.ipv4_include = null;
        return;
    }
    c.config.routing.ipv4_include = ffi_allocator.dupe(u8, routes_in) catch return;
}

/// Set IPv4 routes to EXCLUDE (newline-separated CIDR notations).
/// Only used when enable_custom_routes is true. Pass NULL or "" to clear.
/// String is duped into FFI-owned memory.
export fn softether_set_ipv4_exclude(client: ?*VpnClient, routes: [*:0]const u8) void {
    const c = client orelse return;
    const routes_in = std.mem.span(routes);
    if (routes_in.len == 0) {
        c.config.routing.ipv4_exclude = null;
        return;
    }
    c.config.routing.ipv4_exclude = ffi_allocator.dupe(u8, routes_in) catch return;
}

/// Set IPv6 routes to INCLUDE (newline-separated CIDR notations).
/// Only used when enable_custom_routes is true. Pass NULL or "" to clear.
/// String is duped into FFI-owned memory.
export fn softether_set_ipv6_include(client: ?*VpnClient, routes: [*:0]const u8) void {
    const c = client orelse return;
    const routes_in = std.mem.span(routes);
    if (routes_in.len == 0) {
        c.config.routing.ipv6_include = null;
        return;
    }
    c.config.routing.ipv6_include = ffi_allocator.dupe(u8, routes_in) catch return;
}

/// Set IPv6 routes to EXCLUDE (newline-separated CIDR notations).
/// Only used when enable_custom_routes is true. Pass NULL or "" to clear.
/// String is duped into FFI-owned memory.
export fn softether_set_ipv6_exclude(client: ?*VpnClient, routes: [*:0]const u8) void {
    const c = client orelse return;
    const routes_in = std.mem.span(routes);
    if (routes_in.len == 0) {
        c.config.routing.ipv6_exclude = null;
        return;
    }
    c.config.routing.ipv6_exclude = ffi_allocator.dupe(u8, routes_in) catch return;
}

/// Set an external tunnel file descriptor (for iOS/Android).
/// On mobile, the OS creates the TUN device and provides an fd.
/// Must be called before connect().
export fn softether_set_tunnel_fd(client: ?*VpnClient, fd: i32) void {
    const c = client orelse return;
    c.config.tunnel_fd = fd;
}

/// Set separate tunnel file descriptors for UL (read) and DL (write) directions.
/// Used on iOS with dual socketpairs to prevent upload from starving download.
/// dl_fd = DL bridge fd (Zig → Swift, for writing decrypted packets to utun).
/// ul_fd = UL bridge fd (Swift → Zig, for reading upload packets from utun).
/// Must be called before connect(). Overrides softether_set_tunnel_fd().
export fn softether_set_tunnel_fds(client: ?*VpnClient, dl_fd: i32, ul_fd: i32) void {
    const c = client orelse return;
    c.config.tunnel_rx_fd = ul_fd;
    c.config.tunnel_tx_fd = dl_fd;
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
// Static IP configuration setters
// ============================================================================

/// Set static IPv4 address. Must be called before connect().
export fn softether_set_static_ipv4(client: ?*VpnClient, addr: [*:0]const u8) void {
    const c = client orelse return;
    const s = std.mem.span(addr);
    if (s.len == 0) {
        if (c.config.static_ip) |*si| si.ipv4_address = null;
        return;
    }
    if (c.config.static_ip == null) c.config.static_ip = .{};
    c.config.static_ip.?.ipv4_address = ffi_allocator.dupe(u8, s) catch return;
}

/// Set static IPv4 netmask. Must be called before connect().
export fn softether_set_static_ipv4_netmask(client: ?*VpnClient, addr: [*:0]const u8) void {
    const c = client orelse return;
    const s = std.mem.span(addr);
    if (s.len == 0) {
        if (c.config.static_ip) |*si| si.ipv4_netmask = null;
        return;
    }
    if (c.config.static_ip == null) c.config.static_ip = .{};
    c.config.static_ip.?.ipv4_netmask = ffi_allocator.dupe(u8, s) catch return;
}

/// Set static IPv4 gateway. Must be called before connect().
export fn softether_set_static_ipv4_gateway(client: ?*VpnClient, addr: [*:0]const u8) void {
    const c = client orelse return;
    const s = std.mem.span(addr);
    if (s.len == 0) {
        if (c.config.static_ip) |*si| si.ipv4_gateway = null;
        return;
    }
    if (c.config.static_ip == null) c.config.static_ip = .{};
    c.config.static_ip.?.ipv4_gateway = ffi_allocator.dupe(u8, s) catch return;
}

/// Set static IPv6 address. Must be called before connect().
export fn softether_set_static_ipv6(client: ?*VpnClient, addr: [*:0]const u8) void {
    const c = client orelse return;
    const s = std.mem.span(addr);
    if (s.len == 0) {
        if (c.config.static_ip) |*si| si.ipv6_address = null;
        return;
    }
    if (c.config.static_ip == null) c.config.static_ip = .{};
    c.config.static_ip.?.ipv6_address = ffi_allocator.dupe(u8, s) catch return;
}

/// Set static IPv6 prefix length. Must be called before connect().
export fn softether_set_static_ipv6_prefix(client: ?*VpnClient, prefix: u8) void {
    const c = client orelse return;
    if (c.config.static_ip == null) c.config.static_ip = .{};
    c.config.static_ip.?.ipv6_prefix_len = prefix;
}

/// Set static IPv6 gateway. Must be called before connect().
export fn softether_set_static_ipv6_gateway(client: ?*VpnClient, addr: [*:0]const u8) void {
    const c = client orelse return;
    const s = std.mem.span(addr);
    if (s.len == 0) {
        if (c.config.static_ip) |*si| si.ipv6_gateway = null;
        return;
    }
    if (c.config.static_ip == null) c.config.static_ip = .{};
    c.config.static_ip.?.ipv6_gateway = ffi_allocator.dupe(u8, s) catch return;
}

/// Set DNS servers (comma-separated). Must be called before connect().
/// Set the optional hostname for TLS/SNI, HTTP Host headers, and protocol
/// semantics. When set, the library uses this for SNI instead of the address.
/// Pass an empty string to clear (nulls out server_hostname).
export fn softether_set_hostname(client: ?*VpnClient, hostname: [*:0]const u8) void {
    const c = client orelse return;
    const host_in = std.mem.span(hostname);
    if (host_in.len == 0) {
        c.config.server_hostname = null;
        return;
    }
    const host_slice = ffi_allocator.dupe(u8, host_in) catch return;
    c.config.server_hostname = host_slice;
}

export fn softether_set_dns_servers(client: ?*VpnClient, servers: [*:0]const u8) void {
    const c = client orelse return;
    const servers_in = std.mem.span(servers);

    // Free the previously set list only if this setter allocated it. Configs
    // supplied through VpnClient.init are borrowed and must never be freed.
    const freeOldOwned = struct {
        fn f(si: *client_mod.StaticIpConfig, allocator: Allocator) void {
            if (!si.dns_servers_owned) return;
            if (si.dns_servers) |list| {
                for (list) |srv| allocator.free(srv);
                allocator.free(list);
            }
            si.dns_servers = null;
            si.dns_servers_owned = false;
        }
    }.f;

    if (servers_in.len == 0) {
        if (c.config.static_ip) |*si| freeOldOwned(si, c.allocator);
        return;
    }
    if (c.config.static_ip == null) c.config.static_ip = .{};

    var count: usize = 0;
    var it = std.mem.splitScalar(u8, servers_in, ',');
    while (it.next()) |part| {
        if (std.mem.trim(u8, part, " ").len > 0) count += 1;
    }
    if (count == 0) {
        freeOldOwned(&c.config.static_ip.?, c.allocator);
        return;
    }

    const slices = c.allocator.alloc([]const u8, count) catch return;
    var idx: usize = 0;
    var it2 = std.mem.splitScalar(u8, servers_in, ',');
    while (it2.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " ");
        if (trimmed.len > 0) {
            slices[idx] = c.allocator.dupe(u8, trimmed) catch {
                // Free already-allocated slices before returning
                for (slices[0..idx]) |srv| c.allocator.free(srv);
                c.allocator.free(slices);
                return;
            };
            idx += 1;
        }
    }

    // Swap old list with new one, then free old (only if owned by us)
    const old_dns = c.config.static_ip.?.dns_servers;
    const old_owned = c.config.static_ip.?.dns_servers_owned;
    c.config.static_ip.?.dns_servers = slices;
    c.config.static_ip.?.dns_servers_owned = true;
    if (old_owned) {
        if (old_dns) |list| {
            for (list) |srv| c.allocator.free(srv);
            c.allocator.free(list);
        }
    }
}

/// Set log level (0=err, 1=warn, 2=info, 3=debug).
/// Values 4–5 from the legacy 0–5 range are clamped to 3 (debug).
/// Delegates to the library-level softether_set_log_level_global.
export fn softether_set_log_level_client(client: ?*VpnClient, level: c_int) void {
    _ = client;
    softether_set_log_level_global(level);
}

// ============================================================================
// Protocol Fingerprint Configuration Setters
// ============================================================================

/// Override the client identification string sent to the server.
/// Pass NULL or "" to restore the default ("SoftEther VPN Client").
export fn softether_set_client_str(client: ?*VpnClient, str: [*:0]const u8) void {
    const c = client orelse return;
    const s = std.mem.span(str);
    if (c.config.fingerprint == null) c.config.fingerprint = .{};
    if (s.len == 0) {
        c.config.fingerprint.?.client_str = null;
        return;
    }
    c.config.fingerprint.?.client_str = ffi_allocator.dupe(u8, s) catch return;
}

/// Override the client version number sent to the server.
/// Pass 0 to restore the default (444).
export fn softether_set_client_ver(client: ?*VpnClient, ver: u32) void {
    const c = client orelse return;
    if (ver == 0) {
        if (c.config.fingerprint) |*fp| fp.client_ver = null;
        return;
    }
    if (c.config.fingerprint == null) c.config.fingerprint = .{};
    c.config.fingerprint.?.client_ver = ver;
}

/// Override the client build number sent to the server.
/// Pass 0 to restore the default (9807).
export fn softether_set_client_build(client: ?*VpnClient, build: u32) void {
    const c = client orelse return;
    if (build == 0) {
        if (c.config.fingerprint) |*fp| fp.client_build = null;
        return;
    }
    if (c.config.fingerprint == null) c.config.fingerprint = .{};
    c.config.fingerprint.?.client_build = build;
}

/// Override OS name, version, and title sent to the server.
/// All three must be non-NULL to take effect; pass NULL to clear.
export fn softether_set_os_info(client: ?*VpnClient, name: [*:0]const u8, version: [*:0]const u8, title: [*:0]const u8) void {
    const c = client orelse return;
    const name_s = std.mem.span(name);
    const ver_s = std.mem.span(version);
    const title_s = std.mem.span(title);
    if (name_s.len == 0 or ver_s.len == 0 or title_s.len == 0) {
        if (c.config.fingerprint) |*fp| {
            fp.os_name = null;
            fp.os_version = null;
            fp.os_title = null;
        }
        return;
    }
    if (c.config.fingerprint == null) c.config.fingerprint = .{};
    c.config.fingerprint.?.os_name = ffi_allocator.dupe(u8, name_s) catch return;
    c.config.fingerprint.?.os_version = ffi_allocator.dupe(u8, ver_s) catch return;
    c.config.fingerprint.?.os_title = ffi_allocator.dupe(u8, title_s) catch return;
}

// ============================================================================
// Event Callback
// ============================================================================

/// Per-client FFI callback context. Heap-allocated so multiple VpnClient
/// instances can each carry their own C callback + user_data without
/// stomping over a shared global.
const FfiCallbackCtx = struct {
    c_callback: *const fn (CEventType, CState, ?*anyopaque) callconv(.c) void,
    c_user_data: ?*anyopaque,
};

/// Dispatcher passed to VpnClient.setEventCallback. The Zig-level user_data
/// pointer carries the per-client FfiCallbackCtx.
fn ffiDispatchEvent(event: client_mod.ClientEvent, ud: ?*anyopaque) void {
    const ctx_ptr = ud orelse return;
    const ctx = @as(*FfiCallbackCtx, @ptrCast(@alignCast(ctx_ptr)));
    const event_type: CEventType = switch (event) {
        .state_changed => .state_changed,
        .connected => .connected,
        .disconnected => .disconnected,
        .stats_updated => .stats_updated,
        .error_occurred => .error_occurred,
        else => {
            std.log.warn("ffiDispatchEvent: unhandled event type (new variant added?)", .{});
            return;
        },
    };
    const state: CState = switch (event) {
        .state_changed => |sc| mapState(sc.new_state),
        .connected => CState.connected,
        .disconnected => CState.disconnected,
        else => CState.disconnected,
    };
    ctx.c_callback(event_type, state, ctx.c_user_data);
}

/// Free any FFI-owned callback context attached to the client and clear the
/// callback slot. Safe to call when none is set. Caller must hold c.mutex.
fn clearFfiCallbackCtxLocked(c: *VpnClient) void {
    if (c.event_callback) |cb| {
        // Only FFI-installed callbacks point at ffiDispatchEvent — Zig-native
        // consumers attach their own function pointers and own their user_data.
        if (cb == ffiDispatchEvent) {
            if (c.event_user_data) |old| {
                const old_ctx = @as(*FfiCallbackCtx, @ptrCast(@alignCast(old)));
                ffi_allocator.destroy(old_ctx);
            }
        }
    }
    c.event_callback = null;
    c.event_user_data = null;
}

/// Register an event callback. Pass null to unregister.
///
/// Each client carries its own heap-allocated context, so multiple
/// simultaneously-live clients each route events to their own callback.
export fn softether_set_event_callback(
    client: ?*VpnClient,
    callback: CEventCallback,
    user_data: ?*anyopaque,
) void {
    const c = client orelse return;

    c.mutex.lock();
    defer c.mutex.unlock();

    clearFfiCallbackCtxLocked(c);

    if (callback) |cb| {
        const ctx = ffi_allocator.create(FfiCallbackCtx) catch return;
        ctx.* = .{ .c_callback = cb, .c_user_data = user_data };
        c.event_callback = ffiDispatchEvent;
        c.event_user_data = @as(*anyopaque, @ptrCast(ctx));
    }
}

// ============================================================================
// Version
// ============================================================================

/// Get library version string. Returns pointer to static string.
export fn softether_version() [*:0]const u8 {
    // lib.version is a []const u8 slice, but the underlying bytes are
    // a null-terminated string literal from build_options. Recover the
    // sentinel pointer via @ptrCast.
    return @ptrCast(lib.version.ptr);
}

// ============================================================================
// NIC enumeration
// ============================================================================

/// C-ABI NIC entry (softether_nic_info in include/softether.h).
pub const SoftEtherNicInfo = extern struct {
    /// Interface name: POSIX ifname (≤15 chars) or the Windows adapter GUID
    /// string ("{...}", ≤39 chars). NUL-padded.
    name: [64]u8,
    /// Hardware address; zeroed when the interface has none (e.g. utun).
    mac: [6]u8,
    /// Platform interface index.
    index: u32,
};

/// Enumerate the host's network interfaces.
///
/// Fills `out[0..cap]` with {name, mac, index} entries, loopback excluded.
/// Returns the number of entries written; if the host has more than `cap`
/// interfaces the return value is `-(full_count + 2)` (snprintf-style,
/// offset past the reserved error codes), so callers can grow their buffer
/// and retry. Returns -1 on invalid arguments (null out, cap <= 0) and -2
/// on enumeration failure.
///
/// Stable id semantics (see include/softether.h): `mac` — or the Windows
/// GUID in `name` — is the stable identity across interface renames; POSIX
/// `name` and `index` alone are not stable. Interfaces without a hardware
/// address carry a zeroed `mac` and have NO stable identity (each
/// enumeration may order them differently; key on `name` + `index` only
/// for the duration of one enumeration).
export fn softether_list_interfaces(out: ?[*]SoftEtherNicInfo, cap: c_int) c_int {
    if (out == null or cap <= 0) return -1;

    const adapter_mod = @import("adapter/mod.zig");
    var list = adapter_mod.nic_enumerate.listNics(ffi_allocator) catch return -2;
    defer list.deinit();

    const n = @min(list.items.len, @as(usize, @intCast(cap)));
    for (list.items[0..n], 0..) |item, i| {
        const dst = &out.?[i];
        @memset(&dst.name, 0);
        const name_len = @min(item.name.len, dst.name.len);
        @memcpy(dst.name[0..name_len], item.name[0..name_len]);
        dst.mac = item.mac orelse [_]u8{0} ** 6;
        dst.index = item.index;
    }

    if (list.items.len > n) {
        // Truncated: report the full count as a negative, offset by 2 so
        // the value can never collide with the reserved -1/-2 error codes
        // (a host with exactly 2 interfaces and cap=1 must not look like
        // an enumeration failure).
        const full = @min(list.items.len, @as(usize, std.math.maxInt(c_int)));
        return -@as(c_int, @intCast(full)) - 2;
    }
    return @intCast(n);
}

// ============================================================================
// Network mode (L2 bridge proposal §5.1) — runtime support landed: bridge
// (issue #56) and monitor (issue #55) both run their own data pumps:
// bridge → runBridgeLoopThread (AF_PACKET ingress), monitor →
// runMonitorLoopThread (mirror-only capture). All three setters are safe
// to call before connect(); the connect path branches on the mode flag.
// ============================================================================

/// Set the network operating mode: 0=client (default), 1=bridge, 2=monitor.
/// Invalid values are ignored. Storage-only: this updates the client's
/// config AND the session flag; the connect path branches on the flag.
/// bridge mode is Linux-only (AF_PACKET); monitor mode is portable and
/// captures mirrored hub frames into a bounded ring (+ optional PCAP).
/// If called mid-session (after connect), the running loop is unaffected
/// — the flag applies on the next connect.
export fn softether_set_network_mode(client: ?*VpnClient, mode: c_int) void {
    const c = client orelse return;
    const NetworkMode = client_mod.NetworkMode;
    const parsed: NetworkMode = switch (mode) {
        0 => NetworkMode.client,
        1 => NetworkMode.bridge,
        2 => NetworkMode.monitor,
        else => return,
    };
    // Lock the client mutex so a setter racing with connect()'s mode read
    // (and with getNetworkMode) cannot observe a torn/inconsistent mode.
    c.mutex.lock();
    defer c.mutex.unlock();
    c.config.mode = parsed;
    c.network_mode = parsed;
}

/// Append an ingress interface to the bridge list (deduped, owned copy).
/// Returns 0 on success, -1 on invalid client / empty name / OOM.
/// The resulting list is fully owned by the client: every prior entry is
/// re-duplicated so mixed borrowed/owned states cannot arise.
export fn softether_add_ingress_interface(client: ?*VpnClient, name: ?[*:0]const u8) c_int {
    const c = client orelse return -1;
    const iface = std.mem.span(name orelse return -1);
    if (iface.len == 0) return -1;

    for (c.config.bridge.ingress_ifs) |existing| {
        if (std.mem.eql(u8, existing, iface)) return 0;
    }

    const old = c.config.bridge.ingress_ifs;
    const old_owned = c.config.bridge.ingress_ifs_owned;

    const new_list = c.allocator.alloc([]const u8, old.len + 1) catch return -1;
    var i: usize = 0;
    for (old) |existing| {
        new_list[i] = c.allocator.dupe(u8, existing) catch {
            for (new_list[0..i]) |e| c.allocator.free(e);
            c.allocator.free(new_list);
            return -1;
        };
        i += 1;
    }
    new_list[old.len] = c.allocator.dupe(u8, iface) catch {
        for (new_list[0..i]) |e| c.allocator.free(e);
        c.allocator.free(new_list);
        return -1;
    };

    c.config.bridge.ingress_ifs = new_list;
    c.config.bridge.ingress_ifs_owned = true;
    if (old_owned) {
        for (old) |e| c.allocator.free(e);
        c.allocator.free(old);
    }
    return 0;
}

/// Remove an ingress interface from the bridge list.
/// Returns 0 on success (or if not present), -1 on invalid client / OOM.
export fn softether_remove_ingress_interface(client: ?*VpnClient, name: ?[*:0]const u8) c_int {
    const c = client orelse return -1;
    const iface = std.mem.span(name orelse return -1);
    const old = c.config.bridge.ingress_ifs;
    const old_owned = c.config.bridge.ingress_ifs_owned;

    var keep: usize = 0;
    for (old) |existing| {
        if (!std.mem.eql(u8, existing, iface)) keep += 1;
    }
    if (keep == old.len) return 0; // not present

    const new_list = c.allocator.alloc([]const u8, keep) catch return -1;
    var j: usize = 0;
    for (old) |existing| {
        if (std.mem.eql(u8, existing, iface)) continue;
        new_list[j] = c.allocator.dupe(u8, existing) catch {
            for (new_list[0..j]) |e| c.allocator.free(e);
            c.allocator.free(new_list);
            return -1;
        };
        j += 1;
    }

    c.config.bridge.ingress_ifs = new_list;
    c.config.bridge.ingress_ifs_owned = true;
    if (old_owned) {
        for (old) |e| c.allocator.free(e);
        c.allocator.free(old);
    }
    return 0;
}

/// Set the monitor-mode PCAP capture path (owned copy; "" or NULL clears
/// it). The file is opened when the monitor pump starts (next connect);
/// a bad path aborts the monitor session with the raw file error.
/// Returns 0 on success, -1 on invalid client / OOM.
export fn softether_set_monitor_pcap(client: ?*VpnClient, path: ?[*:0]const u8) c_int {
    const c = client orelse return -1;
    const s = std.mem.span(path orelse "");

    if (c.config.monitor.pcap_file_owned) {
        if (c.config.monitor.pcap_file) |f| c.allocator.free(f);
        c.config.monitor.pcap_file = null;
        c.config.monitor.pcap_file_owned = false;
    }
    if (s.len == 0) return 0; // cleared

    c.config.monitor.pcap_file = c.allocator.dupe(u8, s) catch return -1;
    c.config.monitor.pcap_file_owned = true;
    return 0;
}

// ============================================================================
// Tests
// ============================================================================

test "ffi error mapping" {
    const err = mapClientError(ClientError.ConnectionFailed);
    try std.testing.expectEqual(SoftetherError.connection_failed, err);
}

test "softether_list_interfaces enumerates host NICs" {
    var buf: [64]SoftEtherNicInfo = undefined;
    const n = softether_list_interfaces(&buf, buf.len);
    try std.testing.expect(n > 0);

    // Entries must carry a name, a plausible index, and a MAC or zeros.
    for (buf[0..@intCast(n)]) |entry| {
        try std.testing.expect(entry.name[0] != 0);
        // Loopback must have been filtered out on all platforms.
        try std.testing.expect(!std.mem.startsWith(u8, &entry.name, "lo"));
        try std.testing.expect(std.mem.indexOfScalar(u8, &entry.name, 0) != null); // NUL-terminated
    }
}

test "softether_list_interfaces rejects invalid arguments" {
    var buf: [4]SoftEtherNicInfo = undefined;
    try std.testing.expectEqual(@as(c_int, -1), softether_list_interfaces(null, 4));
    try std.testing.expectEqual(@as(c_int, -1), softether_list_interfaces(&buf, 0));
    try std.testing.expectEqual(@as(c_int, -1), softether_list_interfaces(&buf, -3));
}

test "softether_list_interfaces truncation reports full count" {
    // cap=1 must either fit the host (returns 1) or report truncation
    // with the offset encoding -(full + 2) — never -1/-2.
    var one: [1]SoftEtherNicInfo = undefined;
    const r = softether_list_interfaces(&one, 1);
    try std.testing.expect(r == 1 or r < -2);
    if (r == 1) {
        try std.testing.expect(one[0].name[0] != 0);
    } else {
        // The exact amount is unknowable in a unit test, but the encoding
        // must be -(full + 2): reconstruct and sanity-check the sign.
        try std.testing.expect(r <= -4); // full >= 2 always when truncated
    }
}

test "ffi callback context routes to per-client user_data" {
    // Two distinct clients with two distinct callbacks must each receive
    // their own user_data, not a shared global slot.
    const Counters = struct {
        var a_calls: u32 = 0;
        var b_calls: u32 = 0;
        var last_a_ud: ?*anyopaque = null;
        var last_b_ud: ?*anyopaque = null;

        fn cbA(_: CEventType, _: CState, ud: ?*anyopaque) callconv(.c) void {
            a_calls += 1;
            last_a_ud = ud;
        }
        fn cbB(_: CEventType, _: CState, ud: ?*anyopaque) callconv(.c) void {
            b_calls += 1;
            last_b_ud = ud;
        }
    };
    Counters.a_calls = 0;
    Counters.b_calls = 0;
    Counters.last_a_ud = null;
    Counters.last_b_ud = null;

    var marker_a: u32 = 0xAAAA;
    var marker_b: u32 = 0xBBBB;

    var client_a = VpnClient.init(std.testing.allocator, .{
        .server_address = "a",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer client_a.deinit();

    var client_b = VpnClient.init(std.testing.allocator, .{
        .server_address = "b",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer client_b.deinit();

    softether_set_event_callback(&client_a, Counters.cbA, @ptrCast(&marker_a));
    softether_set_event_callback(&client_b, Counters.cbB, @ptrCast(&marker_b));

    // Dispatch one event into each client. The wrapper must route to the
    // correct C callback with the correct user_data pointer.
    const dispatch_a = client_a.event_callback.?;
    const dispatch_b = client_b.event_callback.?;
    dispatch_a(.{ .connected = .{ .server_ip = 0, .assigned_ip = 0, .gateway_ip = 0 } }, client_a.event_user_data);
    dispatch_b(.{ .connected = .{ .server_ip = 0, .assigned_ip = 0, .gateway_ip = 0 } }, client_b.event_user_data);

    try std.testing.expectEqual(@as(u32, 1), Counters.a_calls);
    try std.testing.expectEqual(@as(u32, 1), Counters.b_calls);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrCast(&marker_a)), Counters.last_a_ud);
    try std.testing.expectEqual(@as(?*anyopaque, @ptrCast(&marker_b)), Counters.last_b_ud);

    // Unregister both — must free the heap-allocated contexts (verified by
    // testing.allocator: a leak would fail this test).
    softether_set_event_callback(&client_a, null, null);
    softether_set_event_callback(&client_b, null, null);

    try std.testing.expect(client_a.event_callback == null);
    try std.testing.expect(client_b.event_callback == null);
}

test "ffi callback context replaced cleanly on re-register" {
    const NoOp = struct {
        fn cb(_: CEventType, _: CState, _: ?*anyopaque) callconv(.c) void {}
    };

    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer c.deinit();

    // Register, replace, replace, unregister — every step must free the old
    // context. The testing allocator catches any leak.
    softether_set_event_callback(&c, NoOp.cb, null);
    softether_set_event_callback(&c, NoOp.cb, null);
    softether_set_event_callback(&c, NoOp.cb, null);
    softether_set_event_callback(&c, null, null);
    try std.testing.expect(c.event_callback == null);
}

test "ffi state mapping" {
    try std.testing.expectEqual(CState.disconnected, mapState(.disconnected));
    try std.testing.expectEqual(CState.connected, mapState(.connected));
    try std.testing.expectEqual(CState.authenticating, mapState(.authenticating));
}

test "ffi set_dns_servers frees replaced and cleared lists" {
    // The testing allocator fails the test on any leak: repeated sets must
    // free the previous list, empty/blank input must free the current list.
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer c.deinit();

    // Initial set
    softether_set_dns_servers(&c, "1.1.1.1, 8.8.8.8");
    var dns = c.config.static_ip.?.dns_servers.?;
    try std.testing.expectEqual(@as(usize, 2), dns.len);
    try std.testing.expectEqualStrings("1.1.1.1", dns[0]);
    try std.testing.expectEqualStrings("8.8.8.8", dns[1]);

    // Re-set (shorter) — replaces, must free the old list
    softether_set_dns_servers(&c, "9.9.9.9");
    dns = c.config.static_ip.?.dns_servers.?;
    try std.testing.expectEqual(@as(usize, 1), dns.len);
    try std.testing.expectEqualStrings("9.9.9.9", dns[0]);

    // Re-set (longer) — replaces again
    softether_set_dns_servers(&c, "4.4.4.4, 8.8.4.4, 1.0.0.1");
    dns = c.config.static_ip.?.dns_servers.?;
    try std.testing.expectEqual(@as(usize, 3), dns.len);

    // Blank (all-whitespace/empty parts) — clears, must free
    softether_set_dns_servers(&c, " , , ");
    try std.testing.expect(c.config.static_ip.?.dns_servers == null);

    // Empty string — clears, must free (and must not create static_ip)
    c.config.static_ip = null;
    softether_set_dns_servers(&c, "");
    try std.testing.expect(c.config.static_ip == null);
}

test "ffi set_dns_servers never frees borrowed config lists" {
    // VpnClient.init takes config by value; a literal dns_servers list is
    // borrowed. The setter must not free it on replace/clear (invalid free
    // would panic under testing.allocator), and deinit must not either.
    const borrowed = [_][]const u8{ "1.1.1.1", "8.8.8.8" };
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
        .static_ip = .{ .dns_servers = &borrowed },
    });
    defer c.deinit();
    try std.testing.expect(!c.config.static_ip.?.dns_servers_owned);

    // Replacing borrowed list with our own allocation — must free only ours
    softether_set_dns_servers(&c, "9.9.9.9");
    try std.testing.expect(c.config.static_ip.?.dns_servers_owned);
    try std.testing.expectEqual(@as(usize, 1), c.config.static_ip.?.dns_servers.?.len);

    // Clearing must free ours, not the original borrowed entries
    softether_set_dns_servers(&c, "");
    try std.testing.expect(c.config.static_ip.?.dns_servers == null);
    try std.testing.expect(!c.config.static_ip.?.dns_servers_owned);
}

test "ffi set_dns_servers list freed by client deinit" {
    // Destroy a client with DNS still configured — deinit must free the
    // setter-owned list (testing.allocator fails on any leak).
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    softether_set_dns_servers(&c, "1.1.1.1, 8.8.8.8, 1.0.0.1");
    try std.testing.expect(c.config.static_ip.?.dns_servers_owned);
    c.deinit(); // no defer: deinit is the only cleanup

    // Borrowed config with no setter involvement must survive deinit untouched
    const borrowed = [_][]const u8{"4.4.4.4"};
    var c2 = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
        .static_ip = .{ .dns_servers = &borrowed },
    });
    c2.deinit();
}

test "ffi network mode setter" {
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer c.deinit();

    const NetworkMode = client_mod.NetworkMode;
    try std.testing.expectEqual(NetworkMode.client, c.config.mode);
    try std.testing.expectEqual(NetworkMode.client, c.getNetworkMode());

    softether_set_network_mode(&c, 1);
    try std.testing.expectEqual(NetworkMode.bridge, c.config.mode);
    try std.testing.expectEqual(NetworkMode.bridge, c.getNetworkMode());
    softether_set_network_mode(&c, 2);
    try std.testing.expectEqual(NetworkMode.monitor, c.config.mode);
    try std.testing.expectEqual(NetworkMode.monitor, c.getNetworkMode());
    softether_set_network_mode(&c, 0);
    try std.testing.expectEqual(NetworkMode.client, c.config.mode);
    try std.testing.expectEqual(NetworkMode.client, c.getNetworkMode());

    // Invalid values are ignored
    softether_set_network_mode(&c, 7);
    try std.testing.expectEqual(NetworkMode.client, c.config.mode);
    try std.testing.expectEqual(NetworkMode.client, c.getNetworkMode());
}

test "ffi add ingress interfaces owned lifecycle" {
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer c.deinit();
    const NetworkMode = client_mod.NetworkMode;
    softether_set_network_mode(&c, 1);
    try std.testing.expectEqual(NetworkMode.bridge, c.config.mode);

    // Empty name rejected
    try std.testing.expectEqual(@as(c_int, -1), softether_add_ingress_interface(&c, ""));
    // Null client rejected
    try std.testing.expectEqual(@as(c_int, -1), softether_add_ingress_interface(null, "en0"));
    // NULL name pointer from C must not dereference
    const null_name: ?[*:0]const u8 = null;
    try std.testing.expectEqual(@as(c_int, -1), softether_add_ingress_interface(&c, null_name));
    try std.testing.expectEqual(@as(c_int, -1), softether_remove_ingress_interface(&c, null_name));

    // Add two
    try std.testing.expectEqual(@as(c_int, 0), softether_add_ingress_interface(&c, "en0"));
    try std.testing.expectEqual(@as(c_int, 0), softether_add_ingress_interface(&c, "en1"));
    var list = c.config.bridge.ingress_ifs;
    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqualStrings("en0", list[0]);
    try std.testing.expectEqualStrings("en1", list[1]);
    try std.testing.expect(c.config.bridge.ingress_ifs_owned);

    // Duplicate is a no-op
    try std.testing.expectEqual(@as(c_int, 0), softether_add_ingress_interface(&c, "en0"));
    try std.testing.expectEqual(@as(usize, 2), c.config.bridge.ingress_ifs.len);

    // Remove one; strings + arrays must be freed correctly (testing allocator)
    try std.testing.expectEqual(@as(c_int, 0), softether_remove_ingress_interface(&c, "en0"));
    list = c.config.bridge.ingress_ifs;
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings("en1", list[0]);

    // Remove absent is a no-op success
    try std.testing.expectEqual(@as(c_int, 0), softether_remove_ingress_interface(&c, "wlan0"));

    // Remove last — empty owned list
    try std.testing.expectEqual(@as(c_int, 0), softether_remove_ingress_interface(&c, "en1"));
    try std.testing.expectEqual(@as(usize, 0), c.config.bridge.ingress_ifs.len);
    try std.testing.expect(c.config.bridge.ingress_ifs_owned);

    // Remaining list freed by deinit — no leak (defer c.deinit())
}

test "ffi add ingress never frees borrowed config lists" {
    // A literal ingress list from VpnClient.init must survive add/remove
    // without being freed (borrowed semantics, mirrors dns_servers contract).
    const borrowed = [_][]const u8{ "en0", "en1" };
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
        .bridge = .{ .ingress_ifs = &borrowed },
    });
    defer c.deinit();
    try std.testing.expect(!c.config.bridge.ingress_ifs_owned);

    // Add replaces the whole list with owned copies — borrowed entries must
    // not be freed (would panic under testing.allocator)
    try std.testing.expectEqual(@as(c_int, 0), softether_add_ingress_interface(&c, "en2"));
    const list = c.config.bridge.ingress_ifs;
    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqualStrings("en0", list[0]);
    try std.testing.expectEqualStrings("en1", list[1]);
    try std.testing.expectEqualStrings("en2", list[2]);
    try std.testing.expect(c.config.bridge.ingress_ifs_owned);

    // Remove — replacements must also not free the literal
    try std.testing.expectEqual(@as(c_int, 0), softether_remove_ingress_interface(&c, "en1"));
    try std.testing.expectEqual(@as(usize, 2), c.config.bridge.ingress_ifs.len);
}

test "ffi monitor pcap setter owned lifecycle" {
    // A borrowed literal pcap path from VpnClient.init must survive the
    // setter without being freed (borrowed semantics, mirrors ingress).
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
        .monitor = .{ .pcap_file = "capture.pcap" },
    });
    defer c.deinit();
    try std.testing.expect(!c.config.monitor.pcap_file_owned);

    // Replace with an owned copy — borrowed string must not be freed.
    try std.testing.expectEqual(@as(c_int, 0), softether_set_monitor_pcap(&c, "new.pcap"));
    try std.testing.expect(c.config.monitor.pcap_file_owned);
    try std.testing.expectEqualStrings("new.pcap", c.config.monitor.pcap_file.?);

    // Replacing an owned string frees the previous owned copy (leak-safe).
    try std.testing.expectEqual(@as(c_int, 0), softether_set_monitor_pcap(&c, "final.pcap"));
    try std.testing.expectEqualStrings("final.pcap", c.config.monitor.pcap_file.?);

    // Empty string clears without freeing a borrowed literal.
    try std.testing.expectEqual(@as(c_int, 0), softether_set_monitor_pcap(&c, ""));
    try std.testing.expect(c.config.monitor.pcap_file == null);
    try std.testing.expect(!c.config.monitor.pcap_file_owned);

    // NULL path after a clear is idempotent; NULL client is invalid.
    try std.testing.expectEqual(@as(c_int, 0), softether_set_monitor_pcap(&c, null));
    try std.testing.expect(c.config.monitor.pcap_file == null);
    try std.testing.expectEqual(@as(c_int, -1), softether_set_monitor_pcap(null, "x.pcap"));
}

test "ffi monitor frame getters require a running pump" {
    var c = VpnClient.init(std.testing.allocator, .{
        .server_address = "x",
        .server_port = 443,
        .hub_name = "h",
        .auth = .{ .anonymous = {} },
    });
    defer c.deinit();

    // No monitor pump running → -1 for both getters (and a no-op out
    // buffer must never be dereferenced).
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(i64, -1), softether_monitor_frame_count(&c));
    try std.testing.expectEqual(@as(i64, -1), softether_monitor_get_frame(&c, 0, &buf, buf.len));
    try std.testing.expectEqual(@as(i64, 0), softether_monitor_get_frame(&c, 0, null, 0));
}
