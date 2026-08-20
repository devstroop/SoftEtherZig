//! Server-side connection accept — the TLS handshake, signature upload, hello,
//! authentication, and Welcome pack exchange, then the session data plane.
//!
//! The `acceptConnection` handler is the `AcceptHandler` for a `Listener`
//! (listener.zig). It runs on the per-connection thread and, after a
//! successful handshake, becomes the session: the TLS socket is wrapped in a
//! `TunnelConnection` and driven by `SessionMain` against a `SessionPa`
//! attached to the L2 switch hub.
//!
//! C reference (4.44):
//! - `TCPAcceptedThread` → `ConnectionAccept` (Connection.c:3052) — the TLS
//!   accept with the server certificate
//! - `ServerDownloadSignature` (Protocol.c) — the connect.cgi watermark POST.
//!   On success it sends NO reply; the Hello is the first HTTP response.
//! - `ServerAccept` (Protocol.c:1966) — hello → auth → welcome
//! - `PackHello` (Protocol.c:8228), `PackWelcome` (Protocol.c:6442)
//! - `SessionMain` (Session.c:108)
//!
//! ## M1 scope
//!
//! - Single virtual hub: the client's `hubname` must equal the server hub name
//!   (case-insensitive), else ERR_HUB_NOT_FOUND. Cluster redirect, tickets,
//!   certificates and RADIUS/NT auth are out of scope (auth.zig notes).
//! - First connection only: `additional_connect` (multi-TCP) handshakes are
//!   not served in M1 (the Zig client keeps `max_connection` at 1).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const tls = @import("../../mayaqua/network/tls.zig");
const http = @import("../../mayaqua/network/http.zig");
const socket = @import("../../mayaqua/network/socket.zig");
const TcpSocket = socket.TcpSocket;

const Pack = @import("../protocol/pack.zig").Pack;
const Protocol = @import("../protocol/softether_protocol.zig").Protocol;
const TunnelConnection = @import("../protocol/tunnel.zig").TunnelConnection;
const watermark = @import("../protocol/watermark.zig");

const auth_mod = @import("auth.zig");
const hub = @import("hub.zig");
const session_mod = @import("session.zig");
const rpc_mod = @import("admin/rpc.zig");
const dispatch_mod = @import("admin/dispatch.zig");
const wpc_mod = @import("wpc.zig");
const udp_accel_mod = @import("udp_accel_server.zig");
const UdpAccelServer = udp_accel_mod.UdpAccelServer;
const ServerSession = session_mod.ServerSession;
const SessionMain = @import("session_main.zig").SessionMain;
const session_registry_mod = @import("session_registry.zig");
const bridge_mod = @import("../../bridge/mod.zig");
const loop_mod = @import("../../bridge/loop.zig");

const log = std.log.scoped(.cedar_server);

// ============================================================================
// Constants
// ============================================================================

/// Server identity string sent in the hello pack (C: `CedarStr()`).
pub const server_str = "SoftEther VPN Server";
/// Server version (C: `SERVER_VERSION` 444).
pub const server_version: u32 = 444;
/// Server build number (C: `SERVER_BUILD_NUMBER` 9807).
pub const server_build: u32 = 9807;

/// Signature upload target (C: `HTTP_VPN_TARGET2`).
const signature_target = "/vpnsvc/connect.cgi";
/// Acceptable alternative to the WaterMark (C: `HTTP_VPN_TARGET_POSTDATA`).
const vpnconnect_magic = "VPNCONNECT";
/// Upper bound for a signature body (C: `MAX_WATERMARK_SIZE` =
/// `SizeOfWaterMark()` + `HTTP_PACK_RAND_SIZE_MAX` * 2).
const max_watermark_size: usize = 8192;
/// Upper bound for an HTTP request head read byte-by-byte.
const max_head_size: usize = 4096;

/// TLS accept handshake timeout in ms (C: `CONNECTING_TIMEOUT` 15 s).
pub const initial_timeout_ms: u32 = 15000;
/// Default session timeout in ms (C policy TimeOut = 20 s).
pub const timeout_default_ms: u32 = 20000;
/// Data-plane read poll in ms. `TlsConn.read` waits at most this long for
/// inbound bytes before returning `error.WouldBlock`, so `SessionMain` can run
/// keep-alives and enforce `timeout_default_ms` instead of blocking on the
/// socket (which has no SO_RCVTIMEO after the handshake).
const session_poll_ms: u32 = 250;

/// Wire error codes (C: Cedar.h `ERR_*`).
const error_hub_not_found: u32 = 8;
const error_auth_failed: u32 = 9;
const err_protocol_error: u32 = 12;
const err_access_denied: u32 = 15;

// ============================================================================
// ServerContext
// ============================================================================

/// Server identity for one accept endpoint: the TLS certificate, the SAM hub
/// (user accounts) and the L2 switch hub. Owned by the server bootstrap; the
/// accept handler borrows it for the connection's lifetime.
///
/// User accounts are configured before the server starts accepting and do not
/// change during M1, so concurrent reads from the connection threads are safe
/// without a lock.
pub const ServerContext = struct {
    allocator: Allocator,
    /// Server TLS certificate chain, PEM (owned by the caller).
    cert_pem: []const u8,
    /// Server TLS private key, PEM (owned by the caller).
    key_pem: []const u8,
    /// Security Accounts Manager hub (auth.zig): user accounts + passwords.
    auth_hub: *auth_mod.Hub,
    /// L2 switch hub (hub.zig): the data-plane forwarding tables.
    switch_hub: *hub.Hub,
    /// Live session/connection registry (session_registry.zig): populated by
    /// `runSession`, read/force-stopped by the admin RPC dispatcher (issue
    /// #88). The vpnserver main owns the underlying value.
    session_registry: *session_registry_mod.SessionRegistry,
    /// Monotonic counter for session/connection naming.
    session_counter: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Admin RPC dispatch server (issue #99): when non-null, enables the
    /// admin method in `handleConnection` for vpncmd-style RPC connections.
    admin_server: ?*dispatch_mod.Server = null,
    /// Bridge mode (C `StStartServer(true)`): when set, the server operates
    /// as a bridge — hub creation is restricted, LocalBridge is the primary
    /// role. Set by the vpnbridge executable.
    bridge_mode: bool = false,
    /// Active LocalBridge instances (admin RPC AddLocalBridge/DeleteLocalBridge).
    local_bridges: std.ArrayListUnmanaged(bridge_mod.LocalBridge) = .{},

    /// Tear down runtime bridges and free the local_bridges list.
    pub fn deinit(self: *ServerContext) void {
        for (self.local_bridges.items) |*lb| {
            lb.stop();
            if (lb.bridge_loop) |*bl| bl.deinit();
            lb.bridge_loop = null;
            if (lb.af_port) |*port| port.close();
            lb.af_port = null;
        }
        self.local_bridges.deinit(self.allocator);
    }
};

// ============================================================================
// Bridge operations vtable — wired into dispatch_mod.BridgeOps
// ============================================================================

pub fn bridgeCreate(ctx: *anyopaque, device_name: []const u8, hub_name: []const u8, tap_mode: bool) bool {
    const self: *ServerContext = @ptrCast(@alignCast(ctx));

    // Duplicate strings so the runtime bridge owns its own copies.
    const owned_dev = self.allocator.dupe(u8, device_name) catch return false;
    errdefer self.allocator.free(owned_dev);
    const owned_hub = self.allocator.dupe(u8, hub_name) catch return false;
    errdefer self.allocator.free(owned_hub);

    var lb = bridge_mod.LocalBridge.init(self.allocator, owned_dev, owned_hub);
    lb.tap_mode = tap_mode;

    // Append to the list BEFORE starting the thread so the pump thread
    // references stable storage (not a stack local).
    self.local_bridges.append(self.allocator, lb) catch |oom| {
        log.err("LocalBridge: OOM appending bridge: {s}", .{@errorName(oom)});
        return false;
    };

    // Open the NIC port.  Failures are non-fatal — the bridge is stored but
    // inactive (online=false) so the admin can see the error and retry.
    const last = &self.local_bridges.items[self.local_bridges.items.len - 1];
    last.openPort() catch |err| {
        log.warn("LocalBridge: open {s} failed: {s}", .{ device_name, @errorName(err) });
        return false;
    };

    // Start the pump thread.
    // NOTE: The sink is a noop placeholder.  Full data-plane integration
    // (LAN -> session forwarding) requires wiring to the hub's packet
    // adapter — tracked as a follow-up task.
    const noop_sink = loop_mod.SessionSink{
        .ctx = undefined,
        .send = &struct {
            fn noop(_: *anyopaque, _: []const u8) anyerror!void {}
        }.noop,
    };
    last.start(noop_sink) catch |err| {
        log.warn("LocalBridge: start {s} failed: {s}", .{ device_name, @errorName(err) });
        return false;
    };

    return true;
}

pub fn bridgeDestroy(ctx: *anyopaque, device_name: []const u8, hub_name: []const u8) bool {
    const self: *ServerContext = @ptrCast(@alignCast(ctx));
    for (self.local_bridges.items, 0..) |*lb, i| {
        if (std.mem.eql(u8, lb.device_name, device_name) and std.mem.eql(u8, lb.hub_name, hub_name)) {
            var removed = self.local_bridges.swapRemove(i);
            removed.stop();
            if (removed.bridge_loop) |*bl| bl.deinit();
            removed.bridge_loop = null;
            if (removed.af_port) |*port| port.close();
            removed.af_port = null;
            self.allocator.free(removed.device_name);
            self.allocator.free(removed.hub_name);
            return true;
        }
    }
    return false;
}

/// The `AcceptHandler` entry point (listener.zig). Runs on the per-connection
/// thread. On failure the connection is closed and the error is logged.
pub fn acceptConnection(ctx: *anyopaque, sock: *TcpSocket, peer_ip: u32, peer_port: u16) void {
    const self: *ServerContext = @ptrCast(@alignCast(ctx));

    // TLS accept with the server certificate (C: `ConnectionAccept` →
    // `StartSSL`). The TLS socket takes ownership of the fd from here on.
    const fd = sock.stream.handle;
    var tls_sock = tls.TlsSocket.accept(self.allocator, fd, .{
        .cert_pem = self.cert_pem,
        .key_pem = self.key_pem,
        .timeout_ms = initial_timeout_ms,
    }) catch |err| {
        std.posix.close(fd);
        log.warn("TLS accept failed ({s}): {s}", .{ fmtIp(peer_ip), @errorName(err) });
        return;
    };
    defer tls_sock.close();

    handleConnection(self, &tls_sock, peer_ip, peer_port) catch |err| {
        log.info("connection from {s} rejected: {s}", .{ fmtIp(peer_ip), @errorName(err) });
    };
}

/// Format a u32 IPv4 address as dotted quad (for logs).
fn fmtIp(ip: u32) [15]u8 {
    var buf: [15]u8 = undefined;
    const b: [4]u8 = @bitCast(ip);
    const used = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch
        return @as([15]u8, @splat('?'));
    @memset(buf[used.len..], 0);
    return buf;
}

/// The full accept sequence for an established TLS connection:
/// signature → hello → method dispatch (admin or login) → session/RPC.
/// Exposed for the end-to-end tests; `acceptConnection` wraps it in TLS
/// accept + close.
pub fn handleConnection(self: *ServerContext, tls_sock: *tls.TlsSocket, peer_ip: u32, peer_port: u16) !void {
    // 1. Signature upload — WaterMark GIF POSTed to connect.cgi. The server
    //    validates it and sends NO reply (C `ServerDownloadSignature`).
    try receiveSignature(self, tls_sock);

    // 2. Hello — our identity + a fresh random challenge (PackHello).
    var hello_random: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&hello_random);
    const hello_bytes = try buildHelloPack(self.allocator, &hello_random);
    defer self.allocator.free(hello_bytes);
    try http.sendHttpResponse(tls_sock, hello_bytes);

    // 3. Read the method Pack and dispatch based on "method" field.
    //    C: `ServerAccept` (Protocol.c:2137) reads the Pack via HttpServerRecv,
    //    then checks `GetMethodFromPack(p, method)` for "admin", "login", etc.
    var buf: [http.max_pack_body_len]u8 = undefined;
    const request = try http.readHttpRequest(tls_sock, &buf);
    var method_pack = try Pack.fromBytes(self.allocator, request.body);
    defer method_pack.deinit();

    const method = method_pack.getStr("method") orelse return error.ProtocolError;

    if (mem.eql(u8, method, "admin") and self.admin_server != null) {
        // 3a. Admin RPC path — C: `AdminAccept` (Admin.c:14638).
        try handleAdmin(self, tls_sock, &method_pack, &hello_random);
    } else if (mem.eql(u8, method, "login")) {
        // 3b. VPN session path — C: `ServerAccept` login branch.
        var established = (try authenticateVpn(self, tls_sock, &method_pack, &hello_random)) orelse return;
        defer established.deinit(self.allocator);
        try runSession(self, tls_sock, &established, peer_ip, peer_port);
    } else if (mem.eql(u8, method, "additional_connect")) {
        // 3c. Multi-TCP additional connection — C: `ServerAccept` at
        //     Protocol.c:4296. The client opens a new TLS socket and
        //     identifies itself with a session key; the server validates
        //     the key, assigns a direction, and returns RC4 keys.
        try handleAdditionalConnect(self, tls_sock, &method_pack, peer_ip, peer_port);
    } else {
        return error.ProtocolError;
    }
}

/// Read and validate the connect.cgi signature POST.
///
/// Mirrors C `ServerDownloadSignature`: POST to `/vpnsvc/connect.cgi`, body
/// within [SizeOfWaterMark, MAX_WATERMARK_SIZE] (or the 10-byte "VPNCONNECT"
/// magic), whose leading bytes equal the WaterMark. On success no response is
/// sent — the Hello response that follows doubles as the reply to this POST.
fn receiveSignature(self: *ServerContext, sock: *tls.TlsSocket) !void {
    _ = self;
    var head_buf: [max_head_size]u8 = undefined;
    const head = try readHead(sock, &head_buf);

    if (!std.ascii.eqlIgnoreCase(head.method, "POST")) return error.InvalidSignature;
    if (!std.ascii.eqlIgnoreCase(head.target, signature_target)) return error.InvalidSignature;

    const body_len = head.content_length;
    if (body_len != vpnconnect_magic.len and
        (body_len < watermark.WaterMark.len or body_len > max_watermark_size))
    {
        return error.InvalidSignature;
    }

    var body_buf: [max_watermark_size]u8 = undefined;
    const body = body_buf[0..body_len];
    var got: usize = 0;
    while (got < body.len) {
        const m = try sock.readBlocking(body[got..]);
        if (m == 0) return error.EndOfStream;
        got += m;
    }

    const is_vpnconnect = mem.eql(u8, body, vpnconnect_magic);
    const is_watermark = body.len >= watermark.WaterMark.len and
        mem.eql(u8, body[0..watermark.WaterMark.len], &watermark.WaterMark);
    if (!is_vpnconnect and !is_watermark) return error.InvalidSignature;

    log.info("signature accepted ({d} bytes)", .{body_len});
}

/// Read one HTTP request head (request line + headers) byte-by-byte, without
/// the terminating CRLFCRLF, and return the request method, target and
/// Content-Length. Bytes past the head stay in the TLS read-ahead buffer.
fn readHead(sock: *tls.TlsSocket, buf: []u8) !struct {
    method: []const u8,
    target: []const u8,
    content_length: usize,
} {
    var head_len: usize = 0;
    while (head_len < buf.len) {
        const n = try sock.readBlocking(buf[head_len .. head_len + 1]);
        if (n == 0) return error.EndOfStream;
        head_len += n;
        if (head_len >= 4 and mem.eql(u8, buf[head_len - 4 .. head_len], "\r\n\r\n")) break;
    }
    if (head_len == buf.len) return error.HeaderTooLarge;

    const head = buf[0 .. head_len - 4];
    const line_end = mem.indexOf(u8, head, "\r\n") orelse return error.InvalidRequest;
    var tokens = mem.tokenizeAny(u8, head[0..line_end], " ");
    const method = tokens.next() orelse return error.InvalidRequest;
    const target = tokens.next() orelse return error.InvalidRequest;

    var content_length: usize = 0;
    var lines = mem.splitSequence(u8, head[line_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        const colon = mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = mem.trim(u8, line[0..colon], " \t");
        const value = mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
        }
    }
    if (content_length == 0) return error.InvalidContentLength;

    return .{ .method = method, .target = target, .content_length = content_length };
}

/// Build the Hello pack body (C: `PackHello`, Protocol.c:8228).
fn buildHelloPack(allocator: Allocator, random: *const [Protocol.sha1_size]u8) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addStr("hello", server_str);
    try pack.addInt("version", server_version);
    try pack.addInt("build", server_build);
    try pack.addData("random", random);
    return pack.toBytes(allocator);
}

/// A session that passed authentication, ready for the data plane.
const EstablishedSession = struct {
    session: ServerSession,
    /// Owned session name (C: `SID-<UPPERUSER>-<tick>`).
    session_name: []u8,
    /// Owned connection name.
    connection_name: []u8,
    /// Owned authenticated username (registry display; case as sent).
    username: []u8,
    /// Optional server-side UDP acceleration engine (S20/rudp).
    udp_server: ?UdpAccelServer = null,

    fn deinit(self: *EstablishedSession, allocator: Allocator) void {
        allocator.free(self.session_name);
        allocator.free(self.connection_name);
        allocator.free(self.username);
        if (self.udp_server) |*us| us.deinit();
    }
};

/// Read the login pack, verify it against the SAM hub, and reply with the
/// Welcome (or an error) pack. Returns null when the client was rejected.
fn authenticateVpn(
    self: *ServerContext,
    tls_sock: *tls.TlsSocket,
    pack: *const Pack,
    hello_random: *const [Protocol.sha1_size]u8,
) !?EstablishedSession {
    // Hub selection (M1: single hub). C: `GetHubnameAndUsernameFromPack` +
    // `GetHub`; missing/unknown hub → ERR_HUB_NOT_FOUND.
    const hubname = pack.getStr("hubname") orelse {
        try sendAuthError(self, tls_sock, error_hub_not_found, false);
        return null;
    };
    if (!std.ascii.eqlIgnoreCase(hubname, self.auth_hub.name)) {
        try sendAuthError(self, tls_sock, error_hub_not_found, false);
        return null;
    }

    // Verify the credentials (auth.zig dispatches anonymous → password).
    const auth_result = auth_mod.authenticate(self.auth_hub, hello_random, pack);
    if (!auth_result.ok) {
        try sendAuthError(self, tls_sock, error_auth_failed, false);
        return null;
    }

    const username = pack.getStr("username") orelse {
        try sendAuthError(self, tls_sock, error_auth_failed, false);
        return null;
    };

    // Negotiate encryption based on client request (C: Protocol.c:3958-3962).
    // Echo back whatever the client asked for; the crypto primitives are
    // already implemented in session.zig (ConnectionCipher, Rc4KeyPair).
    // Default false: a missing field means the client does not expect an
    // app-layer cipher (plaintext-over-TLS), matching the pre-M7 behavior.
    const client_use_encrypt = pack.getBool("use_encrypt") orelse false;
    const client_use_fast_rc4 = pack.getBool("use_fast_rc4") orelse false;
    var session = ServerSession.initWithOptions(self.allocator, hello_random, .{
        .max_connection = 1,
        .timeout = timeout_default_ms,
    });
    session.negotiate(client_use_encrypt, client_use_fast_rc4);

    // Session/connection names (C: `SID-<UPPERUSER>-<tick>`).
    const counter = self.session_counter.fetchAdd(1, .seq_cst);
    const upper = try self.allocator.dupe(u8, username);
    defer self.allocator.free(upper);
    for (upper) |*c| c.* = std.ascii.toUpper(c.*);
    const session_name = try std.fmt.allocPrint(self.allocator, "SID-{s}-{d}", .{ upper, counter });
    errdefer self.allocator.free(session_name);
    const connection_name = try std.fmt.allocPrint(self.allocator, "CONN-{d}", .{counter});
    errdefer self.allocator.free(connection_name);

    // UDP acceleration negotiation (S20/rudp).  Parse the client's request
    // and create a server-side engine if supported (C: Protocol.c:3786-3887).
    var udp_server: ?UdpAccelServer = null;
    const want_udp = (pack.getBool("use_udp_acceleration") orelse false);
    if (want_udp) {
        const client_version: u32 = @intCast(pack.getInt("udp_acceleration_version") orelse 1);
        const client_max_version: u32 = @intCast(pack.getInt("udp_acceleration_max_version") orelse 1);
        const client_ip_u32: u32 = @intCast(pack.getInt("udp_acceleration_client_ip") orelse 0);
        const client_port_u16: u16 = @intCast(pack.getInt("udp_acceleration_client_port") orelse 0);

        // Negotiate the version: highest both support.
        var negotiated_version: u8 = udp_accel_mod.VERSION_ZIG;
        if (client_version >= udp_accel_mod.VERSION_V2 and client_max_version >= udp_accel_mod.VERSION_V2) {
            negotiated_version = udp_accel_mod.VERSION_V2;
        } else if (client_version >= udp_accel_mod.VERSION_V1 and client_max_version >= udp_accel_mod.VERSION_V1) {
            negotiated_version = udp_accel_mod.VERSION_V1;
        }

        // Extract client keys (format-specific).
        const client_key_v1 = pack.getData("udp_acceleration_client_key") orelse &.{};
        const client_key_v2 = pack.getData("udp_acceleration_client_key_v2") orelse &.{};
        const client_key_zig_send = pack.getData("bulk_on_rudp_send_key") orelse &.{};
        const client_key_zig_recv = pack.getData("bulk_on_rudp_recv_key") orelse &.{};
        _ = client_key_zig_recv;

        var server: ?UdpAccelServer = null;
        if (UdpAccelServer.init(self.allocator)) |s| {
            var srv = s;
            srv.initServer(
                client_ip_u32,
                client_port_u16,
                negotiated_version,
                client_key_v1,
                client_key_v2,
                client_key_zig_send,
            );
            server = srv;
        } else |err| {
            log.warn("UDP accel server bind failed: {}", .{err});
        }
    }

    const welcome = try buildWelcomePack(self.allocator, &session, session_name, connection_name, &udp_server);
    defer self.allocator.free(welcome);
    try http.sendHttpResponse(tls_sock, welcome);

    const username_owned = try self.allocator.dupe(u8, username);

    return EstablishedSession{
        .session = session,
        .session_name = session_name,
        .connection_name = connection_name,
        .username = username_owned,
        .udp_server = udp_server,
    };
}

/// Build the Welcome pack body (C: `PackWelcome`, Protocol.c:6442).
fn buildWelcomePack(
    allocator: Allocator,
    session: *const ServerSession,
    session_name: []const u8,
    connection_name: []const u8,
    udp_server: *const ?UdpAccelServer,
) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();

    try session.addWelcomeFields(&pack, session_name, connection_name);

    // UDP acceleration fields.  When a server engine was created, emit the
    // negotiated keys and port; otherwise disable UDP accel (C: PackWelcome
    // when s->UdpAccel is NULL).
    if (udp_server.*) |*us| {
        try pack.addBool("use_udp_acceleration", true);
        try pack.addBool("udp_acceleration_use_encryption", !us.plain_text_mode);
        try pack.addInt("udp_acceleration_version", us.version);

        switch (us.version) {
            udp_accel_mod.VERSION_V1 => {
                try pack.addInt("udp_acceleration_server_port", us.my_port);
                try pack.addData("udp_acceleration_server_key", &us.my_key_v1);
                try pack.addInt("udp_acceleration_server_cookie", us.my_cookie_v1);
                try pack.addInt("udp_acceleration_client_cookie", us.your_cookie_v1);
            },
            udp_accel_mod.VERSION_V2 => {
                try pack.addInt("udp_acceleration_server_port", us.my_port);
                try pack.addData("udp_acceleration_server_key_v2", &us.my_key_v2);
                try pack.addInt("udp_acceleration_server_cookie", us.my_cookie_v1);
                try pack.addInt("udp_acceleration_client_cookie", us.your_cookie_v1);
            },
            else => { // VERSION_ZIG
                try pack.addInt("udp_acceleration_client_port", us.my_port);
                try pack.addData("bulk_on_rudp_send_key", &us.send_key_zig);
                try pack.addData("bulk_on_rudp_recv_key", &us.recv_key_zig);
                try pack.addInt("rudp_bulk_version", 1);
            },
        }
    } else {
        try pack.addBool("use_udp_acceleration", false);
    }

    try pack.addInt("is_azure_session", 0);
    try pack.addInt("policy:NoRouting", 0);
    try pack.addBool("no_send_signature", false);
    try pack.addBool("enable_udp_recovery", false);
    return pack.toBytes(allocator);
}

/// Send the auth-failure reply pack: `error` + `no_save_password`
/// (C: Protocol.c:2842-2868).
fn sendAuthError(self: *ServerContext, tls_sock: *tls.TlsSocket, code: u32, no_save_password: bool) !void {
    var pack = Pack.init(self.allocator);
    defer pack.deinit();
    try pack.addInt("error", code);
    try pack.addBool("no_save_password", no_save_password);
    const body = try pack.toBytes(self.allocator);
    defer self.allocator.free(body);
    try http.sendHttpResponse(tls_sock, body);
}

// ============================================================================
// Admin RPC Accept (issue #99)
// ============================================================================

/// Send an admin error response pack and log the failure.
fn sendAdminError(self: *ServerContext, tls_sock: *tls.TlsSocket, err_code: u32) !void {
    var pack = Pack.init(self.allocator);
    defer pack.deinit();
    try pack.addInt("error", err_code);
    const body = try pack.toBytes(self.allocator);
    defer self.allocator.free(body);
    try http.sendHttpResponse(tls_sock, body);
}

/// Handle an admin RPC connection (C: `AdminAccept`, Admin.c:14638).
///
/// 1. Extract `secure_password` (20-byte SHA-1) from the method Pack
/// 2. Verify against the server's hashed password + hello nonce
/// 3. Send success Pack
/// 4. Start the RPC frame loop (`Rpc.runServer`)
fn handleAdmin(
    self: *ServerContext,
    tls_sock: *tls.TlsSocket,
    method_pack: *const Pack,
    hello_random: *const [Protocol.sha1_size]u8,
) !void {
    const server = self.admin_server.?;

    // Extract secure_password (must be exactly 20 bytes)
    const secure_pw_data = method_pack.getData("secure_password") orelse {
        try sendAdminError(self, tls_sock, err_protocol_error);
        return;
    };
    if (secure_pw_data.len != Protocol.sha1_size) {
        try sendAdminError(self, tls_sock, err_protocol_error);
        return;
    }
    var secure_password: [Protocol.sha1_size]u8 = undefined;
    @memcpy(&secure_password, secure_pw_data);

    // Extract optional hub name (empty = server admin, non-empty = hub admin)
    const hubname = method_pack.getStr("hubname") orelse "";

    // Verify password (C: `AdminCheckPassword`, Admin.c:14783)
    const expected = auth_mod.securePassword(&server.hashed_password, hello_random);
    if (!mem.eql(u8, &expected, &secure_password)) {
        try sendAdminError(self, tls_sock, err_access_denied);
        return;
    }

    // Send success Pack (C: Admin.c:14740-14746)
    var resp = Pack.init(self.allocator);
    defer resp.deinit();
    const resp_body = try resp.toBytes(self.allocator);
    defer self.allocator.free(resp_body);
    try http.sendHttpResponse(tls_sock, resp_body);

    // Start the RPC frame loop (C: `AdminAccept` → `RpcServer`)
    acceptAdmin(self, tls_sock, server, hubname);
}

/// Run the admin RPC server loop on an authenticated TLS connection.
///
/// Mirrors C `AdminAccept` (Admin.c:14761): `StartRpcServer` + `RpcServer`.
/// The socket stays blocking with no idle timeout — the session lives until
/// the client disconnects.
fn acceptAdmin(
    self: *ServerContext,
    tls_sock: *tls.TlsSocket,
    server: *dispatch_mod.Server,
    hubname: []const u8,
) void {
    server.server_ctx = @ptrCast(self);
    var rpc = rpc_mod.startRpcServer(self.allocator, tls_sock, dispatch_mod.adminDispatch, @ptrCast(server));
    rpc.server_mode = true;
    rpc.server_admin_mode = hubname.len == 0;
    rpc.hub_name = hubname;
    rpc.is_vpn_server = true;
    rpc.runServer();
}

/// Run the session data plane: attach a packet adapter for this session to the
/// L2 hub, frame the TLS socket with a `TunnelConnection`, and drive both with
/// `SessionMain` until the peer disconnects, the session times out, or stop is
/// requested. Any `SessionEnd` reason is a normal teardown.
fn runSession(self: *ServerContext, tls_sock: *tls.TlsSocket, established: *EstablishedSession, peer_ip: u32, peer_port: u16) !void {
    const pa = try hub.SessionPa.init(self.switch_hub, self.allocator, established.session_name);
    defer pa.deinit();
    self.switch_hub.attach(pa);

    var conn = TlsConn{ .sock = tls_sock };
    var tunnel = TunnelConnection.init(self.allocator, &conn, TlsConn.read, TlsConn.write);
    defer tunnel.deinit();

    // Build session config with optional UDP acceleration callbacks.
    const SessionConfig = @import("session_main.zig").SessionConfig;
    var session_config = SessionConfig{
        .timeout_ms = established.session.timeout,
    };

    // Store the UDP server in a mutable static for the callbacks.
    // Only one session runs per connection thread, so this is safe.
    const UdpCallbacks = struct {
        var active_server: ?*UdpAccelServer = null;

        fn udpPoll(_: *anyopaque) ?[]const u8 {
            if (active_server) |s| return s.poll();
            return null;
        }
        fn udpSend(_: *anyopaque, data: []const u8, compressed: bool) bool {
            if (active_server) |s| return s.sendBlock(data, compressed);
            return false;
        }
        fn udpReady(_: *anyopaque) bool {
            if (active_server) |s| return s.isSendReady();
            return false;
        }
        fn udpTick(_: *anyopaque) void {
            if (active_server) |s| s.tick();
        }
        fn udpFd(_: *anyopaque) ?posix.socket_t {
            if (active_server) |s| return s.getFd();
            return null;
        }
    };
    if (established.udp_server) |*us| {
        UdpCallbacks.active_server = us;
        session_config.udp_ctx = @ptrCast(us);
        session_config.udp_poll_fn = UdpCallbacks.udpPoll;
        session_config.udp_send_fn = UdpCallbacks.udpSend;
        session_config.udp_ready_fn = UdpCallbacks.udpReady;
        session_config.udp_tick_fn = UdpCallbacks.udpTick;
        session_config.udp_fd_fn = UdpCallbacks.udpFd;
    }

    var main = try SessionMain.init(self.allocator, &tunnel, pa.pa(), session_config);
    // Interpose the per-socket cipher for data-channel encryption (M7).
    main.cipher = established.session.newConnectionCipher();
    // Wire the session policy's max_connection into the session loop so the
    // additional_connect handler enforces the correct limit (C: `s->MaxConnection`).
    main.max_connections = established.session.max_connection;
    defer main.deinit();

    // Register with the session registry (issue #88) so the admin dispatcher
    // can enumerate and force-stop this session. Unregister runs before
    // `main.deinit` (LIFO) so the record's `main` pointer stays valid until
    // the registry frees it.
    const rec = try self.allocator.create(session_registry_mod.SessionRecord);
    rec.* = .{
        .session_name = try self.allocator.dupe(u8, established.session_name),
        .connection_name = try self.allocator.dupe(u8, established.connection_name),
        .username = try self.allocator.dupe(u8, established.username),
        .hub_name = self.auth_hub.name,
        .peer_ip = peer_ip,
        .peer_port = peer_port,
        .created_time = std.time.milliTimestamp(),
        .main = &main,
        .session_key = established.session.session_key,
    };
    self.session_registry.register(rec) catch {
        self.allocator.free(rec.session_name);
        self.allocator.free(rec.connection_name);
        self.allocator.free(rec.username);
        self.allocator.destroy(rec);
        return error.SessionRegistryFull;
    };
    defer _ = self.session_registry.unregister(rec.session_name);

    log.info("session {s} established on hub {s}", .{ established.session_name, self.auth_hub.name });
    main.run() catch |err| switch (err) {
        error.Stopped,
        error.ConnectionClosed,
        error.SessionTimeout,
        error.PacketAdapterInitFailed,
        error.PacketAdapterPutFailed,
        error.PacketAdapterFlushFailed,
        => {
            log.info("session {s} ended: {s}", .{ established.session_name, @errorName(err) });
            return;
        },
        else => return err,
    };
}

/// C `ServerAccept` additional_connect branch (Protocol.c:4296-4483).
/// The client opens a new TLS connection and identifies itself with a
/// session key. The server validates the key, checks the connection limit,
/// assigns a direction (for half-connection mode), generates per-socket
/// RC4 keys if needed, and responds with the assigned direction.
fn handleAdditionalConnect(
    self: *ServerContext,
    tls_sock: *tls.TlsSocket,
    pack: *Pack,
    peer_ip: u32,
    peer_port: u16,
) !void {
    _ = peer_ip;
    _ = peer_port;

    // Extract the 20-byte session key from the client's Pack.
    const session_key_data = pack.getData("session_key") orelse {
        try sendAdditionalConnectError(self, tls_sock, error.InvalidParameter);
        return;
    };
    if (session_key_data.len != Protocol.sha1_size) {
        try sendAdditionalConnectError(self, tls_sock, error.InvalidParameter);
        return;
    }
    var session_key: [Protocol.sha1_size]u8 = undefined;
    @memcpy(&session_key, session_key_data);

    // Look up the existing session by key (C: `GetSessionFromKey`).
    // findBySessionKeyAndReserve validates the halt flag under the registry lock
    // to avoid a stale pointer after the session begins teardown.
    const main = self.session_registry.findBySessionKeyAndReserve(&session_key) orelse {
        log.warn("additional_connect: session key not found or halting", .{});
        try sendAdditionalConnectError(self, tls_sock, error.SessionTimeout);
        return;
    };

    // Atomically reserve a connection slot (C: `Count(s->Connection->CurrentNumConnection) > s->MaxConnection`).
    // Uses compareExchange loop to prevent concurrent requests from bypassing the limit.
    while (true) {
        const current = main.current_connections.load(.acquire);
        if (current >= main.max_connections) {
            log.warn("additional_connect: too many connections ({d}/{d})", .{ current, main.max_connections });
            try sendAdditionalConnectError(self, tls_sock, error.TooManyConnections);
            return;
        }
        if (main.current_connections.cmpxchgStrong(current, current + 1, .seq_cst, .acquire)) |_| {
            // CAS failed — retry (another thread raced us).
            continue;
        } else {
            break; // slot reserved
        }
    }
    // Release the reserved slot on any error below (response build failure,
    // TLS write failure, etc.) so the counter stays accurate.
    errdefer _ = main.current_connections.fetchSub(1, .seq_cst);

    // Determine direction. In half-connection mode, assign the underrepresented
    // direction; otherwise bidirectional (C: `TCP_BOTH`).
    // For M1, always return bidirectional (direction=0).
    const direction: u32 = 0;

    // Generate per-socket RC4 keys if fast-RC4 is active.
    // For now, respond without RC4 keys (plaintext-over-TLS mode).
    // TODO: wire RC4 key generation when fast-RC4 is fully supported.

    // Build and send the success response.
    var resp = Pack.init(self.allocator);
    defer resp.deinit();
    try resp.addInt("error", 0); // ERR_NO_ERROR
    try resp.addInt("direction", direction);

    const resp_bytes = try resp.toBytes(self.allocator);
    defer self.allocator.free(resp_bytes);

    try http.sendHttpResponse(tls_sock, resp_bytes);

    // NOTE: Phase 2 (multi-socket pool in SessionMain) is required to actually
    // use this accepted socket for data-plane traffic. Without it, the TLS
    // socket is closed when this function returns and the client sees a
    // disconnect. Phase 2 will wrap `tls_sock` in a `TunnelConnection`, add it
    // to the session's socket pool, and start polling it for data. For now the
    // connection counter is decremented to avoid stale accounting.
    _ = main.current_connections.fetchSub(1, .seq_cst);

    log.info("additional_connect: session accepted (dir={d}, conns={d})", .{
        direction,
        main.current_connections.load(.acquire),
    });
}

fn sendAdditionalConnectError(self: *ServerContext, tls_sock: *tls.TlsSocket, err: anyerror) !void {
    // C error codes from Cedar.h — match what the client expects.
    const ERR_INVALID_PARAMETER: u32 = 38;
    const ERR_SESSION_TIMEOUT: u32 = 20;
    const ERR_TOO_MANY_CONNECTION: u32 = 49;
    const ERR_INTERNAL_ERROR: u32 = 23;
    const error_code: u32 = switch (err) {
        error.InvalidParameter => ERR_INVALID_PARAMETER,
        error.SessionTimeout => ERR_SESSION_TIMEOUT,
        error.TooManyConnections => ERR_TOO_MANY_CONNECTION,
        else => ERR_INTERNAL_ERROR,
    };
    var resp = Pack.init(self.allocator);
    defer resp.deinit();
    try resp.addInt("error", error_code);

    const resp_bytes = try resp.toBytes(self.allocator);
    defer self.allocator.free(resp_bytes);

    try http.sendHttpResponse(tls_sock, resp_bytes);
}

/// TunnelConnection I/O callbacks over a TlsSocket.
const TlsConn = struct {
    sock: *tls.TlsSocket,

    fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *TlsConn = @ptrCast(@alignCast(ctx));
        const sock = self.sock;

        // Serve decrypted data OpenSSL may already hold buffered — the fd
        // poll below would not see it (read-ahead + SSL_pending).
        if (sock.hasPending()) return sock.read(buf);

        // Bounded wait for inbound bytes. The accepted socket is blocking
        // with no SO_RCVTIMEO (tls.zig drops it after the handshake), so a
        // direct read would block forever and starve SessionMain's
        // keep-alive and inactivity-timeout checks. Polling briefly and
        // returning error.WouldBlock on idle keeps those running.
        var pfd = [_]std.posix.pollfd{.{
            .fd = sock.tcp_fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const pr = std.posix.poll(&pfd, session_poll_ms) catch 0;
        if (pr == 0) return error.WouldBlock;
        return sock.read(buf);
    }

    fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *TlsConn = @ptrCast(@alignCast(ctx));
        try self.sock.writeAll(data);
        return data.len;
    }
};

// ============================================================================
// Tests
// ============================================================================

const builtin = @import("builtin");
const posix = std.posix;
const protocol_mod = @import("../protocol/softether_protocol.zig");

/// Client-side I/O callbacks exposing a TlsSocket as the protocol Writer/Reader.
const ClientIo = struct {
    sock: *tls.TlsSocket,

    fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *ClientIo = @ptrCast(@alignCast(ctx));
        try self.sock.writeAll(data);
        return data.len;
    }

    fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *ClientIo = @ptrCast(@alignCast(ctx));
        return self.sock.readBlocking(buf);
    }
};

var test_dial_fd: c_int = -1;

fn testDial(host: [*:0]const u8, port: u16) callconv(.c) c_int {
    _ = host;
    _ = port;
    return test_dial_fd;
}

const AcceptThreadCtx = struct {
    ctx: *ServerContext,
    fd: posix.socket_t,
};

fn acceptThread(a: *AcceptThreadCtx) void {
    var sock = TcpSocket{ .stream = .{ .handle = a.fd } };
    acceptConnection(a.ctx, &sock, 0, 0);
}

/// Spawn the server accept thread and TLS-connect a client to it over an
/// AF_UNIX socketpair. Caller frees via `deinit` (joins the thread and
/// destroys the heap contexts).
const EndToEnd = struct {
    allocator: Allocator,
    thread: std.Thread,
    client: tls.TlsSocket,
    accept_ctx: *AcceptThreadCtx,
    sctx: *ServerContext,
    registry: *session_registry_mod.SessionRegistry,
    client_closed: bool = false,

    fn deinit(self: *EndToEnd) void {
        if (!self.client_closed) self.client.close();
        self.thread.join();
        self.registry.deinit();
        self.allocator.destroy(self.registry);
        self.allocator.destroy(self.accept_ctx);
        self.allocator.destroy(self.sctx);
    }
};

fn startEndToEnd(
    allocator: Allocator,
    cert_pem: []const u8,
    key_pem: []const u8,
    auth_hub: *auth_mod.Hub,
    switch_hub: *hub.Hub,
) !EndToEnd {
    var fds: [2]posix.socket_t = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SocketPairFailed;

    const sctx = try allocator.create(ServerContext);
    const registry = try allocator.create(session_registry_mod.SessionRegistry);
    registry.* = session_registry_mod.SessionRegistry.init(allocator);
    sctx.* = .{
        .allocator = allocator,
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .auth_hub = auth_hub,
        .switch_hub = switch_hub,
        .session_registry = registry,
    };
    const accept_ctx = try allocator.create(AcceptThreadCtx);
    accept_ctx.* = .{ .ctx = sctx, .fd = fds[0] };
    errdefer allocator.destroy(accept_ctx);
    errdefer allocator.destroy(sctx);
    errdefer allocator.destroy(registry);
    errdefer registry.deinit();
    const thread = try std.Thread.spawn(.{}, acceptThread, .{accept_ctx});

    test_dial_fd = @intCast(fds[1]);
    const client = tls.TlsSocket.connect(allocator, "accept.test", 443, .{
        .allow_self_signed = true,
        .timeout_ms = 10000,
        .external_tcp_dial = testDial,
    }) catch |err| {
        std.posix.close(fds[1]);
        thread.join();
        return err;
    };
    test_dial_fd = -1;

    return .{
        .allocator = allocator,
        .thread = thread,
        .client = client,
        .accept_ctx = accept_ctx,
        .sctx = sctx,
        .registry = registry,
    };
}

test "server.accept full handshake over TLS" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;

    const cert = try tls.generateSelfSignedCert(allocator, "accept.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var auth_hub = try auth_mod.Hub.init(allocator, "VPN");
    defer auth_hub.deinit();
    _ = try auth_hub.addUser("alice", .password, "hunter2");

    const switch_hub = try hub.Hub.init(allocator, "VPN");
    defer switch_hub.deinit();

    var e2e = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem, &auth_hub, switch_hub);
    defer e2e.deinit();

    // Drive the real Zig client protocol against the server.
    var io = ClientIo{ .sock = &e2e.client };
    const writer = protocol_mod.Writer{ .context = &io, .writeFn = ClientIo.write };
    const reader = protocol_mod.Reader{ .context = &io, .readFn = ClientIo.read };

    // This test exercises the TLS handshake, not encryption — send
    // use_encrypt=false so the server stays in plaintext-over-TLS mode.
    var result = try protocol_mod.performHandshakeWithOpts(allocator, writer, reader, "accept.test", "VPN", "alice", "hunter2", false, .{ .use_encrypt = false });
    defer result.hello.deinit(allocator);
    defer result.auth.deinit(allocator);

    try testing.expect(result.auth.success);
    try testing.expect(result.auth.session_key != null);
    try testing.expectEqualStrings("SoftEther VPN Server", result.hello.server_str);
    try testing.expectEqual(@as(u32, server_version), result.hello.server_ver);
    try testing.expectEqual(@as(u32, server_build), result.hello.server_build);
    // Plaintext-over-TLS: the client must see encryption off.
    try testing.expect(!result.auth.server_use_encrypt);

    // Closing the client lets the server session loop observe EOF and end.
    e2e.client.close();
    e2e.client_closed = true;
}

test "server.accept rejects wrong password" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;

    const cert = try tls.generateSelfSignedCert(allocator, "accept.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var auth_hub = try auth_mod.Hub.init(allocator, "VPN");
    defer auth_hub.deinit();
    _ = try auth_hub.addUser("alice", .password, "hunter2");

    const switch_hub = try hub.Hub.init(allocator, "VPN");
    defer switch_hub.deinit();

    var e2e = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem, &auth_hub, switch_hub);
    defer e2e.deinit();

    var io = ClientIo{ .sock = &e2e.client };
    const writer = protocol_mod.Writer{ .context = &io, .writeFn = ClientIo.write };
    const reader = protocol_mod.Reader{ .context = &io, .readFn = ClientIo.read };

    var result = try protocol_mod.performHandshake(allocator, writer, reader, "accept.test", "VPN", "alice", "wrong", false);
    defer result.hello.deinit(allocator);
    defer result.auth.deinit(allocator);

    try testing.expect(!result.auth.success);
    try testing.expectEqual(error_auth_failed, result.auth.error_code);

    e2e.client.close();
    e2e.client_closed = true;
}

test "server.accept authenticates case-insensitive username" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;

    const cert = try tls.generateSelfSignedCert(allocator, "accept.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    // Account registered as "Alice"; the client connects as "alice". SoftEther
    // matches account names case-insensitively (C: `SearchUser`/`StrCmpi`).
    var auth_hub = try auth_mod.Hub.init(allocator, "VPN");
    defer auth_hub.deinit();
    _ = try auth_hub.addUser("Alice", .password, "hunter2");

    const switch_hub = try hub.Hub.init(allocator, "VPN");
    defer switch_hub.deinit();

    var e2e = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem, &auth_hub, switch_hub);
    defer e2e.deinit();

    var io = ClientIo{ .sock = &e2e.client };
    const writer = protocol_mod.Writer{ .context = &io, .writeFn = ClientIo.write };
    const reader = protocol_mod.Reader{ .context = &io, .readFn = ClientIo.read };

    var result = try protocol_mod.performHandshake(allocator, writer, reader, "accept.test", "VPN", "alice", "hunter2", false);
    defer result.hello.deinit(allocator);
    defer result.auth.deinit(allocator);

    try testing.expect(result.auth.success);

    e2e.client.close();
    e2e.client_closed = true;
}

test "server.accept idle session emits keep-alive (bounded data-plane read)" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const tunnel_mod = @import("../protocol/tunnel.zig");

    const cert = try tls.generateSelfSignedCert(allocator, "accept.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var auth_hub = try auth_mod.Hub.init(allocator, "VPN");
    defer auth_hub.deinit();
    _ = try auth_hub.addUser("alice", .password, "hunter2");

    const switch_hub = try hub.Hub.init(allocator, "VPN");
    defer switch_hub.deinit();

    var e2e = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem, &auth_hub, switch_hub);
    defer e2e.deinit();

    var io = ClientIo{ .sock = &e2e.client };
    const writer = protocol_mod.Writer{ .context = &io, .writeFn = ClientIo.write };
    const reader = protocol_mod.Reader{ .context = &io, .readFn = ClientIo.read };

    var result = try protocol_mod.performHandshake(allocator, writer, reader, "accept.test", "VPN", "alice", "hunter2", false);
    defer result.hello.deinit(allocator);
    defer result.auth.deinit(allocator);
    try testing.expect(result.auth.success);

    // Keep the client open and idle. The server session loop's first action on
    // an idle wire is to send a tunnel keep-alive (SessionMain starts with
    // `next_keepalive_time = 0`). A blocking data-plane read would sit in
    // `readBlocking` forever and never reach the keep-alive — receiving it
    // proves the bounded read lets keep-alives and timeouts run.
    var ka_buf: [40]u8 = undefined;
    var ka_have: usize = 0;
    const deadline = std.time.milliTimestamp() + 5000;
    while (ka_have < ka_buf.len and std.time.milliTimestamp() < deadline) {
        const n = e2e.client.readBlocking(ka_buf[ka_have..]) catch 0;
        if (n == 0) break;
        ka_have += n;
    }
    try testing.expect(ka_have >= 8);
    try testing.expectEqual(tunnel_mod.KEEP_ALIVE_MAGIC, mem.readInt(u32, ka_buf[0..4], .big));

    e2e.client.close();
    e2e.client_closed = true;
}

/// Build an ARP-broadcast Ethernet frame for the loopback acceptance test
/// (src MAC is a valid unicast address, dst is the broadcast address). Padded
/// to the Ethernet minimum frame size (60 bytes, FCS excluded) so the gate
/// exercises a valid frame rather than a sub-minimum one.
fn buildLoopbackFrame() ![]u8 {
    const allocator = testing.allocator;
    const dst = [_]u8{0xff} ** 6;
    const src = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    const payload = [_]u8{
        // ARP request: htype=1, ptype=0x0800, hlen=6, plen=4, op=1,
        // sha=11:22:33:44:55:66, spa=10.0.0.1, tha=00..00, tpa=10.0.0.2
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x0a, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x02,
    };
    const min_frame_len = 60;
    const f = try allocator.alloc(u8, min_frame_len);
    @memset(f, 0);
    @memcpy(f[0..6], &dst);
    @memcpy(f[6..12], &src);
    mem.writeInt(u16, f[12..14], 0x0806, .big);
    @memcpy(f[14..][0..payload.len], &payload);
    return f;
}

test "server.accept two sessions exchange a frame through the hub" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;
    const tunnel_mod = @import("../protocol/tunnel.zig");

    const cert = try tls.generateSelfSignedCert(allocator, "accept.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var auth_hub = try auth_mod.Hub.init(allocator, "VPN");
    defer auth_hub.deinit();
    _ = try auth_hub.addUser("alice", .password, "hunter2");

    // One L2 switch hub shared by both sessions — the M1 gate: two clients on
    // the same hub see each other's frames switched at L2.
    const switch_hub = try hub.Hub.init(allocator, "VPN");
    defer switch_hub.deinit();

    var e2e_a = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem, &auth_hub, switch_hub);
    defer e2e_a.deinit();
    var e2e_b = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem, &auth_hub, switch_hub);
    defer e2e_b.deinit();

    // Handshake both clients against the server (same account, same hub).
    var io_a = ClientIo{ .sock = &e2e_a.client };
    var io_b = ClientIo{ .sock = &e2e_b.client };
    const writer_a = protocol_mod.Writer{ .context = &io_a, .writeFn = ClientIo.write };
    const reader_a = protocol_mod.Reader{ .context = &io_a, .readFn = ClientIo.read };
    const writer_b = protocol_mod.Writer{ .context = &io_b, .writeFn = ClientIo.write };
    const reader_b = protocol_mod.Reader{ .context = &io_b, .readFn = ClientIo.read };

    var ha = try protocol_mod.performHandshakeWithOpts(allocator, writer_a, reader_a, "accept.test", "VPN", "alice", "hunter2", false, .{ .use_encrypt = false });
    defer ha.hello.deinit(allocator);
    defer ha.auth.deinit(allocator);
    try testing.expect(ha.auth.success);

    var hb = try protocol_mod.performHandshakeWithOpts(allocator, writer_b, reader_b, "accept.test", "VPN", "alice", "hunter2", false, .{ .use_encrypt = false });
    defer hb.hello.deinit(allocator);
    defer hb.auth.deinit(allocator);
    try testing.expect(hb.auth.success);

    // Both server sessions must be attached to the hub before A sends — a
    // broadcast flood reaches nobody otherwise. Attach happens on the accept
    // thread right after the handshake, so wait (bounded, under the hub
    // mutex) for both.
    var attached: usize = 0;
    const attach_deadline = std.time.milliTimestamp() + 5000;
    while (attached < 2 and std.time.milliTimestamp() < attach_deadline) {
        switch_hub.mutex.lock();
        attached = switch_hub.sessions.items.len;
        switch_hub.mutex.unlock();
        if (attached < 2) std.Thread.sleep(2 * std.time.ns_per_ms);
    }
    try testing.expectEqual(@as(usize, 2), attached);

    // Wrap each client socket as a TunnelConnection. The test opts out of
    // encryption via use_encrypt=false, so the data plane is raw block
    // framing over TLS.
    var tunnel_a = tunnel_mod.TunnelConnection.init(allocator, &io_a, ClientIo.read, ClientIo.write);
    var tunnel_b = tunnel_mod.TunnelConnection.init(allocator, &io_b, ClientIo.read, ClientIo.write);

    // Client A sends one Ethernet frame as a tunnel block; the hub floods the
    // broadcast to B, and B's SessionMain pushes it back down the wire.
    const frame = try buildLoopbackFrame();
    defer allocator.free(frame);
    const blocks = [_][]const u8{frame};
    var send_buf: [tunnel_mod.MAX_PACKET_SIZE * 2]u8 = undefined;
    try tunnel_a.sendBlocksZeroCopy(&blocks, &send_buf);

    // Client B must receive the exact frame. receiveBlocksBatch reads through
    // readBlocking, which polls the fd for 30s — never enter it without known
    // data, or the 8s deadline is not actually enforced. Poll the raw fd (or
    // OpenSSL's already-buffered data) with a short timeout first. Returns 0
    // for keep-alives (the server sends one on an idle wire), so loop until a
    // data batch arrives.
    var out_data: [1][]u8 = undefined;
    var scratch: [tunnel_mod.MAX_PACKET_SIZE * 2]u8 = undefined;
    var received: ?[]const u8 = null;
    const recv_deadline = std.time.milliTimestamp() + 8000;
    while (received == null and std.time.milliTimestamp() < recv_deadline) {
        while (!e2e_b.client.hasPending() and std.time.milliTimestamp() < recv_deadline) {
            var pfd = [_]std.posix.pollfd{.{
                .fd = e2e_b.client.tcp_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            if ((std.posix.poll(&pfd, 50) catch 0) == 0) {
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            break;
        }
        if (std.time.milliTimestamp() >= recv_deadline) break;
        const n = tunnel_b.receiveBlocksBatch(&out_data, &scratch) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        if (n > 0) {
            received = out_data[0];
            break;
        }
    }
    try testing.expect(received != null);
    try testing.expectEqualSlices(u8, frame, received.?);

    e2e_a.client.close();
    e2e_a.client_closed = true;
    e2e_b.client.close();
    e2e_b.client_closed = true;
}
