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
//! - Data plane is plaintext-over-TLS (session_main.zig encryption note): the
//!   server always negotiates `use_encrypt=false`, so the client tunnels
//!   framed blocks directly over the TLS socket without an app-layer cipher.
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
const ServerSession = session_mod.ServerSession;
const SessionMain = @import("session_main.zig").SessionMain;
const session_registry_mod = @import("session_registry.zig");

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
};

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
/// signature → hello → auth/welcome, then the data plane. Exposed for the
/// end-to-end tests; `acceptConnection` wraps it in TLS accept + close.
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

    // 3. Auth — read the login pack, verify, and reply with the Welcome (or an
    //    error) pack.
    var established = (try authenticate(self, tls_sock, &hello_random)) orelse return;
    defer established.deinit(self.allocator);

    // 4. Data plane — attach to the hub and run the session loop.
    try runSession(self, tls_sock, &established, peer_ip, peer_port);
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

    fn deinit(self: *EstablishedSession, allocator: Allocator) void {
        allocator.free(self.session_name);
        allocator.free(self.connection_name);
        allocator.free(self.username);
    }
};

/// Read the login pack, verify it against the SAM hub, and reply with the
/// Welcome (or an error) pack. Returns null when the client was rejected.
fn authenticate(
    self: *ServerContext,
    tls_sock: *tls.TlsSocket,
    hello_random: *const [Protocol.sha1_size]u8,
) !?EstablishedSession {
    var buf: [http.max_pack_body_len]u8 = undefined;
    const request = try http.readHttpRequest(tls_sock, &buf);
    var pack = try Pack.fromBytes(self.allocator, request.body);
    defer pack.deinit();

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
    const auth_result = auth_mod.authenticate(self.auth_hub, hello_random, &pack);
    if (!auth_result.ok) {
        try sendAuthError(self, tls_sock, error_auth_failed, false);
        return null;
    }

    const username = pack.getStr("username") orelse {
        try sendAuthError(self, tls_sock, error_auth_failed, false);
        return null;
    };

    // Build the session with server policy. M1 data plane is plaintext-over-
    // TLS, so encryption is never negotiated regardless of the client request.
    var session = ServerSession.initWithOptions(self.allocator, hello_random, .{
        .max_connection = 1,
        .timeout = timeout_default_ms,
    });
    session.negotiate(false, false);

    // Session/connection names (C: `SID-<UPPERUSER>-<tick>`).
    const counter = self.session_counter.fetchAdd(1, .seq_cst);
    const upper = try self.allocator.dupe(u8, username);
    defer self.allocator.free(upper);
    for (upper) |*c| c.* = std.ascii.toUpper(c.*);
    const session_name = try std.fmt.allocPrint(self.allocator, "SID-{s}-{d}", .{ upper, counter });
    errdefer self.allocator.free(session_name);
    const connection_name = try std.fmt.allocPrint(self.allocator, "CONN-{d}", .{counter});
    errdefer self.allocator.free(connection_name);

    const welcome = try buildWelcomePack(self.allocator, &session, session_name, connection_name);
    defer self.allocator.free(welcome);
    try http.sendHttpResponse(tls_sock, welcome);

    const username_owned = try self.allocator.dupe(u8, username);

    return EstablishedSession{
        .session = session,
        .session_name = session_name,
        .connection_name = connection_name,
        .username = username_owned,
    };
}

/// Build the Welcome pack body (C: `PackWelcome`, Protocol.c:6442).
fn buildWelcomePack(
    allocator: Allocator,
    session: *const ServerSession,
    session_name: []const u8,
    connection_name: []const u8,
) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();

    try session.addWelcomeFields(&pack, session_name, connection_name);

    // Remaining fields C always emits (no UDP acceleration, no Azure session,
    // no special policies in M1).
    try pack.addBool("use_udp_acceleration", false);
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

    var main = try SessionMain.init(self.allocator, &tunnel, pa.pa(), .{
        .timeout_ms = established.session.timeout,
    });
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

    var result = try protocol_mod.performHandshake(allocator, writer, reader, "accept.test", "VPN", "alice", "hunter2", false);
    defer result.hello.deinit(allocator);
    defer result.auth.deinit(allocator);

    try testing.expect(result.auth.success);
    try testing.expect(result.auth.session_key != null);
    try testing.expectEqualStrings("SoftEther VPN Server", result.hello.server_str);
    try testing.expectEqual(@as(u32, server_version), result.hello.server_ver);
    try testing.expectEqual(@as(u32, server_build), result.hello.server_build);
    // M1 negotiates plaintext-over-TLS: the client must see encryption off.
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

    var ha = try protocol_mod.performHandshake(allocator, writer_a, reader_a, "accept.test", "VPN", "alice", "hunter2", false);
    defer ha.hello.deinit(allocator);
    defer ha.auth.deinit(allocator);
    try testing.expect(ha.auth.success);

    var hb = try protocol_mod.performHandshake(allocator, writer_b, reader_b, "accept.test", "VPN", "alice", "hunter2", false);
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

    // Wrap each client socket as a TunnelConnection (M1 negotiates plaintext,
    // so the data plane is raw block framing over TLS).
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
