//! Server admin RPC transport (issue #87).
//!
//! The native admin RPC session: a TLS connection that carries a stream of
//! Pack frames. Each request frame is `[u32 size][Pack bytes]` (size in
//! big-endian, matching C `Endian32`), dispatched on the `function_name`
//! string to a dispatcher table, and answered with a response Pack carrying
//! `error` / `error_code` fields.
//!
//! C reference (4.44):
//! - `StartRpcServer` (Remote.c:429) — the server-side RPC session
//! - `RpcServer` (Remote.c:277) — the request/response loop
//! - `RpcRecvNextCall` (Remote.c:201) — frame read + dispatch + reply
//! - `CallRpcDispatcher` (Remote.c:183) — read `function_name`, call dispatch
//! - `RpcError` / `RpcIsOk` / `RpcGetError` (Remote.c:170,151,139)
//! - `PackError` / `GetErrorFromPack` (Network.c:22792, 22803)
//!
//! ## M2 scope
//!
//! - Transport only: TLS accept + frame read/write + dispatch plumbing. The
//!   dispatcher table (issue #88) and structs (issue #89) live elsewhere.
//! - The accepted socket stays blocking with no SO_RCVTIMEO (tls.zig drops it
//!   after the handshake), so `recvAll` waits indefinitely for the next call
//!   — mirroring C's blocking `RecvAll` loop. No keep-alive or idle timeout.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const tls = @import("../../../mayaqua/network/tls.zig");
const socket = @import("../../../mayaqua/network/socket.zig");
const TcpSocket = socket.TcpSocket;
const pack_mod = @import("../../protocol/pack.zig");
const Pack = pack_mod.Pack;

const log = std.log.scoped(.admin_rpc);

// ============================================================================
// Constants
// ============================================================================

/// Upper bound for one Pack frame (C: `MAX_PACK_SIZE`, same as pack.zig).
pub const max_pack_size = pack_mod.MAX_PACK_SIZE;

/// Unsupported function error (C: Cedar.h `ERR_NOT_SUPPORTED`).
pub const err_not_supported: u32 = 33;

/// TLS accept handshake timeout in ms (C: `CONNECTING_TIMEOUT` 15 s).
const initial_timeout_ms: u32 = 15000;

// ============================================================================
// Rpc session
// ============================================================================

/// One server-side admin RPC session (C `struct RPC`, Remote.h:112-127,
/// server subset). Bound to one TLS connection; single-threaded.
pub const Rpc = struct {
    /// Mirrors C `RPC_DISPATCHER` (Remote.h:109):
    /// `PACK *(RPC_DISPATCHER)(RPC *r, char *function_name, PACK *p)`.
    ///
    /// `rpc` is the owning `*Rpc` session (cast via `@ptrCast`); it is
    /// `*anyopaque` to avoid a Zig type dependency loop between the function
    /// pointer type and the struct holding it (same trick as listener.zig's
    /// `AcceptHandler`).
    ///
    /// Returns a heap-allocated response Pack owned by the transport (freed
    /// after the reply is sent), or null when the function is not supported —
    /// the transport then replies with `ERR_NOT_SUPPORTED`.
    pub const Dispatcher = *const fn (rpc: *anyopaque, function_name: []const u8, request: *Pack) ?*Pack;

    allocator: Allocator,
    sock: *tls.TlsSocket,
    server_mode: bool = true,
    dispatch: Rpc.Dispatcher,
    param: *anyopaque,
    server_admin_mode: bool = false,
    hub_name: []const u8 = "",
    name: []const u8 = "",
    is_vpn_server: bool = false,

    pub fn init(
        allocator: Allocator,
        sock: *tls.TlsSocket,
        dispatch: Rpc.Dispatcher,
        param: *anyopaque,
    ) Rpc {
        return .{
            .allocator = allocator,
            .sock = sock,
            .dispatch = dispatch,
            .param = param,
        };
    }

    /// C `RpcServer` (Remote.c:277): serve requests until the connection ends
    /// or a transport error occurs.
    pub fn runServer(self: *Rpc) void {
        while (true) {
            if (!self.recvNextCall()) return;
        }
    }

    /// C `RpcRecvNextCall` (Remote.c:201). Reads one request frame, dispatches
    /// it, and writes the response frame. Returns false when the connection
    /// closed (gracefully or otherwise) or the frame was invalid.
    pub fn recvNextCall(self: *Rpc) bool {
        var request = recvFrame(self.allocator, self.sock) catch |err| {
            if (err != error.EndOfStream) {
                log.debug("recv frame failed: {s}", .{@errorName(err)});
            }
            return false;
        } orelse return false;
        defer request.deinit();

        var response: *Pack = self.callDispatcher(&request) orelse
            (packError(self.allocator, err_not_supported) catch return false);
        defer {
            response.deinit();
            self.allocator.destroy(response);
        }

        sendFrame(self.sock, self.allocator, response) catch |err| {
            log.debug("send frame failed: {s}", .{@errorName(err)});
            return false;
        };
        return true;
    }

    /// C `CallRpcDispatcher` (Remote.c:183). Missing `function_name` is
    /// treated as "not supported" (null) rather than an explicit error.
    fn callDispatcher(self: *Rpc, request: *Pack) ?*Pack {
        const function_name = request.getStr("function_name") orelse return null;
        return self.dispatch(self, function_name, request);
    }
};

/// C `StartRpcServer` (Remote.c:429). Creates the server-side session value.
/// The transport frees the request/response Packs; the socket is owned by the
/// caller (usually a per-connection accept handler that TLS-accepts first).
pub fn startRpcServer(
    allocator: Allocator,
    sock: *tls.TlsSocket,
    dispatch: Rpc.Dispatcher,
    param: *anyopaque,
) Rpc {
    return Rpc.init(allocator, sock, dispatch, param);
}

// ============================================================================
// Frame I/O — `[u32 size (big-endian)][Pack bytes]`
// ============================================================================

/// Write one frame: a big-endian u32 size followed by the serialized Pack.
/// C: `SendAdd` of `Endian32(b->Size)` then the buffer (Remote.c:383-384).
pub fn sendFrame(sock: *tls.TlsSocket, allocator: Allocator, p: *const Pack) !void {
    const bytes = try p.toBytes(allocator);
    defer allocator.free(bytes);

    var size_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &size_buf, @intCast(bytes.len), .big);
    try sock.writeAll(&size_buf);
    try sock.writeAll(bytes);
}

/// Read one frame, returning the parsed Pack. Returns null on a graceful close
/// before any frame data arrives (peer disconnected between calls). C:
/// `RecvAll` of the size then the payload (Remote.c:210-224).
pub fn recvFrame(allocator: Allocator, sock: *tls.TlsSocket) !?Pack {
    var size_buf: [4]u8 = undefined;
    recvAll(sock, &size_buf) catch |err| switch (err) {
        error.EndOfStream => return null,
        else => return err,
    };

    const size = std.mem.readInt(u32, &size_buf, .big);
    if (size == 0 or size > max_pack_size) return error.InvalidFrameSize;

    const payload = try allocator.alloc(u8, size);
    defer allocator.free(payload);
    try recvAll(sock, payload);

    return try Pack.fromBytes(allocator, payload);
}

/// Read exactly `buf.len` bytes. The accepted TLS socket is blocking with no
/// SO_RCVTIMEO after the handshake, so this waits indefinitely for inbound
/// data (C `RecvAll` blocking semantics for the admin control connection).
fn recvAll(sock: *tls.TlsSocket, buf: []u8) !void {
    var index: usize = 0;
    while (index < buf.len) {
        const n = sock.read(buf[index..]) catch |err| switch (err) {
            error.WouldBlock => {
                var pfd = [_]std.posix.pollfd{.{
                    .fd = sock.tcp_fd,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                _ = std.posix.poll(&pfd, -1) catch return error.Closed;
                continue;
            },
            else => return err,
        };
        if (n == 0) return error.EndOfStream;
        index += n;
    }
}

// ============================================================================
// Error helpers (C: Remote.c / Network.c)
// ============================================================================

/// C `PackError` (Network.c:22792): a Pack carrying only `error = code`.
pub fn packError(allocator: Allocator, code: u32) !*Pack {
    const p = try allocator.create(Pack);
    errdefer allocator.destroy(p);
    p.* = Pack.init(allocator);
    errdefer p.deinit();
    try p.addInt("error", code);
    return p;
}

/// C `RpcError` (Remote.c:170): mark a response Pack as failed.
pub fn rpcError(p: *Pack, err: u32) !void {
    try p.addInt("error", 1);
    try p.addInt("error_code", err);
}

/// C `RpcIsOk` (Remote.c:151): success iff `error == 0` (absent counts as 0).
pub fn rpcIsOk(p: *const Pack) bool {
    return (p.getInt("error") orelse 0) == 0;
}

/// C `RpcGetError` (Remote.c:139): the response's `error_code`.
pub fn rpcGetError(p: *const Pack) u32 {
    return p.getInt("error_code") orelse 0;
}

/// C `GetErrorFromPack` (Network.c:22803): the raw `error` field.
pub fn getErrorFromPack(p: *const Pack) u32 {
    return p.getInt("error") orelse 0;
}

// ============================================================================
// Accept handler (listener.zig AcceptHandler)
// ============================================================================

/// Accept endpoint context: the TLS credentials plus the dispatcher table
/// (issue #88 fills it). Owned by the server bootstrap; the accept handler
/// borrows it for the connection's lifetime.
pub const AdminRpcContext = struct {
    allocator: Allocator,
    cert_pem: []const u8,
    key_pem: []const u8,
    dispatch: Rpc.Dispatcher,
    param: *anyopaque,
};

/// The `AcceptHandler` entry point (listener.zig). Runs on the per-connection
/// thread: TLS-accepts, then serves the admin RPC loop until the client
/// disconnects. Mirrors accept.zig's `acceptConnection`.
pub fn acceptAdminConnection(ctx: *anyopaque, sock: *TcpSocket, peer_ip: u32, peer_port: u16) void {
    _ = peer_port;
    const self: *AdminRpcContext = @ptrCast(@alignCast(ctx));

    const fd = sock.stream.handle;
    var tls_sock = tls.TlsSocket.accept(self.allocator, fd, .{
        .cert_pem = self.cert_pem,
        .key_pem = self.key_pem,
        .timeout_ms = initial_timeout_ms,
    }) catch |err| {
        std.posix.close(fd);
        log.warn("admin RPC TLS accept failed ({s}): {s}", .{ fmtIp(peer_ip), @errorName(err) });
        return;
    };
    defer tls_sock.close();

    var rpc = startRpcServer(self.allocator, &tls_sock, self.dispatch, self.param);
    rpc.runServer();
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

// ============================================================================
// Tests
// ============================================================================

const builtin = @import("builtin");

var test_dial_fd: c_int = -1;

fn testDial(host: [*:0]const u8, port: u16) callconv(.c) c_int {
    _ = host;
    _ = port;
    return test_dial_fd;
}

/// Dispatcher recording call count; returns error=0 + `value` for "Test",
/// null (not supported) otherwise.
const TestParam = struct { calls: usize = 0 };

fn testDispatcher(rpc: *anyopaque, function_name: []const u8, request: *Pack) ?*Pack {
    const rpc_self: *Rpc = @ptrCast(@alignCast(rpc));
    const param: *TestParam = @ptrCast(@alignCast(rpc_self.param));
    param.calls += 1;
    _ = request;
    if (mem.eql(u8, function_name, "Test")) {
        var resp = packError(rpc_self.allocator, 0) catch return null;
        resp.addInt("value", 42) catch {};
        return resp;
    }
    return null;
}

const ServerThreadCtx = struct {
    ctx: *AdminRpcContext,
    fd: std.posix.socket_t,
};

fn adminThread(a: *ServerThreadCtx) void {
    var sock = TcpSocket{ .stream = .{ .handle = a.fd } };
    acceptAdminConnection(a.ctx, &sock, 0, 0);
}

/// Spawn the admin RPC server thread and TLS-connect a client to it over an
/// AF_UNIX socketpair. `param` is the dispatcher param handed to the server.
const EndToEnd = struct {
    allocator: Allocator,
    thread: std.Thread,
    client: tls.TlsSocket,
    thread_ctx: *ServerThreadCtx,
    admin_ctx: *AdminRpcContext,
    param: *TestParam,
    client_closed: bool = false,

    fn deinit(self: *EndToEnd) void {
        if (!self.client_closed) self.client.close();
        self.thread.join();
        self.allocator.destroy(self.thread_ctx);
        self.allocator.destroy(self.admin_ctx);
        self.allocator.destroy(self.param);
    }
};

fn startEndToEnd(allocator: Allocator, cert_pem: []const u8, key_pem: []const u8) !EndToEnd {
    var fds: [2]std.posix.socket_t = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SocketPairFailed;

    const param = try allocator.create(TestParam);
    errdefer allocator.destroy(param);
    param.* = .{};

    const admin_ctx = try allocator.create(AdminRpcContext);
    admin_ctx.* = .{
        .allocator = allocator,
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .dispatch = testDispatcher,
        .param = param,
    };
    const thread_ctx = try allocator.create(ServerThreadCtx);
    thread_ctx.* = .{ .ctx = admin_ctx, .fd = fds[0] };
    errdefer allocator.destroy(thread_ctx);
    errdefer allocator.destroy(admin_ctx);
    const thread = try std.Thread.spawn(.{}, adminThread, .{thread_ctx});

    test_dial_fd = @intCast(fds[1]);
    const client = tls.TlsSocket.connect(allocator, "admin.test", 443, .{
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
        .thread_ctx = thread_ctx,
        .admin_ctx = admin_ctx,
        .param = param,
    };
}

test "server.admin_rpc dispatch round-trip over TLS" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;

    const cert = try tls.generateSelfSignedCert(allocator, "admin.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var e2e = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem);
    defer e2e.deinit();

    // Client sends a "Test" call and reads the response frame.
    var req = Pack.init(allocator);
    defer req.deinit();
    try req.addStr("function_name", "Test");
    try req.addStr("param", "hello");
    try sendFrame(&e2e.client, allocator, &req);

    var resp = (try recvFrame(allocator, &e2e.client)).?;
    defer resp.deinit();

    try testing.expect(rpcIsOk(&resp));
    try testing.expectEqual(@as(u32, 0), getErrorFromPack(&resp));
    try testing.expectEqual(@as(u32, 42), resp.getInt("value").?);
    try testing.expectEqual(@as(usize, 1), e2e.param.calls);

    e2e.client.close();
    e2e.client_closed = true;
}

test "server.admin_rpc unknown function replies ERR_NOT_SUPPORTED" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = testing.allocator;

    const cert = try tls.generateSelfSignedCert(allocator, "admin.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var e2e = try startEndToEnd(allocator, cert.cert_pem, cert.key_pem);
    defer e2e.deinit();

    var req = Pack.init(allocator);
    defer req.deinit();
    try req.addStr("function_name", "NoSuchFunction");
    try sendFrame(&e2e.client, allocator, &req);

    var resp = (try recvFrame(allocator, &e2e.client)).?;
    defer resp.deinit();

    try testing.expect(!rpcIsOk(&resp));
    try testing.expectEqual(err_not_supported, getErrorFromPack(&resp));

    e2e.client.close();
    e2e.client_closed = true;
}

test "server.admin_rpc error helpers" {
    const allocator = testing.allocator;

    var p = Pack.init(allocator);
    defer p.deinit();
    try rpcError(&p, err_not_supported);

    try testing.expect(!rpcIsOk(&p));
    try testing.expectEqual(err_not_supported, rpcGetError(&p));
    try testing.expectEqual(@as(u32, 1), getErrorFromPack(&p));

    var ok = Pack.init(allocator);
    defer ok.deinit();
    try ok.addInt("error", 0);
    try testing.expect(rpcIsOk(&ok));

    // Absent "error" counts as success (C PackGetInt defaults to 0).
    var empty = Pack.init(allocator);
    defer empty.deinit();
    try testing.expect(rpcIsOk(&empty));
}
