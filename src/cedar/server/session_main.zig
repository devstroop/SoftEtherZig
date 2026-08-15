//! Server session main loop — the data-plane orchestration for one session.
//!
//! C reference: `SessionMain` (Session.c:108). Per iteration:
//!
//!   1. receive framed blocks from the wire
//!      (`ConnectionReceive`, Connection.c:1628)
//!   2. drain the received blocks into the hub packet adapter
//!      (`pa->PutPacket` per block, then a NULL flush)
//!   3. pull frames from the hub packet adapter and queue them for sending
//!      (`pa->GetNextPacket`, Session.c:456-558)
//!   4. write the queued frames to the wire (`ConnectionSend`, Connection.c:1015)
//!   5. inject a keep-alive when the wire has been quiet for a while
//!      (`SendKeepAlive`, Connection.c:959)
//!   6. enforce the session inactivity timeout
//!
//! All wire framing/compression/keep-alive is reused from
//! `protocol/tunnel.zig` (`TunnelConnection.receiveBlocksBatch`,
//! `sendBlocksZeroCopy`, `sendKeepalive`) — the same framing the Zig client
//! speaks, so the server stays wire-compatible with it.
//!
//! ## Encryption note
//!
//! The M1 data channel is plaintext-over-TLS: the Zig client's tunnel reads
//! and writes the `TlsSocket` directly (RCA-01 — the client AES-256-CBC path
//! is dead code; `connection_manager.zig`/`vpn_client.zig` wire the tunnel
//! straight to the TLS socket). This module therefore operates on the framed
//! byte stream without any application-layer cipher. `ConnectionCipher`
//! (`session.zig`) remains available for a future data-channel hardening
//! layer and is deliberately not interposed here.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const log = std.log.scoped(.cedar_server);

const tunnel_mod = @import("../protocol/tunnel.zig");
const TunnelConnection = tunnel_mod.TunnelConnection;
const MAX_PACKET_SIZE = tunnel_mod.MAX_PACKET_SIZE;
const MAX_RECV_BLOCKS = tunnel_mod.MAX_RECV_BLOCKS;

/// Default session inactivity timeout (C server policy default: 5 minutes).
/// When no bytes have flowed in either direction for this long, the session
/// is torn down. 0 disables the timeout.
pub const DEFAULT_TIMEOUT_MS: u32 = 300000;

/// Max frames pulled from the packet adapter per loop iteration
/// (C: `MAX_SEND_SOCKET_QUEUE_NUM` = 128, Cedar.h:248).
pub const DEFAULT_MAX_SEND_BATCH: usize = 128;

/// Buffering cap for frames waiting to be sent. Frames are dropped while the
/// pending queue exceeds this (C: `MAX_BUFFERING_PACKET_SIZE`, Cedar.h:245).
pub const DEFAULT_MAX_BUFFERING_SIZE: usize = 1600 * 300;

/// Per-session data statistics (subset of C `TRAFFIC`).
pub const SessionStats = struct {
    /// Blocks received from the wire and handed to the hub.
    rx_blocks: u64 = 0,
    /// Payload bytes received (before framing).
    rx_bytes: u64 = 0,
    /// Blocks pulled from the hub and sent on the wire.
    tx_blocks: u64 = 0,
    /// Payload bytes sent (before framing).
    tx_bytes: u64 = 0,
    /// Keep-alives received and discarded.
    keepalives_recv: u64 = 0,
    /// Keep-alives sent on idle wire.
    keepalives_sent: u64 = 0,
};

/// Hub-facing packet adapter interface (C: `PACKET_ADAPTER`, Session.h:153).
///
/// The L2 hub (`hub.zig`, issue #82) implements this; tests use a mock. A
/// `PacketAdapter` is a value type holding an opaque context plus function
/// pointers, so the hub can hand the session a plain struct.
pub const PacketAdapter = struct {
    ctx: *anyopaque,

    /// Initialize the adapter before the loop runs. Returning false aborts the
    /// session (C: `pa->Init`).
    init: *const fn (ctx: *anyopaque) bool = nullAdapterInit,
    /// Release adapter resources when the session ends (C: `pa->Free`).
    free: *const fn (ctx: *anyopaque) void = nullAdapterFree,
    /// Deliver one received Ethernet frame to the hub. The adapter MUST copy
    /// the frame if it retains it — the slice is only valid for the call
    /// (it aliases the receive scratch buffer). Returning false signals a
    /// device error and tears the session down (C: `pa->PutPacket`).
    put: *const fn (ctx: *anyopaque, frame: []const u8) bool = nullAdapterPut,
    /// Flush pending hub-side work after a batch of puts
    /// (C: `pa->PutPacket(s, NULL, 0)`, Session.c:440-449).
    flush: *const fn (ctx: *anyopaque) bool = nullAdapterFlush,
    /// Return the next frame to send downstream, or null when none is ready.
    /// The returned slice is heap-allocated and owned by the session — the
    /// session frees it after writing it to the wire (C: `pa->GetNextPacket`,
    /// caller frees the returned packet).
    get: *const fn (ctx: *anyopaque) ?[]u8 = nullAdapterGet,

    /// Null-adapter defaults so a mock/tests can override only the callbacks
    /// it needs. The null `init`/`free`/`put`/`flush` are no-ops.
    fn nullAdapterInit(_: *anyopaque) bool {
        return true;
    }
    fn nullAdapterFree(_: *anyopaque) void {}
    fn nullAdapterPut(_: *anyopaque, _: []const u8) bool {
        return true;
    }
    fn nullAdapterFlush(_: *anyopaque) bool {
        return true;
    }
    fn nullAdapterGet(_: *anyopaque) ?[]u8 {
        return null;
    }
};

/// Session loop configuration.
pub const SessionConfig = struct {
    /// Session inactivity timeout in ms; 0 = infinite.
    timeout_ms: u32 = DEFAULT_TIMEOUT_MS,
    /// Max frames pulled from the packet adapter per iteration.
    max_send_batch: usize = DEFAULT_MAX_SEND_BATCH,
    /// Bytes of pending send data allowed before frames start being dropped.
    max_buffering_size: usize = DEFAULT_MAX_BUFFERING_SIZE,
    /// Send keep-alives when the wire is idle. Disable only for tests that
    /// need a deterministic inactivity timeout.
    enable_keepalive: bool = true,
    /// Called at the end of an iteration that made no progress (nothing
    /// received, nothing sent, no keep-alive due). The caller uses it to
    /// block/poll the transport — the analog of C `Select()` inside
    /// `ConnectionReceive`. null → a short sleep to avoid a busy spin.
    wait_fn: ?*const fn (ctx: *anyopaque) void = null,
    wait_ctx: ?*anyopaque = null,
};

/// The session main loop. Owns no sockets and no hub state — it coordinates a
/// borrowed `TunnelConnection` (wire I/O) and a `PacketAdapter` (hub I/O).
///
/// `TunnelConnection.use_compress` must be configured and
/// `initCompression()` called by the caller before `run()`; the loop applies
/// whatever the tunnel is configured with.
pub const SessionMain = struct {
    allocator: Allocator,
    tunnel: *TunnelConnection,
    pa: PacketAdapter,
    config: SessionConfig,

    /// Set by `requestStop` (any thread); the loop ends with `error.Stopped`.
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    last_comm_time: i64 = 0,
    next_keepalive_time: i64 = 0,
    send_queue_bytes: usize = 0,

    // Heap buffers (large; must not live on the stack).
    recv_out: [][]u8,
    recv_scratch: []u8,
    send_buf: []u8,
    send_batch: [][]const u8,

    stats: SessionStats = .{},

    pub fn init(
        allocator: Allocator,
        tunnel: *TunnelConnection,
        pa: PacketAdapter,
        config: SessionConfig,
    ) !SessionMain {
        const recv_out = try allocator.alloc([]u8, MAX_RECV_BLOCKS);
        errdefer allocator.free(recv_out);
        // receiveBlocksBatch admits blocks up to MAX_PACKET_SIZE * 2 each
        // (wire and decompressed), so the scratch must budget that per slot.
        const recv_scratch = try allocator.alloc(u8, MAX_RECV_BLOCKS * (MAX_PACKET_SIZE * 2));
        errdefer allocator.free(recv_scratch);

        const max_batch = if (config.max_send_batch == 0) DEFAULT_MAX_SEND_BATCH else config.max_send_batch;
        const send_batch = try allocator.alloc([]const u8, max_batch);
        errdefer allocator.free(send_batch);
        // sendBlocksZeroCopy writes a 4-byte batch-count header, then per
        // block a 4-byte size header + up to MAX_PACKET_SIZE * 2 payload
        // bytes (compressed frames can expand up to that bound).
        const send_buf = try allocator.alloc(u8, 4 + max_batch * (MAX_PACKET_SIZE * 2 + 4));
        errdefer allocator.free(send_buf);

        return .{
            .allocator = allocator,
            .tunnel = tunnel,
            .pa = pa,
            .config = config,
            .recv_out = recv_out,
            .recv_scratch = recv_scratch,
            .send_buf = send_buf,
            .send_batch = send_batch,
        };
    }

    pub fn deinit(self: *SessionMain) void {
        self.allocator.free(self.send_buf);
        self.allocator.free(self.send_batch);
        self.allocator.free(self.recv_scratch);
        self.allocator.free(self.recv_out);
        self.* = undefined;
    }

    /// Ask the loop to stop; `run` returns `error.Stopped`. Thread-safe:
    /// `run` polls this flag each iteration.
    pub fn requestStop(self: *SessionMain) void {
        self.halt.store(true, .seq_cst);
    }

    /// Run the session loop until stop requested, transport closed, or an
    /// error. End reasons are the `SessionEnd` error set.
    pub fn run(self: *SessionMain) !void {
        if (!self.pa.init(self.pa.ctx)) return error.PacketAdapterInitFailed;
        defer self.pa.free(self.pa.ctx);

        const start = std.time.milliTimestamp();
        self.last_comm_time = start;
        // C: `tcpsock->NextKeepAliveTime == 0` ⇒ the first ConnectionSend
        // immediately sends a keep-alive (NAT hole punching / warmup).
        self.next_keepalive_time = 0;

        while (!self.halt.load(.seq_cst)) {
            var progress = false;

            // 1+2. Receive from the wire, hand each block to the hub. Drain as
            // many complete messages as are buffered (C's ConnectionReceive
            // consumes everything the socket has), but keep the loop bounded
            // so the outbound path and keep-alive are serviced too.
            var recv_batches: usize = 0;
            while (true) {
                const recv_start = self.tunnel.total_recv;
                const recv_count = self.tunnel.receiveBlocksBatch(self.recv_out, self.recv_scratch) catch |err| switch (err) {
                    error.WouldBlock => break, // no full message yet — normal
                    error.ConnectionClosed => return error.ConnectionClosed,
                    else => return err,
                };
                if (recv_count > 0) {
                    for (self.recv_out[0..recv_count]) |frame| {
                        self.stats.rx_blocks += 1;
                        self.stats.rx_bytes += frame.len;
                        if (!self.pa.put(self.pa.ctx, frame)) return error.PacketAdapterPutFailed;
                    }
                }
                if (self.tunnel.total_recv > recv_start) {
                    // Any bytes consumed from the wire (frames, a keep-alive,
                    // or a zero-block message) count as communication — C
                    // updates LastCommTime on every socket read
                    // (Connection.c:2099).
                    self.stats.keepalives_recv = self.tunnel.keepalives_recv;
                    self.touchComm();
                    progress = true;
                }
                // A keep-alive or empty message was consumed; keep draining.
                if (recv_count == 0) continue;
                recv_batches += 1;
                // Cap the drain so a flooding peer cannot starve outbound
                // traffic, keep-alives, or the timeout check.
                if (recv_batches >= MAX_RECV_BLOCKS) break;
                if (self.halt.load(.seq_cst)) break;
            }
            // C calls `pa->PutPacket(s, NULL, 0)` every iteration for server
            // sessions (Session.c:440-449) — the hub flush hook.
            if (!self.pa.flush(self.pa.ctx)) return error.PacketAdapterFlushFailed;

            if (self.halt.load(.seq_cst)) break;

            // 3. Keep-alive on idle wire — C sends it at the top of
            //    ConnectionSend, BEFORE the data batch (Connection.c:1080-1088).
            const now = std.time.milliTimestamp();
            if (self.config.enable_keepalive and now >= self.next_keepalive_time) {
                try self.tunnel.sendKeepalive();
                self.stats.keepalives_sent = self.tunnel.keepalives_sent;
                self.next_keepalive_time = now + self.genNextKeepAliveSpan();
                self.touchComm();
                progress = true;
            }

            // 4. Pull frames from the hub and write them to the wire.
            if (try self.drainAndSend()) progress = true;

            // 5. Session inactivity timeout.
            if (self.config.timeout_ms != 0) {
                const idle = now - self.last_comm_time;
                if (idle >= @as(i64, self.config.timeout_ms)) {
                    log.warn("session timed out after {d} ms of inactivity", .{idle});
                    return error.SessionTimeout;
                }
            }

            if (!progress) {
                if (self.config.wait_fn) |w| {
                    w(self.config.wait_ctx orelse self.pa.ctx);
                } else {
                    std.Thread.sleep(std.time.ns_per_ms);
                }
            }
        }

        return error.Stopped;
    }

    /// Pull up to `max_send_batch` frames from the packet adapter, frame them
    /// with the tunnel (compression included), and write them to the wire.
    /// Returns true if at least one frame was sent.
    fn drainAndSend(self: *SessionMain) !bool {
        var count: usize = 0;
        var sent_bytes: usize = 0;

        while (count < self.send_batch.len) {
            const frame = self.pa.get(self.pa.ctx) orelse break;
            // C drops frames once the pending send queue is over budget
            // (Session.c:473-479).
            if (self.send_queue_bytes + frame.len > self.config.max_buffering_size) {
                self.allocator.free(frame);
                log.warn("dropping frame: send queue over buffering budget", .{});
                continue;
            }
            self.send_batch[count] = frame;
            count += 1;
            sent_bytes += frame.len;
            self.send_queue_bytes += frame.len;
        }

        if (count == 0) return false;

        errdefer for (self.send_batch[0..count]) |f| self.allocator.free(f);
        try self.tunnel.sendBlocksZeroCopy(self.send_batch[0..count], self.send_buf);

        // The frames are owned by the session; free them after the copy.
        for (self.send_batch[0..count]) |f| self.allocator.free(f);

        self.send_queue_bytes = 0; // the whole batch hit the wire
        self.stats.tx_blocks += count;
        self.stats.tx_bytes += sent_bytes;
        self.touchComm();
        return true;
    }

    fn touchComm(self: *SessionMain) void {
        self.last_comm_time = std.time.milliTimestamp();
    }

    /// Keep-alive interval between `timeout/5` and `timeout/2` ms — the C
    /// `GenNextKeepAliveSpan` (Connection.c:948-956). A 0 timeout uses the
    /// default span, so an infinite-timeout session still keeps the peer warm.
    fn genNextKeepAliveSpan(self: *const SessionMain) i64 {
        const a: i64 = if (self.config.timeout_ms == 0) DEFAULT_TIMEOUT_MS else self.config.timeout_ms;
        const half = @divTrunc(a, 2);
        const fifth = @divTrunc(a, 5);
        const b = if (half > 0) std.crypto.random.intRangeAtMost(i64, 0, half) else 0;
        return @max(b, fifth);
    }
};

/// End reasons returned by `SessionMain.run`.
pub const SessionEnd = error{
    /// `requestStop` was called.
    Stopped,
    /// The peer closed the transport (read returned 0).
    ConnectionClosed,
    /// No communication in either direction for `timeout_ms`.
    SessionTimeout,
    /// `PacketAdapter.init` returned false.
    PacketAdapterInitFailed,
    /// `PacketAdapter.put` returned false.
    PacketAdapterPutFailed,
    /// `PacketAdapter.flush` returned false.
    PacketAdapterFlushFailed,
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

/// In-memory byte pipe simulating the TCP/TLS transport. `to_server` is data
/// the client wrote (the server tunnel reads it); `from_server` is data the
/// server wrote (the client reads it).
const Loopback = struct {
    allocator: Allocator,
    to_server: std.ArrayList(u8),
    from_server: std.ArrayList(u8),
    /// When true, reads return 0 (EOF) once the buffer is drained.
    closed: bool = false,

    fn init(allocator: Allocator) Loopback {
        return .{
            .allocator = allocator,
            .to_server = std.ArrayList(u8).empty,
            .from_server = std.ArrayList(u8).empty,
        };
    }

    fn deinit(self: *Loopback) void {
        self.to_server.deinit(self.allocator);
        self.from_server.deinit(self.allocator);
    }

    fn appendToServer(self: *Loopback, data: []const u8) !void {
        try self.to_server.appendSlice(self.allocator, data);
    }

    fn serverRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *Loopback = @ptrCast(@alignCast(ctx));
        if (self.to_server.items.len == 0) {
            if (self.closed) return 0;
            return error.WouldBlock;
        }
        const n = @min(buf.len, self.to_server.items.len);
        @memcpy(buf[0..n], self.to_server.items[0..n]);
        std.mem.copyForwards(u8, self.to_server.items[0 .. self.to_server.items.len - n], self.to_server.items[n..]);
        self.to_server.shrinkRetainingCapacity(self.to_server.items.len - n);
        return n;
    }

    fn serverWrite(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *Loopback = @ptrCast(@alignCast(ctx));
        try self.from_server.appendSlice(self.allocator, data);
        return data.len;
    }

    fn clientRead(ctx: *anyopaque, buf: []u8) anyerror!usize {
        const self: *Loopback = @ptrCast(@alignCast(ctx));
        if (self.from_server.items.len == 0) return error.WouldBlock;
        const n = @min(buf.len, self.from_server.items.len);
        @memcpy(buf[0..n], self.from_server.items[0..n]);
        std.mem.copyForwards(u8, self.from_server.items[0 .. self.from_server.items.len - n], self.from_server.items[n..]);
        self.from_server.shrinkRetainingCapacity(self.from_server.items.len - n);
        return n;
    }

    fn clientWrite(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *Loopback = @ptrCast(@alignCast(ctx));
        try self.to_server.appendSlice(self.allocator, data);
        return data.len;
    }
};

/// Mock hub packet adapter. `received` holds copies of frames delivered via
/// `put`; `to_send` holds frames the hub wants sent (ownership moves to the
/// session via `get`). The mock does NOT free its own memory in `free` — the
/// test fixture owns everything and cleans up after `run` returns.
const MockPa = struct {
    allocator: Allocator,
    received: std.ArrayList([]u8),
    to_send: std.ArrayList([]u8),
    flush_count: usize = 0,
    fail_init: bool = false,
    fail_put: bool = false,
    fail_flush: bool = false,
    /// Set after SessionMain.init; the wait driver uses it to requestStop.
    session: ?*SessionMain = null,
    /// Optional stop predicate consulted by the wait driver.
    stop_when: ?*const fn (self: *MockPa) bool = null,

    fn init(allocator: Allocator) MockPa {
        return .{
            .allocator = allocator,
            .received = std.ArrayList([]u8).empty,
            .to_send = std.ArrayList([]u8).empty,
        };
    }

    fn deinit(self: *MockPa) void {
        for (self.received.items) |f| self.allocator.free(f);
        for (self.to_send.items) |f| self.allocator.free(f);
        self.received.deinit(self.allocator);
        self.to_send.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add a frame for the hub to send (copied — `get` transfers ownership of
    /// the copy to the session).
    fn queueSend(self: *MockPa, frame: []const u8) !void {
        const copy = try self.allocator.dupe(u8, frame);
        errdefer self.allocator.free(copy);
        try self.to_send.append(self.allocator, copy);
    }

    fn pa(self: *MockPa) PacketAdapter {
        return .{
            .ctx = self,
            .init = paInit,
            .free = paFree,
            .put = paPut,
            .flush = paFlush,
            .get = paGet,
        };
    }

    fn paInit(ctx: *anyopaque) bool {
        const self: *MockPa = @ptrCast(@alignCast(ctx));
        return !self.fail_init;
    }
    fn paFree(_: *anyopaque) void {}
    fn paPut(ctx: *anyopaque, frame: []const u8) bool {
        const self: *MockPa = @ptrCast(@alignCast(ctx));
        if (self.fail_put) return false;
        const copy = self.allocator.dupe(u8, frame) catch return false;
        self.received.append(self.allocator, copy) catch {
            self.allocator.free(copy);
            return false;
        };
        return true;
    }
    fn paFlush(ctx: *anyopaque) bool {
        const self: *MockPa = @ptrCast(@alignCast(ctx));
        if (self.fail_flush) return false;
        self.flush_count += 1;
        return true;
    }
    fn paGet(ctx: *anyopaque) ?[]u8 {
        const self: *MockPa = @ptrCast(@alignCast(ctx));
        if (self.to_send.items.len == 0) return null;
        return self.to_send.orderedRemove(0);
    }

    /// Default wait driver: requestStop once `stop_when` is true.
    fn waitDriver(ctx: *anyopaque) void {
        const self: *MockPa = @ptrCast(@alignCast(ctx));
        if (self.stop_when) |pred| {
            if (self.session) |s| {
                if (pred(self)) s.requestStop();
            }
        }
    }
};

/// Build the framing for `frames` (u32 BE count + per-block u32 BE size +
/// data), exactly as `TunnelConnection.sendBlocksZeroCopy` would.
fn frameBlocks(allocator: Allocator, frames: []const []const u8) ![]u8 {
    var total: usize = 4;
    for (frames) |f| total += 4 + f.len;
    const out = try allocator.alloc(u8, total);
    var offset: usize = 0;
    mem.writeInt(u32, out[0..4], @intCast(frames.len), .big);
    offset += 4;
    for (frames) |f| {
        mem.writeInt(u32, out[offset..][0..4], @intCast(f.len), .big);
        offset += 4;
        @memcpy(out[offset..][0..f.len], f);
        offset += f.len;
    }
    return out;
}

/// Run the session and return its end error; any error outside `SessionEnd` is
/// propagated to the caller.
fn runUntilStopped(session: *SessionMain) !void {
    session.run() catch |err| switch (err) {
        error.Stopped => return,
        else => return err,
    };
    return error.RunReturnedVoid;
}

test "server.session_main receive forwards frames to the hub" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{ .wait_fn = MockPa.waitDriver, .wait_ctx = &mock });
    defer session.deinit();
    mock.session = &session;

    // Craft a 2-frame batch on the wire (client → server).
    const f1 = "frame-alpha";
    const f2 = "frame-beta";
    const wire = try frameBlocks(allocator, &.{ f1, f2 });
    defer allocator.free(wire);
    try loop.appendToServer(wire);

    mock.stop_when = struct {
        fn pred(m: *MockPa) bool {
            return m.received.items.len == 2;
        }
    }.pred;

    try runUntilStopped(&session);

    try testing.expectEqual(@as(usize, 2), mock.received.items.len);
    try testing.expectEqualStrings(f1, mock.received.items[0]);
    try testing.expectEqualStrings(f2, mock.received.items[1]);
    try testing.expect(mock.flush_count >= 1);
    try testing.expectEqual(@as(u64, 2), session.stats.rx_blocks);
    try testing.expectEqual(@as(u64, f1.len + f2.len), session.stats.rx_bytes);
}

test "server.session_main sends hub frames on the wire" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();
    try mock.queueSend("hub-frame-1");
    try mock.queueSend("hub-frame-2");
    try mock.queueSend("hub-frame-3");

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{ .wait_fn = MockPa.waitDriver, .wait_ctx = &mock });
    defer session.deinit();
    mock.session = &session;

    mock.stop_when = struct {
        fn pred(m: *MockPa) bool {
            return m.session.?.stats.tx_blocks == 3;
        }
    }.pred;

    try runUntilStopped(&session);

    try testing.expectEqual(@as(u64, 3), session.stats.tx_blocks);
    try testing.expectEqual(@as(u64, 0), mock.to_send.items.len); // all pulled

    // Read the wire with a real client-side tunnel (keep-alive + frames).
    var client_tunnel = TunnelConnection.init(allocator, &loop, Loopback.clientRead, Loopback.clientWrite);
    defer client_tunnel.deinit();
    const out = try allocator.alloc([]u8, MAX_RECV_BLOCKS);
    defer allocator.free(out);
    const scratch = try allocator.alloc(u8, MAX_RECV_BLOCKS * 1600);
    defer allocator.free(scratch);

    // The first server iteration injects a keep-alive; the client tunnel
    // consumes it and reports zero blocks.
    _ = try client_tunnel.receiveBlocksBatch(out, scratch);
    const n = try client_tunnel.receiveBlocksBatch(out, scratch);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("hub-frame-1", out[0]);
    try testing.expectEqualStrings("hub-frame-2", out[1]);
    try testing.expectEqualStrings("hub-frame-3", out[2]);
}

test "server.session_main keep-alive injected on idle wire" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{ .wait_fn = MockPa.waitDriver, .wait_ctx = &mock });
    defer session.deinit();
    mock.session = &session;

    mock.stop_when = struct {
        fn pred(m: *MockPa) bool {
            return m.session.?.stats.keepalives_sent >= 1;
        }
    }.pred;

    try runUntilStopped(&session);

    // The wire must begin with KEEP_ALIVE_MAGIC.
    try testing.expect(loop.from_server.items.len >= 8);
    const magic = mem.readInt(u32, loop.from_server.items[0..4], .big);
    try testing.expectEqual(tunnel_mod.KEEP_ALIVE_MAGIC, magic);
    const ka_size = mem.readInt(u32, loop.from_server.items[4..8], .big);
    try testing.expect(ka_size <= tunnel_mod.MAX_KEEPALIVE_SIZE);
    try testing.expectEqual(@as(u64, 1), session.stats.keepalives_sent);
}

test "server.session_main drops frames over the buffering budget" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();
    // Three frames that together exceed the tiny budget; only some fit.
    const a = "a" ** 20;
    const b = "b" ** 20;
    const c = "c" ** 20;
    try mock.queueSend(a);
    try mock.queueSend(b);
    try mock.queueSend(c);

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{
        .max_buffering_size = 45, // fits frame a + b (40 bytes), drops c
        .wait_fn = MockPa.waitDriver,
        .wait_ctx = &mock,
    });
    defer session.deinit();
    mock.session = &session;

    mock.stop_when = struct {
        fn pred(m: *MockPa) bool {
            return m.session.?.stats.keepalives_sent >= 1;
        }
    }.pred;

    try runUntilStopped(&session);

    // The budget consumed frames a and b (20 bytes each) but popped and freed
    // c — matching C, which pulls every frame from the PA and discards it when
    // over budget (Session.c:475-478).
    try testing.expectEqual(@as(u64, 2), session.stats.tx_blocks);
    try testing.expectEqual(@as(usize, 0), mock.to_send.items.len); // all popped
}

test "server.session_main compression round-trip" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    tunnel.use_compress = true;
    tunnel.initCompression();
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();
    const payload = "compressed payload that repeats repeats repeats repeats repeats repeats";
    try mock.queueSend(payload);

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{ .wait_fn = MockPa.waitDriver, .wait_ctx = &mock });
    defer session.deinit();
    mock.session = &session;

    mock.stop_when = struct {
        fn pred(m: *MockPa) bool {
            return m.session.?.stats.tx_blocks == 1;
        }
    }.pred;

    try runUntilStopped(&session);

    // Read back with a compression-enabled client tunnel.
    var client_tunnel = TunnelConnection.init(allocator, &loop, Loopback.clientRead, Loopback.clientWrite);
    client_tunnel.use_compress = true;
    client_tunnel.initCompression();
    defer client_tunnel.deinit();
    const out = try allocator.alloc([]u8, MAX_RECV_BLOCKS);
    defer allocator.free(out);
    const scratch = try allocator.alloc(u8, MAX_RECV_BLOCKS * 1600);
    defer allocator.free(scratch);

    _ = try client_tunnel.receiveBlocksBatch(out, scratch); // keep-alive
    const n = try client_tunnel.receiveBlocksBatch(out, scratch);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings(payload, out[0]);
}

test "server.session_main inactivity timeout" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();

    // Keep-alives disabled so the 30 ms inactivity window is never reset.
    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{
        .timeout_ms = 30,
        .enable_keepalive = false,
    });
    defer session.deinit();

    try testing.expectError(error.SessionTimeout, session.run());
}

test "server.session_main requestStop ends the loop" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{});
    defer session.deinit();

    session.requestStop();
    try testing.expectError(error.Stopped, session.run());
}

test "server.session_main connection closed by peer" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();
    loop.closed = true; // peer EOF once the buffer drains

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{ .enable_keepalive = false });
    defer session.deinit();

    try testing.expectError(error.ConnectionClosed, session.run());
}

test "server.session_main packet adapter put failure halts the session" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();
    mock.fail_put = true;

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{ .enable_keepalive = false });
    defer session.deinit();

    const wire = try frameBlocks(allocator, &.{"boom"});
    defer allocator.free(wire);
    try loop.appendToServer(wire);

    try testing.expectError(error.PacketAdapterPutFailed, session.run());
}

test "server.session_main packet adapter init failure halts the session" {
    const allocator = testing.allocator;
    var loop = Loopback.init(allocator);
    defer loop.deinit();

    var tunnel = TunnelConnection.init(allocator, &loop, Loopback.serverRead, Loopback.serverWrite);
    defer tunnel.deinit();

    var mock = MockPa.init(allocator);
    defer mock.deinit();
    mock.fail_init = true;

    var session = try SessionMain.init(allocator, &tunnel, mock.pa(), .{});
    defer session.deinit();

    try testing.expectError(error.PacketAdapterInitFailed, session.run());
}

