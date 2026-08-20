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
//! The data channel supports three encryption modes negotiated during session
//! setup: none (plaintext-over-TLS), fast RC4 (symmetric stream cipher per
//! TCP socket), and AES-256-CBC (block cipher with per-packet IV). When
//! encryption is active, `ConnectionCipher` (`session.zig`) is interposed
//! between the tunnel framing and the hub packet adapter: received blocks
//! are decrypted before delivery to the hub, and outbound frames are
//! encrypted before transmission through the tunnel.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
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

/// Data-plane poll timeout in ms for the UDP fd (same as accept.zig's
/// `session_poll_ms`).
const UDP_POLL_MS: u32 = 250;

/// Data-plane poll timeout for extra connection fds. Must match the value in
/// accept.zig (`session_poll_ms`) so the recv and wait paths use the same
/// interval.
const session_poll_ms: u32 = 250;

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

    /// UDP acceleration (optional). When set, the session loop polls the UDP
    /// socket alongside TLS and prefers UDP for outbound data.
    udp_ctx: ?*anyopaque = null,
    /// Receive one data block from the UDP path. Returns null when no data.
    udp_poll_fn: ?*const fn (ctx: *anyopaque) ?[]const u8 = null,
    /// Send a data block via UDP. Returns true on success.
    udp_send_fn: ?*const fn (ctx: *anyopaque, data: []const u8, compressed: bool) bool = null,
    /// Check if the UDP path is active and ready for sending.
    udp_ready_fn: ?*const fn (ctx: *anyopaque) bool = null,
    /// Drive UDP timers (keepalive, dead detection).
    udp_tick_fn: ?*const fn (ctx: *anyopaque) void = null,
    /// Get the UDP socket fd for poll(). Returns null if unavailable.
    udp_fd_fn: ?*const fn (ctx: *anyopaque) ?posix.socket_t = null,
};

/// A TCP connection slot in the multi-TCP pool (C: `TCPSOCK`). Each additional
/// connection accepted via `additional_connect` gets its own slot with an
/// independent `TunnelConnection` state machine, cipher, and congestion counter.
pub const ConnectionSlot = struct {
    /// The block framing state machine for this TCP connection.
    tunnel: TunnelConnection,
    /// Per-socket cipher for data-channel encryption.
    cipher: ?@import("session.zig").ConnectionCipher = null,
    /// Direction: TCP_BOTH=0, TCP_SERVER_TO_CLIENT=1, TCP_CLIENT_TO_SERVER=2.
    direction: u32 = 0,
    /// Congestion counter for send-side socket selection (C: `TCPSOCK.LateCount`).
    /// Incremented when a send returns `WouldBlock`; reset on successful send.
    late_count: u32 = 0,
    /// Set to false when the socket disconnects; cleaned up after recv iteration.
    alive: bool = true,
    /// The TCP socket fd, for poll()-based waiting.
    fd: posix.socket_t = undefined,

    /// Type-erased TLS I/O context (e.g., heap-allocated `TlsConn`). Owned by
    /// this slot — freed when the slot is destroyed.
    tls_context: *anyopaque,
    tls_context_destroy: *const fn (*anyopaque) void,

    pub fn destroy(self: *ConnectionSlot, allocator: Allocator) void {
        self.tunnel.deinit();
        self.tls_context_destroy(self.tls_context);
        allocator.destroy(self);
    }
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
    /// Per-TCP-socket cipher for data-channel encryption. Created from the
    /// session's key material via `ServerSession.newConnectionCipher`.
    cipher: ?@import("session.zig").ConnectionCipher = null,

    /// Borrowed pointer to the `ServerSession` that owns the key material.
    /// Used by `handleAdditionalConnect` to create per-socket ciphers for
    /// extra connections. Valid for the entire session lifetime.
    server_session: ?*const @import("session.zig").ServerSession = null,

    /// Set by `requestStop` (any thread); the loop ends with `error.Stopped`.
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    last_comm_time: i64 = 0,
    next_keepalive_time: i64 = 0,
    send_queue_bytes: usize = 0,

    /// Maximum number of TCP connections allowed for this session (C:
    /// `s->MaxConnection`). Default 1; incremented by `additional_connect`.
    max_connections: u32 = 1,
    /// Current number of active TCP connections (C:
    /// `s->Connection->CurrentNumConnection`). Starts at 1 for the primary
    /// connection; incremented/decremented by `additional_connect` handling.
    current_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    /// Additional TCP connection slots for multi-TCP (C: `Tcp->TcpSockList`).
    /// Each entry is heap-allocated so the `TunnelConnection` inside it stays at
    /// a stable address (it contains zlib state with internal pointers).
    extra: std.ArrayListUnmanaged(*ConnectionSlot) = .{},
    /// Mutex guarding `extra` — held only for brief list mutations, never
    /// across I/O calls.
    extra_mutex: std.Thread.Mutex = .{},
    /// Congestion counter for the primary tunnel (C: primary `TCPSOCK.LateCount`).
    primary_late_count: u32 = 0,

    /// Reference count held by `handleAdditionalConnect` while it accesses the
    /// session after `findBySessionKeyAndReserve` returns. Prevents use-after-
    /// free when the session thread tears down between the registry lookup and
    /// slot insertion. `deinit` waits for this to reach zero.
    extra_slot_ref: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

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
        // Wait for any concurrent `handleAdditionalConnect` to finish before
        // tearing down the session. Without this, the accept thread could be
        // between `findBySessionKeyAndReserve` and `addExtraSlot`, holding a
        // pointer to a stack-local `SessionMain` that is about to be reclaimed.
        while (self.extra_slot_ref.load(.acquire) > 0) {
            std.Thread.yield() catch {};
        }
        // Destroy all extra connection slots.
        {
            self.extra_mutex.lock();
            defer self.extra_mutex.unlock();
            for (self.extra.items) |slot| slot.destroy(self.allocator);
            self.extra.deinit(self.allocator);
        }
        self.allocator.free(self.send_buf);
        self.allocator.free(self.send_batch);
        self.allocator.free(self.recv_scratch);
        self.allocator.free(self.recv_out);
        self.* = undefined;
    }

    /// Push an additional connection slot into the pool (called from the accept
    /// thread). The slot is heap-allocated by the caller and ownership transfers
    /// here.
    pub fn addExtraSlot(self: *SessionMain, slot: *ConnectionSlot) !void {
        self.extra_mutex.lock();
        defer self.extra_mutex.unlock();
        try self.extra.append(self.allocator, slot);
    }

    /// Remove and destroy any dead extra slots (alive == false). Called at the
    /// end of each recv iteration from the session thread.
    fn cleanupDeadSlots(self: *SessionMain) void {
        self.extra_mutex.lock();
        defer self.extra_mutex.unlock();
        var i: usize = 0;
        while (i < self.extra.items.len) {
            if (!self.extra.items[i].alive) {
                const removed = self.extra.swapRemove(i);
                removed.destroy(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    /// Ask the loop to stop; `run` returns `error.Stopped`. Thread-safe:
    /// `run` polls this flag each iteration.
    pub fn requestStop(self: *SessionMain) void {
        self.halt.store(true, .seq_cst);
    }

    /// Thread-safe stop-flag query, complement to `requestStop`. Lets the
    /// admin dispatch report a session that is mid-teardown as disconnecting
    /// instead of fully connected (C `CONNECTING_DISCONNECTING`).
    pub fn isStopRequested(self: *const SessionMain) bool {
        return self.halt.load(.acquire);
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

            // 0. Drive UDP acceleration timers (keepalive, dead detection).
            if (self.config.udp_tick_fn) |tick_fn| {
                if (self.config.udp_ctx) |ctx| tick_fn(ctx);
            }

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
                        // Decrypt the block payload if a cipher is active.
                        const plaintext = if (self.cipher) |*c|
                            c.decryptRecv(self.allocator, frame) catch |err| {
                                log.warn("decrypt failed: {}", .{err});
                                return error.ConnectionClosed;
                            }
                        else
                            frame;
                        defer if (self.cipher != null) self.allocator.free(plaintext);
                        self.stats.rx_blocks += 1;
                        self.stats.rx_bytes += plaintext.len;
                        if (!self.pa.put(self.pa.ctx, plaintext)) return error.PacketAdapterPutFailed;
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

            // 1b. Receive from additional TCP connections (multi-TCP pool).
            // Snapshot the pointer list under the lock (microseconds), then
            // iterate the snapshot lock-free. Slots are heap-allocated so the
            // pointers remain valid even if the list is concurrently modified.
            {
                self.extra_mutex.lock();
                const extra_n = self.extra.items.len;
                var snap_buf: [8]*ConnectionSlot = undefined;
                const snap = if (extra_n <= 8) blk: {
                    @memcpy(snap_buf[0..extra_n], self.extra.items[0..extra_n]);
                    break :blk snap_buf[0..extra_n];
                } else blk: {
                    const buf = try self.allocator.alloc(*ConnectionSlot, extra_n);
                    @memcpy(buf, self.extra.items[0..extra_n]);
                    self.extra_mutex.unlock();
                    defer self.allocator.free(buf);
                    break :blk buf;
                };
                if (extra_n > 8) {} else self.extra_mutex.unlock();

                for (snap) |slot| {
                    if (!slot.alive) continue;
                    var extra_batches: usize = 0;
                    while (true) {
                        const recv_start = slot.tunnel.total_recv;
                        const recv_count = slot.tunnel.receiveBlocksBatch(self.recv_out, self.recv_scratch) catch |err| switch (err) {
                            error.WouldBlock => break,
                            else => {
                                slot.alive = false;
                                _ = self.current_connections.fetchSub(1, .seq_cst);
                                log.info("extra connection error: {} (conns={d})", .{ err, self.current_connections.load(.acquire) });
                                break;
                            },
                        };
                        if (recv_count > 0) {
                            for (self.recv_out[0..recv_count]) |frame| {
                                const plaintext = if (slot.cipher) |*c|
                                    c.decryptRecv(self.allocator, frame) catch |dec_err| {
                                        log.warn("extra decrypt failed: {}", .{dec_err});
                                        slot.alive = false;
                                        _ = self.current_connections.fetchSub(1, .seq_cst);
                                        break;
                                    }
                                else
                                    frame;
                                defer if (slot.cipher != null) self.allocator.free(plaintext);
                                if (!slot.alive) break; // decrypt failed
                                self.stats.rx_blocks += 1;
                                self.stats.rx_bytes += plaintext.len;
                                if (!self.pa.put(self.pa.ctx, plaintext)) return error.PacketAdapterPutFailed;
                            }
                            if (!slot.alive) break;
                        }
                        if (slot.tunnel.total_recv > recv_start) {
                            self.stats.keepalives_recv = slot.tunnel.keepalives_recv;
                            self.touchComm();
                            progress = true;
                        }
                        if (recv_count == 0) continue;
                        extra_batches += 1;
                        if (extra_batches >= MAX_RECV_BLOCKS) break;
                        if (self.halt.load(.seq_cst)) break;
                    }
                }
            }
            // Remove dead extra slots after iteration.
            self.cleanupDeadSlots();

            // 2b. Poll UDP acceleration. Drain all pending blocks into the hub
            // (same path as TLS-received blocks — C: ConnectionReceive drains
            // UdpAccel->RecvBlockQueue into ReceivedBlocks).
            if (self.config.udp_poll_fn) |poll_fn| {
                if (self.config.udp_ctx) |ctx| {
                    var udp_batches: usize = 0;
                    while (udp_batches < MAX_RECV_BLOCKS) {
                        const block = poll_fn(ctx) orelse break;
                        self.stats.rx_blocks += 1;
                        self.stats.rx_bytes += block.len;
                        if (!self.pa.put(self.pa.ctx, block)) return error.PacketAdapterPutFailed;
                        udp_batches += 1;
                        progress = true;
                    }
                }
            }

            if (self.halt.load(.seq_cst)) break;

            // 3. Keep-alive on idle wire — C sends it at the top of
            //    ConnectionSend, BEFORE the data batch (Connection.c:1080-1088).
            //    Each TCP socket gets its own keepalive (Connection.c:1073-1091).
            const now = std.time.milliTimestamp();
            if (self.config.enable_keepalive and now >= self.next_keepalive_time) {
                try self.tunnel.sendKeepalive();
                self.stats.keepalives_sent = self.tunnel.keepalives_sent;
                // Send keep-alive on extra connections too.
                {
                    self.extra_mutex.lock();
                    const ek_n = self.extra.items.len;
                    var ek_buf: [8]*ConnectionSlot = undefined;
                    const ek_snap = if (ek_n <= 8) blk: {
                        @memcpy(ek_buf[0..ek_n], self.extra.items[0..ek_n]);
                        break :blk ek_buf[0..ek_n];
                    } else blk: {
                        const buf = try self.allocator.alloc(*ConnectionSlot, ek_n);
                        @memcpy(buf, self.extra.items[0..ek_n]);
                        self.extra_mutex.unlock();
                        defer self.allocator.free(buf);
                        break :blk buf;
                    };
                    if (ek_n > 8) {} else self.extra_mutex.unlock();
                    for (ek_snap) |slot| {
                        if (!slot.alive) continue;
                        slot.tunnel.sendKeepalive() catch |err| {
                            log.warn("extra keepalive failed: {}", .{err});
                            slot.alive = false;
                            _ = self.current_connections.fetchSub(1, .seq_cst);
                        };
                    }
                }
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
                }
                // Poll extra connection fds (and optionally UDP) together so
                // we wake up quickly when any additional connection has data.
                // Build a single pollfd array for all extra sockets + UDP.
                {
                    self.extra_mutex.lock();
                    const wn = self.extra.items.len;
                    var w_buf: [8]*ConnectionSlot = undefined;
                    const w_snap = if (wn <= 8) blk: {
                        @memcpy(w_buf[0..wn], self.extra.items[0..wn]);
                        break :blk w_buf[0..wn];
                    } else blk: {
                        const buf = try self.allocator.alloc(*ConnectionSlot, wn);
                        @memcpy(buf, self.extra.items[0..wn]);
                        self.extra_mutex.unlock();
                        break :blk buf;
                    };
                    if (wn > 8) {} else self.extra_mutex.unlock();

                    // +1 for optional UDP fd, +1 for optional TLS primary.
                    const extra_count = w_snap.len;
                    const has_udp = self.config.udp_fd_fn != null and self.config.udp_ctx != null;
                    const total = extra_count + @as(usize, if (has_udp) 1 else 0);

                    if (total > 0) {
                        var pfds_buf: [9]posix.pollfd = undefined;
                        var allocated: ?[]posix.pollfd = null;
                        const pfds = if (total <= pfds_buf.len) pfds_buf[0..total] else blk: {
                            const b = try self.allocator.alloc(posix.pollfd, total);
                            allocated = b;
                            break :blk b;
                        };
                        defer if (allocated) |b| self.allocator.free(b);

                        for (w_snap[0..extra_count], 0..) |slot, i| {
                            pfds[i] = .{ .fd = slot.fd, .events = posix.POLL.IN, .revents = 0 };
                        }
                        var next: usize = extra_count;
                        if (has_udp) {
                            if (self.config.udp_fd_fn.?(self.config.udp_ctx.?)) |udp_fd| {
                                pfds[next] = .{ .fd = udp_fd, .events = posix.POLL.IN, .revents = 0 };
                                next += 1;
                            }
                        }
                        _ = posix.poll(pfds[0..next], session_poll_ms) catch 0;
                    } else if (self.config.wait_fn == null) {
                        std.Thread.sleep(std.time.ns_per_ms);
                    }
                }
            }
        }

        return error.Stopped;
    }

    /// Pull up to `max_send_batch` frames from the packet adapter, frame them
    /// with the tunnel (compression included), and write them to the wire.
    /// Returns true if at least one frame was sent.
    ///
    /// When UDP acceleration is active and ready (C: `UdpAccelIsSendReady`),
    /// frames are sent via UDP individually instead of batched over TLS.
    fn drainAndSend(self: *SessionMain) !bool {
        var count: usize = 0;
        var sent_bytes: usize = 0;

        // Check if UDP acceleration is available and ready.
        const use_udp = if (self.config.udp_ready_fn) |ready_fn|
            if (self.config.udp_ctx) |ctx| ready_fn(ctx) else false
        else
            false;

        if (use_udp) {
            // UDP path: send each frame individually via UDP.
            while (count < self.send_batch.len) {
                const frame = self.pa.get(self.pa.ctx) orelse break;
                if (self.send_queue_bytes + frame.len > self.config.max_buffering_size) {
                    self.allocator.free(frame);
                    log.warn("dropping frame: send queue over buffering budget (UDP)", .{});
                    continue;
                }
                const sent = if (self.config.udp_send_fn) |send_fn|
                    if (self.config.udp_ctx) |ctx| send_fn(ctx, frame, false) else false
                else
                    false;
                self.allocator.free(frame);
                if (sent) {
                    count += 1;
                    sent_bytes += frame.len;
                }
                self.send_queue_bytes += frame.len;
            }
            if (count > 0) {
                self.send_queue_bytes = 0;
                self.stats.tx_blocks += count;
                self.stats.tx_bytes += sent_bytes;
                self.touchComm();
                return true;
            }
            return false;
        }

        // TLS path: batch frames and send via the best available tunnel.
        // The "best" tunnel has the lowest late_count (C: `min LateCount`).
        // Snapshot extra slots under lock to find the best send target.
        var send_tunnel = self.tunnel;
        var send_late: *u32 = &self.primary_late_count;
        var send_cipher: *?@import("session.zig").ConnectionCipher = &self.cipher;
        {
            self.extra_mutex.lock();
            for (self.extra.items) |slot| {
                if (!slot.alive) continue;
                if (slot.late_count < send_late.*) {
                    send_tunnel = &slot.tunnel;
                    send_late = &slot.late_count;
                    send_cipher = &slot.cipher;
                }
            }
            self.extra_mutex.unlock();
        }

        // Encrypt with the selected tunnel's cipher.
        while (count < self.send_batch.len) {
            const frame = self.pa.get(self.pa.ctx) orelse break;
            const ciphertext = if (send_cipher.*) |*c|
                c.encryptSend(self.allocator, frame) catch |err| {
                    self.allocator.free(frame);
                    log.warn("encrypt failed: {}", .{err});
                    return error.ConnectionClosed;
                }
            else
                frame;
            if (send_cipher.* != null) self.allocator.free(frame);
            if (self.send_queue_bytes + ciphertext.len > self.config.max_buffering_size) {
                self.allocator.free(ciphertext);
                log.warn("dropping frame: send queue over buffering budget", .{});
                continue;
            }
            self.send_batch[count] = ciphertext;
            count += 1;
            sent_bytes += ciphertext.len;
            self.send_queue_bytes += ciphertext.len;
        }

        if (count == 0) return false;

        send_tunnel.sendBlocksZeroCopy(self.send_batch[0..count], self.send_buf) catch |err| {
            // Track congestion: increment late_count on WouldBlock, abort on
            // hard errors.
            if (err == error.WouldBlock) {
                send_late.* += 1;
                return false;
            } else {
                for (self.send_batch[0..count]) |f| self.allocator.free(f);
                self.send_queue_bytes = 0;
                return err;
            }
        };
        // Reset congestion counter on successful send.
        send_late.* = 0;

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
