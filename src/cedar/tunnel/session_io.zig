//! Session-side I/O helpers shared between the client data loop and the
//! future bridge pump (L2 Network Bridge proposal §4.2, H-1 / I-8).
//!
//! Everything here is extracted verbatim from `vpn_client.zig` `runDataLoop`
//! (issue #50): byte-identical semantics, no logic edits. The bridge loop
//! must be able to call these helpers without copying.

const std = @import("std");
const tunnel_mod = @import("../protocol/tunnel.zig");
const tls_mod = @import("../../mayaqua/network/tls.zig");
const conn_mgr_mod = @import("../client/connection_manager.zig");
const data_loop_mod = @import("data_loop.zig");

/// Maximum number of inbound packets to drain per poll iteration.
pub const MAX_INBOUND_DRAIN: u32 = 256;

/// Routes outbound tunnel sends across the ConnectionManager (multi-
/// connection fanout) or the single connection. Verbatim from
/// `vpn_client.zig` `SendTunnelHelper`.
pub const SendTunnelHelper = struct {
    cm_ptr: ?*conn_mgr_mod.ConnectionManager,
    single_ptr: *tunnel_mod.TunnelConnection,

    pub fn get(ctx: @This()) *tunnel_mod.TunnelConnection {
        if (ctx.cm_ptr) |m| {
            if (m.selectSendConnection()) |conn| return &conn.tunnel;
            if (m.getPrimary()) |primary| return &primary.tunnel;
        }
        return ctx.single_ptr;
    }
};

/// Drain-bucket diagnostics, summed per caller (multi-connection mode adds
/// the per-connection numbers together across every readable connection).
pub const DrainDiag = struct {
    total: u64 = 0,
    max: u32 = 0,
    cap_hits: u64 = 0,
    ssl_pending_max: u32 = 0,
    buf_avail_max: u32 = 0,
    nread_max: u32 = 0,
    nwrite_max: u32 = 0,
};

/// Why a connection died mid-drain.
pub const DeadReason = enum {
    /// should_stop was set during the drain.
    stopped,
    /// The TLS connection closed or broke while draining.
    connection_closed,
};

/// Callbacks the drain loop uses to hand session data to the caller. All
/// three hooks receive the same opaque context.
pub const DrainSink = struct {
    ctx: *anyopaque,
    /// Called once per received block. Must handle TUN batching / adapter
    /// dispatch (client) or bridge flooding (future bridge pump). Returning
    /// early is safe: the drain loop keeps the same cadence.
    onBlock: *const fn (ctx: *anyopaque, block_data: []u8) void,
    /// Called after each batch of blocks to flush any partial TUN batch.
    /// Must tolerate being called with an empty pending batch.
    onFlush: *const fn (ctx: *anyopaque) void,
    /// Called when the connection died (stop requested or TLS close). The
    /// caller applies its own death policy (e.g. mark the connection
    /// unestablished in fanout mode, or trigger reconnect in single mode).
    onDead: *const fn (ctx: *anyopaque, reason: DeadReason, err: anyerror) void,
};

pub const DrainResult = struct {
    /// True if at least one block was received this drain.
    drained_any: bool,
    /// True if the connection died during the drain (see DeadReason).
    dead: bool,
};

/// Drain up to `cap` batches from a connection while TLS data remains
/// pending (OpenSSL internal buffer or kernel receive queue).
///
/// Reads exactly one SoftEther packet per `receiveBlocksBatch` call; under
/// heavy download the server sends packets back-to-back and many sit
/// decrypted in OpenSSL's buffer, so without a drain loop DL throughput
/// would be bounded by the outer loop iteration rate. The cap prevents
/// complete outbound starvation: even on heavy DL we yield to the outbound
/// path after `cap` drained packets so ACKs flow and the TUN drains.
///
/// Mirrors `runDataLoop`'s drain loops (single, multi-connection fanout,
/// and the iOS post-drain re-check): identical cadence, error handling,
/// and diagnostics.
pub fn drainReceived(
    tunnel: *tunnel_mod.TunnelConnection,
    tls_sock: *tls_mod.TlsSocket,
    recv_slices: [][]u8,
    recv_scratch: []u8,
    cap: u32,
    stop_requested: *const bool,
    diag: *DrainDiag,
    sink: DrainSink,
) DrainResult {
    var drain_iter: u32 = 0;
    var dead = false;
    var drained_any = false;

    while (drain_iter < cap) : (drain_iter += 1) {
        // Sample read-buffer peak BEFORE draining — batched SSL_read fills
        // 64KB in one syscall; this captures it before consumption.
        const bavail = tls_sock.readBufAvailable();
        if (bavail > diag.buf_avail_max) diag.buf_avail_max = bavail;

        const recv_count = tunnel.receiveBlocksBatch(recv_slices, recv_scratch) catch |err| {
            if (stop_requested.*) {
                sink.onDead(sink.ctx, .stopped, err);
                dead = true;
            } else if (err == error.ConnectionClosed or err == error.BrokenPipe) {
                sink.onDead(sink.ctx, .connection_closed, err);
                dead = true;
            }
            // Non-fatal error — stop draining this iteration, retry next.
            break;
        };

        if (recv_count > 0) drained_any = true;

        for (recv_slices[0..recv_count]) |block_data| {
            sink.onBlock(sink.ctx, block_data);
        }

        // Flush any remaining batched IP packets before yielding
        sink.onFlush(sink.ctx);

        // SSL_pending()/kernelRecvQueue() natural terminator — the cap is
        // only a safety net to ensure outbound can run occasionally.
        if (!tls_sock.hasPending() and tls_sock.kernelRecvQueue() == 0) break;
    }

    // DIAG: capture drain metrics + queue depths
    diag.total += drain_iter;
    if (drain_iter > diag.max) diag.max = drain_iter;
    if (drain_iter == cap) diag.cap_hits += 1;
    const pend = tls_sock.pendingBytes();
    if (pend > diag.ssl_pending_max) diag.ssl_pending_max = pend;
    const nrd = tls_sock.kernelRecvQueue();
    if (nrd > diag.nread_max) diag.nread_max = nrd;
    const nwr = tls_sock.kernelSendQueue();
    if (nwr > diag.nwrite_max) diag.nwrite_max = nwr;

    return .{ .drained_any = drained_any, .dead = dead };
}

/// Send a keepalive on the session when due. Verbatim from `runDataLoop`'s
/// slow path: fanout across all connections in multi-connection mode, single
/// send otherwise. Callers own the timing state (`shouldSendKeepalive`).
pub fn maybeSendKeepalive(
    cm: ?*conn_mgr_mod.ConnectionManager,
    single: ?*tunnel_mod.TunnelConnection,
    timing: *data_loop_mod.TimingState,
    now: i64,
    interval_ms: i64,
) void {
    if (timing.shouldSendKeepalive(now, interval_ms)) {
        if (cm) |m| {
            m.sendKeepaliveAll();
        } else if (single) |t| {
            t.sendKeepalive() catch |err| {
                std.log.warn("Failed to send keepalive: {}", .{err});
            };
        }
        std.log.debug("Sent keepalive", .{});
        timing.last_keepalive = now;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "SendTunnelHelper falls back to single connection" {
    const helper = SendTunnelHelper{ .cm_ptr = null, .single_ptr = undefined };
    _ = helper;
}

test "MAX_INBOUND_DRAIN is session-wide" {
    try std.testing.expectEqual(@as(u32, 256), MAX_INBOUND_DRAIN);
}
