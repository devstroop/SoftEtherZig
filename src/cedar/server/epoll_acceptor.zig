//! Cross-platform high-performance accept loop.
//!
//! On Linux, uses edge-triggered epoll for batch-accept (mirrors C Cedar's
//! evolution from Select to Poll to Epoll). On other platforms, falls back
//! to poll-based accept.
//!
//! Design goals:
//! - Accept all ready connections per wakeup (batch-accept, O(1) syscalls)
//! - Edge-triggered: only wake on state change, not every 1s
//! - Cross-platform: poll fallback for macOS/Windows/Android/iOS

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.cedar_server);

// ============================================================================
// Constants
// ============================================================================

/// Max connections to accept per epoll_wait/poll cycle. Prevents starvation
/// of other work when a burst of connections arrives.
pub const MAX_ACCEPT_BATCH: u32 = 128;

/// Default epoll wait timeout in ms (0 = non-blocking, -1 = block forever).
/// We use a modest timeout so the accept loop can check the `halt` flag.
pub const EPOLL_WAIT_TIMEOUT_MS: i32 = 500;

/// Fallback poll timeout in ms for non-Linux platforms.
pub const POLL_TIMEOUT_MS: i32 = 500;

/// Max events returned per epoll_wait call.
pub const EPOLL_MAX_EVENTS: u32 = 16;

// ============================================================================
// AcceptedConnection (mirrors socket.AcceptedConnection but with raw fd)
// ============================================================================

pub const AcceptedFd = struct {
    fd: posix.socket_t,
    peer_addr: posix.sockaddr,
    peer_len: posix.socklen_t,
};

// ============================================================================
// EpollAcceptor (Linux)
// ============================================================================

/// Linux epoll-based acceptor with edge-triggered notifications.
/// Accepts all ready connections in a batch per wakeup.
const EpollAcceptor = struct {
    epoll_fd: posix.fd_t,

    pub fn init(listen_fd: posix.socket_t) !EpollAcceptor {
        const epfd = linux.epoll_create1(0);
        if (@as(isize, @bitCast(epfd)) < 0) {
            log.err("epoll_create1 failed: {}", .{posix.errno(epfd)});
            return error.SystemResources;
        }

        var ev = linux.epoll_event{
            .events = linux.EPOLL.IN | linux.EPOLL.ET,
            .data = .{ .fd = listen_fd },
        };
        const rc = linux.epoll_ctl(@intCast(epfd), linux.EPOLL.CTL_ADD, listen_fd, &ev);
        if (@as(isize, @bitCast(rc)) < 0) {
            posix.close(@intCast(epfd));
            log.err("epoll_ctl ADD failed: {}", .{posix.errno(rc)});
            return error.SystemResources;
        }

        return .{ .epoll_fd = @intCast(epfd) };
    }

    pub fn deinit(self: *EpollAcceptor) void {
        posix.close(self.epoll_fd);
    }

    /// Wait for events. Returns the number of ready events.
    pub fn wait(self: *EpollAcceptor, events: []linux.epoll_event, timeout_ms: i32) !u32 {
        const n = linux.epoll_wait(self.epoll_fd, events.ptr, @intCast(events.len), timeout_ms);
        const signed_n: isize = @bitCast(n);
        if (signed_n < 0) {
            const errno = posix.errno(n);
            if (errno == .INTR) return 0;
            log.err("epoll_wait failed: {}", .{errno});
            return error.Io;
        }
        return @intCast(signed_n);
    }
};

// ============================================================================
// PollAcceptor (fallback for non-Linux)
// ============================================================================

/// Poll-based acceptor for platforms without epoll.
const PollAcceptor = struct {
    listen_fd: posix.socket_t,

    pub fn init(listen_fd: posix.socket_t) !PollAcceptor {
        return .{ .listen_fd = listen_fd };
    }

    pub fn deinit(self: *PollAcceptor) void {
        _ = self;
    }

    pub fn wait(self: *PollAcceptor, timeout_ms: i32) !bool {
        var pfd = [_]posix.pollfd{
            .{ .fd = self.listen_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        const n = try posix.poll(&pfd, timeout_ms);
        return n > 0 and (pfd[0].revents & posix.POLL.IN) != 0;
    }
};

/// Callback signature for accepted connections: fd, peer_ip, peer_port, context.
pub const AcceptCallback = *const fn (fd: posix.socket_t, peer_ip: u32, peer_port: u16, ctx: *anyopaque) void;

// ============================================================================
// Acceptor (cross-platform)
// ============================================================================

pub const Acceptor = struct {
    listen_fd: posix.socket_t,

    pub fn init(listen_fd: posix.socket_t) Acceptor {
        return .{ .listen_fd = listen_fd };
    }

    /// Accept all ready connections in a batch. For each accepted connection,
    /// calls `callback` with the fd, peer address, peer port, and context.
    /// Returns the total number of connections accepted in this batch.
    pub fn acceptBatch(
        self: *Acceptor,
        callback: AcceptCallback,
        ctx: *anyopaque,
        max_batch: u32,
    ) u32 {
        var count: u32 = 0;
        while (count < max_batch) {
            var addr: posix.sockaddr = undefined;
            var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
            const conn_fd = posix.accept(self.listen_fd, &addr, &addrlen, 0) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionAborted => break,
                error.FileDescriptorNotASocket, error.ConnectionResetByPeer => break,
                else => {
                    log.warn("accept failed: {s}", .{@errorName(err)});
                    break;
                },
            };

            const peer_ip = extractPeerIp4(&addr);
            const peer_port = extractPeerPort(&addr);

            callback(conn_fd, peer_ip, peer_port, ctx);
            count += 1;
        }
        return count;
    }
};

// ============================================================================
// Cross-platform accept loop
// ============================================================================

/// The core accept loop type. On Linux this uses epoll edge-triggered;
/// on other platforms it uses poll.
pub const PlatformAcceptor = if (builtin.os.tag == .linux) struct {
    epoll: EpollAcceptor,

    pub fn init(listen_fd: posix.socket_t) !PlatformAcceptor {
        return .{ .epoll = try EpollAcceptor.init(listen_fd) };
    }

    pub fn deinit(self: *PlatformAcceptor) void {
        self.epoll.deinit();
    }

    /// Wait and batch-accept. Calls `callback(fd, peer_ip, peer_port, ctx)` for
    /// each accepted connection. Returns total accepted count.
    pub fn waitAndAccept(
        self: *PlatformAcceptor,
        listen_fd: posix.socket_t,
        callback: AcceptCallback,
        ctx: *anyopaque,
        timeout_ms: i32,
        max_batch: u32,
    ) !u32 {
        var events: [EPOLL_MAX_EVENTS]linux.epoll_event = undefined;
        const n = try self.epoll.wait(&events, timeout_ms);

        var total: u32 = 0;
        for (events[0..n]) |ev| {
            if (ev.data.fd == listen_fd) {
                // Edge-triggered: drain all pending connections.
                var addr: posix.sockaddr = undefined;
                var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
                while (total < max_batch) {
                    const conn_fd = posix.accept(listen_fd, &addr, &addrlen, 0) catch |err| switch (err) {
                        error.WouldBlock, error.ConnectionAborted => break,
                        error.FileDescriptorNotASocket, error.ConnectionResetByPeer => break,
                        else => {
                            log.warn("epoll accept failed: {s}", .{@errorName(err)});
                            break;
                        },
                    };
                    const peer_ip = extractPeerIp4(&addr);
                    const peer_port = extractPeerPort(&addr);
                    callback(conn_fd, peer_ip, peer_port, ctx);
                    total += 1;
                }
            }
        }
        return total;
    }
} else struct {
    poll: PollAcceptor,

    pub fn init(listen_fd: posix.socket_t) !PlatformAcceptor {
        return .{ .poll = try PollAcceptor.init(listen_fd) };
    }

    pub fn deinit(self: *PlatformAcceptor) void {
        self.poll.deinit();
    }

    /// Poll + accept. On non-Linux, accepts at most one connection per poll
    /// wakeup (poll is level-triggered).
    pub fn waitAndAccept(
        self: *PlatformAcceptor,
        listen_fd: posix.socket_t,
        callback: AcceptCallback,
        ctx: *anyopaque,
        timeout_ms: i32,
        max_batch: u32,
    ) !u32 {
        const ready = try self.poll.wait(timeout_ms);
        if (!ready) return 0;

        var count: u32 = 0;
        while (count < max_batch) {
            var addr: posix.sockaddr = undefined;
            var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
            const conn_fd = posix.accept(listen_fd, &addr, &addrlen, 0) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionAborted => break,
                error.FileDescriptorNotASocket, error.ConnectionResetByPeer => break,
                else => {
                    log.warn("poll accept failed: {s}", .{@errorName(err)});
                    break;
                },
            };
            const peer_ip = extractPeerIp4(&addr);
            const peer_port = extractPeerPort(&addr);
            callback(conn_fd, peer_ip, peer_port, ctx);
            count += 1;
        }
        return count;
    }
};

// ============================================================================
// Helpers
// ============================================================================

const builtin = @import("builtin");

/// Extract IPv4 address from a sockaddr (host byte order).
fn extractPeerIp4(addr: *const posix.sockaddr) u32 {
    if (addr.family == posix.AF.INET) {
        const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
        return std.mem.bigToNative(u32, sin.addr);
    }
    return 0;
}

/// Extract port from a sockaddr (host byte order).
fn extractPeerPort(addr: *const posix.sockaddr) u16 {
    if (addr.family == posix.AF.INET) {
        const sin: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
        return std.mem.bigToNative(u16, sin.port);
    }
    return 0;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "epoll_acceptor extractPeerIp4" {
    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 443),
        .addr = std.mem.nativeToBig(u32, 0x0A000001), // 10.0.0.1
    };
    const any: *const posix.sockaddr = @ptrCast(&addr);
    try testing.expectEqual(@as(u32, 0x0A000001), extractPeerIp4(any));
    try testing.expectEqual(@as(u16, 443), extractPeerPort(any));
}

test "epoll_acceptor extractPeerIp4 non-ipv4" {
    var addr = posix.sockaddr.un{ .family = posix.AF.UNIX, .path = undefined };
    const any: *const posix.sockaddr = @ptrCast(&addr);
    try testing.expectEqual(@as(u32, 0), extractPeerIp4(any));
    try testing.expectEqual(@as(u16, 0), extractPeerPort(any));
}
