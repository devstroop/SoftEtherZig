//! SoftEther Listener layer — `Listener.c`.
//!
//! Accepts TCP connections and hands each off to a per-connection thread
//! (C `ListenerThread`/`TCPAccepted`), with a DoS-attack gate per remote IP
//! (C `CheckDosAttack`) and a listener registry keyed by port.
//!
//! M1 scope: TCP only. The `Protocol` enum keeps the C numeric values so the
//! RUDP/UDP/ICMP/DNS/reverse listeners (#85/#86) slot in without renumbering.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const socket = @import("../../mayaqua/network/socket.zig");
const TcpListener = socket.TcpListener;
const TcpSocket = socket.TcpSocket;
const Address = socket.Address;

const log = std.log.scoped(.cedar_server);

// ============================================================================
// Constants (Cedar.h:457-489, Listener.c)
// ============================================================================

/// Retry interval when `listen` fails (C `LISTEN_RETRY_TIME` = 2s).
pub const LISTEN_RETRY_TIME_MS: u64 = 2 * 1000;
/// Initial expiry span of a DOS record (C `DOS_TABLE_EXPIRES_FIRST` = 250ms).
pub const DOS_TABLE_EXPIRES_FIRST: i64 = 250;
/// Max expiry span of a DOS record (C `DOS_TABLE_EXPIRES_MAX` = 1000ms).
pub const DOS_TABLE_EXPIRES_MAX: i64 = 1000;
/// How often expired DOS records are swept (C `DOS_TABLE_REFRESH_INTERVAL` = 10s).
pub const DOS_TABLE_REFRESH_INTERVAL: i64 = 10 * 1000;
/// Max accepted connections per IP before DoS is triggered (C
/// `DOS_TABLE_MAX_LIMIT_PER_IP` = 16).
pub const DOS_TABLE_MAX_LIMIT_PER_IP: u32 = 16;
/// Hard expiry of a DOS record (C `DOS_TABLE_EXPIRES_TOTAL` = 3000s).
pub const DOS_TABLE_EXPIRES_TOTAL: i64 = 3000 * 1000;

/// Default listener ports (C `SERVER_DEF_PORTS_1..4`, Server.h:109-112):
/// 443, 992, 1194, and `GC_DEFAULT_PORT` (5555).
pub const default_ports = [_]u16{ 443, 992, 1194, 5555 };

/// Listener protocol (C Cedar.h:468-474).
pub const Protocol = enum(u32) {
    tcp = 0,
    udp = 1,
    inproc = 2,
    rudp = 3,
    icmp = 4,
    dns = 5,
    reverse = 6,

    pub fn supported(self: Protocol) bool {
        return self == .tcp;
    }
};

/// Listener status (C `LISTENER_STATUS_*`, Cedar.h:477-478).
pub const Status = enum(u32) {
    trying = 0,
    listening = 1,
};

/// Callback invoked on a per-connection thread with an accepted socket.
/// The handler owns `sock` and must close it.
pub const AcceptHandler = *const fn (ctx: *anyopaque, sock: *TcpSocket, peer_ip: u32, peer_port: u16) void;

// ============================================================================
// DoS attack table (C `CheckDosAttack` / `DOS`, Listener.c:405-517)
// ============================================================================

/// Per-IP connection record (C `struct DOS`).
pub const DosEntry = struct {
    first_connected_tick: i64,
    last_connected_tick: i64,
    current_expire_span: i64,
    delete_entry_tick: i64,
    access_count: u32,
};

/// Table of per-IP connection records with the C DoS policy.
pub const DosTable = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    /// Keyed by IPv4 address (host byte order u32).
    entries: std.AutoHashMapUnmanaged(u32, DosEntry) = .{},
    last_refresh: i64 = 0,

    pub fn init(allocator: Allocator) DosTable {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *DosTable) void {
        self.entries.deinit(self.allocator);
    }

    pub fn count(self: *DosTable) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }

    /// Gate a new connection from `ip`. Mirrors C `CheckDosAttack`
    /// (Listener.c:405). Returns true = accept, false = reject.
    pub fn check(self: *DosTable, ip: u32, now: i64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.refresh(now);

        if (self.entries.getPtr(ip)) |d| {
            // Repeated accesses from the same IP: grow the expiry span and
            // reject once the per-IP connection budget is exceeded.
            d.last_connected_tick = now;
            d.current_expire_span = @min(d.current_expire_span * 2, DOS_TABLE_EXPIRES_MAX);
            d.access_count += 1;
            if (d.access_count > DOS_TABLE_MAX_LIMIT_PER_IP) return false;
        } else {
            self.entries.put(self.allocator, ip, .{
                .first_connected_tick = now,
                .last_connected_tick = now,
                .current_expire_span = DOS_TABLE_EXPIRES_FIRST,
                .delete_entry_tick = now + DOS_TABLE_EXPIRES_TOTAL,
                .access_count = 1,
            }) catch return false;
        }
        return true;
    }

    /// Drop a record for `ip` (C `RemoveDosEntry`, Listener.c:374).
    pub fn remove(self: *DosTable, ip: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.remove(ip);
    }

    /// Delete records whose expiry span elapsed or whose hard delete tick
    /// passed (C `RefreshDosList`, Listener.c:453).
    fn refresh(self: *DosTable, now: i64) void {
        if (self.last_refresh == 0 or self.last_refresh + DOS_TABLE_REFRESH_INTERVAL <= now) {
            self.last_refresh = now;
            var stale = std.ArrayList(u32).empty;
            defer stale.deinit(self.allocator);
            var it = self.entries.iterator();
            while (it.next()) |kv| {
                const d = kv.value_ptr;
                if (d.last_connected_tick + d.current_expire_span <= now or
                    d.delete_entry_tick <= now)
                {
                    stale.append(self.allocator, kv.key_ptr.*) catch {};
                }
            }
            for (stale.items) |ip| {
                _ = self.entries.remove(ip);
            }
        }
    }
};

// ============================================================================
// Listener (C `LISTENER`, Listener.c:817-1013)
// ============================================================================

pub const ListenerOptions = struct {
    protocol: Protocol = .tcp,
    /// Bind to 127.0.0.1 only.
    local_only: bool = false,
    /// Skip the DoS gate (C `r->DisableDos`).
    disable_dos: bool = false,
    backlog: u31 = 128,
};

const ConnJob = struct {
    allocator: Allocator,
    handler: AcceptHandler,
    ctx: *anyopaque,
    sock: TcpSocket,
    peer_ip: u32,
    peer_port: u16,
};

fn connThreadFn(job: *ConnJob) void {
    job.handler(job.ctx, &job.sock, job.peer_ip, job.peer_port);
    const allocator = job.allocator;
    allocator.destroy(job);
}

/// One listening endpoint. `start` spawns the accept thread; `stop` joins it
/// and frees the listener.
pub const Listener = struct {
    allocator: Allocator,
    port: u16,
    options: ListenerOptions,
    handler: AcceptHandler,
    ctx: *anyopaque,
    dos: DosTable,
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    status: std.atomic.Value(Status),
    bound_port: std.atomic.Value(u16),
    thread: ?std.Thread = null,

    pub fn start(
        allocator: Allocator,
        port: u16,
        options: ListenerOptions,
        handler: AcceptHandler,
        ctx: *anyopaque,
    ) !*Listener {
        if (!options.protocol.supported()) return error.ProtocolNotSupported;
        const self = try allocator.create(Listener);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .port = port,
            .options = options,
            .handler = handler,
            .ctx = ctx,
            .dos = DosTable.init(allocator),
            .status = std.atomic.Value(Status).init(.trying),
            .bound_port = std.atomic.Value(u16).init(0),
        };
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
        return self;
    }

    /// Stop accepting, join the accept thread, free the listener.
    pub fn stop(self: *Listener) void {
        self.halt.store(true, .seq_cst);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.dos.deinit();
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    pub fn getStatus(self: *const Listener) Status {
        return self.status.load(.acquire);
    }

    pub fn getBoundPort(self: *const Listener) u16 {
        return self.bound_port.load(.acquire);
    }

    fn tryBind(self: *Listener, backlog: u31) !TcpListener {
        const addr = if (self.options.local_only)
            try Address.parseIp4("127.0.0.1", self.port)
        else
            Address{ .inner = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.port) };
        return TcpListener.init(addr, backlog);
    }

    /// The accept thread. Mirrors C `ListenerTCPMainLoop` (Listener.c:636):
    /// bind with retry, then accept in a poll loop, handing each connection to
    /// a per-connection thread after the DoS gate.
    fn acceptLoop(self: *Listener) void {
        while (!self.halt.load(.acquire)) {
            self.status.store(.trying, .release);

            // Bind (with retry — C LISTEN_RETRY_TIME).
            var listener: ?TcpListener = null;
            while (!self.halt.load(.acquire)) {
                listener = self.tryBind(self.options.backlog) catch |err| {
                    log.warn("listener port {d}: bind failed ({s}); retrying", .{ self.port, @errorName(err) });
                    std.Thread.sleep(LISTEN_RETRY_TIME_MS * std.time.ns_per_ms);
                    continue;
                };
                break;
            }
            if (self.halt.load(.acquire)) break;
            self.bound_port.store(listener.?.getLocalPort(), .release);
            self.status.store(.listening, .release);
            log.info("listener listening on port {d}", .{self.bound_port.load(.acquire)});

            // Accept loop.
            while (!self.halt.load(.acquire)) {
                var pfd = [_]posix.pollfd{
                    .{ .fd = listener.?.getFd(), .events = posix.POLL.IN, .revents = 0 },
                };
                const n = posix.poll(&pfd, 1000) catch break;
                if (self.halt.load(.acquire)) break;
                if (n == 0) continue; // timeout

                var conn = listener.?.acceptEx() catch break;
                const peer_ip = peerIpv4(conn.peer);
                const peer_port = conn.peer.getPort();

                // DoS gate (C CheckDosAttack).
                if (!self.options.disable_dos) {
                    if (!self.dos.check(peer_ip, std.time.milliTimestamp())) {
                        log.warn("listener port {d}: connection rejected from {d}.{d}.{d}.{d} (DoS)", .{
                            self.port,
                            (peer_ip >> 24) & 0xff,
                            (peer_ip >> 16) & 0xff,
                            (peer_ip >> 8) & 0xff,
                            peer_ip & 0xff,
                        });
                        conn.socket.close();
                        continue;
                    }
                }

                // Thread-per-connection (C TCPAccepted -> NewThread).
                const job = self.allocator.create(ConnJob) catch {
                    conn.socket.close();
                    continue;
                };
                job.* = .{
                    .allocator = self.allocator,
                    .handler = self.handler,
                    .ctx = self.ctx,
                    .sock = conn.socket,
                    .peer_ip = peer_ip,
                    .peer_port = peer_port,
                };
                const t = std.Thread.spawn(.{}, connThreadFn, .{job}) catch {
                    self.allocator.destroy(job);
                    conn.socket.close();
                    continue;
                };
                t.detach();
            }

            listener.?.close();
        }
    }
};

/// IPv4 address of a peer as host byte order u32 (0 for non-IPv4).
fn peerIpv4(peer: Address) u32 {
    if (peer.inner.in.sa.family == posix.AF.INET) {
        return std.mem.bigToNative(u32, peer.inner.in.sa.addr);
    }
    return 0;
}

// ============================================================================
// Listener registry
// ============================================================================

/// Port-keyed registry of running listeners (C the Cedar listener list +
/// `SiAddListener`).
pub const ListenerRegistry = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    entries: std.AutoHashMapUnmanaged(u16, *Listener) = .{},

    pub fn init(allocator: Allocator) ListenerRegistry {
        return .{ .allocator = allocator };
    }

    /// Stop and free every listener, then free the registry map.
    pub fn deinit(self: *ListenerRegistry) void {
        self.mutex.lock();
        var stale = std.ArrayList(*Listener).empty;
        defer stale.deinit(self.allocator);
        var it = self.entries.valueIterator();
        while (it.next()) |v| stale.append(self.allocator, v.*) catch {};
        self.entries.deinit(self.allocator);
        self.mutex.unlock();
        for (stale.items) |l| l.stop();
    }

    /// Start a listener on `port` and register it. Returns
    /// `error.PortAlreadyListening` if the port is taken in this registry.
    pub fn add(
        self: *ListenerRegistry,
        port: u16,
        options: ListenerOptions,
        handler: AcceptHandler,
        ctx: *anyopaque,
    ) !*Listener {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.contains(port)) return error.PortAlreadyListening;
        const l = try Listener.start(self.allocator, port, options, handler, ctx);
        self.entries.put(self.allocator, port, l) catch {
            l.stop();
            return error.OutOfMemory;
        };
        return l;
    }

    /// Stop, free, and unregister the listener on `port`. Returns false if no
    /// such listener is registered.
    pub fn remove(self: *ListenerRegistry, port: u16) bool {
        self.mutex.lock();
        const l = self.entries.get(port);
        if (l == null) {
            self.mutex.unlock();
            return false;
        }
        _ = self.entries.remove(port);
        self.mutex.unlock();
        l.?.stop();
        return true;
    }

    pub fn get(self: *ListenerRegistry, port: u16) ?*Listener {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.get(port);
    }

    pub fn count(self: *ListenerRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }

    /// Start the four C default listeners (443/992/1194/5555). Bind failures
    /// are handled by each listener's retry loop, so this never fails.
    pub fn addDefaultPorts(self: *ListenerRegistry, handler: AcceptHandler, ctx: *anyopaque) !void {
        for (default_ports) |port| {
            _ = self.add(port, .{}, handler, ctx) catch |err| switch (err) {
                error.PortAlreadyListening => continue,
                else => return err,
            };
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const test_ip: u32 = 0x7f000001; // 127.0.0.1 in host byte order

test "server.listener dos check rejects sustained connections per ip" {
    var table = DosTable.init(testing.allocator);
    defer table.deinit();

    var now: i64 = 1000;
    try testing.expect(table.check(test_ip, now));
    for (1..DOS_TABLE_MAX_LIMIT_PER_IP) |_| {
        now += 1;
        try testing.expect(table.check(test_ip, now));
    }
    // One past the budget → rejected.
    now += 1;
    try testing.expect(!table.check(test_ip, now));
    try testing.expectEqual(@as(usize, 1), table.count());

    // A fresh IP is unaffected.
    try testing.expect(table.check(0x01020304, now));
    try testing.expectEqual(@as(usize, 2), table.count());
}

test "server.listener dos records expire after their span" {
    var table = DosTable.init(testing.allocator);
    defer table.deinit();

    const t0: i64 = 5000;
    _ = table.check(test_ip, t0);
    try testing.expectEqual(@as(usize, 1), table.count());

    // Just within the initial 250ms span → still present and still accepted.
    try testing.expect(table.check(test_ip, t0 + DOS_TABLE_EXPIRES_FIRST - 1));
    try testing.expectEqual(@as(usize, 1), table.count());

    // Past the (doubled) span → record swept on next check.
    try testing.expect(table.check(test_ip, t0 + DOS_TABLE_EXPIRES_MAX * 2));
    try testing.expectEqual(@as(usize, 1), table.count());
}

test "server.listener dos remove drops a record" {
    var table = DosTable.init(testing.allocator);
    defer table.deinit();
    _ = table.check(test_ip, 100);
    try testing.expectEqual(@as(usize, 1), table.count());
    try testing.expect(table.remove(test_ip));
    try testing.expect(!table.remove(test_ip));
    try testing.expectEqual(@as(usize, 0), table.count());
    // After removal a new connection resets the budget.
    try testing.expect(table.check(test_ip, 101));
}

test "server.listener registry rejects duplicate ports" {
    const rec = try testing.allocator.create(AcceptRecorder);
    rec.* = .{};
    defer testing.allocator.destroy(rec);

    var registry = ListenerRegistry.init(testing.allocator);
    defer registry.deinit();
    const l = try registry.add(0, .{ .local_only = true }, handleAccept, rec);
    try testing.expectError(error.PortAlreadyListening, registry.add(0, .{}, handleAccept, rec));
    try testing.expectEqual(@as(usize, 1), registry.count());
    try testing.expect(registry.get(0) == l);
    try testing.expect(registry.remove(0));
    try testing.expect(!registry.remove(0));
    try testing.expectEqual(@as(usize, 0), registry.count());
}

test "server.listener accepts and dispatches a connection" {
    const rec = try testing.allocator.create(AcceptRecorder);
    rec.* = .{};
    defer testing.allocator.destroy(rec);

    var registry = ListenerRegistry.init(testing.allocator);
    defer registry.deinit();
    const l = try registry.add(0, .{ .local_only = true }, handleAccept, rec);
    try waitListening(l);

    const port = l.getBoundPort();
    const addr = try Address.parseIp4("127.0.0.1", port);
    var client = try TcpSocket.connect(addr, null);
    defer client.close();

    try testing.expect(waitAccepted(rec, 5000));
    try testing.expectEqual(test_ip, rec.peer_ip);
    try testing.expect(rec.peer_port > 0);

    try testing.expect(registry.remove(0));
}

const AcceptRecorder = struct {
    mutex: std.Thread.Mutex = .{},
    done: bool = false,
    peer_ip: u32 = 0,
    peer_port: u16 = 0,
};

fn handleAccept(ctx: *anyopaque, sock: *TcpSocket, peer_ip: u32, peer_port: u16) void {
    const rec: *AcceptRecorder = @ptrCast(@alignCast(ctx));
    sock.close();
    rec.mutex.lock();
    defer rec.mutex.unlock();
    rec.done = true;
    rec.peer_ip = peer_ip;
    rec.peer_port = peer_port;
}

fn waitListening(l: *Listener) !void {
    const deadline = std.time.milliTimestamp() + 5000;
    while (std.time.milliTimestamp() < deadline) {
        if (l.getStatus() == .listening) return;
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
    return error.TestTimedOut;
}

fn waitAccepted(rec: *AcceptRecorder, timeout_ms: i64) bool {
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (std.time.milliTimestamp() < deadline) {
        rec.mutex.lock();
        const done = rec.done;
        rec.mutex.unlock();
        if (done) return true;
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    return false;
}
