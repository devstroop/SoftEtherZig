//! Server session/connection registry (issue #88, PR A).
//!
//! M1 runs one data-plane session per accepted connection (`max_connection=1`),
//! but nothing tracked them server-side: `accept.zig` created/destroyed the
//! `SessionMain` locally. This registry gives the admin RPC dispatcher a
//! thread-safe view of live sessions (C `SERVER->SessionList` +
//! `SERVER->ConnectionList` subset) and a way to force-stop one
//! (`SessionMain.requestStop`, which `DeleteSession`/`DisconnectConnection`
//! will call).
//!
//! Ownership: `register` takes ownership of the record (and its owned fields);
//! `unregister`/`deinit` free it. Session threads must unregister before
//! tearing down the `SessionMain` it points at — `runSession` registers right
//! after `SessionMain.init` and unregisters in a defer that runs before
//! `main.deinit` (LIFO).
//!
//! Concurrency: every operation runs under the internal mutex and never hands
//! out a raw `*SessionRecord` (a record can be freed by a concurrent
//! `unregister`/`deinit` the moment the lock drops). Observers use `snapshot`
//! for owned copies; actions such as `requestStop` look the record up and act
//! on it while still holding the lock.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const session_main = @import("session_main.zig");
const SessionMain = session_main.SessionMain;

/// One live session. `session_name`/`connection_name`/`username` are owned
/// heap slices; `hub_name` is borrowed from the (single) hub, which outlives
/// every session. `main` is borrowed from the session thread and is valid
/// while the record is registered.
pub const SessionRecord = struct {
    session_name: []u8,
    connection_name: []u8,
    username: []u8,
    hub_name: []const u8,
    peer_ip: u32 = 0,
    peer_port: u16 = 0,
    created_time: i64 = 0,
    main: *SessionMain,

    fn free(self: *SessionRecord, allocator: Allocator) void {
        allocator.free(self.session_name);
        allocator.free(self.connection_name);
        allocator.free(self.username);
        const a = allocator;
        a.destroy(self);
    }
};

/// A copy of a session record safe to hold after the session thread exits.
/// Strings are owned; freed with `freeList` or per-item `free`.
pub const SessionSnapshot = struct {
    session_name: []u8,
    connection_name: []u8,
    username: []u8,
    hub_name: []u8,
    peer_ip: u32 = 0,
    peer_port: u16 = 0,
    created_time: i64 = 0,

    fn free(self: *SessionSnapshot, allocator: Allocator) void {
        allocator.free(self.session_name);
        allocator.free(self.connection_name);
        allocator.free(self.username);
        allocator.free(self.hub_name);
    }
};

/// Thread-safe registry of live sessions, keyed by session name (C
/// `SERVER->SessionList`). Matches session and connection names
/// case-insensitively (SoftEther naming is case-insensitive).
pub const SessionRegistry = struct {
    allocator: Allocator,
    mutex: std.Thread.Mutex = .{},
    sessions: std.ArrayListUnmanaged(*SessionRecord) = .{},

    pub fn init(allocator: Allocator) SessionRegistry {
        return .{ .allocator = allocator, .sessions = .empty };
    }

    /// Free every record. Callers must have stopped all session threads first.
    pub fn deinit(self: *SessionRegistry) void {
        self.mutex.lock();
        for (self.sessions.items) |rec| rec.free(self.allocator);
        self.sessions.deinit(self.allocator);
        self.sessions = .empty;
        self.mutex.unlock();
    }

    /// Take ownership of a session record. Returns `error.UserExists` when a
    /// session with the same (case-insensitive) name is already registered.
    pub fn register(self: *SessionRegistry, rec: *SessionRecord) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.findLocked(rec.session_name) != null) return error.UserExists;
        self.sessions.append(self.allocator, rec) catch return error.OutOfMemory;
    }

    /// Remove and free the record for `session_name`. Returns false when no
    /// such session is registered.
    pub fn unregister(self: *SessionRegistry, session_name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = self.indexLocked(session_name) orelse return false;
        const rec = self.sessions.swapRemove(idx);
        rec.free(self.allocator);
        return true;
    }

    pub fn count(self: *SessionRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.items.len;
    }

    /// Ask a session's `SessionMain` to stop (C: `SessionEnd` on the target
    /// session). Returns false when the session does not exist. The session
    /// thread observes `error.Stopped` from `run()` and tears itself down.
    pub fn requestStop(self: *SessionRegistry, session_name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const rec = self.findLocked(session_name) orelse return false;
        rec.main.requestStop();
        return true;
    }

    /// Same as `requestStop`, but looked up by connection name
    /// (C `DisconnectConnection`: `Disconnect(c, c->ConnectionList)`).
    /// Returns false when no connection with that name is live.
    pub fn requestStopByConnection(self: *SessionRegistry, connection_name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const rec = self.findByConnectionLocked(connection_name) orelse return false;
        rec.main.requestStop();
        return true;
    }

    /// Same as `requestStop`, but the session must belong to `hub_name`
    /// (C `DeleteSession`: `GetSessionByName(h, name)` on the target hub).
    /// Returns false when no such session is live on that hub.
    pub fn requestStopOnHub(self: *SessionRegistry, hub_name: []const u8, session_name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const rec = self.findOnHubLocked(hub_name, session_name) orelse return false;
        rec.main.requestStop();
        return true;
    }

    /// Snapshot all live sessions into freshly allocated records the caller
    /// owns (free with `freeSnapshot`). Safe to hold after sessions exit.
    pub fn snapshot(self: *SessionRegistry, allocator: Allocator) ![]SessionSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        var out = std.ArrayListUnmanaged(SessionSnapshot){};
        errdefer {
            for (out.items) |*s| s.free(allocator);
            out.deinit(allocator);
        }
        for (self.sessions.items) |rec| {
            var snap = SessionSnapshot{
                .session_name = try allocator.dupe(u8, rec.session_name),
                .connection_name = try allocator.dupe(u8, rec.connection_name),
                .username = try allocator.dupe(u8, rec.username),
                .hub_name = try allocator.dupe(u8, rec.hub_name),
                .peer_ip = rec.peer_ip,
                .peer_port = rec.peer_port,
                .created_time = rec.created_time,
            };
            errdefer snap.free(allocator);
            try out.append(allocator, snap);
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn freeSnapshot(allocator: Allocator, list: []SessionSnapshot) void {
        for (list) |*s| s.free(allocator);
        allocator.free(list);
    }

    fn findLocked(self: *SessionRegistry, session_name: []const u8) ?*SessionRecord {
        const idx = self.indexLocked(session_name) orelse return null;
        return self.sessions.items[idx];
    }

    fn findByConnectionLocked(self: *SessionRegistry, connection_name: []const u8) ?*SessionRecord {
        for (self.sessions.items) |rec| {
            if (eqlIgnoreCase(rec.connection_name, connection_name)) return rec;
        }
        return null;
    }

    fn findOnHubLocked(self: *SessionRegistry, hub_name: []const u8, session_name: []const u8) ?*SessionRecord {
        for (self.sessions.items) |rec| {
            if (eqlIgnoreCase(rec.hub_name, hub_name) and eqlIgnoreCase(rec.session_name, session_name)) return rec;
        }
        return null;
    }

    fn indexLocked(self: *SessionRegistry, session_name: []const u8) ?usize {
        for (self.sessions.items, 0..) |rec, i| {
            if (eqlIgnoreCase(rec.session_name, session_name)) return i;
        }
        return null;
    }
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

// ============================================================================
// Tests
// ============================================================================

const TestMain = struct {
    stopped: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

/// Minimal stand-in for `SessionMain` with `halt` at the same byte offset as
/// the real struct (it follows `allocator`/`tunnel`/`pa`/`config`). The
/// registry's `requestStop` calls the real `SessionMain.requestStop`, which
/// stores true at that offset; the padding makes the store land in the fake's
/// `halt` so the test can observe the flip without sockets or a tunnel.
const FakeMain = struct {
    _pad: [@offsetOf(SessionMain, "halt")]u8 = [_]u8{0} ** @offsetOf(SessionMain, "halt"),
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn wasStopped(self: *const FakeMain) bool {
        return self.halt.load(.acquire);
    }
};

test "server.session_registry register/unregister" {
    const allocator = testing.allocator;
    var reg = SessionRegistry.init(allocator);
    defer reg.deinit();

    var fake: FakeMain align(@alignOf(SessionMain)) = .{};
    const rec = try allocator.create(SessionRecord);
    rec.* = .{
        .session_name = try allocator.dupe(u8, "SID-ALICE-0"),
        .connection_name = try allocator.dupe(u8, "CONN-0"),
        .username = try allocator.dupe(u8, "Alice"),
        .hub_name = "DEFAULT",
        .peer_ip = 0x0A000001,
        .peer_port = 40000,
        .created_time = 12345,
        .main = @ptrCast(@alignCast(&fake)),
    };
    try reg.register(rec);

    try testing.expectEqual(@as(usize, 1), reg.count());

    // Snapshot observes the registered record.
    const snap = try reg.snapshot(allocator);
    defer SessionRegistry.freeSnapshot(allocator, snap);
    try testing.expectEqual(@as(usize, 1), snap.len);
    try testing.expectEqualStrings("SID-ALICE-0", snap[0].session_name);
    try testing.expectEqualStrings("CONN-0", snap[0].connection_name);
    try testing.expectEqual(@as(u32, 0x0A000001), snap[0].peer_ip);

    // requestStop flips the session's halt flag (via SessionMain.requestStop);
    // name matching is case-insensitive.
    try testing.expect(!fake.wasStopped());
    try testing.expect(reg.requestStop("sid-alice-0"));
    try testing.expect(fake.wasStopped());
    try testing.expect(!reg.requestStop("SID-NOPE"));

    // Duplicate registration rejected.
    const dup = try allocator.create(SessionRecord);
    dup.* = .{
        .session_name = try allocator.dupe(u8, "SID-ALICE-0"),
        .connection_name = try allocator.dupe(u8, "CONN-1"),
        .username = try allocator.dupe(u8, "Alice"),
        .hub_name = "DEFAULT",
        .main = @ptrCast(@alignCast(&fake)),
    };
    try testing.expectError(error.UserExists, reg.register(dup));
    // The rejected record stays caller-owned — free its fields here.
    allocator.free(dup.session_name);
    allocator.free(dup.connection_name);
    allocator.free(dup.username);
    allocator.destroy(dup);

    // Unregister frees the record.
    try testing.expect(reg.unregister("SID-ALICE-0"));
    try testing.expectEqual(@as(usize, 0), reg.count());
    try testing.expect(!reg.unregister("SID-ALICE-0"));
}

test "server.session_registry snapshot round-trip" {
    const allocator = testing.allocator;
    var reg = SessionRegistry.init(allocator);
    defer reg.deinit();

    var fake: FakeMain align(@alignOf(SessionMain)) = .{};
    const rec = try allocator.create(SessionRecord);
    rec.* = .{
        .session_name = try allocator.dupe(u8, "SID-BOB-1"),
        .connection_name = try allocator.dupe(u8, "CONN-1"),
        .username = try allocator.dupe(u8, "Bob"),
        .hub_name = "DEFAULT",
        .peer_ip = 0xC0000201,
        .peer_port = 5555,
        .created_time = 999,
        .main = @ptrCast(@alignCast(&fake)),
    };
    try reg.register(rec);

    const snap = try reg.snapshot(allocator);
    defer SessionRegistry.freeSnapshot(allocator, snap);

    try testing.expectEqual(@as(usize, 1), snap.len);
    try testing.expectEqualStrings("SID-BOB-1", snap[0].session_name);
    try testing.expectEqualStrings("Bob", snap[0].username);
    try testing.expectEqual(@as(u16, 5555), snap[0].peer_port);
    try testing.expectEqual(@as(i64, 999), snap[0].created_time);
}

test "server.session_registry unregister frees and snapshot survives teardown" {
    const allocator = testing.allocator;
    var reg = SessionRegistry.init(allocator);
    defer reg.deinit();

    var fake: FakeMain align(@alignOf(SessionMain)) = .{};
    const rec = try allocator.create(SessionRecord);
    rec.* = .{
        .session_name = try allocator.dupe(u8, "SID-CAROL-2"),
        .connection_name = try allocator.dupe(u8, "CONN-2"),
        .username = try allocator.dupe(u8, "Carol"),
        .hub_name = "DEFAULT",
        .main = @ptrCast(@alignCast(&fake)),
    };
    try reg.register(rec);

    // Snapshot copies owned strings — still valid after the session record is
    // unregistered and freed.
    const snap = try reg.snapshot(allocator);
    defer SessionRegistry.freeSnapshot(allocator, snap);

    try testing.expect(reg.unregister("SID-CAROL-2"));
    try testing.expectEqual(@as(usize, 0), reg.count());

    try testing.expectEqualStrings("SID-CAROL-2", snap[0].session_name);
    try testing.expectEqualStrings("Carol", snap[0].username);
    try testing.expectEqualStrings("DEFAULT", snap[0].hub_name);
}

test "server.session_registry requestStopByConnection" {
    const allocator = testing.allocator;
    var reg = SessionRegistry.init(allocator);
    defer reg.deinit();

    var fake: FakeMain align(@alignOf(SessionMain)) = .{};
    const rec = try allocator.create(SessionRecord);
    rec.* = .{
        .session_name = try allocator.dupe(u8, "SID-DAVE-3"),
        .connection_name = try allocator.dupe(u8, "CONN-3"),
        .username = try allocator.dupe(u8, "Dave"),
        .hub_name = "DEFAULT",
        .main = @ptrCast(@alignCast(&fake)),
    };
    try reg.register(rec);

    try testing.expect(!fake.wasStopped());
    try testing.expect(reg.requestStopByConnection("conn-3"));
    try testing.expect(fake.wasStopped());
    try testing.expect(!reg.requestStopByConnection("CONN-NOPE"));
}

test "server.session_registry requestStopOnHub is hub-scoped" {
    const allocator = testing.allocator;
    var reg = SessionRegistry.init(allocator);
    defer reg.deinit();

    var fake_a: FakeMain align(@alignOf(SessionMain)) = .{};
    const rec_a = try allocator.create(SessionRecord);
    rec_a.* = .{
        .session_name = try allocator.dupe(u8, "SID-EVE-4"),
        .connection_name = try allocator.dupe(u8, "CONN-4"),
        .username = try allocator.dupe(u8, "Eve"),
        .hub_name = "VPN",
        .main = @ptrCast(@alignCast(&fake_a)),
    };
    try reg.register(rec_a);

    var fake_b: FakeMain align(@alignOf(SessionMain)) = .{};
    const rec_b = try allocator.create(SessionRecord);
    rec_b.* = .{
        .session_name = try allocator.dupe(u8, "SID-FRANK-5"),
        .connection_name = try allocator.dupe(u8, "CONN-5"),
        .username = try allocator.dupe(u8, "Frank"),
        .hub_name = "TEST",
        .main = @ptrCast(@alignCast(&fake_b)),
    };
    try reg.register(rec_b);

    // The same session name on another hub is not stopped.
    try testing.expect(!fake_b.wasStopped());
    try testing.expect(!reg.requestStopOnHub("VPN", "SID-FRANK-5"));
    try testing.expect(!fake_b.wasStopped());

    // Correct hub + name (case-insensitive) stops the session.
    try testing.expect(reg.requestStopOnHub("vpn", "sid-eve-4"));
    try testing.expect(fake_a.wasStopped());
    try testing.expect(!reg.requestStopOnHub("VPN", "SID-NOPE"));
}
