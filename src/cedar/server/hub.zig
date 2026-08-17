//! Virtual Hub L2 switch — the hub data plane.
//!
//! C reference: `StorePacket` (Hub.c:4068) and its helpers. Each session
//! attached to the hub gets a `SessionPa` — a per-session `PacketAdapter`
//! (`session_main.PacketAdapter`) that:
//!
//!   - `put` delivers a frame received from the wire into the switch
//!     (C `HubPaPutPacket`, Hub.c:3683 → `StorePacket`)
//!   - `get` pops the next frame the switch queued for this session
//!     (C `HubPaGetNextPacket`, Hub.c:3649)
//!
//! Forwarding model (C `StorePacket`, Hub.c:4068):
//!
//!   1. parse the Ethernet header (dst/src MAC, ethertype, broadcast flag)
//!   2. learn the source MAC into the MAC table (one owning session, refreshed
//!      on use; a new sender on the same MAC migrates the entry — the default
//!      C behaviour with `CheckMac` disabled)
//!   3. resolve the destination: unicast via the MAC table; broadcast
//!      (ff:ff:ff:ff:ff:ff), multicast (group bit), or an unknown destination
//!      MAC floods to every other session
//!   4. learn the source IPv4 from IP/ARP frames into the IP table
//!   5. flood paths pass a broadcast-storm limiter and each destination queue
//!      is capped (`MAX_STORED_QUEUE_NUM` — the flooding quota)
//!
//! M1 simplifications (documented deviations from C):
//!   - No VLAN-tag parsing (`NoManageVlanId` is always on).
//!   - No per-session policies, ACLs, traffic limiters, or monitor ports.
//!   - No DHCPv4 exclusion when learning the IP table.
//!   - The IP table is learned but not yet consulted for forwarding (L2
//!     switching is MAC-based in M1).
//!   - No 802.3-length frames (only 0x0800/0x0806 style ethertypes parsed).
//!
//! Thread-safety: a single `Hub.mutex` guards the MAC/IP tables, the session
//! list, and every session queue, so multiple session threads (each running
//! `SessionMain`) can share one hub.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const session_main = @import("session_main.zig");
const PacketAdapter = session_main.PacketAdapter;
const acl_mod = @import("acl.zig");
const AccessList = acl_mod.AccessList;
const AccessRule = acl_mod.AccessRule;
const HubFilters = acl_mod.HubFilters;
const logging_mod = @import("logging.zig");
const Log = logging_mod.LOG;
const HubLogConfig = logging_mod.HubLogConfig;
const ra_mod = @import("ra.zig");

// ============================================================================
// Constants (C: Cedar.h / Hub.c)
// ============================================================================

/// Maximum MAC address table entries (C: `MAX_MAC_TABLES`).
pub const MAX_MAC_TABLES: usize = 65536;
/// Maximum IP address table entries (C: `MAX_IP_TABLES`).
pub const MAX_IP_TABLES: usize = 65536;
/// Frames buffered per session before flooding drops (C: `MAX_STORED_QUEUE_NUM`).
pub const MAX_STORED_QUEUE_NUM: usize = 384;
/// MAC table entry lifetime (C: `MAC_TABLE_EXPIRE_TIME` = 600s).
pub const MAC_TABLE_EXPIRE_TIME: i64 = 600_000;
/// IP table entry lifetime (C: `IP_TABLE_EXPIRE_TIME` = 60s).
pub const IP_TABLE_EXPIRE_TIME: i64 = 60_000;
/// How often expired MAC entries are flushed while learning
/// (C: `OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL` = 1000ms).
pub const MAC_FLUSH_INTERVAL: i64 = 1_000;
/// How often expired IP entries are flushed (C: `OLD_IP_ADDRESS_ENTRY_FLUSH_INTERVAL`).
pub const IP_FLUSH_INTERVAL: i64 = 1_000;
/// Broadcast storm measurement window (C: `STORM_CHECK_SPAN` = 500ms).
pub const STORM_CHECK_SPAN: i64 = 500;
/// Broadcast discard threshold start (C: `STORM_DISCARD_VALUE_START` = 3).
pub const STORM_DISCARD_VALUE_START: u32 = 3;
/// Broadcast discard threshold cap (C: `STORM_DISCARD_VALUE_END` = 1024).
pub const STORM_DISCARD_VALUE_END: u32 = 1024;
/// Broadcasts/s after which storm limiting starts (C default 32).
pub const DEFAULT_BROADCAST_STORM_THRESHOLD: u32 = 32;

pub const MAC_BROADCAST = [6]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

// ============================================================================
// Ethernet parsing
// ============================================================================

/// Minimal parsed Ethernet header (no VLAN support in M1).
pub const ParsedFrame = struct {
    dst: [6]u8,
    src: [6]u8,
    /// Ethernet type, big-endian (e.g. 0x0800 = IPv4, 0x0806 = ARP).
    ethertype: u16,
    /// True for broadcast (ff:ff:ff:ff:ff:ff) and multicast (group bit set)
    /// destination MACs — C `PKT->BroadcastPacket` (TcpIp.c:2220-2249).
    broadcast: bool,
};

/// Parse an Ethernet frame header. Returns null for frames too short to
/// contain a MAC header (14 bytes).
pub fn parseEthernet(frame: []const u8) ?ParsedFrame {
    if (frame.len < 14) return null;
    var dst: [6]u8 = undefined;
    var src: [6]u8 = undefined;
    @memcpy(&dst, frame[0..6]);
    @memcpy(&src, frame[6..12]);
    const ethertype = mem.readInt(u16, frame[12..14], .big);
    var broadcast = true;
    for (dst) |b| {
        if (b != 0xff) {
            broadcast = false;
            break;
        }
    }
    if (dst[0] & 0x01 != 0) broadcast = true;
    return .{ .dst = dst, .src = src, .ethertype = ethertype, .broadcast = broadcast };
}

/// Source MACs that make a frame illegal (C: `PKT->InvalidSourcePacket`):
/// all-ff, all-00, or equal to the destination.
pub fn isInvalidSource(src: [6]u8, dst: [6]u8) bool {
    var all_ff = true;
    var all_zero = true;
    for (src) |b| {
        if (b != 0xff) all_ff = false;
        if (b != 0x00) all_zero = false;
    }
    return all_ff or all_zero or mem.eql(u8, &src, &dst);
}

// ============================================================================
// Table entries
// ============================================================================

/// MAC table entry: a learned source MAC and its owning session (C `MAC_TABLE_ENTRY`).
pub const MacEntry = struct {
    /// The session that last sent this source MAC.
    session: *SessionPa,
    updated: i64,
    created: i64,
};

/// IP table entry: a learned source IP and the session/MAC it belongs to
/// (C `IP_TABLE_ENTRY`). Learned for bookkeeping; not used for M1 forwarding.
pub const IpEntry = struct {
    session: *SessionPa,
    mac: [6]u8,
    updated: i64,
    created: i64,
};

/// Per-session broadcast storm limiter state (C `STORM`/`HUB_PA->StormList`).
/// M1 tracks one counter per session rather than per (mac, src-ip, dst-ip).
const StormState = struct {
    current_broadcast_num: u32 = 0,
    check_start_tick: i64 = 0,
    discard_value: u32 = 0,
};

/// IPv6 table entry: a learned source IPv6 and the session/MAC it belongs to.
pub const Ip6Entry = struct {
    session: *SessionPa,
    mac: [6]u8,
    updated: i64,
    created: i64,
};

/// Maximum IPv6 address table entries.
pub const MAX_IP6_TABLES: usize = 65536;
/// IPv6 table entry lifetime in ms.
pub const IP6_TABLE_EXPIRE_TIME: i64 = 60_000;

// ============================================================================
// Session packet adapter
// ============================================================================

/// Per-session hub packet adapter. One per session; handed to `SessionMain`
/// via `pa()`. The hub writes frames into `outbound` (under `Hub.mutex`) and
/// the session thread pulls them with `get`.
pub const SessionPa = struct {
    hub: *Hub,
    /// Owned session name (C `SESSION->Name`).
    name: []u8,
    allocator: Allocator,
    /// Frames the switch queued for this session, in delivery order.
    /// Each slice is heap-allocated and owned until `get` transfers it.
    outbound: std.ArrayList([]u8) = .{},
    outbound_bytes: usize = 0,
    storm: StormState = .{},
    /// True while the session is in the hub's session list.
    attached: bool = false,

    pub fn init(hub: *Hub, allocator: Allocator, name: []const u8) !*SessionPa {
        const self = try allocator.create(SessionPa);
        errdefer allocator.destroy(self);
        self.* = .{
            .hub = hub,
            .name = try allocator.dupe(u8, name),
            .allocator = allocator,
            .outbound = .empty,
        };
        return self;
    }

    /// Detach from the hub (if attached), free queued frames and the name.
    pub fn deinit(self: *SessionPa) void {
        if (self.attached) self.hub.detach(self);
        for (self.outbound.items) |f| self.allocator.free(f);
        self.outbound.deinit(self.allocator);
        self.allocator.free(self.name);
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// The `PacketAdapter` to hand to `SessionMain`.
    pub fn pa(self: *SessionPa) PacketAdapter {
        return .{
            .ctx = self,
            .init = paInit,
            .free = paFree,
            .put = paPut,
            .flush = paFlush,
            .get = paGet,
        };
    }

    fn paInit(_: *anyopaque) bool {
        return true; // attach is explicit via Hub.attach
    }

    fn paFree(_: *anyopaque) void {}

    /// C `HubPaPutPacket` (Hub.c:3683): hand the frame to the switch. Always
    /// accepts (drops are silent inside `StorePacket`, matching C).
    fn paPut(ctx: *anyopaque, frame: []const u8) bool {
        const self: *SessionPa = @ptrCast(@alignCast(ctx));
        self.hub.storePacket(self, frame);
        return true;
    }

    /// C `pa->PutPacket(s, NULL, 0)` flush hook. Delayed-packet replay is out
    /// of M1 scope; nothing to do.
    fn paFlush(_: *anyopaque) bool {
        return true;
    }

    /// C `HubPaGetNextPacket` (Hub.c:3649): pop the next queued frame, or null
    /// when the queue is empty. The returned slice is owned by the caller.
    fn paGet(ctx: *anyopaque) ?[]u8 {
        const self: *SessionPa = @ptrCast(@alignCast(ctx));
        self.hub.mutex.lock();
        defer self.hub.mutex.unlock();
        if (self.outbound.items.len == 0) return null;
        const frame = self.outbound.orderedRemove(0);
        self.outbound_bytes -|= frame.len;
        return frame;
    }
};

// ============================================================================
// Hub — the L2 switch
// ============================================================================

/// Per-hub data-plane statistics.
pub const HubStats = struct {
    /// Frames delivered to a unicast destination session.
    unicast_frames: u64 = 0,
    /// Frames delivered as broadcast/multicast/unknown-destination floods.
    flooded_frames: u64 = 0,
    /// Frames dropped (parse failure, invalid source, full queue, storm).
    dropped_frames: u64 = 0,
    /// Flooded frames dropped by the broadcast-storm limiter.
    storm_dropped: u64 = 0,
};

/// The Virtual Hub L2 switch. Owns the MAC/IP tables and the session list;
/// session frames live in each `SessionPa`'s queue.
pub const Hub = struct {
    allocator: Allocator,
    /// Owned hub name (e.g. "DEFAULT").
    name: []u8,
    /// Guards tables, the session list, and all session queues.
    mutex: std.Thread.Mutex = .{},
    mac_table: std.AutoHashMapUnmanaged([6]u8, MacEntry) = .{},
    ip_table: std.AutoHashMapUnmanaged(u32, IpEntry) = .{},
    sessions: std.ArrayList(*SessionPa) = .{},
    last_mac_flush_tick: i64 = 0,
    last_ip_flush_tick: i64 = 0,
    /// Broadcasts/s above which flooding starts being limited
    /// (C: hub option `BroadcastStormDetectionThreshold`; 0 = unlimited).
    storm_threshold: u32 = DEFAULT_BROADCAST_STORM_THRESHOLD,
    stats: HubStats = .{},
    /// SecureNAT live instance — opaque pointer to `securenat.SecureNAT`.
    /// Avoids circular import; callers cast via the securenat module.
    secure_nat: ?*anyopaque = null,
    /// Hub-level access list (ingress/egress packet filtering).
    access_list: AccessList = undefined,
    /// Hub-level protocol filters (PPPoE, OSPF, IPv4/IPv6/NonIP/BPDU).
    filters: HubFilters = .{},
    /// Hub log configuration.
    log_config: HubLogConfig = .{},
    /// Hub security logger (C: `HUB.SecurityLogger`).
    security_logger: ?*Log = null,
    /// Hub MAC address (6 bytes, used for RA source link-layer and EUI-64).
    hub_mac: [6]u8 = .{ 0x02, 0xAC, 0x11, 0x22, 0x33, 0x44 },
    /// Hub link-local IPv6 address (16 bytes, fe80::EUI-64 from hub_mac).
    hub_ipv6: [16]u8 = .{0} ** 16,
    /// IPv6 address table: learned source IPv6 → entry (C: Hub.IPv6Table).
    ip6_table: std.AutoHashMapUnmanaged([16]u8, Ip6Entry) = .{},
    /// Counter for ICMPv6 messages (NS/NA) — used as nonce.
    hub_ipv6_id: u32 = 0,

    pub fn init(allocator: Allocator, name: []const u8) !*Hub {
        const self = try allocator.create(Hub);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
            .mac_table = std.AutoHashMapUnmanaged([6]u8, MacEntry).empty,
            .ip_table = std.AutoHashMapUnmanaged(u32, IpEntry).empty,
            .ip6_table = std.AutoHashMapUnmanaged([16]u8, Ip6Entry).empty,
            .sessions = .empty,
            .access_list = AccessList.init(allocator),
            .hub_ipv6 = ra_mod.eui64LinkLocal(.{ 0x02, 0xAC, 0x11, 0x22, 0x33, 0x44 }),
        };
        return self;
    }

    pub fn deinit(self: *Hub) void {
        // Stop SecureNAT first — it holds a SessionPa that references this hub.
        self.disableSecureNAT();
        // Stop the security logger.
        if (self.security_logger) |l| l.deinit();
        const allocator = self.allocator;
        self.access_list.deinit();
        self.mutex.lock();
        self.mac_table.deinit(allocator);
        self.ip_table.deinit(allocator);
        self.ip6_table.deinit(allocator);
        for (self.sessions.items) |pa| pa.attached = false;
        self.sessions.deinit(allocator);
        self.mutex.unlock();
        allocator.free(self.name);
        allocator.destroy(self);
    }

    /// Number of sessions currently attached.
    pub fn sessionCount(self: *Hub) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.items.len;
    }

    // ---- Session lifecycle -------------------------------------------------

    /// Register a session's packet adapter with the switch (C: a session
    /// joining the hub). Idempotent.
    pub fn attach(self: *Hub, pa: *SessionPa) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (pa.attached) return;
        pa.attached = true;
        self.sessions.append(self.allocator, pa) catch {
            pa.attached = false;
            return;
        };
    }

    /// Unregister a session: remove it from the session list and purge its
    /// MAC/IP table entries. Queued frames are left for `SessionPa.deinit`.
    pub fn detach(self: *Hub, pa: *SessionPa) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!pa.attached) return;
        pa.attached = false;
        for (self.sessions.items, 0..) |s, i| {
            if (s == pa) {
                _ = self.sessions.swapRemove(i);
                break;
            }
        }
        self.removeEntriesOf(pa);
    }

    fn removeEntriesOf(self: *Hub, pa: *SessionPa) void {
        var it = self.mac_table.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.session == pa) _ = self.mac_table.remove(kv.key_ptr.*);
        }
        var ipit = self.ip_table.iterator();
        while (ipit.next()) |kv| {
            if (kv.value_ptr.session == pa) _ = self.ip_table.remove(kv.key_ptr.*);
        }
        var ip6it = self.ip6_table.iterator();
        while (ip6it.next()) |kv| {
            if (kv.value_ptr.session == pa) _ = self.ip6_table.remove(kv.key_ptr.*);
        }
    }

    // ---- SecureNAT lifecycle -----------------------------------------------

    /// Enable SecureNAT on this hub (C: `EnableSecureNATEx(h, true)`).
    /// Idempotent if already enabled.
    /// Thread-safe: double-check pattern prevents duplicate instances.
    pub fn enableSecureNAT(self: *Hub, config: anytype) !void {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.secure_nat != null) return; // already running
        }
        // Import is deferred to break the circular dependency.
        const securenat_mod = @import("securenat.zig");
        // init() may lock hub.mutex internally (via attach), so it must
        // be called with the hub mutex UNLOCKED.
        const s = try securenat_mod.SecureNAT.init(self.allocator, self, config);
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.secure_nat != null) {
                // Another thread raced and enabled SecureNAT first — clean up.
                s.deinit();
                return;
            }
            self.secure_nat = @ptrCast(s);
        }
    }

    /// Disable SecureNAT on this hub (C: `EnableSecureNATEx(h, false)`).
    /// Stops the polling thread and frees the `SecureNAT` instance.
    /// Thread-safe: the hub mutex is held for the pointer clear, but the
    /// SecureNAT.deinit may internally lock the hub mutex (via detach).
    pub fn disableSecureNAT(self: *Hub) void {
        // Extract the pointer under the lock, then deinit outside to avoid
        // holding the hub mutex while SecureNAT.deinit tries to lock it.
        const ptr = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            const p = self.secure_nat orelse return;
            self.secure_nat = null;
            break :blk p;
        };
        const securenat_mod = @import("securenat.zig");
        const s: *securenat_mod.SecureNAT = @alignCast(@ptrCast(ptr));
        s.deinit();
    }

    /// Query whether SecureNAT is currently running on this hub.
    /// Thread-safe: reads under the hub mutex.
    pub fn isSecureNATEnabled(self: *Hub) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.secure_nat != null;
    }

    // ---- Access list management -------------------------------------------

    /// Add an access rule to this hub's access list. Returns the assigned rule ID.
    pub fn addAccessRule(self: *Hub, rule: AccessRule) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.access_list.add(rule);
    }

    /// Remove an access rule by ID. Returns true if found and removed.
    pub fn removeAccessRule(self: *Hub, id: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.access_list.remove(id);
    }

    /// Get the number of access rules.
    pub fn accessRuleCount(self: *Hub) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.access_list.rules.items.len;
    }

    /// Update hub-level protocol filters.
    pub fn setFilters(self: *Hub, filters: HubFilters) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.filters = filters;
    }

    // ---- Security logger ---------------------------------------------------

    /// Start the hub security logger (C: `HUB.SecurityLogger`).
    /// Creates the log directory and spawns the writer thread.
    pub fn startSecurityLogger(self: *Hub) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.security_logger != null) return; // already running

        var buf: [256]u8 = undefined;
        const dir = std.fmt.bufPrint(&buf, "{s}/{s}", .{
            logging_mod.HUB_SECURITY_LOG_DIR_NAME,
            self.name,
        }) catch return error.NameTooLong;

        const l = try Log.init(self.allocator, dir, logging_mod.HUB_SECURITY_LOG_PREFIX, self.log_config.security_log_switch_type);
        self.security_logger = l;
    }

    /// Stop the hub security logger.
    pub fn stopSecurityLogger(self: *Hub) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.security_logger) |l| {
            l.deinit();
            self.security_logger = null;
        }
    }

    /// Log a security event to the hub's security logger.
    pub fn securityLog(self: *Hub, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lock();
        const logger = self.security_logger;
        self.mutex.unlock();
        if (logger) |l| l.printf(fmt, args);
    }

    /// Update the hub log configuration.
    pub fn setLogConfig(self: *Hub, config: HubLogConfig) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.log_config = config;
    }

    // ---- Switching ---------------------------------------------------------

    /// The hub switch entry point — C `StorePacket` (Hub.c:4068).
    ///
    /// `frame` is only valid for the duration of the call; the switch copies
    /// anything it delivers.
    pub fn storePacket(self: *Hub, src: *SessionPa, frame: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Reject frames from a session that is no longer attached: learning
        // its MAC/IP would create table entries pointing at a freed adapter
        // (use-after-free on later unicast delivery).
        if (!src.attached) {
            self.stats.dropped_frames += 1;
            return;
        }

        const parsed = parseEthernet(frame) orelse {
            self.stats.dropped_frames += 1;
            return;
        };
        if (isInvalidSource(parsed.src, parsed.dst)) {
            self.stats.dropped_frames += 1;
            return;
        }

        // Hub-level ingress filters + ACL evaluation (C: Phase A+B of
        // ApplyAccessListToStoredPacket, Hub.c:2872).
        const ctx = acl_mod.parsePacketContext(frame) orelse {
            self.stats.dropped_frames += 1;
            return;
        };
        if (acl_mod.matchesHubFilters(&ctx, &self.filters)) {
            self.stats.dropped_frames += 1;
            return;
        }
        const acl_result = acl_mod.evaluateAccessList(self.access_list.rules.items, &ctx);
        if (!acl_result.pass) {
            self.stats.dropped_frames += 1;
            return;
        }

        const now = std.time.milliTimestamp();

        // 1. Learn the source MAC (C: MacHashTable insert/refresh/migrate).
        self.learnMac(src, parsed.src, now);

        // 2. Learn the source IPv4/IPv6 for IP/ARP frames.
        self.learnIp4(src, parsed, frame, now);
        self.learnIp6(src, parsed, frame, now);

        // 3. Resolve the destination.
        var broadcast_mode = parsed.broadcast;
        var dest_pa: ?*SessionPa = null;
        if (!broadcast_mode) {
            const entry = self.mac_table.get(parsed.dst);
            if (entry) |e| {
                if (e.session == src) {
                    // Addressed to self — discard (C Hub.c:4492-4497).
                    self.stats.dropped_frames += 1;
                    return;
                }
                dest_pa = e.session;
            } else {
                // Unknown destination — flood (C Hub.c:4477-4481).
                broadcast_mode = true;
            }
        }

        // 4. Forward.
        if (!broadcast_mode) {
            self.deliver(dest_pa.?, frame, false);
        } else {
            if (!self.checkBroadcastStorm(src, now)) {
                self.stats.dropped_frames += 1;
                self.stats.storm_dropped += 1;
                return;
            }
            for (self.sessions.items) |sess| {
                if (sess != src) self.deliver(sess, frame, true);
            }
        }
    }

    /// Deliver a copy of `frame` to a destination session's outbound queue.
    /// Drops silently when the queue is full (C `StorePacketToHubPa`, the
    /// flooding quota / `MAX_STORED_QUEUE_NUM`).
    fn deliver(self: *Hub, dest: *SessionPa, frame: []const u8, is_flooding: bool) void {
        if (dest.outbound.items.len >= MAX_STORED_QUEUE_NUM) {
            self.stats.dropped_frames += 1;
            return;
        }
        const copy = self.allocator.dupe(u8, frame) catch {
            self.stats.dropped_frames += 1;
            return;
        };
        dest.outbound.append(self.allocator, copy) catch {
            self.allocator.free(copy);
            self.stats.dropped_frames += 1;
            return;
        };
        dest.outbound_bytes += copy.len;
        if (is_flooding) {
            self.stats.flooded_frames += 1;
        } else {
            self.stats.unicast_frames += 1;
        }
    }

    // ---- MAC learning ------------------------------------------------------

    fn learnMac(self: *Hub, src: *SessionPa, mac: [6]u8, now: i64) void {
        const gop = self.mac_table.getOrPut(self.allocator, mac) catch {
            self.stats.dropped_frames += 1;
            return;
        };
        if (gop.found_existing) {
            // Existing entry: refresh/migrate regardless of table size (C
            // Hub.c:4340-4420 — the `SearchHash` hit path never checks
            // `MAX_MAC_TABLES`).
            gop.value_ptr.session = src;
            gop.value_ptr.updated = now;
            return;
        }
        // New entry: populate immediately so the expiry sweep cannot mistake
        // the fresh (zero-initialized) slot for a stale one, then flush
        // expired entries and enforce capacity (C order:
        // `DeleteExpiredMacTableEntry` before the `MAX_MAC_TABLES` check).
        gop.value_ptr.* = .{
            .session = src,
            .updated = now,
            .created = now,
        };
        if (self.last_mac_flush_tick == 0 or
            self.last_mac_flush_tick + MAC_FLUSH_INTERVAL < now)
        {
            self.last_mac_flush_tick = now;
            _ = self.flushExpiredMac(now);
        }
        if (self.mac_table.count() > MAX_MAC_TABLES) {
            _ = self.mac_table.remove(mac);
            self.stats.dropped_frames += 1;
        }
    }

    /// Remove MAC entries not touched in `MAC_TABLE_EXPIRE_TIME` ms
    /// (C `DeleteExpiredMacTableEntry`, Hub.c:6081). Returns how many expired.
    pub fn flushExpiredMac(self: *Hub, now: i64) usize {
        var expired: usize = 0;
        var it = self.mac_table.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.updated + MAC_TABLE_EXPIRE_TIME <= now) {
                _ = self.mac_table.remove(kv.key_ptr.*);
                expired += 1;
            }
        }
        return expired;
    }

    // ---- IP learning -------------------------------------------------------

    /// Learn the source IPv4 for IPv4 and ARP frames (C Hub.c:4680-4710).
    /// Skipped for multicast/loopback/zero source addresses.
    fn learnIp4(self: *Hub, src: *SessionPa, parsed: ParsedFrame, frame: []const u8, now: i64) void {
        const src_ip: ?u32 = switch (parsed.ethertype) {
            0x0800 => blk: { // IPv4 — src IP at offset 14 + 12
                if (frame.len < 14 + 16) break :blk null;
                break :blk mem.readInt(u32, frame[14 + 12 ..][0..4], .big);
            },
            0x0806 => blk: { // ARP — sender IP at offset 14 + 14, HW ethernet/Proto 0x0800
                if (frame.len < 14 + 18) break :blk null;
                const arp = frame[14..];
                const hw = mem.readInt(u16, arp[0..2], .big);
                const proto = mem.readInt(u16, arp[2..4], .big);
                if (hw != 1 or proto != 0x0800) break :blk null;
                if (arp[4] != 6 or arp[5] != 4) break :blk null;
                break :blk mem.readInt(u32, arp[14..18], .big);
            },
            else => null,
        };
        const ip = src_ip orelse return;
        if (ip == 0 or ip == 0xffffffff) return;
        // Skip multicast (224.0.0.0/4) and loopback (127.0.0.0/8) sources.
        if ((ip >> 24) & 0xe0 == 0xe0) return;
        if ((ip >> 24) == 127) return;

        if (self.ip_table.count() >= MAX_IP_TABLES) return;
        if (self.last_ip_flush_tick == 0 or
            self.last_ip_flush_tick + IP_FLUSH_INTERVAL < now)
        {
            self.last_ip_flush_tick = now;
            _ = self.flushExpiredIp(now);
        }
        const gop = self.ip_table.getOrPut(self.allocator, ip) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .session = src,
                .mac = parsed.src,
                .updated = now,
                .created = now,
            };
        } else {
            gop.value_ptr.session = src;
            gop.value_ptr.mac = parsed.src;
            gop.value_ptr.updated = now;
        }
    }

    /// Remove IP entries not touched in `IP_TABLE_EXPIRE_TIME` ms
    /// (C `DeleteExpiredIpTableEntry`, Hub.c:6119). Returns how many expired.
    pub fn flushExpiredIp(self: *Hub, now: i64) usize {
        var expired: usize = 0;
        var it = self.ip_table.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.updated + IP_TABLE_EXPIRE_TIME <= now) {
                _ = self.ip_table.remove(kv.key_ptr.*);
                expired += 1;
            }
        }
        return expired;
    }

    // ---- IPv6 learning -----------------------------------------------------

    /// Learn the source IPv6 address from IPv6 frames (C Hub.c:4492-4600).
    /// Skips multicast, loopback, and zero source addresses.
    fn learnIp6(self: *Hub, src: *SessionPa, parsed: ParsedFrame, frame: []const u8, now: i64) void {
        if (parsed.ethertype != 0x86DD) return;
        if (frame.len < 14 + 40 + 8) return;

        const ip6 = frame[14..];
        // Source address is at IPv6 header offset 8..24.
        var src_addr: [16]u8 = undefined;
        @memcpy(&src_addr, ip6[8..24]);

        // Skip loopback (::1), unspecified (::), and multicast (ff00::/8).
        if (src_addr[0] == 0xff) return;
        var all_zero = true;
        for (src_addr) |b| {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) return;
        if (src_addr[0] == 0xfe and src_addr[1] == 0x80) {
            // Link-local is valid — learn it.
        } else if (src_addr[0] == 0xfc or src_addr[0] == 0xfd) {
            // ULA is valid.
        } else if ((src_addr[0] & 0xfe) == 0x20) {
            // Global unicast (2000::/3).
        } else {
            return; // skip other types
        }

        if (self.ip6_table.count() >= MAX_IP6_TABLES) return;

        const src_mac: [6]u8 = .{ frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] };
        const gop = self.ip6_table.getOrPut(self.allocator, src_addr) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .session = src,
                .mac = src_mac,
                .updated = now,
                .created = now,
            };
        } else {
            gop.value_ptr.session = src;
            gop.value_ptr.mac = src_mac;
            gop.value_ptr.updated = now;
        }
    }

    /// Remove IPv6 table entries not touched in `IP6_TABLE_EXPIRE_TIME` ms.
    pub fn flushExpiredIp6(self: *Hub, now: i64) usize {
        var expired: usize = 0;
        var it = self.ip6_table.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.updated + IP6_TABLE_EXPIRE_TIME <= now) {
                _ = self.ip6_table.remove(kv.key_ptr.*);
                expired += 1;
            }
        }
        return expired;
    }

    // ---- Broadcast storm limiter -------------------------------------------

    /// Simplified C `CheckBroadcastStorm` (Hub.c:3934): per-session counter.
    /// Once the flood rate for a session exceeds `storm_threshold`, packets are
    /// discarded with a probability that doubles each detected storm interval.
    fn checkBroadcastStorm(self: *Hub, pa: *SessionPa, now: i64) bool {
        const threshold = self.storm_threshold;
        if (threshold == 0) return true;

        const st = &pa.storm;
        st.current_broadcast_num +|= 1;

        if (st.check_start_tick == 0 or
            st.check_start_tick > now or
            st.check_start_tick + STORM_CHECK_SPAN < now)
        {
            const rate = @as(u64, st.current_broadcast_num) * 1000 / @as(u64, STORM_CHECK_SPAN);
            const old_diff = if (now > st.check_start_tick) now - st.check_start_tick else 0;
            st.check_start_tick = now;
            st.current_broadcast_num = 0;
            if (rate >= threshold) {
                if (st.discard_value < STORM_DISCARD_VALUE_END) {
                    st.discard_value = @max(st.discard_value, 1) * 2;
                }
                return false;
            } else if (st.discard_value >= 1) {
                const decay = @as(u64, @max(old_diff, 0)) / @as(u64, STORM_CHECK_SPAN);
                st.discard_value = @intCast(@as(u64, st.discard_value) / @max(decay, 2));
            }
        }

        if (st.discard_value >= STORM_DISCARD_VALUE_START) {
            if (st.discard_value >= 128) return false;
            if (std.crypto.random.intRangeAtMost(u32, 0, st.discard_value - 1) != 0) return false;
        }
        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn makeHub() !*Hub {
    return Hub.init(testing.allocator, "DEFAULT");
}

fn makePa(hub: *Hub, name: []const u8) !*SessionPa {
    const pa = try SessionPa.init(hub, testing.allocator, name);
    hub.attach(pa);
    return pa;
}

/// Build a minimal Ethernet frame: dst + src + ethertype + payload.
fn buildFrame(dst: [6]u8, src: [6]u8, ethertype: u16, payload: []const u8) ![]u8 {
    const allocator = testing.allocator;
    const f = try allocator.alloc(u8, 14 + payload.len);
    @memcpy(f[0..6], &dst);
    @memcpy(f[6..12], &src);
    mem.writeInt(u16, f[12..14], ethertype, .big);
    if (payload.len > 0) @memcpy(f[14..], payload);
    return f;
}

fn macBytes(m: []const u8) [6]u8 {
    var out: [6]u8 = undefined;
    for (0..6) |i| {
        out[i] = std.fmt.parseUnsigned(u8, m[i * 2 .. i * 2 + 2], 16) catch unreachable;
    }
    return out;
}

test "server.hub.parseEthernet extracts header fields" {
    const allocator = testing.allocator;
    const f = try buildFrame(MAC_BROADCAST, macBytes("112233445566"), 0x0800, &.{0xaa});
    defer allocator.free(f);

    const p = parseEthernet(f).?;
    try testing.expectEqualSlices(u8, &MAC_BROADCAST, &p.dst);
    const src_mac = macBytes("112233445566");
    try testing.expectEqualSlices(u8, &src_mac, &p.src);
    try testing.expectEqual(@as(u16, 0x0800), p.ethertype);
    try testing.expect(p.broadcast);
}

test "server.hub.parseEthernet multicast sets broadcast" {
    // 01:00:5e:00:00:01 (IPv4 multicast) has the group bit set.
    const f = try buildFrame(macBytes("01005e000001"), macBytes("112233445566"), 0x0800, &.{});
    defer testing.allocator.free(f);
    try testing.expect(parseEthernet(f).?.broadcast);
}

test "server.hub.parseEthernet short frame rejected" {
    try testing.expect(parseEthernet("too short") == null);
}

test "server.hub.invalid sources rejected" {
    try testing.expect(isInvalidSource(MAC_BROADCAST, macBytes("223344556677")));
    try testing.expect(isInvalidSource([6]u8{ 0, 0, 0, 0, 0, 0 }, macBytes("223344556677")));
    try testing.expect(isInvalidSource(macBytes("aabbccddeeff"), macBytes("aabbccddeeff")));
    try testing.expect(!isInvalidSource(macBytes("aabbccddeeff"), macBytes("112233445566")));
}

test "server.hub unicast exchange between two sessions" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // A → B: B's MAC is unknown yet, so this floods and teaches A's MAC.
    const f1 = try buildFrame(mac_b, mac_a, 0x0800, &.{0x01});
    defer allocator.free(f1);
    hub.storePacket(a, f1);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
    try testing.expectEqualSlices(u8, f1, b.outbound.items[0]);

    // B → A: A's MAC is now learned → unicast, delivered only to A.
    const f2 = try buildFrame(mac_a, mac_b, 0x0800, &.{0x02});
    defer allocator.free(f2);
    hub.storePacket(b, f2);
    try testing.expectEqual(@as(usize, 1), a.outbound.items.len);
    try testing.expectEqualSlices(u8, f2, a.outbound.items[0]);
    // B must not have received its own frame back.
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}

test "server.hub flood to all sessions for unknown and broadcast" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();
    const c = try makePa(hub, "C");
    defer c.deinit();

    const mac_a = macBytes("020000000001");

    // Unknown unicast destination → flood to B and C.
    const f1 = try buildFrame(macBytes("0200000000ff"), mac_a, 0x0800, &.{0x11});
    defer allocator.free(f1);
    hub.storePacket(a, f1);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
    try testing.expectEqual(@as(usize, 1), c.outbound.items.len);
    try testing.expectEqual(@as(usize, 0), a.outbound.items.len); // not echoed back

    // Broadcast → flood to B and C.
    const f2 = try buildFrame(MAC_BROADCAST, mac_a, 0x0800, &.{0x22});
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 2), b.outbound.items.len);
    try testing.expectEqual(@as(usize, 2), c.outbound.items.len);
}

test "server.hub mac learning routes unicast and migrates owner" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    const mac_x = macBytes("02000000000a");
    const mac_a = macBytes("020000000001");

    // A announces mac_x (unknown → flood).
    const f1 = try buildFrame(macBytes("0200000000ff"), mac_x, 0x0800, &.{});
    defer allocator.free(f1);
    hub.storePacket(a, f1);
    try testing.expect(hub.mac_table.contains(mac_x));
    try testing.expectEqual(a, hub.mac_table.get(mac_x).?.session);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);

    // B claims the same mac_x → ownership migrates to B.
    const f2 = try buildFrame(macBytes("0200000000ff"), mac_x, 0x0800, &.{});
    defer allocator.free(f2);
    hub.storePacket(b, f2);
    try testing.expectEqual(b, hub.mac_table.get(mac_x).?.session);
    try testing.expectEqual(@as(usize, 1), a.outbound.items.len);

    // Now a unicast to mac_x goes only to B (A gains no further frames).
    const f3 = try buildFrame(mac_x, mac_a, 0x0800, &.{});
    defer allocator.free(f3);
    hub.storePacket(a, f3);
    try testing.expectEqual(@as(usize, 2), b.outbound.items.len);
    try testing.expectEqual(@as(usize, 1), a.outbound.items.len);
}

test "server.hub packet to own mac is dropped" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const mac_a = macBytes("020000000001");

    // A sends to its own MAC → discarded, not echoed.
    const f = try buildFrame(mac_a, mac_a, 0x0800, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), a.outbound.items.len);
}

test "server.hub short and invalid-source frames dropped" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    hub.storePacket(a, "short");
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);

    // All-zero source MAC is invalid.
    const f = try buildFrame(macBytes("020000000002"), [6]u8{ 0, 0, 0, 0, 0, 0 }, 0x0800, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);
}

test "server.hub ip learning from ipv4 and arp" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const mac_a = macBytes("020000000001");

    // IPv4 frame with src IP 192.168.1.5 (bytes at offset 26..30).
    var ip_payload: [20]u8 = .{0x45} ** 20;
    mem.writeInt(u32, ip_payload[12..16], 0xc0a80105, .big);
    const f1 = try buildFrame(macBytes("020000000002"), mac_a, 0x0800, &ip_payload);
    defer allocator.free(f1);
    hub.storePacket(a, f1);
    try testing.expect(hub.ip_table.contains(0xc0a80105));
    try testing.expectEqual(a, hub.ip_table.get(0xc0a80105).?.session);

    // ARP frame with sender IP 10.0.0.9 (sender IP at offset 14+14=28).
    var arp_payload: [8]u8 = undefined;
    mem.writeInt(u16, arp_payload[0..2], 1, .big); // hw type ethernet
    mem.writeInt(u16, arp_payload[2..4], 0x0800, .big); // proto IPv4
    arp_payload[4] = 6; // hw size
    arp_payload[5] = 4; // proto size
    const f2 = try buildFrame(macBytes("020000000002"), mac_a, 0x0806, &arp_payload);
    defer allocator.free(f2);
    // ARP payload needs 18+ bytes for sender IP (offset 14+14). Extend it.
    const f2b = try allocator.alloc(u8, 14 + 18);
    defer allocator.free(f2b);
    @memcpy(f2b[0..6], &macBytes("020000000002"));
    @memcpy(f2b[6..12], &mac_a);
    mem.writeInt(u16, f2b[12..14], 0x0806, .big);
    @memcpy(f2b[14 .. 14 + 8], &arp_payload);
    mem.writeInt(u32, f2b[14 + 14 ..][0..4], 0x0a000009, .big);
    hub.storePacket(a, f2b);
    try testing.expect(hub.ip_table.contains(0x0a000009));
    try testing.expectEqual(a, hub.ip_table.get(0x0a000009).?.session);
}

test "server.hub mac table aging drops stale entries" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    const now = std.time.milliTimestamp();
    const f = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expect(hub.mac_table.contains(mac_a));

    // Age the entry past the expiry window and flush.
    hub.mac_table.getPtr(mac_a).?.updated = now - MAC_TABLE_EXPIRE_TIME - 1;
    const expired = hub.flushExpiredMac(now);
    try testing.expectEqual(@as(usize, 1), expired);
    try testing.expect(!hub.mac_table.contains(mac_a));

    // Unknown destination again → flood.
    const f2 = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 2), b.outbound.items.len);
}

test "server.hub queue capped at MAX_STORED_QUEUE_NUM" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();
    const mac_a = macBytes("020000000001");

    // Broadcasts flood to B; fill B's queue beyond the cap.
    for (0..MAX_STORED_QUEUE_NUM + 50) |_| {
        const f = try buildFrame(MAC_BROADCAST, mac_a, 0x0800, &.{0x77});
        defer allocator.free(f);
        hub.storePacket(a, f);
    }
    try testing.expectEqual(@as(usize, MAX_STORED_QUEUE_NUM), b.outbound.items.len);
}

test "server.hub broadcast storm limiter drops floods" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    hub.storm_threshold = 1; // any sustained flood rate triggers limiting
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();
    const mac_a = macBytes("020000000001");

    // C measures from the first packet (Hub.c:4017): one broadcast over the
    // 500ms window == 2/s, already over a threshold of 1, so it is dropped.
    const f1 = try buildFrame(MAC_BROADCAST, mac_a, 0x0800, &.{});
    defer allocator.free(f1);
    hub.storePacket(a, f1);
    const first_window_ok = b.outbound.items.len;
    try testing.expectEqual(@as(usize, 0), first_window_ok);

    // Directly raise the discard value (as a detected storm would) and verify
    // subsequent floods are refused.
    a.storm.discard_value = STORM_DISCARD_VALUE_START;
    a.storm.check_start_tick = std.time.milliTimestamp() - STORM_CHECK_SPAN - 1;

    const before = b.outbound.items.len;
    const f2 = try buildFrame(MAC_BROADCAST, mac_a, 0x0800, &.{});
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    // With discard_value=3 the packet survives with probability 1/3; loop many
    // times to observe drops and no deliveries when it discards.
    var delivered: usize = 0;
    for (0..100) |_| {
        const f = try buildFrame(MAC_BROADCAST, mac_a, 0x0800, &.{});
        defer allocator.free(f);
        const before_loop = b.outbound.items.len;
        hub.storePacket(a, f);
        if (b.outbound.items.len > before_loop) delivered += 1;
    }
    _ = before;
    // The limiter must have dropped at least some floods.
    try testing.expect(delivered < 100);
}

test "server.hub detached session frames are rejected" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();
    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    const f = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expect(hub.mac_table.contains(mac_a));

    // After detach, a late frame from the session must be rejected and must
    // not re-learn MAC/IP entries pointing at the detached adapter.
    hub.detach(a);
    const before = b.outbound.items.len;
    const f2 = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expect(!hub.mac_table.contains(mac_a));
    try testing.expectEqual(before, b.outbound.items.len);
    try testing.expect(hub.stats.dropped_frames > 0);
}

test "server.hub detach purges table entries" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();
    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    const f = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expect(hub.mac_table.contains(mac_a));

    hub.detach(a);
    try testing.expect(!hub.mac_table.contains(mac_a));
    try testing.expectEqual(@as(usize, 1), hub.sessionCount());
    try testing.expect(!a.attached);
}

// ============================================================================
// ACL integration tests
// ============================================================================

test "server.hub ACL discard rule blocks matching traffic" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // Add a rule: discard all TCP (protocol 6) traffic.
    _ = try hub.addAccessRule(.{
        .discard = true,
        .protocol = 6,
    });

    // TCP frame — should be discarded by ACL.
    var tcp_payload: [20]u8 = .{0} ** 20;
    tcp_payload[0] = 0x45; // IPv4 IHL
    tcp_payload[9] = 6; // protocol = TCP
    mem.writeInt(u32, tcp_payload[12..16], 0xc0a80101, .big); // src IP
    mem.writeInt(u32, tcp_payload[16..20], 0xc0a80102, .big); // dst IP
    const f = try buildFrame(mac_b, mac_a, 0x0800, &tcp_payload);
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);
    try testing.expect(hub.stats.dropped_frames > 0);

    // UDP frame — should pass (no matching rule).
    var udp_payload: [20]u8 = .{0} ** 20;
    udp_payload[0] = 0x45;
    udp_payload[9] = 17; // protocol = UDP
    mem.writeInt(u32, udp_payload[12..16], 0xc0a80101, .big);
    mem.writeInt(u32, udp_payload[16..20], 0xc0a80102, .big);
    const f2 = try buildFrame(mac_b, mac_a, 0x0800, &udp_payload);
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}

test "server.hub ACL pass rule allows matching traffic" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // Rule: pass all traffic from 192.168.1.0/24 (src IP match).
    _ = try hub.addAccessRule(.{
        .discard = false,
        .src_ip = (192 << 24) | (168 << 16) | (1 << 8) | 0,
        .src_mask = 0xFFFFFF00,
    });

    // Frame from 192.168.1.1 — matches the pass rule.
    var payload: [20]u8 = .{0} ** 20;
    payload[0] = 0x45;
    mem.writeInt(u32, payload[12..16], 0xc0a80101, .big);
    mem.writeInt(u32, payload[16..20], 0xc0a80102, .big);
    const f = try buildFrame(mac_b, mac_a, 0x0800, &payload);
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}

test "server.hub hub filters discard PPPoE" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    hub.setFilters(.{ .filter_pppoe = true });

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // PPPoE frame (EtherType 0x8863) — should be dropped.
    const f = try buildFrame(mac_b, mac_a, 0x8863, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);

    // Normal IPv4 frame — should pass.
    const f2 = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}

test "server.hub hub filters discard OSPF" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    hub.setFilters(.{ .filter_ospf = true });

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // OSPF frame (IPv4 protocol 89) — should be dropped.
    var payload: [20]u8 = .{0} ** 20;
    payload[0] = 0x45;
    payload[9] = 89; // OSPF
    mem.writeInt(u32, payload[12..16], 0xc0a80101, .big);
    mem.writeInt(u32, payload[16..20], 0xc0a80102, .big);
    const f = try buildFrame(mac_b, mac_a, 0x0800, &payload);
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);

    // TCP frame — should pass.
    payload[9] = 6;
    const f2 = try buildFrame(mac_b, mac_a, 0x0800, &payload);
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}

test "server.hub hub filters discard IPv4" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    hub.setFilters(.{ .filter_ipv4 = true });

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // IPv4 frame — dropped.
    const f = try buildFrame(mac_b, mac_a, 0x0800, &.{});
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);

    // ARP frame — also dropped (filter_ipv4 includes ARP).
    const f2 = try buildFrame(mac_b, mac_a, 0x0806, &.{});
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);

    // IPv6 frame — should pass.
    const f3 = try buildFrame(mac_b, mac_a, 0x86DD, &.{});
    defer allocator.free(f3);
    hub.storePacket(a, f3);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}

test "server.hub ACL remove drops existing rule" {
    const allocator = testing.allocator;
    const hub = try makeHub();
    defer hub.deinit();
    const a = try makePa(hub, "A");
    defer a.deinit();
    const b = try makePa(hub, "B");
    defer b.deinit();

    const mac_a = macBytes("020000000001");
    const mac_b = macBytes("020000000002");

    // Add a discard rule.
    const rule_id = try hub.addAccessRule(.{ .discard = true, .protocol = 6 });
    try testing.expectEqual(@as(usize, 1), hub.accessRuleCount());

    // TCP frame — dropped.
    var payload: [20]u8 = .{0} ** 20;
    payload[0] = 0x45;
    payload[9] = 6;
    const f = try buildFrame(mac_b, mac_a, 0x0800, &payload);
    defer allocator.free(f);
    hub.storePacket(a, f);
    try testing.expectEqual(@as(usize, 0), b.outbound.items.len);

    // Remove the rule.
    try testing.expect(hub.removeAccessRule(rule_id));
    try testing.expectEqual(@as(usize, 0), hub.accessRuleCount());

    // TCP frame — now passes.
    const f2 = try buildFrame(mac_b, mac_a, 0x0800, &payload);
    defer allocator.free(f2);
    hub.storePacket(a, f2);
    try testing.expectEqual(@as(usize, 1), b.outbound.items.len);
}
