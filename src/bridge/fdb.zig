//! MAC learning table for the L2 bridge engine (proposal §4.3).
//!
//! Hash-based MAC → port mapping with aging. Pure logic, no I/O — fully
//! unit-testable with an injected clock (deterministic, no timing flakiness).
//!
//! Behavior:
//! - `lookup(mac)` → the port a MAC was last seen on, or null (unknown →
//!   flood by the engine).
//! - `learn(mac, port, now)` → create or refresh an entry. A MAC seen on a
//!   different port moves (re-learn on move).
//! - `age(now)` → drop entries idle for longer than `aging_s`. Called on the
//!   bridge loop tick.
//! - `max_entries` overflow → table drops new entries (`learn` returns
//!   `error.TableFull`) and the engine floods instead (proposal §4.3).

const std = @import("std");

/// Default aging timeout for FDB entries (proposal §4.3).
pub const DEFAULT_AGING_S: u32 = 300;

/// Default maximum number of FDB entries (proposal §4.3).
pub const DEFAULT_MAX_ENTRIES: u32 = 4096;

/// MAC address type — 6 bytes, compares by value.
pub const MacAddress = [6]u8;

/// One learned entry: which port a MAC was last seen on, and when.
pub const FdbEntry = struct {
    mac: MacAddress,
    port: u16,
    /// Last-seen tick (seconds). Aging compares `now - last_seen`.
    last_seen: u32,
    /// VLAN ID. 0 = untagged (default, backward-compatible).
    vlan_id: u16 = 0,
};

/// Hash-based MAC → port table.
///
/// Storage: fixed-size open-addressing table with linear probing, sized to
/// `max_entries`. `entries` is the live count; `age()` recompacts on demand.
/// The table is not thread-safe — the bridge loop is the only mutator (it
/// owns both the FDB and the engine).
pub const FdbTable = struct {
    /// Live entries in the hash table. Tombstone-free deletion via
    /// `last_seen == 0` sentinel? No — a real entry can legitimately have
    /// last_seen 0 at epoch start. We use a separate `occupied` bit instead.
    slots: []Slot,
    occupied: []bool,
    /// Insertion order ring for overflow eviction (FIFO).
    order: []OrderKey,
    order_len: usize = 0,
    order_head: usize = 0,
    /// Number of live entries.
    count: usize = 0,
    /// Aging timeout in seconds.
    aging_s: u32 = DEFAULT_AGING_S,
    /// Max live entries before `learn` returns `error.TableFull`.
    max_entries: usize = DEFAULT_MAX_ENTRIES,
    allocator: std.mem.Allocator,

    const Slot = struct {
        mac: MacAddress,
        port: u16,
        last_seen: u32,
        vlan_id: u16,
    };

    /// Composite key for the order ring (MAC + VLAN).
    const OrderKey = struct {
        mac: MacAddress,
        vlan_id: u16,
    };

    /// Initialize with the default capacity (`DEFAULT_MAX_ENTRIES`).
    pub fn init(allocator: std.mem.Allocator) !FdbTable {
        return initCapacity(allocator, DEFAULT_MAX_ENTRIES);
    }

    /// Initialize with a custom capacity. `capacity` becomes `max_entries`.
    pub fn initCapacity(allocator: std.mem.Allocator, capacity: usize) !FdbTable {
        if (capacity == 0) return error.InvalidCapacity;
        const slots = try allocator.alloc(Slot, capacity);
        errdefer allocator.free(slots);
        const occupied = try allocator.alloc(bool, capacity);
        errdefer allocator.free(occupied);
        @memset(occupied, false);
        const order = try allocator.alloc(OrderKey, capacity);
        errdefer allocator.free(order);
        return .{
            .slots = slots,
            .occupied = occupied,
            .order = order,
            .allocator = allocator,
            .max_entries = capacity,
        };
    }

    pub fn deinit(self: *FdbTable) void {
        self.allocator.free(self.slots);
        self.allocator.free(self.occupied);
        self.allocator.free(self.order);
        self.* = undefined;
    }

    fn hash(mac: MacAddress, vlan_id: u16) u64 {
        // FNV-1a over the 6 MAC bytes + 2-byte VLAN ID; spread via mixing
        // so a burst of same-vendor MACs (identical OUI) does not cluster.
        var h: u64 = 0xcbf29ce484222325;
        for (mac) |b| {
            h = (h ^ b) *% 0x100000001b3;
        }
        // Include VLAN ID in the hash.
        h = (h ^ (vlan_id & 0xFF)) *% 0x100000001b3;
        h = (h ^ (@as(u64, vlan_id) >> 8)) *% 0x100000001b3;
        // final avalanche
        h ^= h >> 33;
        h *%= 0xff51afd7ed558ccd;
        h ^= h >> 33;
        return h;
    }

    fn probeStart(mac: MacAddress, vlan_id: u16, cap: usize) usize {
        return @intCast(hash(mac, vlan_id) % cap);
    }

    /// Find the slot index for `mac`+`vlan_id` if present. Linear probe
    /// bounded by the table size; returns null when absent.
    fn findSlot(self: *const FdbTable, mac: MacAddress, vlan_id: u16) ?usize {
        var i = probeStart(mac, vlan_id, self.slots.len);
        for (0..self.slots.len) |_| {
            if (!self.occupied[i]) return null;
            if (self.slots[i].vlan_id == vlan_id and std.mem.eql(u8, &self.slots[i].mac, &mac)) return i;
            i = (i + 1) % self.slots.len;
        }
        return null;
    }

    /// Look up the port a MAC was last seen on (VLAN-aware).
    pub fn lookup(self: *const FdbTable, mac: MacAddress, vlan_id: u16) ?u16 {
        const idx = self.findSlot(mac, vlan_id) orelse return null;
        return self.slots[idx].port;
    }

    /// Legacy lookup: treats untagged (vlan_id=0) as the default.
    pub fn lookupUntagged(self: *const FdbTable, mac: MacAddress) ?u16 {
        return self.lookup(mac, 0);
    }

    /// Learn (create or refresh) an entry. `now` is seconds since an
    /// arbitrary epoch (the bridge loop's injected clock).
    ///
    /// Returns `error.TableFull` when the table is at capacity and no
    /// existing entry can be reused — the engine floods the frame instead.
    pub fn learn(self: *FdbTable, mac: MacAddress, port: u16, now: u32) FdbError!void {
        return self.learnVlan(mac, port, now, 0);
    }

    /// Learn with explicit VLAN ID.
    pub fn learnVlan(self: *FdbTable, mac: MacAddress, port: u16, now: u32, vlan_id: u16) FdbError!void {
        if (self.findSlot(mac, vlan_id)) |idx| {
            // Refresh or re-learn on move.
            self.slots[idx].port = port;
            self.slots[idx].last_seen = now;
            self.touchOrder(mac, vlan_id);
            return;
        }

        if (self.count >= self.max_entries) {
            // Overflow: evict the oldest learned MAC (FIFO) to keep the
            // bridge working under churn; the engine floods while full.
            self.evictOldest();
        }

        var i = probeStart(mac, vlan_id, self.slots.len);
        for (0..self.slots.len) |_| {
            if (!self.occupied[i]) {
                self.slots[i] = .{ .mac = mac, .port = port, .last_seen = now, .vlan_id = vlan_id };
                self.occupied[i] = true;
                self.count += 1;
                self.appendOrder(mac, vlan_id);
                return;
            }
            i = (i + 1) % self.slots.len;
        }
        return error.TableFull;
    }

    /// Remove entries idle longer than `aging_s`. Returns how many were
    /// aged out (useful for diagnostics).
    pub fn age(self: *FdbTable, now: u32) usize {
        var aged: usize = 0;
        for (self.occupied, 0..) |occ, i| {
            if (!occ) continue;
            if (now - self.slots[i].last_seen > self.aging_s) {
                self.occupied[i] = false;
                self.count -= 1;
                aged += 1;
            }
        }
        if (aged > 0) self.rebuildOrder();
        return aged;
    }

    /// Number of live entries.
    pub fn len(self: *const FdbTable) usize {
        return self.count;
    }

    // ---- order ring bookkeeping ----

    fn appendOrder(self: *FdbTable, mac: MacAddress, vlan_id: u16) void {
        const key = OrderKey{ .mac = mac, .vlan_id = vlan_id };
        if (self.order_len < self.order.len) {
            self.order[self.order_len] = key;
            self.order_len += 1;
        } else {
            // Ring full (count == capacity): overwrite the head.
            self.order[self.order_head] = key;
            self.order_head = (self.order_head + 1) % self.order.len;
        }
    }

    fn touchOrder(self: *FdbTable, mac: MacAddress, vlan_id: u16) void {
        // Move an existing entry to the tail (most-recent). Linear scan is
        // fine: order ring is bounded by max_entries and only touched on
        // learns.
        var found: ?usize = null;
        var i: usize = 0;
        while (i < self.order_len) : (i += 1) {
            if (self.order[i].vlan_id == vlan_id and std.mem.eql(u8, &self.order[i].mac, &mac)) {
                found = i;
                break;
            }
        }
        const idx = found orelse return;
        const key = OrderKey{ .mac = mac, .vlan_id = vlan_id };
        if (self.order_len < self.order.len) {
            // Shift down and append.
            var j = idx;
            while (j + 1 < self.order_len) : (j += 1) {
                self.order[j] = self.order[j + 1];
            }
            self.order[self.order_len - 1] = key;
        } else {
            // Ring full: rotate so the touched MAC lands at tail.
            const tail = (self.order_head + self.order.len - 1) % self.order.len;
            var cursor = idx;
            while (cursor != tail) {
                const next = (cursor + 1) % self.order.len;
                self.order[cursor] = self.order[next];
                cursor = next;
            }
            self.order[tail] = key;
        }
    }

    fn evictOldest(self: *FdbTable) void {
        if (self.order_len == 0) return;
        const victim_key = if (self.order_len < self.order.len) self.order[0] else self.order[self.order_head];
        if (self.findSlot(victim_key.mac, victim_key.vlan_id)) |idx| {
            self.occupied[idx] = false;
            self.count -= 1;
        }
        // Compact the order ring.
        if (self.order_len < self.order.len) {
            var j: usize = 1;
            while (j < self.order_len) : (j += 1) {
                self.order[j - 1] = self.order[j];
            }
            self.order_len -= 1;
        } else {
            self.order_head = (self.order_head + 1) % self.order.len;
        }
    }

    /// After aging deleted slots, rebuild the order ring from live entries.
    fn rebuildOrder(self: *FdbTable) void {
        var out: usize = 0;
        for (self.occupied, 0..) |occ, i| {
            if (!occ) continue;
            self.order[out] = .{ .mac = self.slots[i].mac, .vlan_id = self.slots[i].vlan_id };
            out += 1;
        }
        self.order_len = out;
        self.order_head = 0;
    }
};

pub const FdbError = error{TableFull};

// ============================================================================
// Tests
// ============================================================================

fn makeMac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) MacAddress {
    return .{ a, b, c, d, e, f };
}

test "fdb learn + lookup + refresh" {
    var t = try FdbTable.init(std.testing.allocator);
    defer t.deinit();

    try t.learn(makeMac(1, 2, 3, 4, 5, 6), 1, 100);
    try std.testing.expectEqual(@as(?u16, 1), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 0));
    try std.testing.expectEqual(@as(usize, 1), t.len());

    // Refresh extends the entry; port unchanged.
    try t.learn(makeMac(1, 2, 3, 4, 5, 6), 1, 400);
    try std.testing.expectEqual(@as(usize, 1), t.len());
    try std.testing.expectEqual(@as(?u16, 1), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 0));
}

test "fdb aging drops idle entries, keeps fresh" {
    var t = try FdbTable.init(std.testing.allocator);
    defer t.deinit();
    t.aging_s = 300;

    try t.learn(makeMac(1, 1, 1, 1, 1, 1), 1, 0);
    try t.learn(makeMac(2, 2, 2, 2, 2, 2), 2, 100);

    // At t=350: entry 1 (seen 0) is 350s old → aged; entry 2 (seen 100) is 250s old → kept.
    const aged = t.age(350);
    try std.testing.expectEqual(@as(usize, 1), aged);
    try std.testing.expectEqual(@as(?u16, null), t.lookup(makeMac(1, 1, 1, 1, 1, 1), 0));
    try std.testing.expectEqual(@as(?u16, 2), t.lookup(makeMac(2, 2, 2, 2, 2, 2), 0));
    try std.testing.expectEqual(@as(usize, 1), t.len());

    // Exactly at the boundary (aging_s elapsed) is still fresh.
    try t.learn(makeMac(1, 1, 1, 1, 1, 1), 1, 350);
    _ = t.age(650);
    try std.testing.expectEqual(@as(?u16, 1), t.lookup(makeMac(1, 1, 1, 1, 1, 1), 0));
}

test "fdb overflow floods via TableFull after evicting oldest" {
    var t = try FdbTable.initCapacity(std.testing.allocator, 3);
    defer t.deinit();

    try t.learn(makeMac(1, 0, 0, 0, 0, 0), 1, 10);
    try t.learn(makeMac(2, 0, 0, 0, 0, 0), 1, 20);
    try t.learn(makeMac(3, 0, 0, 0, 0, 0), 1, 30);
    try std.testing.expectEqual(@as(usize, 3), t.len());

    // Fourth learn: evicts oldest (1,0,0,0,0,0), inserts new.
    try t.learn(makeMac(4, 0, 0, 0, 0, 0), 2, 40);
    try std.testing.expectEqual(@as(usize, 3), t.len());
    try std.testing.expectEqual(@as(?u16, null), t.lookup(makeMac(1, 0, 0, 0, 0, 0), 0));
    try std.testing.expectEqual(@as(?u16, 2), t.lookup(makeMac(4, 0, 0, 0, 0, 0), 0));
}

test "fdb re-learn on move (port flip)" {
    var t = try FdbTable.init(std.testing.allocator);
    defer t.deinit();

    try t.learn(makeMac(1, 2, 3, 4, 5, 6), 1, 10);
    try t.learn(makeMac(1, 2, 3, 4, 5, 6), 3, 20);
    try std.testing.expectEqual(@as(?u16, 3), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 0));
    try std.testing.expectEqual(@as(usize, 1), t.len());
}

test "fdb VLAN-aware: same MAC on different VLANs are separate entries" {
    var t = try FdbTable.init(std.testing.allocator);
    defer t.deinit();

    try t.learnVlan(makeMac(1, 2, 3, 4, 5, 6), 1, 10, 100);
    try t.learnVlan(makeMac(1, 2, 3, 4, 5, 6), 2, 20, 200);

    try std.testing.expectEqual(@as(?u16, 1), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 100));
    try std.testing.expectEqual(@as(?u16, 2), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 200));
    try std.testing.expectEqual(@as(?u16, null), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 300));
    try std.testing.expectEqual(@as(usize, 2), t.len());
}

test "fdb VLAN-aware: refresh within same VLAN keeps entry" {
    var t = try FdbTable.init(std.testing.allocator);
    defer t.deinit();

    try t.learnVlan(makeMac(1, 2, 3, 4, 5, 6), 1, 10, 100);
    try t.learnVlan(makeMac(1, 2, 3, 4, 5, 6), 3, 20, 100); // same VLAN, port move

    try std.testing.expectEqual(@as(?u16, 3), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 100));
    try std.testing.expectEqual(@as(usize, 1), t.len());
}

test "fdb VLAN-aware: aging is VLAN-aware" {
    var t = try FdbTable.init(std.testing.allocator);
    defer t.deinit();
    t.aging_s = 300;

    try t.learnVlan(makeMac(1, 2, 3, 4, 5, 6), 1, 0, 100);
    try t.learnVlan(makeMac(1, 2, 3, 4, 5, 6), 2, 0, 200); // same MAC, different VLAN

    const aged = t.age(350);
    try std.testing.expectEqual(@as(usize, 2), aged);
    try std.testing.expectEqual(@as(?u16, null), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 100));
    try std.testing.expectEqual(@as(?u16, null), t.lookup(makeMac(1, 2, 3, 4, 5, 6), 200));
}