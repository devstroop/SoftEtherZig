//! Monitor role (L2 Network Bridge proposal §5.4, H-4; issue #55).
//!
//! Passive capture of session L2 frames: a bounded ring (default 4096
//! frames, drop-and-count on overflow) plus an optional PCAP file writer.
//! Mirror-only — the monitor never emits frames to a NIC or into the
//! session (I-8 pump family, mirror variant). Doubles as the validator
//! for the bridge data path: if the monitor ring fills with frames from
//! the hub, the session is carrying L2 traffic.
//!
//! Protocol wiring (H-4): monitor mode must pack `require_monitor_mode=true`
//! at auth time — otherwise the server never sets up a monitor session and
//! the client would only observe its own session traffic. The pump (in
//! vpn_client.zig) owns the TunnelConnection and calls `capture()` for every
//! inbound block.

const std = @import("std");

/// Must match `adapter/af_packet.zig`'s session L2 frame budget.
pub const SESSION_FRAME_BUDGET: usize = 1514;

/// Default ring capacity in frames.
pub const DEFAULT_RING_CAPACITY: u32 = 4096;

/// Ring frame slot (frame data is heap-allocated per frame).
const FrameSlot = struct {
    data: ?[]u8 = null,
};

/// Bounded ring mirroring session L2 frames. When full, new frames are
/// dropped and counted (`frames_dropped`) — never evicts old captures.
pub const MonitorRing = struct {
    allocator: std.mem.Allocator,
    capacity: u32,
    head: u32 = 0,
    count: u32 = 0,
    slots: []FrameSlot,

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !MonitorRing {
        if (capacity == 0) return error.EmptyRingCapacity;
        const slots = try allocator.alloc(FrameSlot, capacity);
        // alloc() leaves memory undefined — a partially filled ring must
        // still have well-defined slots, otherwise deinit() frees garbage
        // optionals (review #119, critical).
        for (slots) |*slot| slot.* = .{};
        return .{
            .allocator = allocator,
            .capacity = capacity,
            .slots = slots,
        };
    }

    pub fn deinit(self: *MonitorRing) void {
        for (self.slots) |*slot| {
            if (slot.data) |d| self.allocator.free(d);
        }
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn isEmpty(self: *const MonitorRing) bool {
        return self.count == 0;
    }

    /// Frames currently held.
    pub fn used(self: *const MonitorRing) u32 {
        return self.count;
    }

    /// Append a frame. Returns false (and counts a drop) when full.
    pub fn push(self: *MonitorRing, frame: []const u8) bool {
        if (self.count == self.capacity) return false;
        const copy = self.allocator.dupe(u8, frame) catch return false;
        const idx = (self.head + self.count) % self.capacity;
        self.slots[idx].data = copy;
        self.count += 1;
        return true;
    }

    /// Iterate stored frames oldest → newest. Caller frees nothing.
    pub fn iterator(self: *const MonitorRing) RingIterator {
        return .{ .ring = self, .pos = 0 };
    }
};

pub const RingIterator = struct {
    ring: *const MonitorRing,
    pos: u32 = 0,

    pub fn next(self: *RingIterator) ?[]const u8 {
        if (self.pos >= self.ring.count) return null;
        const idx = (self.ring.head + self.pos) % self.ring.capacity;
        self.pos += 1;
        return self.ring.slots[idx].data.?;
    }
};

/// Aggregate monitor stats (FFI `softether_get_monitor_stats`).
pub const MonitorStats = struct {
    /// Frames mirrored into the ring (== captured from the session).
    frames_captured: u64 = 0,
    /// Frames dropped because the ring was full (drop-and-count).
    frames_dropped: u64 = 0,
    /// Payload bytes captured.
    bytes_captured: u64 = 0,
    /// Ring slots currently in use.
    ring_used: u32 = 0,
    /// PCAP records written to the file.
    pcap_records: u64 = 0,
    /// PCAP record bytes (headers + frames) written.
    pcap_bytes: u64 = 0,
    /// PCAP write failures (I/O error, disk full, closed file).
    pcap_write_errors: u64 = 0,
};

/// Minimal pcap file writer (global header + Ethernet records).
/// Written little-endian for portable readability (magic 0xa1b2c3d4).
pub const PcapWriter = struct {
    file: std.fs.File,
    records: u64 = 0,
    bytes: u64 = 0,
    write_errors: u64 = 0,
    /// Set after a record is interrupted mid-payload: blocks future
    /// appends so the capture never mixes partial records with valid ones.
    faulted: bool = false,

    pub const GLOBAL_HEADER_LEN = 24;
    pub const RECORD_HEADER_LEN = 16;
    pub const LINKTYPE_ETHERNET: u32 = 1;

    /// Create (or truncate) the capture file and write the global header.
    pub fn create(path: []const u8) !PcapWriter {
        const file = try std.fs.cwd().createFile(path, .{
            .truncate = true,
            .read = true,
        });
        errdefer file.close();

        var w = PcapWriter{ .file = file };
        try w.writeGlobalHeader();
        return w;
    }

    fn writeGlobalHeader(self: *PcapWriter) !void {
        var buf: [GLOBAL_HEADER_LEN]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], 0xa1b2c3d4, .little);
        std.mem.writeInt(u16, buf[4..6], 2, .little); // version major
        std.mem.writeInt(u16, buf[6..8], 4, .little); // version minor
        std.mem.writeInt(i32, buf[8..12], 0, .little); // thiszone
        std.mem.writeInt(u32, buf[12..16], 0, .little); // sigfigs
        std.mem.writeInt(u32, buf[16..20], @intCast(SESSION_FRAME_BUDGET), .little); // snaplen
        std.mem.writeInt(u32, buf[20..24], LINKTYPE_ETHERNET, .little);
        try self.file.writeAll(&buf);
        self.bytes += GLOBAL_HEADER_LEN;
    }

    /// Append one Ethernet frame as a pcap record. Failures are counted,
    /// never fatal.
    pub fn writeFrame(self: *PcapWriter, frame: []const u8) void {
        if (self.faulted) {
            // A previous record was interrupted mid-write and the file was
            // truncated back to the last good boundary — appending now
            // would corrupt the capture structure, so keep rejecting.
            self.write_errors += 1;
            return;
        }
        const rec_start = self.bytes;
        var hdr: [RECORD_HEADER_LEN]u8 = undefined;
        const ts = std.time.microTimestamp();
        const ts_sec: u32 = @truncate(@as(u64, @intCast(@max(ts, 0))) / 1_000_000);
        const ts_usec: u32 = @truncate(@as(u64, @intCast(@max(ts, 0))) % 1_000_000);
        const incl_len: u32 = @intCast(frame.len);
        std.mem.writeInt(u32, hdr[0..4], ts_sec, .little);
        std.mem.writeInt(u32, hdr[4..8], ts_usec, .little);
        std.mem.writeInt(u32, hdr[8..12], incl_len, .little);
        std.mem.writeInt(u32, hdr[12..16], incl_len, .little);
        self.file.writeAll(&hdr) catch {
            self.write_errors += 1;
            return;
        };
        self.file.writeAll(frame) catch {
            self.write_errors += 1;
            // Partial record: truncate back to the last good record
            // boundary so the file stays parseable, then stop appending
            // (subsequent records would be misaligned) (review #119).
            self.file.setEndPos(rec_start) catch {};
            self.faulted = true;
            return;
        };
        self.records += 1;
        self.bytes += RECORD_HEADER_LEN + frame.len;
    }

    pub fn close(self: *PcapWriter) void {
        self.file.close();
    }
};

/// The monitor pump state: ring + optional PCAP writer + counters.
pub const MonitorLoop = struct {
    allocator: std.mem.Allocator,
    ring: MonitorRing,
    pcap: ?PcapWriter = null,
    stats: MonitorStats = .{},

    /// Serializes the pump thread (`capture`) against FFI readers
    /// (`frameCount` / `readFrame`). init returns the loop by value while
    /// unlocked, so the default copy is safe; after init the loop is only
    /// ever used through pointers.
    mutex: std.Thread.Mutex = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        ring_capacity: u32,
        pcap_path: ?[]const u8,
    ) !MonitorLoop {
        var loop = MonitorLoop{
            .allocator = allocator,
            .ring = try MonitorRing.init(allocator, ring_capacity),
        };
        errdefer loop.ring.deinit();
        if (pcap_path) |path| {
            loop.pcap = try PcapWriter.create(path);
        }
        return loop;
    }

    pub fn deinit(self: *MonitorLoop) void {
        if (self.pcap) |*p| p.close();
        self.ring.deinit();
        self.* = undefined;
    }

    /// Mirror one session L2 frame: ring + PCAP (if configured).
    pub fn capture(self: *MonitorLoop, frame: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (frame.len > SESSION_FRAME_BUDGET) return; // H-3: budget clamp
        if (self.ring.push(frame)) {
            self.stats.frames_captured += 1;
            self.stats.bytes_captured += frame.len;
        } else {
            self.stats.frames_dropped += 1;
        }
        if (self.pcap) |*p| {
            p.writeFrame(frame);
            self.stats.pcap_records = p.records;
            self.stats.pcap_bytes = p.bytes;
            self.stats.pcap_write_errors = p.write_errors;
        }
    }

    /// Live cumulative stats snapshot (fields tracked in exactly one place,
    /// so repeated polling never inflates).
    pub fn getStats(self: *MonitorLoop) MonitorStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        var s = self.stats;
        s.ring_used = self.ring.used();
        return s;
    }

    /// Frames currently held in the ring (thread-safe FFI snapshot).
    pub fn frameCount(self: *MonitorLoop) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.ring.used();
    }

    /// Copy one stored frame (0 = oldest) into `dst`. Returns the byte
    /// count written, or null when `index` is out of range.
    pub fn readFrame(self: *MonitorLoop, index: u32, dst: []u8) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.ring.count) return null;
        const idx = (self.ring.head + index) % self.ring.capacity;
        const frame = self.ring.slots[idx].data.?;
        const n = @min(frame.len, dst.len);
        @memcpy(dst[0..n], frame[0..n]);
        return n;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "monitor ring: bounded, drop-and-count on overflow" {
    var ring = try MonitorRing.init(testing.allocator, 3);
    defer ring.deinit();

    const f1 = "frame-one";
    const f2 = "frame-two";
    const f3 = "frame-three";
    const f4 = "frame-four";

    try testing.expect(ring.push(f1));
    try testing.expect(ring.push(f2));
    try testing.expect(ring.push(f3));
    try testing.expectEqual(@as(u32, 3), ring.used());

    // Full → new frames dropped, oldest captures retained.
    try testing.expect(!ring.push(f4));
    try testing.expectEqual(@as(u32, 3), ring.used());

    var it = ring.iterator();
    try testing.expectEqualStrings(f1, it.next().?);
    try testing.expectEqualStrings(f2, it.next().?);
    try testing.expectEqualStrings(f3, it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "monitor ring: wraps past head" {
    var ring = try MonitorRing.init(testing.allocator, 2);
    defer ring.deinit();
    try ring.push("a");
    try ring.push("b");
    try ring.push("c"); // full — dropped (no eviction)
    try testing.expectEqual(@as(u32, 2), ring.used());
    var it = ring.iterator();
    try testing.expectEqualStrings("a", it.next().?);
    try testing.expectEqualStrings("b", it.next().?);
}

test "pcap writer: global header + Ethernet records, tcpdump-readable shape" {
    const path = "zig-cache-test-monitor.pcap";
    defer std.fs.cwd().deleteFile(path) catch {};

    var w = try PcapWriter.create(path);
    const f1 = [_]u8{0xAA} ** 64;
    const f2 = [_]u8{0xBB} ** 128;
    w.writeFrame(&f1);
    w.writeFrame(&f2);
    try testing.expectEqual(@as(u64, 2), w.records);
    try testing.expectEqual(@as(u64, 24 + 16 + 64 + 16 + 128), w.bytes);
    w.close();

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const size = (try file.stat()).size;
    try testing.expectEqual(@as(u64, 24 + 16 + 64 + 16 + 128), size);

    var buf: [24 + 16]u8 = undefined;
    _ = try file.readAll(&buf);
    // Magic + version + linktype (little-endian).
    try testing.expectEqual(@as(u32, 0xa1b2c3d4), std.mem.readInt(u32, buf[0..4], .little));
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, buf[4..6], .little));
    try testing.expectEqual(@as(u16, 4), std.mem.readInt(u16, buf[6..8], .little));
    try testing.expectEqual(@as(u32, 1514), std.mem.readInt(u32, buf[16..20], .little)); // snaplen
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, buf[20..24], .little)); // LINKTYPE_ETHERNET
    // First record header: incl/orig len == 64.
    try testing.expectEqual(@as(u32, 64), std.mem.readInt(u32, buf[24..28], .little));
    try testing.expectEqual(@as(u32, 64), std.mem.readInt(u32, buf[28..32], .little));
}

test "monitor loop: capture counts, budget clamp, overflow" {
    var loop = try MonitorLoop.init(testing.allocator, 2, null);
    defer loop.deinit();

    loop.capture(&[_]u8{1} ** 100);
    loop.capture(&[_]u8{2} ** 100);
    loop.capture(&[_]u8{3} ** 100); // full → dropped
    loop.capture(&[_]u8{4} ** (SESSION_FRAME_BUDGET + 1)); // H-3 clamp

    const s = loop.getStats();
    try testing.expectEqual(@as(u64, 2), s.frames_captured);
    try testing.expectEqual(@as(u64, 1), s.frames_dropped);
    try testing.expectEqual(@as(u64, 200), s.bytes_captured);
    try testing.expectEqual(@as(u32, 2), s.ring_used);
    try testing.expectEqual(@as(u64, 0), s.pcap_records);

    // FFI-facing accessors: count + oldest-first indexed reads.
    try testing.expectEqual(@as(u32, 2), loop.frameCount());
    var buf: [256]u8 = undefined;
    const n0 = loop.readFrame(0, &buf).?;
    try testing.expectEqual(@as(usize, 100), n0);
    try testing.expectEqual(@as(u8, 1), buf[0]);
    const n1 = loop.readFrame(1, buf[0..64]).?; // truncated copy
    try testing.expectEqual(@as(usize, 64), n1);
    try testing.expectEqual(@as(u8, 2), buf[0]);
    try testing.expect(loop.readFrame(2, &buf) == null); // out of range
}
