//! Outbound-only NAT engine — per-flow state, outbound sockets (issue #94).
//!
//! C reference: `Virtual.c` `NnNewNatIcmp`, `NnNewNatUdp`, `NnNewNatTcp`,
//! `NnGetNatEntryForRecv`, `NnGetNatEntryForSend`, `NnDeleteSession`.
//!
//! Scope (M3):
//!   - Outbound-only (most common SOHO case).
//!   - TCP/UDP/ICMP endpoints backed by real outbound sockets.
//!   - No inbound port-mapping (deferred to M4).
//!   - No full userspace TCP/IP stack — NAT state per flow, no reassembly.
//!
//! Thread-safety: the `NatEngine.mutex` guards the entry tables, counters,
//! and public-IP cache. Per-entry socket I/O is single-threaded (each entry
//! owns its socket).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const ip_mod = @import("../../mayaqua/kernel/ip.zig");
const types_mod = @import("../../mayaqua/kernel/types.zig");

const log = std.log.scoped(.cedar_nat);

// ============================================================================
// Constants (C: Virtual.h / Nat.c)
// ============================================================================

/// Maximum concurrent NAT entries (C: `MAX_NAT_ENTRIES` = 65536).
pub const MAX_NAT_ENTRIES: u32 = 65536;
/// Default TCP NAT session timeout (ms) (C: `NAT_TCP_TIMEOUT` = 300s).
pub const NAT_TCP_TIMEOUT_MS: i64 = 300_000;
/// Default UDP NAT session timeout (ms) (C: `NAT_UDP_TIMEOUT` = 30s).
pub const NAT_UDP_TIMEOUT_MS: i64 = 30_000;
/// Default ICMP NAT session timeout (ms) (C: `NAT_ICMP_TIMEOUT` = 30s).
pub const NAT_ICMP_TIMEOUT_MS: i64 = 30_000;
/// Cleanup sweep interval (ms) (C: `NAT_TABLE_CHECK_INTERVAL` = 1s).
pub const NAT_SWEEP_INTERVAL_MS: i64 = 1_000;
/// Maximum TCP connect timeout (ms) (C: `NAT_TCP_CONNECT_TIMEOUT` = 10s).
pub const NAT_TCP_CONNECT_TIMEOUT_MS: i64 = 10_000;
/// Maximum pending outbound connections (C: `NAT_MAX_CONNECT_QUEUE` = 256).
pub const NAT_MAX_CONNECT_QUEUE: u32 = 256;

// ============================================================================
// Protocol constants
// ============================================================================

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

// ============================================================================
// NAT entry status (C: Virtual.h STATUS_*)
// ============================================================================

pub const NatStatus = enum(u8) {
    /// TCP: SYN sent, awaiting SYN-ACK.
    connecting = 0,
    /// TCP: connected, data flowing.
    established = 1,
    /// Entry is closing (FIN sent or timeout).
    closing = 2,
    /// ICMP/UDP: active.
    active = 3,
};

// ============================================================================
// Error sets for packet forwarding / receive stubs
// ============================================================================

pub const ForwardError = error{
    /// Stub — not yet implemented in this PR.
    NotYetImplemented,
};

pub const ReceiveError = error{
    /// Stub — not yet implemented in this PR.
    NotYetImplemented,
};

// ============================================================================
// Flow key — identifies a unique NAT flow
// ============================================================================

pub const FlowKey = struct {
    src_ip: u32,
    src_port: u16,
    dest_ip: u32,
    dest_port: u16,
    protocol: u8,

    pub fn hash(self: FlowKey) u64 {
        var h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
        const bytes = [_]u8{
            @truncate(self.src_ip >> 0),
            @truncate(self.src_ip >> 8),
            @truncate(self.src_ip >> 16),
            @truncate(self.src_ip >> 24),
            @truncate(self.src_port >> 0),
            @truncate(self.src_port >> 8),
            @truncate(self.dest_ip >> 0),
            @truncate(self.dest_ip >> 8),
            @truncate(self.dest_ip >> 16),
            @truncate(self.dest_ip >> 24),
            @truncate(self.dest_port >> 0),
            @truncate(self.dest_port >> 8),
            self.protocol,
        };
        for (bytes) |b| {
            h ^= b;
            h *= 0x100000001b3; // FNV-1a prime
        }
        return h;
    }

    pub fn eql(self: FlowKey, other: FlowKey) bool {
        return self.src_ip == other.src_ip and
            self.src_port == other.src_port and
            self.dest_ip == other.dest_ip and
            self.dest_port == other.dest_port and
            self.protocol == other.protocol;
    }
};

// ============================================================================
// NAT entry — per-flow state
// ============================================================================

pub const NatEntry = struct {
    id: u32,
    status: NatStatus,
    protocol: u8,

    /// Client-side (inside) address.
    src_ip: u32,
    src_port: u16,

    /// Original destination (outside) address.
    dest_ip: u32,
    dest_port: u16,

    /// Public (outbound) address — the socket we allocated.
    public_ip: u32,
    public_port: u16,

    /// Public-facing flow key for receive-direction lookup.
    /// Maps (public_ip:public_port -> dest_ip:dest_port) so inbound replies
    /// find the correct NAT session.
    recv_key: FlowKey,

    created_time: i64,
    last_comm_time: i64,
    total_sent: u64,
    total_recv: u64,

    /// TCP sequence tracking.
    last_seq: u32,
    last_ack: u32,

    /// Cached hash codes for fast table lookup (C `HashCodeForSend/Recv`).
    hash_code_for_send: u64,
    hash_code_for_recv: u64,

    /// Outbound file descriptor (real OS socket). -1 = not connected yet.
    outbound_fd: std.posix.socket_t,

    pub fn flowKey(self: *const NatEntry) FlowKey {
        return .{
            .src_ip = self.src_ip,
            .src_port = self.src_port,
            .dest_ip = self.dest_ip,
            .dest_port = self.dest_port,
            .protocol = self.protocol,
        };
    }

    pub fn reverseFlowKey(self: *const NatEntry) FlowKey {
        return .{
            .src_ip = self.dest_ip,
            .src_port = self.dest_port,
            .dest_ip = self.src_ip,
            .dest_port = self.src_port,
            .protocol = self.protocol,
        };
    }

    pub fn timeoutMs(self: *const NatEntry) i64 {
        return switch (self.protocol) {
            PROTO_TCP => NAT_TCP_TIMEOUT_MS,
            PROTO_UDP => NAT_UDP_TIMEOUT_MS,
            PROTO_ICMP => NAT_ICMP_TIMEOUT_MS,
            else => NAT_UDP_TIMEOUT_MS,
        };
    }

    pub fn isExpired(self: *const NatEntry, now: i64) bool {
        return (now - self.last_comm_time) > self.timeoutMs();
    }

    pub fn closeSocket(self: *NatEntry) void {
        if (self.outbound_fd != std.math.maxInt(std.posix.socket_t)) {
            std.posix.close(self.outbound_fd);
            self.outbound_fd = std.math.maxInt(std.posix.socket_t);
        }
    }
};

// ============================================================================
// NAT entry table — hash-based lookup
// ============================================================================

const BucketSize = 256;

pub const NatTable = struct {
    /// Buckets: each bucket is a list of entries with the same bucket index.
    buckets: [BucketSize]std.ArrayListUnmanaged(NatEntry),
    count: u32,

    pub fn init() NatTable {
        return .{
            .buckets = [_]std.ArrayListUnmanaged(NatEntry){} ** BucketSize,
            .count = 0,
        };
    }

    pub fn deinit(self: *NatTable, allocator: Allocator) void {
        for (&self.buckets) |*bucket| {
            for (bucket.items) |*entry| entry.closeSocket();
            bucket.deinit(allocator);
        }
        self.count = 0;
    }

    fn bucketIndex(key: FlowKey) usize {
        return @intCast(key.hash() % BucketSize);
    }

    pub fn insert(self: *NatTable, allocator: Allocator, entry: NatEntry) !void {
        const idx = bucketIndex(entry.flowKey());
        try self.buckets[idx].append(allocator, entry);
        self.count +%= 1;
    }

    pub fn find(self: *const NatTable, key: FlowKey) ?*const NatEntry {
        const idx = bucketIndex(key);
        for (self.buckets[idx].items) |*entry| {
            if (entry.flowKey().eql(key)) return entry;
        }
        return null;
    }

    pub fn findMut(self: *NatTable, key: FlowKey) ?*NatEntry {
        const idx = bucketIndex(key);
        for (self.buckets[idx].items) |*entry| {
            if (entry.flowKey().eql(key)) return entry;
        }
        return null;
    }

    pub fn remove(self: *NatTable, key: FlowKey) bool {
        const idx = bucketIndex(key);
        const bucket = &self.buckets[idx];
        for (0..bucket.items.len) |i| {
            if (bucket.items[i].flowKey().eql(key)) {
                var removed = bucket.swapRemove(i);
                removed.closeSocket();
                self.count -|= 1;
                return true;
            }
        }
        return false;
    }

    /// Find an entry by receive key (C: `NnGetNatEntryForRecv`).
    pub fn findRecv(self: *const NatTable, recv_key: FlowKey) ?*const NatEntry {
        const idx = bucketIndex(recv_key);
        for (self.buckets[idx].items) |*entry| {
            if (entry.recv_key.eql(recv_key)) return entry;
        }
        return null;
    }

    /// Remove all expired entries. Returns the number removed.
    pub fn sweepExpired(self: *NatTable, now: i64) u32 {
        var removed: u32 = 0;
        for (&self.buckets) |*bucket| {
            var i: usize = 0;
            while (i < bucket.items.len) {
                if (bucket.items[i].isExpired(now)) {
                    var entry = bucket.swapRemove(i);
                    entry.closeSocket();
                    self.count -|= 1;
                    removed +%= 1;
                } else {
                    i += 1;
                }
            }
        }
        return removed;
    }

    /// Delete the oldest entry for a given source IP + protocol
    /// (C: `NnGetOldestNatEntryOfIp`). Falls back to the global oldest
    /// entry when no matching entry exists.
    pub fn deleteOldestForIp(self: *NatTable, src_ip: u32, protocol: u8) bool {
        var oldest_idx: ?usize = null;
        var oldest_time: i64 = std.math.maxInt(i64);
        var oldest_bucket: ?usize = null;

        // First pass: find matching entry by src_ip + protocol.
        for (&self.buckets, 0..) |*bucket, bi| {
            for (bucket.items, 0..) |entry, ei| {
                if (entry.src_ip == src_ip and entry.protocol == protocol) {
                    if (entry.created_time < oldest_time) {
                        oldest_time = entry.created_time;
                        oldest_idx = ei;
                        oldest_bucket = bi;
                    }
                }
            }
        }

        // Second pass: if no match, fall back to global oldest.
        if (oldest_bucket == null) {
            for (&self.buckets, 0..) |*bucket, bi| {
                for (bucket.items, 0..) |entry, ei| {
                    if (entry.created_time < oldest_time) {
                        oldest_time = entry.created_time;
                        oldest_idx = ei;
                        oldest_bucket = bi;
                    }
                }
            }
        }

        if (oldest_bucket) |bi| {
            if (oldest_idx) |ei| {
                var removed = self.buckets[bi].swapRemove(ei);
                removed.closeSocket();
                self.count -|= 1;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// NAT engine — top-level coordinator
// ============================================================================

pub const NatEngine = struct {
    allocator: Allocator,

    mutex: std.Thread.Mutex = .{},

    /// Client-side (virtual LAN) subnet gateway IP.
    virtual_ip: u32,
    /// Public (outbound) IP obtained from the host interface.
    public_ip: u32,

    /// NAT entry table.
    table: NatTable,

    /// Next entry ID (monotonic).
    next_id: u32,

    /// Total sessions created / destroyed.
    total_created: u64,
    total_destroyed: u64,

    /// Maximum concurrent entries.
    max_entries: u32,

    pub fn init(allocator: Allocator, virtual_ip: u32, public_ip: u32) NatEngine {
        return .{
            .allocator = allocator,
            .virtual_ip = virtual_ip,
            .public_ip = public_ip,
            .table = NatTable.init(),
            .next_id = 1,
            .max_entries = MAX_NAT_ENTRIES,
        };
    }

    pub fn deinit(self: *NatEngine) void {
        self.table.deinit(self.allocator);
    }

    /// Create a new ICMP echo NAT entry (C: `NnNewNatIcmp`).
    pub fn newIcmpEntry(
        self: *NatEngine,
        src_ip: u32,
        src_port: u16,
        dest_ip: u32,
        dest_port: u16,
        now: i64,
    ) !NatEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.table.count >= self.max_entries) {
            _ = self.table.deleteOldestForIp(src_ip, PROTO_ICMP);
        }

        const id = self.next_id;
        self.next_id +%= 1;

        const entry = NatEntry{
            .id = id,
            .status = .active,
            .protocol = PROTO_ICMP,
            .src_ip = src_ip,
            .src_port = src_port,
            .dest_ip = dest_ip,
            .dest_port = dest_port,
            .public_ip = self.public_ip,
            .public_port = src_port,
            .recv_key = .{
                .src_ip = self.public_ip,
                .src_port = src_port,
                .dest_ip = dest_ip,
                .dest_port = dest_port,
                .protocol = PROTO_ICMP,
            },
            .created_time = now,
            .last_comm_time = now,
            .total_sent = 0,
            .total_recv = 0,
            .last_seq = 0,
            .last_ack = 0,
            .hash_code_for_send = 0,
            .hash_code_for_recv = 0,
            .outbound_fd = std.math.maxInt(std.posix.socket_t),
        };

        try self.table.insert(self.allocator, entry);
        self.total_created +%= 1;
        log.debug("NAT: new ICMP entry id={d} {any}:{d} -> {any}:{d}", .{
            id,
            fmtIp(src_ip),
            src_port,
            fmtIp(dest_ip),
            dest_port,
        });

        return entry;
    }

    /// Create a new UDP NAT entry (C: `NnNewNatUdp`).
    pub fn newUdpEntry(
        self: *NatEngine,
        src_ip: u32,
        src_port: u16,
        dest_ip: u32,
        dest_port: u16,
        now: i64,
    ) !NatEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.table.count >= self.max_entries) {
            _ = self.table.deleteOldestForIp(src_ip, PROTO_UDP);
        }

        // Allocate an outbound UDP socket.
        const fd = try std.posix.socket(std.posix.AF_INET, std.posix.SOCK_DGRAM, std.posix.IPPROTO_UDP);
        errdefer std.posix.close(fd);

        // Bind to any available port.
        var addr: std.posix.sockaddr.in = .{
            .port = 0,
            .addr = std.mem.nativeToBig(u32, self.public_ip),
        };
        try std.posix.bind(fd, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in));

        // Get the assigned port.
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        try std.posix.getsockname(fd, @ptrCast(&addr), &addr_len);
        const public_port = std.mem.bigToNative(u16, addr.port);

        const id = self.next_id;
        self.next_id +%= 1;

        const entry = NatEntry{
            .id = id,
            .status = .active,
            .protocol = PROTO_UDP,
            .src_ip = src_ip,
            .src_port = src_port,
            .dest_ip = dest_ip,
            .dest_port = dest_port,
            .public_ip = self.public_ip,
            .public_port = public_port,
            .recv_key = .{
                .src_ip = dest_ip,
                .src_port = dest_port,
                .dest_ip = self.public_ip,
                .dest_port = public_port,
                .protocol = PROTO_UDP,
            },
            .created_time = now,
            .last_comm_time = now,
            .total_sent = 0,
            .total_recv = 0,
            .last_seq = 0,
            .last_ack = 0,
            .hash_code_for_send = 0,
            .hash_code_for_recv = 0,
            .outbound_fd = fd,
        };

        try self.table.insert(self.allocator, entry);
        self.total_created +%= 1;
        log.debug("NAT: new UDP entry id={d} {any}:{d} -> {any}:{d} (public :{d})", .{
            id,
            fmtIp(src_ip),
            src_port,
            fmtIp(dest_ip),
            dest_port,
            public_port,
        });

        return entry;
    }

    /// Create a new TCP NAT entry (C: `NnNewNatTcp`).
    pub fn newTcpEntry(
        self: *NatEngine,
        src_ip: u32,
        src_port: u16,
        dest_ip: u32,
        dest_port: u16,
        now: i64,
    ) !NatEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.table.count >= self.max_entries) {
            _ = self.table.deleteOldestForIp(src_ip, PROTO_TCP);
        }

        // Allocate an outbound TCP socket.
        const fd = try std.posix.socket(std.posix.AF_INET, std.posix.SOCK_STREAM, std.posix.IPPROTO_TCP);
        errdefer std.posix.close(fd);

        // Bind to any available port.
        var addr: std.posix.sockaddr.in = .{
            .port = 0,
            .addr = std.mem.nativeToBig(u32, self.public_ip),
        };
        try std.posix.bind(fd, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in));

        // Get the assigned port.
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        try std.posix.getsockname(fd, @ptrCast(&addr), &addr_len);
        const public_port = std.mem.bigToNative(u16, addr.port);

        // Non-blocking connect.
        try std.posix.fcntl(fd, std.posix.F.SETFL, .{ .NONBLOCK = true });

        var dest_addr: std.posix.sockaddr.in = .{
            .port = std.mem.nativeToBig(u16, dest_port),
            .addr = std.mem.nativeToBig(u32, dest_ip),
        };
        _ = std.posix.connect(fd, @ptrCast(&dest_addr), @sizeOf(std.posix.sockaddr.in)) catch |err| switch (err) {
            error.WouldBlock => {}, // Expected for non-blocking connect.
            else => return err,
        };

        const id = self.next_id;
        self.next_id +%= 1;

        const entry = NatEntry{
            .id = id,
            .status = .connecting,
            .protocol = PROTO_TCP,
            .src_ip = src_ip,
            .src_port = src_port,
            .dest_ip = dest_ip,
            .dest_port = dest_port,
            .public_ip = self.public_ip,
            .public_port = public_port,
            .recv_key = .{
                .src_ip = dest_ip,
                .src_port = dest_port,
                .dest_ip = self.public_ip,
                .dest_port = public_port,
                .protocol = PROTO_TCP,
            },
            .created_time = now,
            .last_comm_time = now,
            .total_sent = 0,
            .total_recv = 0,
            .last_seq = 0,
            .last_ack = 0,
            .hash_code_for_send = 0,
            .hash_code_for_recv = 0,
            .outbound_fd = fd,
        };

        try self.table.insert(self.allocator, entry);
        self.total_created +%= 1;
        log.debug("NAT: new TCP entry id={d} {any}:{d} -> {any}:{d} (public :{d})", .{
            id,
            fmtIp(src_ip),
            src_port,
            fmtIp(dest_ip),
            dest_port,
            public_port,
        });

        return entry;
    }

    /// Look up an entry for the send direction (C: `NnGetNatEntryForSend`).
    pub fn lookupSend(self: *NatEngine, key: FlowKey) ?NatEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.table.find(key)) |entry| {
            return entry.*;
        }
        return null;
    }

    /// Look up an entry for the receive direction (C: `NnGetNatEntryForRecv`).
    /// A reply from `src_ip:src_port` to `dest_ip:dest_port` matches an entry
    /// whose `recv_key` has (src_ip=dest_ip, dest_ip=src_ip).
    pub fn lookupRecv(self: *NatEngine, src_ip: u32, src_port: u16, dest_ip: u32, dest_port: u16, protocol: u8) ?NatEntry {
        const key = FlowKey{
            .src_ip = dest_ip,
            .src_port = dest_port,
            .dest_ip = src_ip,
            .dest_port = src_port,
            .protocol = protocol,
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.table.findRecv(key)) |entry| {
            return entry.*;
        }
        return null;
    }

    /// Delete an entry (C: `NnDeleteSession`).
    pub fn deleteEntry(self: *NatEngine, key: FlowKey) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.table.remove(key)) {
            self.total_destroyed +%= 1;
            return true;
        }
        return false;
    }

    /// Sweep expired entries (C: `NnSweepNatTable`).
    pub fn sweep(self: *NatEngine, now: i64) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const removed = self.table.sweepExpired(now);
        self.total_destroyed +%= removed;
        return removed;
    }

    /// Update the last-comm timestamp for an entry.
    pub fn touch(self: *NatEngine, key: FlowKey, now: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.table.findMut(key)) |entry| {
            entry.last_comm_time = now;
        }
    }

    /// Snapshot all entries (for admin status display).
    pub fn snapshotEntries(self: *NatEngine) []NatEntry {
        self.mutex.lock();
        defer self.mutex.unlock();

        var all = std.ArrayListUnmanaged(NatEntry){};
        for (self.table.buckets) |bucket| {
            for (bucket.items) |entry| {
                all.append(self.allocator, entry) catch break;
            }
        }
        return all.toOwnedSlice(self.allocator) catch return &.{};
    }

    /// Forward an outbound IP packet from the virtual host.
    /// Looks up the flow, rewrites the source address to the public NAT
    /// address, and writes to the outbound socket.
    /// TODO(C: Virtual.c NnSendNatPacket) — currently a stub for PR #163.
    pub fn forwardPacket(self: *NatEngine, packet: []const u8) ForwardError!void {
        _ = self;
        _ = packet;
        return error.NotYetImplemented;
    }

    /// Process a reply packet received on the public NAT socket.
    /// Looks up the flow by recv_key, rewrites the destination address back
    /// to the virtual host, and enqueues for delivery to the hub.
    /// TODO(C: Virtual.c NnRecvNatPacket) — currently a stub for PR #163.
    pub fn receivePacket(self: *NatEngine, packet: []const u8) ReceiveError!void {
        _ = self;
        _ = packet;
        return error.NotYetImplemented;
    }
};

// ============================================================================
// Helper — format IP for debug logs
// ============================================================================

fn fmtIp(ip: u32) [15]u8 {
    var buf: [15]u8 = undefined;
    const b: [4]u8 = .{
        @truncate(ip >> 24),
        @truncate(ip >> 16),
        @truncate(ip >> 8),
        @truncate(ip >> 0),
    };
    const len = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch return "???.???.???.???";
    @memcpy(buf[0..len.len], len);
    return buf;
}

// ============================================================================
// Tests
// ============================================================================

/// Helper to create a NatEntry with all required fields (tests only).
fn makeTestEntry(
    id: u32,
    protocol: u8,
    src_ip: u32,
    src_port: u16,
    dest_ip: u32,
    dest_port: u16,
    public_ip: u32,
    public_port: u16,
    created_time: i64,
) NatEntry {
    return .{
        .id = id,
        .status = if (protocol == PROTO_TCP) .connecting else .active,
        .protocol = protocol,
        .src_ip = src_ip,
        .src_port = src_port,
        .dest_ip = dest_ip,
        .dest_port = dest_port,
        .public_ip = public_ip,
        .public_port = public_port,
        .recv_key = .{
            .src_ip = dest_ip,
            .src_port = dest_port,
            .dest_ip = public_ip,
            .dest_port = public_port,
            .protocol = protocol,
        },
        .created_time = created_time,
        .last_comm_time = created_time,
        .total_sent = 0,
        .total_recv = 0,
        .last_seq = 0,
        .last_ack = 0,
        .hash_code_for_send = 0,
        .hash_code_for_recv = 0,
        .outbound_fd = std.math.maxInt(std.posix.socket_t),
    };
}

test "nat.FlowKey hash and equality" {
    const a = FlowKey{ .src_ip = 0x0A000001, .src_port = 12345, .dest_ip = 0xC0A80101, .dest_port = 80, .protocol = PROTO_TCP };
    const b = FlowKey{ .src_ip = 0x0A000001, .src_port = 12345, .dest_ip = 0xC0A80101, .dest_port = 80, .protocol = PROTO_TCP };
    const c = FlowKey{ .src_ip = 0x0A000001, .src_port = 12345, .dest_ip = 0xC0A80101, .dest_port = 80, .protocol = PROTO_UDP };

    try testing.expect(a.eql(b));
    try testing.expect(!a.eql(c));
    try testing.expectEqual(a.hash(), b.hash());
}

test "nat.NatTable insert and find" {
    const allocator = testing.allocator;
    var table = NatTable.init();
    defer table.deinit(allocator);

    const key = FlowKey{ .src_ip = 0x0A000001, .src_port = 1000, .dest_ip = 0xC0A80101, .dest_port = 80, .protocol = PROTO_TCP };
    var entry = makeTestEntry(1, PROTO_TCP, 0x0A000001, 1000, 0xC0A80101, 80, 0x01020304, 5000, 1000);
    entry.total_sent = 100;
    entry.total_recv = 200;
    entry.last_comm_time = 2000;

    try table.insert(allocator, entry);
    try testing.expectEqual(@as(u32, 1), table.count);

    const found = table.find(key);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u32, 1), found.?.id);
    try testing.expectEqual(@as(u64, 200), found.?.total_recv);
}

test "nat.NatTable findRecv matches recv_key" {
    const allocator = testing.allocator;
    var table = NatTable.init();
    defer table.deinit(allocator);

    const entry = makeTestEntry(1, PROTO_UDP, 0x0A000001, 1000, 0xC0A80101, 53, 0x01020304, 5000, 1000);
    try table.insert(allocator, entry);

    // Receive lookup: reply from server (0xC0A80101:53) to public (0x01020304:5000).
    const recv_key = FlowKey{
        .src_ip = 0xC0A80101,
        .src_port = 53,
        .dest_ip = 0x01020304,
        .dest_port = 5000,
        .protocol = PROTO_UDP,
    };
    const found = table.findRecv(recv_key);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u32, 1), found.?.id);
}

test "nat.NatTable remove" {
    const allocator = testing.allocator;
    var table = NatTable.init();
    defer table.deinit(allocator);

    const key = FlowKey{ .src_ip = 0x0A000001, .src_port = 1000, .dest_ip = 0xC0A80101, .dest_port = 80, .protocol = PROTO_TCP };
    try table.insert(allocator, makeTestEntry(1, PROTO_TCP, 0x0A000001, 1000, 0xC0A80101, 80, 0x01020304, 5000, 1000));

    try testing.expect(table.remove(key));
    try testing.expectEqual(@as(u32, 0), table.count);
    try testing.expect(table.find(key) == null);
    try testing.expect(!table.remove(key));
}

test "nat.NatTable sweepExpired removes stale entries" {
    const allocator = testing.allocator;
    var table = NatTable.init();
    defer table.deinit(allocator);

    try table.insert(allocator, makeTestEntry(1, PROTO_UDP, 0x0A000001, 1000, 0xC0A80101, 53, 0x01020304, 5000, 1000));
    try table.insert(allocator, makeTestEntry(2, PROTO_UDP, 0x0A000002, 2000, 0xC0A80101, 53, 0x01020304, 5001, 50000));
    try testing.expectEqual(@as(u32, 2), table.count);

    // Sweep at time=50000: entry 1 (last_comm=1000) is expired, entry 2 is not.
    const removed = table.sweepExpired(50000);
    try testing.expectEqual(@as(u32, 1), removed);
    try testing.expectEqual(@as(u32, 1), table.count);
}

test "nat.NatTable deleteOldestForIp" {
    const allocator = testing.allocator;
    var table = NatTable.init();
    defer table.deinit(allocator);

    try table.insert(allocator, makeTestEntry(1, PROTO_UDP, 0x0A000001, 1000, 0xC0A80101, 53, 0x01020304, 5000, 1000));
    try table.insert(allocator, makeTestEntry(2, PROTO_UDP, 0x0A000001, 2000, 0xC0A80101, 53, 0x01020304, 5001, 2000));
    try testing.expectEqual(@as(u32, 2), table.count);

    // Should delete oldest (id=1, created_time=1000).
    try testing.expect(table.deleteOldestForIp(0x0A000001, PROTO_UDP));
    try testing.expectEqual(@as(u32, 1), table.count);
}

test "nat.NatTable deleteOldestForIp falls back to global oldest" {
    const allocator = testing.allocator;
    var table = NatTable.init();
    defer table.deinit(allocator);

    try table.insert(allocator, makeTestEntry(1, PROTO_UDP, 0x0A000001, 1000, 0xC0A80101, 53, 0x01020304, 5000, 2000));
    try table.insert(allocator, makeTestEntry(2, PROTO_TCP, 0x0A000002, 2000, 0xC0A80101, 80, 0x01020304, 5001, 1000));

    // No matching src_ip=0xFF for PROTO_UDP, should fall back to global oldest (id=2, time=1000).
    try testing.expect(table.deleteOldestForIp(0xFF, PROTO_UDP));
    try testing.expectEqual(@as(u32, 1), table.count);
    // Entry 1 should remain.
    const key1 = FlowKey{ .src_ip = 0x0A000001, .src_port = 1000, .dest_ip = 0xC0A80101, .dest_port = 53, .protocol = PROTO_UDP };
    try testing.expect(table.find(key1) != null);
}

test "nat.NatEngine creates ICMP entry" {
    const allocator = testing.allocator;
    var engine = NatEngine.init(allocator, 0x0A000001, 0x01020304);
    defer engine.deinit();

    const entry = try engine.newIcmpEntry(0x0A000001, 1000, 0xC0A80101, 0, 1000);
    try testing.expectEqual(@as(u8, PROTO_ICMP), entry.protocol);
    try testing.expectEqual(@as(u32, 0x01020304), entry.public_ip);
    try testing.expectEqual(@as(u16, 1000), entry.public_port);
    try testing.expectEqual(@as(u64, 1), engine.total_created);
    try testing.expectEqual(@as(u32, 1), engine.table.count);

    const key = FlowKey{ .src_ip = 0x0A000001, .src_port = 1000, .dest_ip = 0xC0A80101, .dest_port = 0, .protocol = PROTO_ICMP };
    const found = engine.lookupSend(key);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u32, entry.id), found.?.id);
}

test "nat.NatEngine creates UDP entry with bound socket" {
    const allocator = testing.allocator;
    var engine = NatEngine.init(allocator, 0x0A000001, 0x01020304);
    defer engine.deinit();

    const entry = try engine.newUdpEntry(0x0A000001, 1000, 0xC0A80101, 53, 1000);
    try testing.expectEqual(@as(u8, PROTO_UDP), entry.protocol);
    try testing.expect(entry.outbound_fd != std.math.maxInt(std.posix.socket_t));
    try testing.expect(entry.public_port > 0);
    try testing.expectEqual(@as(u32, 1), engine.table.count);

    engine.deleteEntry(entry.flowKey());
}

test "nat.NatEngine creates TCP entry with non-blocking socket" {
    const allocator = testing.allocator;
    var engine = NatEngine.init(allocator, 0x0A000001, 0x01020304);
    defer engine.deinit();

    const entry = try engine.newTcpEntry(0x0A000001, 1000, 0xC0A80101, 80, 1000);
    try testing.expectEqual(@as(u8, PROTO_TCP), entry.protocol);
    try testing.expectEqual(NatStatus.connecting, entry.status);
    try testing.expect(entry.outbound_fd != std.math.maxInt(std.posix.socket_t));
    try testing.expect(entry.public_port > 0);

    engine.deleteEntry(entry.flowKey());
}

test "nat.NatEngine lookupRecv uses recv_key" {
    const allocator = testing.allocator;
    var engine = NatEngine.init(allocator, 0x0A000001, 0x01020304);
    defer engine.deinit();

    const entry = try engine.newUdpEntry(0x0A000001, 1000, 0xC0A80101, 53, 1000);

    // Reply from server (0xC0A80101:53) to public (0x01020304:entry.public_port).
    const found = engine.lookupRecv(0xC0A80101, 53, engine.public_ip, entry.public_port, PROTO_UDP);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u32, entry.id), found.?.id);

    engine.deleteEntry(entry.flowKey());
}

test "nat.NatEngine sweep removes expired entries" {
    const allocator = testing.allocator;
    var engine = NatEngine.init(allocator, 0x0A000001, 0x01020304);
    defer engine.deinit();

    _ = try engine.newIcmpEntry(0x0A000001, 1000, 0xC0A80101, 0, 1000);
    _ = try engine.newIcmpEntry(0x0A000002, 2000, 0xC0A80101, 0, 50000);

    try testing.expectEqual(@as(u32, 2), engine.table.count);

    const removed = engine.sweep(50000);
    try testing.expectEqual(@as(u32, 1), removed);
    try testing.expectEqual(@as(u32, 1), engine.table.count);
}

test "nat.NatEngine respects max_entries by evicting oldest" {
    const allocator = testing.allocator;
    var engine = NatEngine.init(allocator, 0x0A000001, 0x01020304);
    defer engine.deinit();
    engine.max_entries = 2;

    _ = try engine.newIcmpEntry(0x0A000001, 1000, 0xC0A80101, 0, 1000);
    _ = try engine.newIcmpEntry(0x0A000001, 2000, 0xC0A80101, 0, 2000);
    try testing.expectEqual(@as(u32, 2), engine.table.count);

    // Third entry from same IP should evict oldest.
    _ = try engine.newIcmpEntry(0x0A000001, 3000, 0xC0A80101, 0, 3000);
    try testing.expectEqual(@as(u32, 2), engine.table.count);

    // Entry 1000 should be gone (evicted).
    const key1 = FlowKey{ .src_ip = 0x0A000001, .src_port = 1000, .dest_ip = 0xC0A80101, .dest_port = 0, .protocol = PROTO_ICMP };
    try testing.expect(engine.table.find(key1) == null);
}

test "nat.NatEntry.isExpired respects protocol timeouts" {
    const tcp = makeTestEntry(1, PROTO_TCP, 0, 0, 0, 0, 0, 0, 0);
    // Override last_comm_time to test timeout.
    var tcp_mut = tcp;
    tcp_mut.last_comm_time = 100_000;

    // TCP timeout is 300s = 300000ms. At t=350000, delta=250000 < 300000 -> not expired.
    try testing.expect(!tcp_mut.isExpired(350_000));
    // At t=450000, delta=350000 > 300000 -> expired.
    try testing.expect(tcp_mut.isExpired(450_000));
}
