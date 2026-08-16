//! Npcap L2 ingress port (L2 Network Bridge proposal §4.1; issue #61).
//!
//! Windows-only NetPort implementation over Npcap (`pcap.dll`), bound to a
//! named interface, used by the bridge pump (issue #56) as the
//! physical-side ingress. Mirrors `port.l3Port()` and `af_packet.afPacketPort()`:
//! the caller owns the `NpcapPort` instance; the pump drives I/O through the
//! vtable.
//!
//! Design decisions (proposal §4.6, §6; issue #61):
//! - **Dynamic pcap.dll** (no build-time dependency): LoadLibrary + GetProcAddress
//!   like the Wintun wrapper in `tap_windows.zig`. When the DLL (or Npcap
//!   service) is absent, open() fails with `error.NpcapNotInstalled` — a
//!   clean, documented degrade; the client itself is unaffected.
//! - **Name mapping:** `nic_enumerate.zig` reports Windows interfaces by their
//!   stable GUID string (`{...}`). Npcap device names are
//!   `\Device\NPF_{GUID}`. open() accepts the GUID, a bare friendly name
//!   (wrapped as `\Device\NPF_{name}`), or a full `\Device\NPF_...` name,
//!   and verifies the candidate against `pcap_findalldevs`.
//! - **Promiscuous is open-time only** (Npcap cannot toggle it on a live
//!   handle): `pcap_open_live(..., promisc=1, ...)`; setPromiscuous(false)
//!   is a logged no-op (documented variance from af_packet).
//! - **Polling model (decided in #61):** Npcap handles have no pollable fd
//!   on Windows, so `getFd()` returns `invalid_fd` and each port runs a
//!   dedicated worker thread feeding a bounded SPSC ring (slots of
//!   `SESSION_FRAME_BUDGET` bytes). The pump drains non-pollable ports every
//!   iteration (read() pops the ring) — the polling loop itself never blocks
//!   on Npcap.
//! - **MTU clamp (H-3):** frames larger than 1514 are dropped and counted in
//!   `PortStats.drops`. Npcap captures with snaplen 65535 so truncated-frame
//!   skips are unnecessary.
//! - **Host-IP warning (H-5):** Npcap itself does not deliver the NIC's
//!   address list; the warning is emitted at the app layer when the bridge
//!   ingress is configured (documented limitation on Windows).

const std = @import("std");
const builtin = @import("builtin");
const port_mod = @import("port.zig");
const NetPort = port_mod.NetPort;
const PortLayer = port_mod.PortLayer;
const PortStats = port_mod.PortStats;

// Shared Windows API import (single @cImport block — see tap_windows.zig).
const kernel32 = @import("../cedar/protocol/c_imports.zig").c;

/// Session L2 frame budget (proposal §4.6) — must match af_packet.zig.
pub const SESSION_FRAME_BUDGET: usize = 1514;

/// Ring capacity: frames buffered per port before the pump drains.
pub const RX_QUEUE_CAP: usize = 256;

const LPCSTR = [*:0]const u8;
const HMODULE = ?*anyopaque;
const PCAP_ERRBUF_SIZE: usize = 256;

const PcapIf = extern struct {
    next: ?*PcapIf,
    name: ?LPCSTR,
    description: ?LPCSTR,
    addresses: ?*anyopaque,
    flags: u32,
};

const PcapPkthdr = extern struct {
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    len: u32,
};

const PcapApi = struct {
    dll: HMODULE,
    openLive: *const fn (LPCSTR, c_int, c_int, c_int, [*]u8) callconv(.c) ?*anyopaque,
    nextEx: *const fn (*anyopaque, *?*const PcapPkthdr, *?[*]const u8) callconv(.c) c_int,
    sendPacket: *const fn (*anyopaque, [*]const u8, c_int) callconv(.c) c_int,
    close: *const fn (*anyopaque) callconv(.c) void,
    getErr: *const fn (*anyopaque) callconv(.c) ?LPCSTR,
    dataLink: *const fn (*anyopaque) callconv(.c) c_int,
    findalldevs: *const fn (*?*PcapIf, [*]u8) callconv(.c) c_int,
    freealldevs: *const fn (*PcapIf) callconv(.c) void,

    /// Release the loaded DLL. Undoes `load()` on partially-initialized
    /// open paths so a failed `open()` does not leak the module reference.
    fn unload(self: *PcapApi) void {
        if (self.dll) |dll| {
            _ = kernel32.FreeLibrary(@ptrCast(@alignCast(dll)));
            self.dll = null;
        }
    }

    fn load() !PcapApi {
        const dll = kernel32.LoadLibraryA("pcap.dll");
        if (dll == null) {
            std.log.warn("npcap: pcap.dll not found — Npcap is not installed", .{});
            return NpcapError.NpcapNotInstalled;
        }
        return .{
            .dll = dll,
            .openLive = @ptrCast(kernel32.GetProcAddress(dll, "pcap_open_live") orelse return NpcapError.NpcapNotInstalled),
            .nextEx = @ptrCast(kernel32.GetProcAddress(dll, "pcap_next_ex") orelse return NpcapError.NpcapNotInstalled),
            .sendPacket = @ptrCast(kernel32.GetProcAddress(dll, "pcap_sendpacket") orelse return NpcapError.NpcapNotInstalled),
            .close = @ptrCast(kernel32.GetProcAddress(dll, "pcap_close") orelse return NpcapError.NpcapNotInstalled),
            .getErr = @ptrCast(kernel32.GetProcAddress(dll, "pcap_geterr") orelse return NpcapError.NpcapNotInstalled),
            .dataLink = @ptrCast(kernel32.GetProcAddress(dll, "pcap_datalink") orelse return NpcapError.NpcapNotInstalled),
            .findalldevs = @ptrCast(kernel32.GetProcAddress(dll, "pcap_findalldevs") orelse return NpcapError.NpcapNotInstalled),
            .freealldevs = @ptrCast(kernel32.GetProcAddress(dll, "pcap_freealldevs") orelse return NpcapError.NpcapNotInstalled),
        };
    }
};

/// Errors specific to the Npcap port lifecycle.
pub const NpcapError = error{
    /// Ports can only be opened on Windows.
    NotWindows,
    /// pcap.dll (Npcap) is not installed — clean, documented degrade.
    NpcapNotInstalled,
    /// Interface name could not be resolved to an Npcap device.
    InterfaceNotFound,
    /// pcap_open_live failed (device busy, permissions, …).
    OpenFailed,
    /// Port has been closed.
    DeviceClosed,
    /// Frames larger than the session budget (1514) are not forwarded (H-3).
    FrameTooLarge,
};

const RxSlot = struct {
    len: usize = 0,
    data: [SESSION_FRAME_BUDGET]u8 = undefined,
};

/// Npcap port implementation.
///
/// Owned by the pump like an L3 device behind `l3Port`; `npcapPort()` fills
/// it and hands back a `NetPort` pointing at it. `open()` loads pcap.dll,
/// resolves the interface, starts the RX worker thread and returns; every
/// entry point fails fast with `error.NotWindows` on non-Windows targets.
pub const NpcapPort = struct {
    allocator: std.mem.Allocator,
    ifname: []const u8 = "",
    api: ?PcapApi = null,
    handle: ?*anyopaque = null,
    mac: ?[6]u8 = null,
    stats: PortStats = .{},
    promisc: bool = false,

    // RX worker: single producer (thread) / single consumer (pump).
    thread: ?std.Thread = null,
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    queue: [RX_QUEUE_CAP]RxSlot = [_]RxSlot{.{}} ** RX_QUEUE_CAP,

    /// Open the Npcap device for `ifname` and start the RX worker.
    pub fn open(self: *NpcapPort) NpcapError!void {
        if (comptime builtin.os.tag != .windows) return error.NotWindows;

        const api = PcapApi.load() catch return error.NpcapNotInstalled;
        self.api = api;
        // Every failure after this point must release the DLL reference so
        // repeated opens of an unavailable/invalid interface do not leak a
        // pcap.dll module handle (PR #150 review).
        errdefer {
            self.api.?.unload();
            self.api = null;
        }

        // Resolve the Npcap device name for the requested interface.
        var dev_name_buf: [512]u8 = undefined;
        const dev_name = self.resolveDeviceName(&dev_name_buf, api) orelse {
            std.log.warn("npcap: interface '{s}' not found (use the GUID from softether_list_interfaces)", .{self.ifname});
            return error.InterfaceNotFound;
        };

        var errbuf: [PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** PCAP_ERRBUF_SIZE;
        // Blocking reads with a 10 ms read timeout: the dedicated worker
        // thread waits, so idle loops cost ~0% CPU (Npcap's event-driven
        // wait returns when a frame arrives or the timeout elapses).
        const handle = api.openLive(@ptrCast(dev_name.ptr), 65535, 1, 10, &errbuf) orelse {
            std.log.warn("npcap: open '{s}' failed: {s}", .{ dev_name, std.mem.sliceTo(&errbuf, 0) });
            return error.OpenFailed;
        };
        self.handle = handle;
        errdefer {
            api.close(handle);
            self.handle = null;
        }

        // Warn when the link type is not Ethernet (DLT_EN10MB = 1).
        const dl = api.dataLink(handle);
        if (dl != 1) {
            std.log.warn("npcap: interface '{s}' link type {d} (expected 1/EN10MB) — frames may not be Ethernet", .{ self.ifname, dl });
        }
        self.promisc = true;

        self.thread = std.Thread.spawn(.{}, rxWorker, .{self}) catch |err| {
            std.log.warn("npcap: rx worker spawn failed: {}", .{err});
            return error.OpenFailed;
        };
        std.log.info("npcap: ingress port '{s}' open on {s}", .{ self.ifname, dev_name });
    }

    /// Map `self.ifname` to an Npcap device name (`\Device\NPF_{GUID}`).
    /// Accepts the GUID as reported by softether_list_interfaces, a bare
    /// friendly name, or a full \Device\NPF_... name; verifies against
    /// pcap_findalldevs. Returns a null-terminated name in `buf`.
    fn resolveDeviceName(self: *NpcapPort, buf: []u8, api: PcapApi) ?[:0]const u8 {
        const ifname = self.ifname;
        var errbuf: [PCAP_ERRBUF_SIZE]u8 = [_]u8{0} ** PCAP_ERRBUF_SIZE;
        var devs: ?*PcapIf = null;
        if (api.findalldevs(&devs, &errbuf) != 0) return null;
        defer if (devs) |d| api.freealldevs(d);

        // Candidate name, in order of precedence.
        var cand_buf: [512]u8 = undefined;
        const candidate: [:0]const u8 = if (std.mem.startsWith(u8, ifname, "\\Device\\NPF_"))
            std.fmt.bufPrintZ(&cand_buf, "{s}", .{ifname}) catch return null
        else if (std.mem.startsWith(u8, ifname, "{"))
            std.fmt.bufPrintZ(&cand_buf, "\\Device\\NPF_{s}", .{ifname}) catch return null
        else
            std.fmt.bufPrintZ(&cand_buf, "\\Device\\NPF_{{{s}}}", .{ifname}) catch return null;

        var node = devs;
        while (node) |dev| : (node = dev.next) {
            const dev_name = if (dev.name) |nm| std.mem.span(nm) else continue;
            if (std.ascii.eqlIgnoreCase(dev_name, candidate)) {
                const out = std.fmt.bufPrintZ(buf, "{s}", .{dev_name}) catch return null;
                return out;
            }
        }

        // Last resort: friendly-name-ish match on description (contains the
        // requested name case-insensitively).
        node = devs;
        while (node) |dev| : (node = dev.next) {
            const desc = if (dev.description) |d| std.mem.span(d) else continue;
            if (std.ascii.indexOfIgnoreCase(desc, ifname) != null) {
                const dev_name = std.mem.span(dev.name.?);
                const out = std.fmt.bufPrintZ(buf, "{s}", .{dev_name}) catch return null;
                return out;
            }
        }
        return null;
    }

    pub fn close(self: *NpcapPort) void {
        if (comptime builtin.os.tag != .windows) return;
        self.halt.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.handle) |h| {
            if (self.api) |api| api.close(h);
            self.handle = null;
        }
        if (self.api) |api| {
            if (api.dll) |dll| {
                const dllp: *kernel32.struct_HINSTANCE__ = @ptrCast(@alignCast(dll));
                _ = kernel32.FreeLibrary(dllp);
            }
            self.api = null;
        }
        self.head.store(0, .monotonic);
        self.tail.store(0, .monotonic);
    }

    /// Read one raw Ethernet frame from the SPSC ring. Returns null when
    /// empty (the pump drains non-pollable ports every iteration). Frames
    /// larger than the session budget are dropped by the worker (H-3) and
    /// counted in `stats.drops`.
    pub fn read(self: *NpcapPort, buf: []u8) anyerror!?usize {
        if (comptime builtin.os.tag != .windows) return error.NotWindows;
        if (self.handle == null) return error.DeviceClosed;

        const h = self.head.load(.acquire);
        const t = self.tail.load(.acquire);
        if (h == t) return null;

        const slot = &self.queue[h % RX_QUEUE_CAP];
        const len = slot.len;
        if (len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..len], slot.data[0..len]);
        self.head.store(h + 1, .release);
        self.stats.rx_pkts += 1;
        self.stats.rx_bytes += len;
        return len;
    }

    /// Send one raw Ethernet frame. Frames larger than the session budget
    /// are rejected with `error.FrameTooLarge` and counted as drops (H-3).
    pub fn write(self: *NpcapPort, data: []const u8) anyerror!usize {
        if (comptime builtin.os.tag != .windows) return error.NotWindows;
        const api = self.api orelse return error.DeviceClosed;
        const handle = self.handle orelse return error.DeviceClosed;
        if (data.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return error.FrameTooLarge;
        }
        if (api.sendPacket(handle, data.ptr, @intCast(data.len)) != 0) return error.TxFailed;
        self.stats.tx_pkts += 1;
        self.stats.tx_bytes += data.len;
        return data.len;
    }

    /// Promiscuous mode is applied at open time only (Npcap cannot toggle a
    /// live handle); disabling is a logged no-op (documented variance).
    pub fn setPromiscuous(self: *NpcapPort, on: bool) NpcapError!void {
        if (comptime builtin.os.tag != .windows) return error.NotWindows;
        if (self.handle == null) return error.DeviceClosed;
        if (!on and self.promisc) {
            std.log.info("npcap: promiscuous mode cannot be toggled off on a live Npcap handle; port stays promiscuous until close", .{});
        }
    }

    /// RX worker: loop pcap_next_ex (10 ms read timeout), push frames into
    /// the ring. Frames over the budget are dropped and counted (H-3); when
    /// the ring is full, incoming frames are dropped (counted) — the pump
    /// drains every iteration, so saturation is a LAN-flood condition. A
    /// 1 ms sleep on idle guards against pcap builds that ignore the read
    /// timeout and return immediately.
    fn rxWorker(self: *NpcapPort) void {
        const api = self.api.?;
        const handle = self.handle.?;
        while (!self.halt.load(.acquire)) {
            var hdr: ?*const PcapPkthdr = null;
            var data: ?[*]const u8 = null;
            const rc = api.nextEx(handle, &hdr, &data);
            if (rc <= 0) {
                if (rc == -1) {
                    const err = if (api.getErr(handle)) |e| std.mem.sliceTo(e, 0) else "(no detail)";
                    std.log.err("npcap: rx error on '{s}': {s}", .{ self.ifname, err });
                }
                // rc == 0: no packet (timeout); rc == -2: handle broken.
                if (rc == -2) break;
                if (rc == 0) std.Thread.sleep(1 * std.time.ns_per_ms);
                continue;
            }
            const len: usize = hdr.?.caplen;
            if (len == 0 or len > SESSION_FRAME_BUDGET) {
                self.stats.drops += 1;
                continue;
            }
            const t = self.tail.load(.acquire);
            if (t - self.head.load(.acquire) >= RX_QUEUE_CAP) {
                self.stats.drops += 1;
                continue;
            }
            const slot = &self.queue[t % RX_QUEUE_CAP];
            @memcpy(slot.data[0..len], data.?[0..len]);
            slot.len = len;
            self.tail.store(t + 1, .release);
        }
    }
};

/// Wrap an `NpcapPort` behind the `NetPort` interface.
pub fn npcapPort(port: *NpcapPort, allocator: std.mem.Allocator, ifname: []const u8) NetPort {
    port.* = .{ .allocator = allocator, .ifname = ifname };
    const V = struct {
        fn open(impl_: *anyopaque) anyerror!void {
            return asPort(impl_).open();
        }
        fn close(impl_: *anyopaque) void {
            asPort(impl_).close();
        }
        fn read(impl_: *anyopaque, buf: []u8) anyerror!?usize {
            return asPort(impl_).read(buf);
        }
        fn write(impl_: *anyopaque, data: []const u8) anyerror!usize {
            return asPort(impl_).write(data);
        }
        fn getFd(impl_: *anyopaque) std.posix.fd_t {
            _ = impl_;
            return NetPort.invalid_fd; // Npcap has no pollable fd — worker thread + ring
        }
        fn getName(impl_: *anyopaque) []const u8 {
            return asPort(impl_).ifname;
        }
        fn getMac(impl_: *anyopaque) ?[6]u8 {
            return asPort(impl_).mac;
        }
        fn getMtu(impl_: *anyopaque) usize {
            _ = impl_;
            return SESSION_FRAME_BUDGET;
        }
        fn getLayer(impl_: *anyopaque) PortLayer {
            _ = impl_;
            return .l2;
        }
        fn setPromiscuous(impl_: *anyopaque, on: bool) void {
            asPort(impl_).setPromiscuous(on) catch {};
        }
        fn getStats(impl_: *anyopaque) PortStats {
            return asPort(impl_).stats;
        }
        fn asPort(impl_: *anyopaque) *NpcapPort {
            return @as(*NpcapPort, @ptrCast(@alignCast(impl_)));
        }
    };
    return .{
        .impl = @ptrCast(port),
        .vtable = &.{
            .open = &V.open,
            .close = &V.close,
            .read = &V.read,
            .write = &V.write,
            .getFd = &V.getFd,
            .getName = &V.getName,
            .getMac = &V.getMac,
            .getMtu = &V.getMtu,
            .getLayer = &V.getLayer,
            .setPromiscuous = &V.setPromiscuous,
            .getStats = &V.getStats,
        },
    };
}

// ============================================================================
// Tests
// ============================================================================

test "npcapPort vtable metadata (non-Windows safe)" {
    var port = NpcapPort{ .allocator = std.testing.allocator };
    const p = npcapPort(&port, std.testing.allocator, "en0");
    try std.testing.expectEqual(PortLayer.l2, p.getLayer());
    try std.testing.expectEqual(@as(usize, SESSION_FRAME_BUDGET), p.getMtu());
    try std.testing.expectEqualStrings("en0", p.getName());
    try std.testing.expectEqual(NetPort.invalid_fd, p.getFd());
    const s = p.getStats();
    try std.testing.expectEqual(@as(u64, 0), s.drops);
}

test "npcapPort rejects non-Windows targets" {
    var port = NpcapPort{ .allocator = std.testing.allocator };
    const p = npcapPort(&port, std.testing.allocator, "en0");
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var buf = [_]u8{0} ** 64;
    try std.testing.expectError(error.NotWindows, p.open());
    try std.testing.expectError(error.NotWindows, p.write(&buf));
    try std.testing.expectError(error.NotWindows, p.read(&buf));
    p.setPromiscuous(true);
}

test "npcapPort open degrades cleanly without Npcap" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    var port = NpcapPort{ .allocator = std.testing.allocator };
    const p = npcapPort(&port, std.testing.allocator, "no-such-interface-xyz");
    // Bare CI runners have no pcap.dll → NpcapNotInstalled; with Npcap
    // installed, the bogus name must fail name resolution cleanly. The
    // client contract: a clean error, never a crash or hang.
    var open_err: ?anyerror = null;
    p.open() catch |e| {
        open_err = e;
    };
    switch (open_err orelse return error.TestExpectedError) {
        error.NpcapNotInstalled, error.InterfaceNotFound, error.OpenFailed, error.NotWindows => {},
        else => return open_err.?,
    }
    p.close();
}

test "npcapPort ring is SPSC: push then pop, drop on full" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    var port = NpcapPort{ .allocator = std.testing.allocator };
    // Dummy handle so read() takes the ring path (only null-ness is checked).
    port.handle = @ptrFromInt(1);

    // Fill the ring past capacity (producer side), then drain (consumer).
    for (0..RX_QUEUE_CAP + 10) |i| {
        const t = port.tail.load(.acquire);
        if (t - port.head.load(.acquire) >= RX_QUEUE_CAP) continue; // full → drop
        const slot = &port.queue[t % RX_QUEUE_CAP];
        slot.len = 60;
        @memset(slot.data[0..60], @intCast(i & 0xFF));
        port.tail.store(t + 1, .release);
    }
    try std.testing.expectEqual(@as(usize, RX_QUEUE_CAP), port.tail.load(.acquire) - port.head.load(.acquire));

    var buf: [2048]u8 = undefined;
    var n_read: usize = 0;
    while (try port.read(&buf)) |n| {
        n_read += 1;
        try std.testing.expect(n == 60);
    }
    try std.testing.expectEqual(@as(usize, RX_QUEUE_CAP), n_read);
    port.handle = null;
}
