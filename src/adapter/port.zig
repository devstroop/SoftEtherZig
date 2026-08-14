//! NetPort — first-class network port interface.
//!
//! Makes the "local side" of a VPN connection an explicit, pluggable
//! abstraction (L2 Network Bridge proposal §4.1). Today the client opens one
//! L3 virtual device (utun / tun_linux / Wintun / fd_adapter) and shuttles IP
//! packets; bridge and monitor roles (future milestones) plug L2 ports
//! (af_packet / bpf / npcap / ether_manager) behind the same interface.
//!
//! L3 devices are wrapped unchanged via `l3Port()`; the owning
//! `VirtualAdapter` keeps responsibility for open/close/configure lifecycle
//! (l3 ports are already open when handed to the port) — the port's
//! open()/close() are no-ops for L3 so the data pump treats every port
//! uniformly.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Layer a port operates at.
pub const PortLayer = enum {
    /// IP packets (utun, tun_linux, Wintun, fd_adapter)
    l3,
    /// Raw Ethernet frames (af_packet, bpf, npcap, ether_manager)
    l2,
};

/// Port traffic counters. Consumed by bridge/monitor stats and diagnostics.
pub const PortStats = struct {
    rx_pkts: u64 = 0,
    rx_bytes: u64 = 0,
    tx_pkts: u64 = 0,
    tx_bytes: u64 = 0,
    drops: u64 = 0,
};

/// Pollable/handle-based interface to a network port.
///
/// The data pump must never reach into a device's internals — all I/O,
/// metadata and statistics go through this interface.
pub const NetPort = struct {
    impl: *anyopaque,
    vtable: *const VTable,

    /// Platform-correct "no pollable fd" sentinel (-1 on POSIX,
    /// INVALID_HANDLE_VALUE on Windows where posix.fd_t is a handle).
    pub const invalid_fd: posix.fd_t = if (builtin.os.tag == .windows)
        std.os.windows.INVALID_HANDLE_VALUE
    else
        @as(posix.fd_t, -1);

    pub const VTable = struct {
        open: *const fn (impl: *anyopaque) anyerror!void,
        close: *const fn (impl: *anyopaque) void,
        read: *const fn (impl: *anyopaque, buf: []u8) anyerror!?usize,
        write: *const fn (impl: *anyopaque, data: []const u8) anyerror!usize,
        getFd: *const fn (impl: *anyopaque) posix.fd_t,
        getName: *const fn (impl: *anyopaque) []const u8,
        getMac: *const fn (impl: *anyopaque) ?[6]u8,
        getMtu: *const fn (impl: *anyopaque) usize,
        getLayer: *const fn (impl: *anyopaque) PortLayer,
        setPromiscuous: *const fn (impl: *anyopaque, on: bool) void,
        getStats: *const fn (impl: *anyopaque) PortStats,
    };

    pub fn open(self: NetPort) anyerror!void {
        return self.vtable.open(self.impl);
    }

    pub fn close(self: NetPort) void {
        self.vtable.close(self.impl);
    }

    /// Read one packet/frame. Returns null on non-blocking no-data.
    pub fn read(self: NetPort, buf: []u8) anyerror!?usize {
        return self.vtable.read(self.impl, buf);
    }

    pub fn write(self: NetPort, data: []const u8) anyerror!usize {
        return self.vtable.write(self.impl, data);
    }

    /// Pollable handle for the data pump. Returns -1 when the port is not
    /// fd-pollable (e.g. Wintun uses event handles).
    pub fn getFd(self: NetPort) posix.fd_t {
        return self.vtable.getFd(self.impl);
    }

    pub fn getName(self: NetPort) []const u8 {
        return self.vtable.getName(self.impl);
    }

    pub fn getMac(self: NetPort) ?[6]u8 {
        return self.vtable.getMac(self.impl);
    }

    /// Maximum frame the port can carry at its layer.
    pub fn getMtu(self: NetPort) usize {
        return self.vtable.getMtu(self.impl);
    }

    pub fn getLayer(self: NetPort) PortLayer {
        return self.vtable.getLayer(self.impl);
    }

    /// L2 ports enter promiscuous mode; L3 virtual devices have no shared
    /// medium, so this is a no-op there.
    pub fn setPromiscuous(self: NetPort, on: bool) void {
        self.vtable.setPromiscuous(self.impl, on);
    }

    pub fn getStats(self: NetPort) PortStats {
        return self.vtable.getStats(self.impl);
    }
};

/// Wrap an existing L3 device behind a `NetPort` with unchanged behavior.
/// `max_frame` is the port's maximum readable frame size (device module's
/// MAX_PACKET_SIZE). The device must already be open; lifecycle (open/close/
/// configure) stays with the owning VirtualAdapter.
pub fn l3Port(comptime T: type, device: *T, comptime max_frame: usize) NetPort {
    const P = L3Port(T, max_frame);
    return .{ .impl = @ptrCast(device), .vtable = &l3VTable(P) };
}

fn l3VTable(comptime P: type) NetPort.VTable {
    return .{
        .open = &P.open,
        .close = &P.close,
        .read = &P.read,
        .write = &P.write,
        .getFd = &P.getFd,
        .getName = &P.getName,
        .getMac = &P.getMac,
        .getMtu = &P.getMtu,
        .getLayer = &P.getLayer,
        .setPromiscuous = &P.setPromiscuous,
        .getStats = &P.getStats,
    };
}

/// Generic L3 device port implementation. Adapts the device's platform
/// quirks (`@hasDecl`/`@hasField`) so one wrapper serves utun, tun_linux,
/// Wintun and fd_adapter.
fn L3Port(comptime T: type, comptime max_frame: usize) type {
    return struct {
        fn device(impl: *anyopaque) *T {
            return @as(*T, @ptrCast(@alignCast(impl)));
        }

        // Lifecycle: the owning VirtualAdapter creates and opens the device
        // before wrapping it, so the port's open/close are no-ops for L3.
        fn open(impl: *anyopaque) anyerror!void {
            _ = device(impl);
        }

        fn close(impl: *anyopaque) void {
            _ = device(impl);
        }

        fn read(impl: *anyopaque, buf: []u8) anyerror!?usize {
            return device(impl).read(buf);
        }

        fn write(impl: *anyopaque, data: []const u8) anyerror!usize {
            return device(impl).write(data);
        }

        fn getFd(impl: *anyopaque) posix.fd_t {
            const dev = device(impl);
            if (@hasDecl(T, "getFd")) return dev.getFd();
            return NetPort.invalid_fd; // Wintun: event-handle based, not fd-pollable
        }

        fn getName(impl: *anyopaque) []const u8 {
            return device(impl).getName();
        }

        fn getMac(impl: *anyopaque) ?[6]u8 {
            return device(impl).getMac();
        }

        fn getMtu(impl: *anyopaque) usize {
            _ = device(impl);
            return max_frame;
        }

        fn getLayer(impl: *anyopaque) PortLayer {
            _ = device(impl);
            return .l3;
        }

        fn setPromiscuous(impl: *anyopaque, on: bool) void {
            _ = device(impl);
            _ = on;
        }

        fn getStats(impl: *anyopaque) PortStats {
            const dev = device(impl);
            const s = dev.getStats();
            var out = PortStats{};
            const Stats = @TypeOf(s);
            if (@hasField(Stats, "packets_sent")) {
                // utun shape: packets_sent/bytes_sent/packets_received/
                // bytes_received/errors/dropped
                out.tx_pkts = s.packets_sent;
                out.tx_bytes = s.bytes_sent;
                out.rx_pkts = s.packets_received;
                out.rx_bytes = s.bytes_received;
                if (@hasField(Stats, "dropped")) out.drops = s.dropped;
            }
            if (@hasField(Stats, "send_packets")) {
                // tun_linux / Wintun / fd_adapter shape:
                // send_packets/send_bytes/recv_packets/recv_bytes
                out.tx_pkts = s.send_packets;
                out.tx_bytes = s.send_bytes;
                out.rx_pkts = s.recv_packets;
                out.rx_bytes = s.recv_bytes;
            }
            return out;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const FakeDevice = struct {
    open_count: usize = 0,
    closed: bool = false,
    data: []const u8 = &.{},
    stats: utunStats = .{},

    const test_fd: posix.fd_t = if (builtin.os.tag == .windows) @ptrFromInt(3) else 7;

    fn open(_: std.mem.Allocator) error{}!*FakeDevice {
        unreachable;
    }
    fn close(self: *FakeDevice) void {
        self.closed = true;
    }
    fn getName(_: *const FakeDevice) []const u8 {
        return "fake0";
    }
    fn getMac(_: *const FakeDevice) [6]u8 {
        return .{ 0x02, 0x00, 0x5E, 0x01, 0x02, 0x03 };
    }
    fn getFd(_: *const FakeDevice) posix.fd_t {
        return test_fd;
    }
    fn isOpen(_: *const FakeDevice) bool {
        return true;
    }
    fn read(self: *FakeDevice, buf: []u8) !?usize {
        if (self.data.len == 0) return null;
        const n = @min(buf.len, self.data.len);
        @memcpy(buf[0..n], self.data[0..n]);
        return n;
    }
    fn write(self: *FakeDevice, data: []const u8) !usize {
        self.data = data;
        return data.len;
    }
    fn getStats(_: *const FakeDevice) utunStats {
        return .{ .packets_sent = 3, .bytes_sent = 300, .packets_received = 4, .bytes_received = 400, .dropped = 1 };
    }
    fn configure(_: *FakeDevice, _: u32, _: u32, _: u32) !void {}
};

const utunStats = struct {
    packets_sent: u64 = 0,
    bytes_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_received: u64 = 0,
    errors: u64 = 0,
    dropped: u64 = 0,
};

const tunStats = struct {
    send_packets: u64 = 0,
    send_bytes: u64 = 0,
    recv_packets: u64 = 0,
    recv_bytes: u64 = 0,
};

test "l3Port vtable round-trip" {
    var dev = FakeDevice{};
    const port = l3Port(FakeDevice, &dev, 1514);

    try std.testing.expectEqual(PortLayer.l3, port.getLayer());
    try std.testing.expectEqual(@as(usize, 1514), port.getMtu());
    try std.testing.expectEqualStrings("fake0", port.getName());
    try std.testing.expectEqual(FakeDevice.test_fd, port.getFd());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x5E, 0x01, 0x02, 0x03 }, &port.getMac().?);
    var empty_buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try port.read(&empty_buf));

    const payload = "hello";
    try std.testing.expectEqual(payload.len, try port.write(payload));
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, payload.len), try port.read(&buf));
}

test "l3Port stats mapping (utun shape)" {
    var dev = FakeDevice{};
    const port = l3Port(FakeDevice, &dev, 1514);
    const s = port.getStats();
    try std.testing.expectEqual(@as(u64, 3), s.tx_pkts);
    try std.testing.expectEqual(@as(u64, 300), s.tx_bytes);
    try std.testing.expectEqual(@as(u64, 4), s.rx_pkts);
    try std.testing.expectEqual(@as(u64, 400), s.rx_bytes);
    try std.testing.expectEqual(@as(u64, 1), s.drops);
}

test "l3Port stats mapping (tun shape, no drops field)" {
    const FakeTun = struct {
        stats: tunStats = .{ .send_packets = 9, .send_bytes = 900, .recv_packets = 8, .recv_bytes = 800 },
        fn read(_: *@This(), _: []u8) !?usize {
            return null;
        }
        fn write(_: *@This(), data: []const u8) !usize {
            return data.len;
        }
        fn getFd(_: *const @This()) posix.fd_t {
            return NetPort.invalid_fd;
        }
        fn getName(_: *const @This()) []const u8 {
            return "tunX";
        }
        fn getMac(_: *const @This()) [6]u8 {
            return .{ 1, 2, 3, 4, 5, 6 };
        }
        fn getStats(_: *const @This()) tunStats {
            return .{ .send_packets = 9, .send_bytes = 900, .recv_packets = 8, .recv_bytes = 800 };
        }
    };
    var dev = FakeTun{};
    const port = l3Port(FakeTun, &dev, 2048);
    const s = port.getStats();
    try std.testing.expectEqual(@as(u64, 9), s.tx_pkts);
    try std.testing.expectEqual(@as(u64, 900), s.tx_bytes);
    try std.testing.expectEqual(@as(u64, 8), s.rx_pkts);
    try std.testing.expectEqual(@as(u64, 800), s.rx_bytes);
    try std.testing.expectEqual(@as(u64, 0), s.drops);
    try std.testing.expectEqual(NetPort.invalid_fd, port.getFd()); // no-fd device
}

test "l3Port promiscuous is a no-op" {
    var dev = FakeDevice{};
    const port = l3Port(FakeDevice, &dev, 1514);
    port.setPromiscuous(true);
    port.setPromiscuous(false);
}
