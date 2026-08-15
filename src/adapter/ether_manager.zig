//! Android EthernetManager best-effort L2 ingress port (L2 Network Bridge
//! proposal §4.1, issue #59).
//!
//! Android runs the Linux kernel, so the raw-socket machinery is AF_PACKET
//! (`af_packet.zig`): the kernel grants the fd when the process actually has
//! CAP_NET_RAW — rooted devices, USB-Ethernet (OTG) adapters, or setups
//! where a root-granted helper hands the fd over (the same H-7 pattern as
//! the macOS BPF helper). This module adds what Android-specific wiring the
//! platform demands on top of that shared core:
//!
//! - **EthernetManager-style enumeration:** Android exposes wired NICs
//!   (USB-Ethernet) as kernel netdevs named `eth*`, `rndis*`, `usb*`,
//!   `enx*` etc. `open()` validates the configured name against getifaddrs(3)
//!   and, best-effort, falls back to the first wired NIC it can find.
//! - **Capability detection (H-8):** open() surfaces a missing CAP_NET_RAW
//!   grant as `error.NoCapability` — a clean, enumerable failure. Absent any
//!   exposed NIC the port fails with `error.UnsupportedRole`.
//! - **Never silently falls back to client mode:** a failed open() propagates
//!   an error to the bridge pump; the pump aborts bridge mode rather than
//!   silently continuing as an L3 client (issue #59 acceptance).
//!
//! Best-effort only: stock Android apps cannot open raw sockets, so the
//! supported topologies are rooted devices / OTG ethernet / root-granted
//! helpers. Vendor HAL variance is out of scope (documented in the ops
//! guide, I-13).

const std = @import("std");
const builtin = @import("builtin");
const port_mod = @import("port.zig");
const af_packet = @import("af_packet.zig");
const NetPort = port_mod.NetPort;
const PortLayer = port_mod.PortLayer;
const PortStats = port_mod.PortStats;

/// Zig has no `.android` OS tag — Android is the Linux kernel with the
/// android/androideabi ABI (repo convention, see `mod.zig`).
pub const is_android = builtin.os.tag == .linux and
    (builtin.abi == .android or builtin.abi == .androideabi);

/// Errors specific to the Android best-effort port lifecycle.
pub const EtherManagerError = error{
    /// Ports can only be opened on Android.
    NotAndroid,
    /// No wired NIC is exposed by the platform (no root, no OTG ethernet,
    /// vendor HAL hid the interface). Best-effort port cannot be used —
    /// "unsupported role" (issue #59).
    UnsupportedRole,
    /// Interface name invalid or not found.
    InterfaceNotFound,
    /// socket(AF_PACKET) failed (e.g. no CAP_NET_RAW — H-8).
    OpenFailed,
    /// bind(2) to the interface failed.
    BindFailed,
    /// Port has been closed / fd is invalid.
    DeviceClosed,
    /// Caller lacks CAP_NET_RAW (H-8); open() returned EPERM on socket(2).
    NoCapability,
    /// Frames larger than the session budget (1514) are not forwarded (H-3).
    FrameTooLarge,
};

/// Wired-NIC name prefixes on Android (EthernetManager / USB ethernet /
/// RNDIS tethering / systemd-style enx<MAC>). Wireless (wlan*), tunnel
/// (tun*/utun*/ppp*) and loopback are never considered "wired".
const WIRED_PREFIXES = [_][]const u8{ "eth", "enx", "enp", "ens", "usb", "rndis" };

fn isWiredName(name: []const u8) bool {
    for (WIRED_PREFIXES) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return true;
    }
    return false;
}

/// getifaddrs(3) entry — same shape as `nic_enumerate` / `af_packet`.
const IfAddrs = extern struct {
    ifa_next: ?*IfAddrs,
    ifa_name: [*:0]const u8,
    ifa_flags: c_uint,
    ifa_addr: ?*const std.posix.sockaddr,
    ifa_netmask: ?*const std.posix.sockaddr,
    ifa_ifu: extern union {
        ifu_broadaddr: ?*const std.posix.sockaddr,
        ifu_dstaddr: ?*const std.posix.sockaddr,
    },
    ifa_data: ?*anyopaque,
};

/// Walk getifaddrs(3) once. Returns:
///   - `name` itself when it is a present interface,
///   - otherwise the first wired NIC (best-effort fallback),
///   - `error.UnsupportedRole` when no wired NIC is exposed at all,
///   - `error.InterfaceNotFound` when the configured name does not exist and
///     enumeration itself failed (platform hid everything).
///
/// Kernel-generic (works on any getifaddrs host — tests run on Linux CI);
/// the Android-only gate lives in `open()`.
fn resolveWiredIfname(name: []const u8, buf: []u8) EtherManagerError![]const u8 {
    const getifaddrs = @extern(*const fn (?*?*IfAddrs) callconv(.c) c_int, .{ .name = "getifaddrs" });
    const freeifaddrs = @extern(*const fn (?*IfAddrs) callconv(.c) void, .{ .name = "freeifaddrs" });

    var head: ?*IfAddrs = null;
    if (getifaddrs(&head) != 0) {
        if (name.len == 0 or name.len >= af_packet.IFNAMSIZ) return error.InterfaceNotFound;
        return error.UnsupportedRole;
    }
    defer if (head) |h| freeifaddrs(h);

    var node = head;
    var fallback: ?[]const u8 = null;
    while (node) |entry| : (node = entry.ifa_next) {
        const ifname = std.mem.span(entry.ifa_name);
        if (std.mem.eql(u8, ifname, name)) {
            if (name.len >= buf.len) return error.InterfaceNotFound;
            @memcpy(buf[0..name.len], name);
            return buf[0..name.len];
        }
        if (isWiredName(ifname) and fallback == null) fallback = ifname;
    }

    // Best-effort fallback: the platform's wired NIC (USB ethernet) even
    // when the configured name doesn't match (Android renames NICs across
    // reboots / HAL versions).
    if (fallback) |fb| {
        if (fb.len >= buf.len) return error.InterfaceNotFound;
        std.log.info("ether_manager: best-effort — interface '{s}' not found, using wired NIC '{s}'", .{ name, fb });
        @memcpy(buf[0..fb.len], fb);
        return buf[0..fb.len];
    }
    return error.UnsupportedRole;
}

/// Android best-effort L2 port.
///
/// Composition over the AF_PACKET core (`AfPacketPort`): the raw-socket
/// machinery, CAP_NET_RAW probe (NoCapability), MTU clamp (H-3), host-IP
/// warning (H-5) and promiscuous membership are all af_packet's. This port
/// adds the Android-facing layer: Android-only gate, EthernetManager-style
/// NIC resolution and the "unsupported role" degrade.
///
/// The pump owns this instance (as it owns an L3 device behind `l3Port`);
/// `etherManagerPort()` fills it and hands back a `NetPort` pointing at it.
pub const EtherManagerPort = struct {
    inner: af_packet.AfPacketPort = .{},
    ifname: []const u8 = "",

    pub fn open(self: *EtherManagerPort) EtherManagerError!void {
        if (comptime !is_android) return error.NotAndroid;

        // Best-effort NIC resolution (EthernetManager-style enumeration).
        var name_buf: [af_packet.IFNAMSIZ]u8 = undefined;
        const resolved = try resolveWiredIfname(self.ifname, &name_buf);
        std.log.info("ether_manager: android ingress interface '{s}'", .{resolved});

        // Delegate to the AF_PACKET core: socket(AF_PACKET) probe surfaces
        // EPERM (no CAP_NET_RAW — unrooted device) as error.NoCapability.
        self.inner.ifname = resolved;
        try self.inner.open();
    }

    pub fn close(self: *EtherManagerPort) void {
        self.inner.close();
    }

    /// Read one raw Ethernet frame (AF_PACKET, non-blocking).
    pub fn read(self: *EtherManagerPort, buf: []u8) anyerror!?usize {
        return self.inner.read(buf);
    }

    /// Send one raw Ethernet frame on the bound interface.
    pub fn write(self: *EtherManagerPort, data: []const u8) anyerror!usize {
        return self.inner.write(data);
    }

    pub fn setPromiscuous(self: *EtherManagerPort, on: bool) anyerror!void {
        return self.inner.setPromiscuous(on);
    }
};

/// Wrap an `EtherManagerPort` behind the `NetPort` interface.
pub fn etherManagerPort(port: *EtherManagerPort, ifname: []const u8) NetPort {
    port.* = .{ .ifname = ifname };
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
            return asPort(impl_).inner.fd;
        }
        fn getName(impl_: *anyopaque) []const u8 {
            return asPort(impl_).ifname;
        }
        fn getMac(impl_: *anyopaque) ?[6]u8 {
            return asPort(impl_).inner.mac;
        }
        fn getMtu(impl_: *anyopaque) usize {
            _ = impl_;
            return af_packet.SESSION_FRAME_BUDGET;
        }
        fn getLayer(impl_: *anyopaque) PortLayer {
            _ = impl_;
            return .l2;
        }
        fn setPromiscuous(impl_: *anyopaque, on: bool) void {
            asPort(impl_).setPromiscuous(on) catch {};
        }
        fn getStats(impl_: *anyopaque) PortStats {
            return asPort(impl_).inner.stats;
        }

        fn asPort(impl_: *anyopaque) *EtherManagerPort {
            return @ptrCast(@alignCast(impl_));
        }
    };
    return .{
        .impl = port,
        .vtable = &.{
            .open = V.open,
            .close = V.close,
            .read = V.read,
            .write = V.write,
            .getFd = V.getFd,
            .getName = V.getName,
            .getMac = V.getMac,
            .getMtu = V.getMtu,
            .getLayer = V.getLayer,
            .setPromiscuous = V.setPromiscuous,
            .getStats = V.getStats,
        },
    };
}

// ============================================================================
// Tests
// ============================================================================

test "etherManagerPort vtable metadata (all targets safe)" {
    var port = EtherManagerPort{};
    const p = etherManagerPort(&port, "eth0");
    try std.testing.expectEqual(PortLayer.l2, p.getLayer());
    try std.testing.expectEqual(@as(usize, af_packet.SESSION_FRAME_BUDGET), p.getMtu());
    try std.testing.expectEqualStrings("eth0", p.getName());
    try std.testing.expectEqual(NetPort.invalid_fd, p.getFd());
    const s = p.getStats();
    try std.testing.expectEqual(@as(u64, 0), s.drops);
    try std.testing.expectEqual(@as(?[6]u8, null), p.getMac());
}

test "etherManagerPort rejects non-Android targets" {
    var port = EtherManagerPort{};
    const p = etherManagerPort(&port, "eth0");
    if (comptime is_android) return error.SkipZigTest;
    try std.testing.expectError(error.NotAndroid, p.open());
}

test "etherManagerPort wired-NIC name classification" {
    try std.testing.expect(isWiredName("eth0"));
    try std.testing.expect(isWiredName("rndis0"));
    try std.testing.expect(isWiredName("usb0"));
    try std.testing.expect(isWiredName("enx001122334455"));
    try std.testing.expect(!isWiredName("lo"));
    try std.testing.expect(!isWiredName("wlan0"));
    try std.testing.expect(!isWiredName("tun0"));
    try std.testing.expect(!isWiredName("utun3"));
    try std.testing.expect(!isWiredName("ppp0"));
}

test "etherManagerPort best-effort resolution (kernel-generic)" {
    // Runs on any getifaddrs host (Linux CI included). The loopback
    // interface exists on every host — the configured name wins. Its
    // spelling differs per OS: "lo" (Linux) / "lo0" (macOS).
    var buf: [af_packet.IFNAMSIZ]u8 = undefined;
    const r = resolveWiredIfname("lo", &buf) catch {
        const r0 = try resolveWiredIfname("lo0", &buf);
        try std.testing.expectEqualStrings("lo0", r0);
        return;
    };
    try std.testing.expectEqualStrings("lo", r);

    // A bogus name falls back to a wired NIC; hosts without one degrade to
    // the clean "unsupported role" error. Either outcome is valid.
    const fallback = resolveWiredIfname("zz-bogus-interface", &buf) catch |err| {
        try std.testing.expectEqual(EtherManagerError.UnsupportedRole, err);
        return;
    };
    try std.testing.expect(fallback.len > 0);
}

test "etherManagerPort delegates I/O to the AF_PACKET core" {
    if (builtin.os.tag != .linux and comptime !is_android) return error.SkipZigTest;
    var port = EtherManagerPort{};
    const p = etherManagerPort(&port, "eth0");
    // Not open — the AF_PACKET core's DeviceClosed must surface through
    // the delegation (proves read/write reach the shared machinery).
    try std.testing.expectError(error.DeviceClosed, p.write(&[_]u8{0} ** 64));
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.DeviceClosed, p.read(&buf));
}