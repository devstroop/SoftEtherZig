//! AF_PACKET L2 ingress port (L2 Network Bridge proposal §4.1, H-3/H-5/H-8).
//!
//! Linux-only NetPort implementation over AF_PACKET (SOCK_RAW, ETH_P_ALL)
//! bound to a named interface, used by the bridge pump (issue #56) as the
//! physical-side ingress. Mirrors `port.l3Port()`: the caller owns the
//! `AfPacketPort` instance and the returned `NetPort` points at it; the pump
//! drives open/close/read/write uniformly through the vtable.
//!
//! Design decisions (proposal §4.6, §6):
//! - **CAP_NET_RAW detection (H-8):** `socket(AF_PACKET)` fails with EPERM
//!   without the capability. `open()` surfaces that as `error.NoCapability`
//!   — clean failure, never a crash or silent passthrough.
//! - **MTU clamp (H-3):** the session's L2 frame budget is 1514 bytes
//!   (14-byte Ethernet header + 1500 payload). An interface MTU > 1500 logs a
//!   warning at open; frames larger than 1514 are dropped and counted in
//!   `PortStats.drops`. Jumbo frames are unsupported in v1.
//! - **Host-IP warning (H-5):** if the ingress NIC carries an IPv4/IPv6
//!   address, open() warns — the host's own traffic would be bridged into
//!   the VPN (MAC exclusion lands in a later milestone).
//! - **PACKET_MR_PROMISC** membership is toggled via `setPromiscuous(bool)`
//!   (PACKET_ADD/DROP_MEMBERSHIP). v1 deliberately does not use the
//!   PACKET_MMAP ring (documented; revisit if profiling demands).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const port_mod = @import("port.zig");
const NetPort = port_mod.NetPort;
const PortLayer = port_mod.PortLayer;
const PortStats = port_mod.PortStats;

/// Session L2 frame budget (proposal §4.6): 14-byte header + 1500 payload.
/// Frames above this are dropped and counted in `PortStats.drops`.
pub const SESSION_FRAME_BUDGET: usize = 1514;

/// Prefix length of an interface name (IFNAMSIZ - 1).
pub const IFNAMSIZ: usize = 16;

/// Linux AF_PACKET family id.
const AF_PACKET: u32 = 17;
/// Ethernet protocol selector for the packet socket (network byte order).
const ETH_P_ALL: u16 = 0x0003;
/// Promiscuous membership request type (PACKET_MR_PROMISC).
const PACKET_MR_PROMISC: u16 = 1;

const SOL_PACKET: c_int = 263;
const PACKET_ADD_MEMBERSHIP: c_int = 1;
const PACKET_DROP_MEMBERSHIP: c_int = 2;
const SIOCGIFINDEX: c_uint = 0x8933;
const SIOCGIFMTU: c_uint = 0x8921;
const SIOCGIFHWADDR: c_uint = 0x8927;

const SockaddrLl = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: c_int,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

const PacketMreq = extern struct {
    mr_ifindex: c_int,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [8]u8,
};

const IfreqIndex = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    ifr_ifindex: c_int,
    padding: [22]u8,
};

const IfreqMtu = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    ifr_mtu: c_int,
    padding: [22]u8,
};

const IfreqHwaddr = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    // Raw 16-byte sockaddr region; `sa_data` naming differs per platform
    // (Linux: `data`, BSDs: `sa_data`) so copy bytes 2..8 manually.
    ifr_hwaddr: [16]u8,
    padding: [8]u8,
};

/// Errors specific to AF_PACKET port lifecycle.
pub const AfPacketError = error{
    /// Ports can only be opened on Linux.
    NotLinux,
    /// Interface name invalid or not found.
    InterfaceNotFound,
    /// socket(AF_PACKET) failed (e.g. no CAP_NET_RAW — H-8).
    OpenFailed,
    /// bind(2) to the interface failed.
    BindFailed,
    /// setsockopt(PACKET_ADD/DROP_MEMBERSHIP) failed.
    PromiscFailed,
    /// Port has been closed / fd is invalid.
    DeviceClosed,
    /// Caller lacks CAP_NET_RAW (H-8); open() returned EPERM on socket(2).
    NoCapability,
    /// Frames larger than the session budget (1514) are not forwarded (H-3).
    FrameTooLarge,
};

/// AF_PACKET port implementation.
///
/// The pump owns this instance (as it owns an L3 device behind `l3Port`);
/// `afPacketPort()` fills it and hands back a `NetPort` pointing at it.
/// `open()` performs all syscalls; on non-Linux targets every entry point
/// fails fast with `error.NotLinux`.
pub const AfPacketPort = struct {
    ifname: []const u8 = "",
    fd: posix.fd_t = NetPort.invalid_fd,
    ifindex: c_int = -1,
    mac: ?[6]u8 = null,
    iface_mtu: usize = 1500,
    stats: PortStats = .{},
    promisc: bool = false,

    /// Resolve the interface index without opening an AF_PACKET socket:
    /// a plain AF_INET DGRAM socket needs no special capability.
    fn resolveIndex(name: []const u8) AfPacketError!c_int {
        if (name.len == 0 or name.len >= IFNAMSIZ) return error.InterfaceNotFound;
        const s = posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch return error.InterfaceNotFound;
        defer posix.close(s);
        var req = IfreqIndex{ .ifr_name = [_]u8{0} ** IFNAMSIZ, .ifr_ifindex = 0, .padding = [_]u8{0} ** 22 };
        @memcpy(req.ifr_name[0..name.len], name);
        if (std.c.ioctl(s, SIOCGIFINDEX, @intFromPtr(&req)) < 0) return error.InterfaceNotFound;
        return req.ifr_ifindex;
    }

    fn ethProtoAll() u16 {
        // Kernel expects network byte order for the packet-socket protocol.
        return std.mem.nativeToBig(u16, ETH_P_ALL);
    }

    pub fn open(self: *AfPacketPort) AfPacketError!void {
        if (comptime builtin.os.tag != .linux) return error.NotLinux;
        self.ifindex = try resolveIndex(self.ifname);

        // H-8: without CAP_NET_RAW, socket(2) fails with EPERM — detect at
        // open and fail cleanly.
        const sock = posix.socket(AF_PACKET, posix.SOCK.RAW | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, ethProtoAll()) catch |err| switch (builtin.os.tag) {
            // EPERM maps to AccessDenied on Linux (incl. Android abi),
            // PermissionDenied elsewhere. Only mention the name that
            // exists per target.
            .linux => switch (err) {
                error.AccessDenied => return error.NoCapability,
                else => return error.OpenFailed,
            },
            else => switch (err) {
                error.PermissionDenied => return error.NoCapability,
                else => return error.OpenFailed,
            },
        };
        self.fd = sock;
        errdefer self.close();

        const ll = SockaddrLl{
            .sll_family = @intCast(AF_PACKET),
            .sll_protocol = ethProtoAll(),
            .sll_ifindex = self.ifindex,
            .sll_hatype = 0,
            .sll_pkttype = 0,
            .sll_halen = 0,
            .sll_addr = [_]u8{0} ** 8,
        };
        posix.bind(sock, @ptrCast(&ll), @sizeOf(SockaddrLl)) catch return error.BindFailed;

        // Interface metadata (best effort; a miss is not fatal).
        self.mac = self.readHwAddr() catch null;
        self.iface_mtu = self.readMtu() catch 1500;
        if (self.iface_mtu > 1500) {
            std.log.warn("af_packet: interface '{s}' MTU {d} > 1500 — jumbo frames unsupported, frames > 1514 will be dropped (H-3)", .{ self.ifname, self.iface_mtu });
        }

        // H-5: warn when the ingress NIC carries a host IP address.
        if (hostAddressesPresent(self.ifname)) {
            std.log.warn("af_packet: interface '{s}' has a host IP address — the host's own traffic would be bridged into the VPN (H-5)", .{self.ifname});
        }

        // PACKET_MR_PROMISC: bring promiscuous mode to the requested state.
        if (self.promisc) {
            self.setPromiscuous(true) catch {};
        }
    }

    /// ioctl(SIOCGIFHWADDR) — 6-byte MAC of the interface.
    fn readHwAddr(self: *const AfPacketPort) AfPacketError![6]u8 {
        var req = IfreqHwaddr{
            .ifr_name = [_]u8{0} ** IFNAMSIZ,
            .ifr_hwaddr = undefined,
            .padding = [_]u8{0} ** 8,
        };
        @memcpy(req.ifr_name[0..self.ifname.len], self.ifname);
        if (std.c.ioctl(self.fd, SIOCGIFHWADDR, @intFromPtr(&req)) < 0) return error.InterfaceNotFound;
        var mac: [6]u8 = undefined;
        @memcpy(&mac, req.ifr_hwaddr[2..8]);
        return mac;
    }

    /// ioctl(SIOCGIFMTU) — interface MTU in bytes.
    fn readMtu(self: *const AfPacketPort) AfPacketError!usize {
        var req = IfreqMtu{
            .ifr_name = [_]u8{0} ** IFNAMSIZ,
            .ifr_mtu = 0,
            .padding = [_]u8{0} ** 22,
        };
        @memcpy(req.ifr_name[0..self.ifname.len], self.ifname);
        if (std.c.ioctl(self.fd, SIOCGIFMTU, @intFromPtr(&req)) < 0) return error.InterfaceNotFound;
        return @intCast(req.ifr_mtu);
    }

    pub fn close(self: *AfPacketPort) void {
        if (self.fd != NetPort.invalid_fd) {
            posix.close(self.fd);
            self.fd = NetPort.invalid_fd;
        }
    }

    /// Read one raw Ethernet frame. Returns null when no data is pending
    /// (non-blocking socket). Frames larger than the session budget are
    /// consumed, counted in `stats.drops` and not reported (H-3).
    pub fn read(self: *AfPacketPort, buf: []u8) anyerror!?usize {
        if (comptime builtin.os.tag != .linux) return error.NotLinux;
        if (self.fd == NetPort.invalid_fd) return error.DeviceClosed;
        const n = posix.recvfrom(self.fd, buf, 0, null, null) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };
        if (n > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return null;
        }
        self.stats.rx_pkts += 1;
        self.stats.rx_bytes += n;
        return n;
    }

    /// Send one raw Ethernet frame. Frames larger than the session budget
    /// are rejected with `error.FrameTooLarge` and counted as drops (H-3).
    pub fn write(self: *AfPacketPort, data: []const u8) anyerror!usize {
        if (comptime builtin.os.tag != .linux) return error.NotLinux;
        if (self.fd == NetPort.invalid_fd) return error.DeviceClosed;
        if (data.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return error.FrameTooLarge;
        }
        const ll = SockaddrLl{
            .sll_family = @intCast(AF_PACKET),
            .sll_protocol = ethProtoAll(),
            .sll_ifindex = self.ifindex,
            .sll_hatype = 0,
            .sll_pkttype = 0,
            .sll_halen = 0,
            .sll_addr = [_]u8{0} ** 8,
        };
        const n = posix.sendto(self.fd, data, 0, @ptrCast(&ll), @sizeOf(SockaddrLl)) catch |err| switch (err) {
            error.WouldBlock => return error.TxBusy,
            else => return err,
        };
        self.stats.tx_pkts += 1;
        self.stats.tx_bytes += n;
        return n;
    }

    /// PACKET_ADD/DROP_MEMBERSHIP for PACKET_MR_PROMISC. The socket is
    /// bound to the interface so membership is already interface-scoped.
    pub fn setPromiscuous(self: *AfPacketPort, on: bool) AfPacketError!void {
        if (comptime builtin.os.tag != .linux) return error.NotLinux;
        if (self.fd == NetPort.invalid_fd) return error.DeviceClosed;
        const req = PacketMreq{
            .mr_ifindex = self.ifindex,
            .mr_type = PACKET_MR_PROMISC,
            .mr_alen = 0,
            .mr_address = [_]u8{0} ** 8,
        };
        const opt = if (on) PACKET_ADD_MEMBERSHIP else PACKET_DROP_MEMBERSHIP;
        const optname: u32 = @intCast(opt);
        posix.setsockopt(self.fd, SOL_PACKET, optname, std.mem.asBytes(&req)) catch {
            self.promisc = false;
            return error.PromiscFailed;
        };
        self.promisc = on;
    }
};

/// Wrap an `AfPacketPort` behind the `NetPort` interface.
pub fn afPacketPort(port: *AfPacketPort, ifname: []const u8) NetPort {
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
        fn getFd(impl_: *anyopaque) posix.fd_t {
            return asPort(impl_).fd;
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
        fn asPort(impl_: *anyopaque) *AfPacketPort {
            return @as(*AfPacketPort, @ptrCast(@alignCast(impl_)));
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

/// getifaddrs(3) entry — same shape as `nic_enumerate`.
const IfAddrs = extern struct {
    ifa_next: ?*IfAddrs,
    ifa_name: [*:0]const u8,
    ifa_flags: c_uint,
    ifa_addr: ?*const posix.sockaddr,
    ifa_netmask: ?*const posix.sockaddr,
    ifa_ifu: extern union {
        ifu_broadaddr: ?*const posix.sockaddr,
        ifu_dstaddr: ?*const posix.sockaddr,
    },
    ifa_data: ?*anyopaque,
};

/// H-5 probe: does the interface carry any IPv4/IPv6 address?
/// getifaddrs(3) — same shape as `nic_enumerate`.
fn hostAddressesPresent(ifname: []const u8) bool {
    if (comptime builtin.os.tag != .linux) return false;
    const getifaddrs = @extern(*const fn (?*?*IfAddrs) callconv(.c) c_int, .{ .name = "getifaddrs" });
    const freeifaddrs = @extern(*const fn (?*IfAddrs) callconv(.c) void, .{ .name = "freeifaddrs" });

    var head: ?*IfAddrs = null;
    if (getifaddrs(&head) != 0) return false;
    defer if (head) |h| freeifaddrs(h);

    var node = head;
    while (node) |entry| : (node = entry.ifa_next) {
        const name = std.mem.span(entry.ifa_name);
        if (!std.mem.eql(u8, name, ifname)) continue;
        const addr = entry.ifa_addr orelse continue;
        const family = addr.family;
        // AF_INET (2) or AF_INET6 (10) — has a host IP.
        if (family == 2 or family == 10) return true;
    }
    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "afPacketPort vtable metadata (non-Linux safe)" {
    var port = AfPacketPort{};
    const p = afPacketPort(&port, "eth0");
    try std.testing.expectEqual(PortLayer.l2, p.getLayer());
    try std.testing.expectEqual(@as(usize, SESSION_FRAME_BUDGET), p.getMtu());
    try std.testing.expectEqualStrings("eth0", p.getName());
    try std.testing.expectEqual(NetPort.invalid_fd, p.getFd());
    const s = p.getStats();
    try std.testing.expectEqual(@as(u64, 0), s.drops);
}

test "afPacketPort rejects non-Linux targets" {
    var port = AfPacketPort{};
    const p = afPacketPort(&port, "eth0");
    if (builtin.os.tag == .linux) return error.SkipZigTest;
    try std.testing.expectError(error.NotLinux, p.open());
    try std.testing.expectError(error.NotLinux, p.write(&[_]u8{0} ** 64));
    try std.testing.expectError(error.NotLinux, p.read(&[_]u8{0} ** 64));
    p.setPromiscuous(true);
}

test "afPacketPort session frame budget drop accounting" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var port = AfPacketPort{ .ifname = "lo" };
    const p = afPacketPort(&port, "lo");

    // open() on CI (root) or with CAP_NET_RAW; skip cleanly otherwise.
    p.open() catch {
        // lo always exists; a plain skip keeps the matrix green when the
        // runner lacks CAP_NET_RAW.
        return error.SkipZigTest;
    };
    defer p.close();

    // An oversized frame must be counted as a drop, not forwarded.
    const oversized = [_]u8{0} ** (SESSION_FRAME_BUDGET + 1);
    try std.testing.expectError(error.FrameTooLarge, p.write(&oversized));
    var s = p.getStats();
    try std.testing.expectEqual(@as(u64, 1), s.drops);

    // A valid loopback frame round-trips within budget.
    const frame = [_]u8{0} ** 64;
    const sent = try p.write(&frame);
    try std.testing.expectEqual(@as(usize, 64), sent);
    var buf: [2048]u8 = undefined;
    _ = try p.read(&buf);
    s = p.getStats();
    try std.testing.expect(s.tx_pkts >= 1);
    try std.testing.expect(s.rx_pkts >= 1);
}