//! BPF L2 ingress port (L2 Network Bridge proposal §4.1, H-7).
//!
//! macOS-only NetPort implementation over the Berkeley Packet Filter
//! (`/dev/bpfN`), bound to a named interface, used by the bridge pump
//! (issue #56) as the physical-side ingress. Mirrors `port.l3Port()` and
//! `af_packet.afPacketPort()`: the caller owns the `BpfPort` instance and
//! the returned `NetPort` points at it; the pump drives open/close/read/
//! write uniformly through the vtable.
//!
//! Design decisions (proposal §4.6, §6, §10 H-7):
//! - **Privilege (H-7):** `/dev/bpfN` requires root on macOS. open() first
//!   tries the direct path (works when the process runs as root, e.g. via
//!   `sudo`), then falls back to the setuid `softether-utun-helper` in
//!   `--bpf-open` mode — a tightly-scoped allowlist-only fd-passing mode
//!   (no shell), security-reviewed with the `security-review` label gate.
//!   If neither is possible → clean `error.NoCapability`.
//! - **MTU clamp (H-3):** the session's L2 frame budget is 1514 bytes
//!   (14-byte Ethernet header + 1500 payload). Frames larger than 1514 are
//!   dropped and counted in `PortStats.drops`.
//! - **Host-IP warning (H-5):** if the ingress NIC carries an IPv4/IPv6
//!   address, open() warns — the host's own traffic would be bridged into
//!   the VPN (MAC exclusion lands in a later milestone).
//! - **One frame per read:** BPF returns a buffer of `bpf_hdr`-prefixed
//!   frames. `BIOCIMMEDIATE` flushes per-packet, but small frames can still
//!   coalesce, so read() parses the header chain and serves exactly one
//!   frame per call, stashing the remainder internally.
//! - **Promiscuous:** `BIOCPROMISC` is one-way on macOS (no unset ioctl);
//!   setPromiscuous(true) applies it, setPromiscuous(false) is a logged
//!   no-op (documented variance from af_packet).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const port_mod = @import("port.zig");
const NetPort = port_mod.NetPort;
const PortLayer = port_mod.PortLayer;
const PortStats = port_mod.PortStats;

/// Session L2 frame budget (proposal §4.6) — must match af_packet.zig.
pub const SESSION_FRAME_BUDGET: usize = 1514;

/// Prefix length of an interface name (IFNAMSIZ - 1).
pub const IFNAMSIZ: usize = 16;

/// Maximum BPF buffer size we request (BIOCSBLEN).
pub const BPF_BUFFER_SIZE: usize = 65536;

// /dev/bpfN ioctl numbers (macOS <net/bpf.h>, verified against the SDK:
// _IOWR('B',102,u_int)=0xc0044266, _IOW('B',108,ifreq)=0x8020426c,
// _IO('B',105)=0x20004269, _IOW('B',112,u_int)=0x80044270). ioctl() takes
// a c_int; the request codes exceed i32::MAX, so they are stored as
// bitcast c_int. Note: macOS has NO BIOCNONBLOCK — the fd is set
// non-blocking with fcntl at open time.
const BIOCSBLEN: c_int = @bitCast(@as(u32, 0xc0044266)); // set buffer length
const BIOCSETIF: c_int = @bitCast(@as(u32, 0x8020426c)); // set interface
const BIOCPROMISC: c_int = @bitCast(@as(u32, 0x20004269)); // force promiscuous
const BIOCIMMEDIATE: c_int = @bitCast(@as(u32, 0x80044270)); // return immediately on packet

const SIOCGIFMTU: c_int = @bitCast(@as(u32, 0xc0206933)); // get interface MTU (SDK-verified)

const DLT_EN10MB: u32 = 1; // Ethernet link type

/// Request struct for BIOCSETIF (struct ifreq = ifr_name[16] + 16-byte
/// union; the kernel copies sizeof(struct ifreq) = 32 bytes from the code).
const IfreqSetif = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    ifru_pad: [16]u8,
};

/// bpf_hdr as the kernel writes it (macOS 64-bit): timeval(16) + caplen(4) +
/// datalen(4) + hdrlen(2) + pad(2) = 28 bytes.
const BpfHdrSize: usize = 28;

/// Errors specific to the BPF port lifecycle.
pub const BpfError = error{
    /// Ports can only be opened on macOS.
    NotMacos,
    /// Interface name invalid or not found.
    InterfaceNotFound,
    /// Direct /dev/bpfN open failed and no privileged path was available.
    NoCapability,
    /// The setuid helper refused or failed to grant a BPF fd.
    HelperFailed,
    /// bind-level attach (BIOCSETIF) failed.
    AttachFailed,
    /// ioctl(BIOCPROMISC) failed.
    PromiscFailed,
    /// Port has been closed / fd is invalid.
    DeviceClosed,
    /// Frames larger than the session budget (1514) are not forwarded (H-3).
    FrameTooLarge,
};

/// BPF port implementation.
///
/// The pump owns this instance (as it owns an L3 device behind `l3Port`);
/// `bpfPort()` fills it and hands back a `NetPort` pointing at it.
/// `open()` performs all syscalls; on non-macOS targets every entry point
/// fails fast with `error.NotMacos`.
pub const BpfPort = struct {
    allocator: std.mem.Allocator,
    ifname: []const u8 = "",
    fd: posix.fd_t = NetPort.invalid_fd,
    mac: ?[6]u8 = null,
    iface_mtu: usize = 1500,
    stats: PortStats = .{},
    promisc: bool = false,

    /// Read scratch buffer (allocated at open) + unconsumed remainder.
    scratch: []u8 = &.{},
    pending_start: usize = 0,
    pending_len: usize = 0,

    /// Open the first free /dev/bpfN and attach it to `ifname`.
    ///
    /// Direct path first (root); falls back to the setuid helper in
    /// `--bpf-open` mode when EPERM/EACCES (H-7). Returns clean
    /// `error.NoCapability` when neither path can grant a device.
    pub fn open(self: *BpfPort) BpfError!void {
        if (comptime builtin.os.tag != .macos) return error.NotMacos;
        if (self.ifname.len == 0 or self.ifname.len >= IFNAMSIZ) return error.InterfaceNotFound;

        self.scratch = self.allocator.alloc(u8, BPF_BUFFER_SIZE) catch {
            return error.NoCapability;
        };

        var bpf_fd: posix.fd_t = NetPort.invalid_fd;

        // Direct path: open /dev/bpfN without privilege escalation.
        bpf_fd = self.tryDirectOpen() catch blk: {
            // Escalated path (H-7): setuid helper --bpf-open, allowlist-only.
            const utun_escalate = @import("utun_escalate.zig");
            break :blk utun_escalate.escalatedBpfOpen(self.allocator, self.ifname) catch |err| {
                std.log.warn("bpf: helper could not grant /dev/bpfN for '{s}': {}", .{ self.ifname, err });
                self.allocator.free(self.scratch);
                self.scratch = &.{};
                return switch (err) {
                    error.HelperNotFound, error.HelperLaunchFailed, error.HelperFailed, error.AcceptFailed, error.RecvFailed, error.NoFdReceived => error.NoCapability,
                    else => error.HelperFailed,
                };
            };
        };
        self.fd = bpf_fd;
        errdefer self.close();

        // Attach the interface and configure capture.
        self.setInterface() catch {
            return error.AttachFailed;
        };
        if (self.promisc) {
            self.setPromiscuous(true) catch {};
        }
        self.setImmediate() catch {};

        // Metadata (best effort; a miss is not fatal).
        self.mac = self.readMac() catch null;
        self.iface_mtu = self.readMtu() catch 1500;
        if (self.iface_mtu > 1500) {
            std.log.warn("bpf: interface '{s}' MTU {d} > 1500 — jumbo frames unsupported, frames > 1514 will be dropped (H-3)", .{ self.ifname, self.iface_mtu });
        }

        // H-5: warn when the ingress NIC carries a host IP address.
        if (hostAddressesPresent(self.ifname)) {
            std.log.warn("bpf: interface '{s}' has a host IP address — the host's own traffic would be bridged into the VPN (H-5)", .{self.ifname});
        }
    }

    /// Try /dev/bpf0..9 directly (process must already be root).
    fn tryDirectOpen(self: *BpfPort) BpfError!posix.fd_t {
        var path_buf: [16]u8 = undefined;
        for (0..10) |unit| {
            const path = std.fmt.bufPrintZ(&path_buf, "/dev/bpf{d}", .{unit}) catch continue;
            const fd = posix.openZ(path, .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0) catch {
                continue; // in use or absent — try next unit
            };
            if (self.setBufferLength(fd)) |_| {} else |_| {}
            return fd;
        }
        return error.NoCapability;
    }

    fn setBufferLength(self: *BpfPort, fd: posix.fd_t) BpfError!void {
        _ = self;
        const len: c_uint = BPF_BUFFER_SIZE;
        if (std.c.ioctl(fd, BIOCSBLEN, @intFromPtr(&len)) < 0) return error.AttachFailed;
    }

    fn setInterface(self: *BpfPort) BpfError!void {
        var req = IfreqSetif{
            .ifr_name = [_]u8{0} ** IFNAMSIZ,
            .ifru_pad = [_]u8{0} ** 16,
        };
        @memcpy(req.ifr_name[0..self.ifname.len], self.ifname);
        if (std.c.ioctl(self.fd, BIOCSETIF, @intFromPtr(&req)) < 0) return error.AttachFailed;
    }

    /// BIOCIMMEDIATE: flush to userspace as soon as a frame arrives. Small
    /// frames may still coalesce — read() handles the header chain.
    fn setImmediate(self: *BpfPort) BpfError!void {
        const on: c_uint = 1;
        if (std.c.ioctl(self.fd, BIOCIMMEDIATE, @intFromPtr(&on)) < 0) return error.AttachFailed;
    }

    /// macOS has no BIOCNONBLOCK; the fd is opened O_NONBLOCK already
    /// (direct path and the setuid helper both set it), so this is a no-op.
    pub fn close(self: *BpfPort) void {
        if (self.fd != NetPort.invalid_fd) {
            posix.close(self.fd);
            self.fd = NetPort.invalid_fd;
        }
        if (self.scratch.len > 0) {
            self.allocator.free(self.scratch);
            self.scratch = &.{};
        }
        self.pending_start = 0;
        self.pending_len = 0;
    }

    /// Read one raw Ethernet frame. Returns null when no data is pending
    /// (non-blocking). BPF returns a buffer of bpf_hdr-prefixed frames, so
    /// the header chain is parsed and exactly one frame served per call;
    /// the remainder is kept for the next read. Frames larger than the
    /// session budget are consumed, counted in `stats.drops` and not
    /// reported (H-3).
    pub fn read(self: *BpfPort, buf: []u8) anyerror!?usize {
        if (comptime builtin.os.tag != .macos) return error.NotMacos;
        if (self.fd == NetPort.invalid_fd) return error.DeviceClosed;

        // Serve from the stashed remainder first.
        if (self.pending_len > 0) {
            const frame = self.nextPendingFrame() orelse return null;
            if (frame.len > SESSION_FRAME_BUDGET) {
                self.stats.drops += 1;
                return self.read(buf); // skip oversized, keep parsing
            }
            if (frame.len > buf.len) return error.NoSpaceLeft;
            @memcpy(buf[0..frame.len], frame);
            self.stats.rx_pkts += 1;
            self.stats.rx_bytes += frame.len;
            return frame.len;
        }

        const n = posix.read(self.fd, self.scratch) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };
        if (n == 0) return null;

        // Parse the bpf_hdr chain: stash every frame, then serve the first.
        self.pending_start = 0;
        self.pending_len = self.parseFrames(n);
        if (self.pending_len == 0) return null;
        const frame = self.nextPendingFrame() orelse return null;
        if (frame.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return self.read(buf);
        }
        if (frame.len > buf.len) return error.NoSpaceLeft;
        @memcpy(buf[0..frame.len], frame);
        self.stats.rx_pkts += 1;
        self.stats.rx_bytes += frame.len;
        return frame.len;
    }

    /// Stash every complete frame in the just-read buffer, re-encoding the
    /// chain as `[hdr][frame][hdr][frame]...` in scratch so nextPendingFrame
    /// can walk it uniformly. Malformed tails (partial header) are dropped.
    fn parseFrames(self: *BpfPort, n: usize) usize {
        var off: usize = 0;
        var write_off: usize = 0;
        while (off + BpfHdrSize <= n) {
            const hdr = self.scratch[off .. off + BpfHdrSize];
            const hdrlen = @as(usize, hdr[24]) | (@as(usize, hdr[25]) << 8);
            const caplen = @as(usize, hdr[16]) | (@as(usize, hdr[17]) << 8) |
                (@as(usize, hdr[18]) << 16) | (@as(usize, hdr[19]) << 24);
            if (hdrlen < BpfHdrSize or hdrlen + caplen > n - off) break; // malformed tail
            const frame = self.scratch[off + hdrlen .. off + hdrlen + caplen];
            if (write_off + BpfHdrSize + caplen > self.scratch.len) break;
            // Synthetic header: hdrlen=28, caplen=<frame len>.
            const out = self.scratch[write_off .. write_off + BpfHdrSize];
            @memset(out, 0);
            out[16] = @intCast(caplen & 0xFF);
            out[17] = @intCast((caplen >> 8) & 0xFF);
            out[18] = @intCast((caplen >> 16) & 0xFF);
            out[19] = @intCast((caplen >> 24) & 0xFF);
            out[24] = BpfHdrSize;
            std.mem.copyForwards(u8, self.scratch[write_off + BpfHdrSize ..][0..caplen], frame);
            write_off += BpfHdrSize + caplen;
            off += hdrlen + caplen;
        }
        return write_off;
    }

    /// Pop the next frame from the pending remainder (frames are stored
    /// back-to-back in scratch; the parser restores the header chain).
    fn nextPendingFrame(self: *BpfPort) ?[]const u8 {
        if (self.pending_len == 0) return null;
        const off = self.pending_start;
        const n = off + self.pending_len;
        if (off + BpfHdrSize > n) {
            self.pending_len = 0;
            return null;
        }
        const hdr = self.scratch[off .. off + BpfHdrSize];
        const hdrlen = @as(usize, hdr[24]) | (@as(usize, hdr[25]) << 8);
        const caplen = @as(usize, hdr[16]) | (@as(usize, hdr[17]) << 8) |
            (@as(usize, hdr[18]) << 16) | (@as(usize, hdr[19]) << 24);
        if (hdrlen < BpfHdrSize or hdrlen + caplen > n - off) {
            self.pending_len = 0;
            return null;
        }
        const frame = self.scratch[off + hdrlen .. off + hdrlen + caplen];
        self.pending_start = off + hdrlen + caplen;
        self.pending_len = n - self.pending_start;
        return frame;
    }

    /// Send one raw Ethernet frame. Frames larger than the session budget
    /// are rejected with `error.FrameTooLarge` and counted as drops (H-3).
    pub fn write(self: *BpfPort, data: []const u8) anyerror!usize {
        if (comptime builtin.os.tag != .macos) return error.NotMacos;
        if (self.fd == NetPort.invalid_fd) return error.DeviceClosed;
        if (data.len > SESSION_FRAME_BUDGET) {
            self.stats.drops += 1;
            return error.FrameTooLarge;
        }
        const n = posix.write(self.fd, data) catch |err| switch (err) {
            error.WouldBlock => return error.TxBusy,
            else => return err,
        };
        self.stats.tx_pkts += 1;
        self.stats.tx_bytes += n;
        return n;
    }

    /// BIOCPROMISC is one-way on macOS — there is no unset ioctl. Enabling
    /// is applied; disabling is a logged no-op (documented variance).
    pub fn setPromiscuous(self: *BpfPort, on: bool) BpfError!void {
        if (comptime builtin.os.tag != .macos) return error.NotMacos;
        if (self.fd == NetPort.invalid_fd) return error.DeviceClosed;
        if (!on) {
            if (self.promisc) {
                std.log.info("bpf: promiscuous mode cannot be disabled on macOS (BIOCPROMISC is one-way); port stays promiscuous until close", .{});
            }
            return;
        }
        if (std.c.ioctl(self.fd, BIOCPROMISC, @as(c_uint, 0)) < 0) return error.PromiscFailed;
        self.promisc = true;
    }

    /// Interface MAC via getifaddrs(3) AF_LINK sockaddr_dl.
    fn readMac(self: *const BpfPort) BpfError![6]u8 {
        return macForInterface(self.ifname) orelse error.InterfaceNotFound;
    }

    /// Interface MTU via SIOCGIFMTU on a plain AF_INET DGRAM socket.
    fn readMtu(self: *const BpfPort) BpfError!usize {
        const s = posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch return error.InterfaceNotFound;
        defer posix.close(s);
        var req = IfreqSetif{
            .ifr_name = [_]u8{0} ** IFNAMSIZ,
            .ifru_pad = [_]u8{0} ** 16,
        };
        @memcpy(req.ifr_name[0..self.ifname.len], self.ifname);
        if (std.c.ioctl(s, SIOCGIFMTU, @intFromPtr(&req)) < 0) return error.InterfaceNotFound;
        // The MTU is returned in the first 4 bytes of the union region.
        const mtu: u32 = @bitCast(@as(i32, @bitCast(req.ifru_pad[0..4].*)));
        return @intCast(mtu);
    }
};

/// Wrap a `BpfPort` behind the `NetPort` interface.
pub fn bpfPort(port: *BpfPort, allocator: std.mem.Allocator, ifname: []const u8) NetPort {
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
        fn asPort(impl_: *anyopaque) *BpfPort {
            return @as(*BpfPort, @ptrCast(@alignCast(impl_)));
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
// getifaddrs(3) helpers (MAC + host-IP probe) — same shape as nic_enumerate
// ============================================================================

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

extern "c" fn getifaddrs(ifap: *?*IfAddrs) c_int;
extern "c" fn freeifaddrs(ifa: *IfAddrs) void;

/// sockaddr_dl: len(1) family(1) index(2) type(1) nlen(1) alen(1) slen(1)
/// data[12]; long ifnames overflow the inline buffer — walk bytes bounded
/// by sdl_len (same walk as nic_enumerate).
const AF_LINK: u8 = 18;

/// Look up the 6-byte MAC of `ifname` via the AF_LINK getifaddrs entry.
fn macForInterface(ifname: []const u8) ?[6]u8 {
    var head: ?*IfAddrs = null;
    if (getifaddrs(&head) != 0) return null;
    defer if (head) |h| freeifaddrs(h);

    var node = head;
    while (node) |entry| : (node = entry.ifa_next) {
        const name = std.mem.span(entry.ifa_name);
        if (!std.mem.eql(u8, name, ifname)) continue;
        const addr = entry.ifa_addr orelse continue;
        if (addr.family != AF_LINK) continue;

        const raw: [*]const u8 = @ptrCast(addr);
        const sdl_len: usize = raw[0];
        const nlen: usize = raw[4 + 1];
        const alen: usize = raw[4 + 2];
        if (alen < 6) return null;
        const mac_off: usize = 8 + nlen;
        if (mac_off + 6 > sdl_len) return null;
        var mac: [6]u8 = undefined;
        @memcpy(&mac, raw[mac_off .. mac_off + 6]);
        return mac;
    }
    return null;
}

/// H-5 probe: does the interface carry any IPv4/IPv6 address?
fn hostAddressesPresent(ifname: []const u8) bool {
    var head: ?*IfAddrs = null;
    if (getifaddrs(&head) != 0) return false;
    defer if (head) |h| freeifaddrs(h);

    var node = head;
    while (node) |entry| : (node = entry.ifa_next) {
        const name = std.mem.span(entry.ifa_name);
        if (!std.mem.eql(u8, name, ifname)) continue;
        const addr = entry.ifa_addr orelse continue;
        // AF_INET (2) or AF_INET6 (30 on macOS).
        if (addr.family == 2 or addr.family == 30) return true;
    }
    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "bpfPort vtable metadata (non-macOS safe)" {
    var port = BpfPort{ .allocator = std.testing.allocator };
    const p = bpfPort(&port, std.testing.allocator, "en0");
    try std.testing.expectEqual(PortLayer.l2, p.getLayer());
    try std.testing.expectEqual(@as(usize, SESSION_FRAME_BUDGET), p.getMtu());
    try std.testing.expectEqualStrings("en0", p.getName());
    try std.testing.expectEqual(NetPort.invalid_fd, p.getFd());
    const s = p.getStats();
    try std.testing.expectEqual(@as(u64, 0), s.drops);
}

test "bpfPort rejects non-macOS targets" {
    var port = BpfPort{ .allocator = std.testing.allocator };
    const p = bpfPort(&port, std.testing.allocator, "en0");
    if (builtin.os.tag == .macos) return error.SkipZigTest;
    var buf = [_]u8{0} ** 64;
    try std.testing.expectError(error.NotMacos, p.open());
    try std.testing.expectError(error.NotMacos, p.write(&buf));
    try std.testing.expectError(error.NotMacos, p.read(&buf));
    p.setPromiscuous(true);
}

test "bpfPort session frame budget drop accounting" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var port = BpfPort{ .allocator = std.testing.allocator };
    const p = bpfPort(&port, std.testing.allocator, "lo0");

    // open() requires root (direct) or the setuid helper; skip cleanly
    // otherwise — keeps the macOS CI matrix green without privilege.
    p.open() catch return error.SkipZigTest;
    defer p.close();

    const oversized = [_]u8{0} ** (SESSION_FRAME_BUDGET + 1);
    try std.testing.expectError(error.FrameTooLarge, p.write(&oversized));
    var s = p.getStats();
    try std.testing.expectEqual(@as(u64, 1), s.drops);

    const frame = [_]u8{0} ** 64;
    const sent = try p.write(&frame);
    try std.testing.expectEqual(@as(usize, 64), sent);
    var buf: [2048]u8 = undefined;
    _ = try p.read(&buf);
    s = p.getStats();
    try std.testing.expect(s.tx_pkts >= 1);
    try std.testing.expect(s.rx_pkts >= 1);
}

test "bpfPort frame chain parser (root-free)" {
    // Craft a kernel-style buffer: [hdr len 28, caplen 40][40B][hdr][caplen 20][20B]
    // followed by a malformed tail, and verify parseFrames re-encodes it so
    // nextPendingFrame pops one frame per call, in order.
    var port = BpfPort{ .allocator = std.testing.allocator };
    port.scratch = try std.testing.allocator.alloc(u8, 4096);
    defer std.testing.allocator.free(port.scratch);

    var raw: [200]u8 = undefined;
    @memset(&raw, 0);
    const mk_hdr = struct {
        fn f(buf: []u8, caplen: usize) usize {
            buf[16] = @intCast(caplen & 0xFF);
            buf[17] = @intCast((caplen >> 8) & 0xFF);
            buf[24] = 28;
            return 28 + caplen;
        }
    }.f;
    var off: usize = 0;
    off += mk_hdr(raw[off..], 40);
    @memset(raw[off - 40 .. off], 0xaa);
    off += mk_hdr(raw[off..], 20);
    @memset(raw[off - 20 .. off], 0xbb);
    off += mk_hdr(raw[off..], 200); // caplen exceeds remaining — malformed
    // parseFrames walks self.scratch (the BPF read buffer) — feed it the
    // crafted chain (176 valid bytes; the malformed tail is cut off).
    @memcpy(port.scratch[0..176], raw[0..176]);
    port.pending_start = 0;
    port.pending_len = port.parseFrames(176);
    try std.testing.expectEqual(@as(usize, 60 + 2 * 28), port.pending_len);

    var got: usize = 0;
    var last_byte: u8 = 0;
    while (port.nextPendingFrame()) |frame| {
        last_byte = frame[0];
        got += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), got);
    try std.testing.expectEqual(@as(u8, 0xbb), last_byte);
}

test "bpfPort open degrades cleanly (no privilege / bad interface)" {
    // On a bare CI runner there is no setuid helper → NoCapability; with
    // root or a helper the attach must fail cleanly on a bogus interface.
    // The client contract: a clean error, never a crash or hang.
    var port = BpfPort{ .allocator = std.testing.allocator };
    const p = bpfPort(&port, std.testing.allocator, "no-such-if-xyz");
    var open_err: ?anyerror = null;
    p.open() catch |e| {
        open_err = e;
    };
    switch (open_err orelse return error.TestExpectedError) {
        error.NoCapability, error.HelperFailed, error.AttachFailed, error.InterfaceNotFound, error.NotMacos => {},
        else => return open_err.?,
    }
    p.close();
}

test "bpfPort frame chain parsing serves one frame per read" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var port = BpfPort{ .allocator = std.testing.allocator };
    const p = bpfPort(&port, std.testing.allocator, "lo0");
    p.open() catch return error.SkipZigTest;
    defer p.close();

    // Two small frames coalesced in one BPF read must come out as two
    // separate read() results (one frame per call contract).
    const frame_a = [_]u8{0xaa} ** 40;
    const frame_b = [_]u8{0xbb} ** 40;
    _ = try p.write(&frame_a);
    _ = try p.write(&frame_b);

    var buf: [2048]u8 = undefined;
    var saw_a = false;
    var saw_b = false;
    for (0..8) |_| {
        const n = (try p.read(&buf)) orelse break;
        if (n == 40 and buf[0] == 0xaa) saw_a = true;
        if (n == 40 and buf[0] == 0xbb) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}
