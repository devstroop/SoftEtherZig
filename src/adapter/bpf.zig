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

/// bpf_hdr as the kernel writes it on macOS: a COMPACT 8-byte timeval
/// (4-byte tv_sec + 4-byte tv_usec, NOT the 64-bit 16-byte struct timeval)
/// followed by bh_caplen (4), bh_datalen (4), bh_hdrlen (2) and 2 padding
/// bytes = 20 bytes; the kernel sets bh_hdrlen = BPF_WORDALIGN(18) = 20.
/// Field offsets therefore match the 32-bit layout: caplen@8, hdrlen@16.
/// Confirmed empirically from kernel-captured bytes on a macOS runner:
/// `91a6816a 0f640c00 2c000000 2c000000 1400 0200` (caplen/datalen 44,
/// hdrlen 20). (PR #150 review claimed a 16-byte timeval/28-byte header —
/// that ABI is NOT what the macOS BPF stack emits.)
const BpfHdrSize: usize = 20;
const BpfCaplenOffset: usize = 8;
const BpfHdrlenOffset: usize = 16;

/// BPF_WORDALIGN from <net/bpf.h>: records in the kernel chain start at
/// 4-byte-aligned boundaries (sizeof(int)), not the raw record length.
fn bpfWordAlign(x: usize) usize {
    return (x + 3) & ~@as(usize, 3);
}

/// Conservative interface-name allowlist, mirrored from the setuid helper's
/// `validIfname`: no separators, no shell metacharacters. Enforced in the
/// parent before the name reaches the helper (PR #150 review) so a
/// user-controlled bridge interface can never smuggle shell syntax into
/// the escalation path (which now execs via an argument vector, no shell).
fn validIfname(name: []const u8) bool {
    if (name.len == 0 or name.len >= IFNAMSIZ) return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_' or c == ':' or c == '-' or c == '.';
        if (!ok) return false;
    }
    return true;
}

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
        if (!validIfname(self.ifname)) return error.InterfaceNotFound;

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
        if (self.pending_len == 0) {
            std.log.warn("bpf: read {d} raw bytes but parsed no frames; first bytes: {x}", .{ n, self.scratch[0..@min(n, 24)] });
            return null;
        }
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
            // Raw kernel bpf_hdr (macOS compact timeval): caplen@8, hdrlen@16.
            const hdr = self.scratch[off .. off + BpfHdrSize];
            const hdrlen = @as(usize, hdr[BpfHdrlenOffset]) | (@as(usize, hdr[BpfHdrlenOffset + 1]) << 8);
            const caplen = @as(usize, hdr[BpfCaplenOffset]) | (@as(usize, hdr[BpfCaplenOffset + 1]) << 8) |
                (@as(usize, hdr[BpfCaplenOffset + 2]) << 16) | (@as(usize, hdr[BpfCaplenOffset + 3]) << 24);
            if (hdrlen < BpfHdrSize or hdrlen + caplen > n - off) break; // malformed tail
            const frame = self.scratch[off + hdrlen .. off + hdrlen + caplen];
            if (write_off + BpfHdrSize + caplen > self.scratch.len) break;
            // Re-encode each record with a fresh (zeroed) header so the
            // scratch chain is back-to-back [hdr][frame][hdr][frame]...
            // (no word-align padding) for nextPendingFrame to walk.
            const out = self.scratch[write_off .. write_off + BpfHdrSize];
            @memset(out, 0);
            out[BpfCaplenOffset] = @intCast(caplen & 0xFF);
            out[BpfCaplenOffset + 1] = @intCast((caplen >> 8) & 0xFF);
            out[BpfCaplenOffset + 2] = @intCast((caplen >> 16) & 0xFF);
            out[BpfCaplenOffset + 3] = @intCast((caplen >> 24) & 0xFF);
            out[BpfCaplenOffset + 4] = out[BpfCaplenOffset];
            out[BpfCaplenOffset + 5] = out[BpfCaplenOffset + 1];
            out[BpfCaplenOffset + 6] = out[BpfCaplenOffset + 2];
            out[BpfCaplenOffset + 7] = out[BpfCaplenOffset + 3];
            out[BpfHdrlenOffset] = BpfHdrSize;
            std.mem.copyForwards(u8, self.scratch[write_off + BpfHdrSize ..][0..caplen], frame);
            write_off += BpfHdrSize + caplen;
            // Kernel chains separate records with BPF_WORDALIGN(len), not
            // the raw record length (PR #150 review).
            off += bpfWordAlign(hdrlen + caplen);
        }
        return write_off;
    }

    /// Pop the next frame from the pending remainder (frames are stored
    /// back-to-back in scratch as [hdr][frame] records; the parser restores
    /// the header chain and drops word-align padding).
    fn nextPendingFrame(self: *BpfPort) ?[]const u8 {
        if (self.pending_len == 0) return null;
        const off = self.pending_start;
        const n = off + self.pending_len;
        if (off + BpfHdrSize > n) {
            self.pending_len = 0;
            return null;
        }
        const hdr = self.scratch[off .. off + BpfHdrSize];
        const hdrlen = @as(usize, hdr[BpfHdrlenOffset]) | (@as(usize, hdr[BpfHdrlenOffset + 1]) << 8);
        const caplen = @as(usize, hdr[BpfCaplenOffset]) | (@as(usize, hdr[BpfCaplenOffset + 1]) << 8) |
            (@as(usize, hdr[BpfCaplenOffset + 2]) << 16) | (@as(usize, hdr[BpfCaplenOffset + 3]) << 24);
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
    try std.testing.expectEqual(@as(u64, 1), p.getStats().drops);

    const frame = [_]u8{0} ** 64;
    const sent = p.write(&frame) catch |e| {
        std.log.warn("budget test: write failed: {}", .{e});
        return e;
    };
    try std.testing.expectEqual(@as(usize, 64), sent);
    // macOS lo0 does not echo bpf writes back to the tap, so generate real
    // loopback traffic: a UDP datagram to 127.0.0.1 (captured on egress
    // and/or on the looped-back input).
    sendUdpProbe() catch |e| {
        std.log.warn("budget test: udp probe failed: {}", .{e});
    };
    var buf: [2048]u8 = undefined;
    const deadline = std.time.milliTimestamp() + 3_000;
    while (std.time.milliTimestamp() < deadline and p.getStats().rx_pkts == 0) {
        _ = (pollRead(p, &buf) catch |e| {
            std.log.warn("budget test: pollRead failed: {}", .{e});
            return e;
        }) orelse continue;
    }
    if (p.getStats().rx_pkts == 0) {
        std.log.warn("budget test: no rx within deadline (tx={d} rx={d} drops={d})", .{ p.getStats().tx_pkts, p.getStats().rx_pkts, p.getStats().drops });
        return error.FrameEchoTimeout;
    }
    const stats = p.getStats();
    try std.testing.expect(stats.tx_pkts >= 1);
    try std.testing.expect(stats.rx_pkts >= 1);
}

test "bpfPort frame chain parser (root-free)" {
    // Craft a kernel-style buffer in the real macOS bpf_hdr layout (20-byte
    // header, compact 8-byte timeval, caplen@8, datalen@12, hdrlen@16):
    // [hdr caplen 41][41B][hdr caplen 20][20B] followed by a malformed
    // tail, and verify parseFrames re-encodes it (advancing records by
    // BPF_WORDALIGN) so nextPendingFrame pops one frame per call, in order.
    var port = BpfPort{ .allocator = std.testing.allocator };
    port.scratch = try std.testing.allocator.alloc(u8, 4096);
    defer std.testing.allocator.free(port.scratch);

    var raw: [200]u8 = undefined;
    @memset(&raw, 0);
    const mk_hdr = struct {
        fn f(buf: []u8, caplen: usize) usize {
            std.mem.writeInt(u32, buf[8..12], @intCast(caplen), .little);
            std.mem.writeInt(u32, buf[12..16], @intCast(caplen), .little);
            std.mem.writeInt(u16, buf[16..18], 20, .little);
            return 20 + caplen;
        }
    }.f;
    var off: usize = 0;
    off += mk_hdr(raw[off..], 41); // odd length — next record is word-aligned
    @memset(raw[off - 41 .. off], 0xaa);
    off = bpfWordAlign(off); // 20 + 41 = 61 → aligned to 64
    off += mk_hdr(raw[off..], 20);
    @memset(raw[off - 20 .. off], 0xbb);
    off += mk_hdr(raw[off..], 200); // caplen exceeds remaining — malformed
    // parseFrames walks self.scratch (the BPF read buffer) — feed it the
    // crafted chain (104 valid bytes; the malformed tail is cut off).
    @memcpy(port.scratch[0..160], raw[0..160]);
    port.pending_start = 0;
    port.pending_len = port.parseFrames(160);
    try std.testing.expectEqual(@as(usize, 2 * 20 + 41 + 20), port.pending_len);

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

test "bpfPort live tap read on real lo0 traffic" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var port = BpfPort{ .allocator = std.testing.allocator };
    const p = bpfPort(&port, std.testing.allocator, "lo0");
    p.open() catch return error.SkipZigTest;
    defer p.close();

    // Write path on the live fd (tx accounting); macOS lo0 does not echo
    // bpf writes back to the tap, so the read path is exercised with real
    // loopback traffic (UDP datagram to 127.0.0.1).
    const frame_a = [_]u8{0xaa} ** 40;
    const frame_b = [_]u8{0xbb} ** 40;
    _ = p.write(&frame_a) catch |e| {
        std.log.warn("live test: write a failed: {}", .{e});
        return e;
    };
    _ = p.write(&frame_b) catch |e| {
        std.log.warn("live test: write b failed: {}", .{e});
        return e;
    };
    sendUdpProbe() catch |e| {
        std.log.warn("live test: udp probe failed: {}", .{e});
    };

    var buf: [2048]u8 = undefined;
    var frames_read: usize = 0;
    const deadline = std.time.milliTimestamp() + 3_000;
    while (std.time.milliTimestamp() < deadline and frames_read < 2) {
        const n = (pollRead(p, &buf) catch |e| {
            std.log.warn("live test: pollRead failed: {}", .{e});
            return e;
        }) orelse continue;
        frames_read += 1;
        try std.testing.expect(n >= 40); // real Ethernet/IP frame
        try std.testing.expect(n <= SESSION_FRAME_BUDGET);
    }
    const s = p.getStats();
    try std.testing.expect(s.tx_pkts >= 2);
    try std.testing.expect(frames_read >= 1);
    try std.testing.expect(s.rx_pkts >= 1);
}

/// Send one UDP datagram to 127.0.0.1:9 — travels over lo0 and is
/// captured by the attached BPF tap (egress and/or looped-back input).
fn sendUdpProbe() !void {
    const s = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(s);
    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.bigToNative(u16, 9),
        .addr = 0x7f000001,
        .zero = [_]u8{0} ** 8,
    };
    const sock: *const posix.sockaddr = @ptrCast(&addr);
    _ = try posix.sendto(s, "bpf-live-probe", 0, sock, @sizeOf(posix.sockaddr.in));
}

/// Non-blocking read with a poll() guard: the lo0 echo arrives after the
/// write returns, so a bare read would hit WouldBlock on CI.
fn pollRead(p: NetPort, buf: []u8) !?usize {
    var pfd = [1]posix.pollfd{
        .{ .fd = p.getFd(), .events = posix.POLL.IN, .revents = 0 },
    };
    while (true) {
        if (p.read(buf)) |n| {
            return n;
        } else |err| switch (err) {
            error.WouldBlock => {},
            else => return err,
        }
        const r = posix.poll(&pfd, 500) catch return error.PollFailed;
        if (r == 0) return null;
    }
}
