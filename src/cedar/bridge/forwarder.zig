const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.bridge_forwarder);
const adapter_mod = @import("../../adapter/mod.zig");

/// Pure L2 frame copier between an ingress raw socket and a TAP device.
/// No L3 processing, no ARP, no header modification — raw Ethernet frames
/// pass through byte-for-byte unchanged.
///
/// Flow:
///   ingress (AF_PACKET) → forwardToTap() → TAP fd → data loop UL path
///   data loop DL path → TAP fd → kernel routing → LAN (no explicit copy needed)
pub const BridgeForwarder = struct {
    ingress_fd: i32,
    is_open: bool,

    pub fn init(allocator: std.mem.Allocator, ingress_iface: []const u8) !BridgeForwarder {
        _ = allocator;
        const fd = try openIngressSocket(ingress_iface);
        return BridgeForwarder{ .ingress_fd = fd, .is_open = true };
    }

    pub fn deinit(self: *BridgeForwarder) void {
        if (self.is_open) {
            std.posix.close(self.ingress_fd);
            self.is_open = false;
        }
    }

    pub fn getIngressFd(self: *const BridgeForwarder) i32 {
        return self.ingress_fd;
    }

    /// Read a raw L2 frame from the ingress interface and write it to the
    /// given TAP fd. Returns true if a frame was forwarded.
    pub fn forwardToTap(self: *BridgeForwarder, buf: []u8, tap_fd: i32) !bool {
        const n = try std.posix.read(self.ingress_fd, buf);
        if (n == 0) return false;
        try writeAll(tap_fd, buf[0..n]);
        return true;
    }

    /// Write an IP packet directly to the ingress raw socket (LAN side).
    /// Used for VPN→LAN forwarding in bridge mode.
    /// Prepends a minimal Ethernet header with broadcast destination MAC.
    /// Writes the complete L2 frame in a single write to avoid the kernel
    /// emitting two separate packets on the raw socket.
    pub fn writeToIngress(self: *const BridgeForwarder, ip_packet: []const u8) !void {
        const eth_hdr = [14]u8{
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst: broadcast
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src: bridge MAC
            0x08, 0x00, // EtherType: IPv4
        };
        // Pre-assemble full frame in stack buffer
        var frame: [14 + adapter_mod.MAX_PACKET_SIZE]u8 = undefined;
        @memcpy(frame[0..14], &eth_hdr);
        @memcpy(frame[14..][0..ip_packet.len], ip_packet);
        try writeAll(self.ingress_fd, frame[0 .. 14 + ip_packet.len]);
    }
};

/// Retry write until all bytes are written (handles short writes from signals).
fn writeAll(fd: i32, buf: []const u8) !void {
    var n: usize = 0;
    while (n < buf.len) {
        n += try std.posix.write(fd, buf[n..]);
    }
}

fn openIngressSocket(iface: []const u8) !i32 {
    if (builtin.os.tag == .linux) {
        return openLinuxRawSocket(iface);
    } else if (builtin.os.tag == .macos) {
        return error.NotYetImplemented;
    } else {
        return error.UnsupportedPlatform;
    }
}

fn openLinuxRawSocket(iface: []const u8) !i32 {
    const fd = try std.posix.socket(17, 3, 0x0300);
    errdefer std.posix.close(fd);

    const SIOCGIFINDEX: c_int = 0x8933;
    var ifr = IfreqIndex{
        .ifrn_name = [_]u8{0} ** 16,
        .ifru_ifindex = 0,
    };
    const name_len = @min(iface.len, ifr.ifrn_name.len - 1);
    @memcpy(ifr.ifrn_name[0..name_len], iface[0..name_len]);

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(sock);

    if (std.c.ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        log.err("failed to get interface index for {s}: errno={}", .{ iface, std.c._errno().* });
        return error.InvalidInterface;
    }

    var sll = SockAddrLl{
        .sll_family = 17,
        .sll_protocol = 0x0300,
        .sll_ifindex = ifr.ifru_ifindex,
        .sll_hatype = 0,
        .sll_pkttype = 0,
        .sll_halen = 0,
        .sll_addr = [_]u8{0} ** 8,
    };
    try std.posix.bind(fd, @ptrCast(&sll), @sizeOf(SockAddrLl));

    // Enable promiscuous mode so the socket receives all frames on the
    // interface, not just those addressed to the interface's MAC.
    const SOL_PACKET: c_int = 263;
    const PACKET_ADD_MEMBERSHIP: c_int = 1;
    const PACKET_MR_PROMISC: c_int = 1;
    var mr = PacketMreq{
        .mr_ifindex = @intCast(ifr.ifru_ifindex),
        .mr_type = PACKET_MR_PROMISC,
        .mr_alen = 0,
        .mr_address = [_]u8{0} ** 8,
    };
    if (std.c.setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, @ptrCast(&mr), @sizeOf(PacketMreq)) != 0) {
        log.warn("failed to enable promiscuous mode on {s}: errno={} — bridge will only see frames addressed to interface MAC; set CAP_NET_RAW/CAP_NET_ADMIN to enable", .{ iface, std.c._errno().* });
    }

    log.info("bound raw socket to {s} (idx={d}, promiscuous)", .{ iface, ifr.ifru_ifindex });
    return fd;
}

const IfreqIndex = extern struct {
    // struct ifreq on x86_64 Linux is 40 bytes: 16-byte name + 24-byte union.
    // We only need the ifindex from the union, but must match the full size
    // to avoid stack buffer overflow from the kernel writing into the union.
    ifrn_name: [16]u8,
    ifru_ifindex: c_int,
    _pad: [20]u8 = [_]u8{0} ** 20,
};

const SockAddrLl = extern struct {
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
    /// Kernel expects unsigned short (2 bytes), must match exactly.
    mr_type: u16,
    /// Kernel expects unsigned short (2 bytes).
    mr_alen: u16,
    mr_address: [8]u8,
};
