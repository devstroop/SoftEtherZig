//! nic_enumerate — platform NIC enumeration primitive.
//!
//! Gathers `{name, mac, index}` for the host's network interfaces
//! (L2 Network Bridge proposal §4.1). This module provides the per-OS
//! gathering primitive only; the public FFI surface
//! (`softether_list_interfaces`) is issue #48 on top of this.
//!
//! Platforms:
//!   - macOS / iOS     — getifaddrs(3), AF_LINK sockaddr_dl
//!   - Linux / Android — getifaddrs(3), AF_PACKET sockaddr_ll
//!   - Windows         — GetAdaptersAddresses (iphlpapi), GUID + MAC

const std = @import("std");
const builtin = @import("builtin");

pub const NicInfo = struct {
    /// Interface name (e.g. "en0", "eth0", "{GUID}" on Windows).
    /// Caller-owned slice — see `listNics` ownership contract.
    name: []const u8,
    /// Stable hardware address when the interface has one.
    mac: ?[6]u8,
    /// Platform interface index (if_nametoindex / if_index / IfIndex).
    index: u32,
};

pub const NicList = struct {
    items: []NicInfo,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *NicList) void {
        for (self.items) |item| {
            self.allocator.free(item.name);
        }
        self.allocator.free(self.items);
        self.items = &.{};
    }
};

/// Enumerate physical + virtual NICs present on the host.
/// The caller owns the returned list (see NicList.deinit).
pub fn listNics(allocator: std.mem.Allocator) !NicList {
    if (builtin.os.tag == .windows) {
        return listNicsWindows(allocator);
    }
    return listNicsGetifaddrs(allocator);
}

// ============================================================================
// GetAdaptersAddresses(3) path — Windows (iphlpapi)
//
// Layout translated from iptypes.h (IP_ADAPTER_ADDRESSES_LH, WinNT 6.0+ ABIs
// this library targets: x86_64-windows and aarch64-windows). Only the prefix
// containing the fields we consume is declared; the rest is opaque. AdapterName
// is the interface GUID string, which the FFI level documents as the stable id
// (MAC may be absent on virtual adapters).
// ============================================================================

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

const GAA_FLAG_SKIP_UNICAST: u32 = 0x0001;
const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

const IpAdapterAddresses = extern struct {
    /// union { ULONGLONG Alignment; struct { ULONG Length; IF_INDEX IfIndex; } }
    head: extern union {
        alignment: u64,
        fields: extern struct {
            length: u32,
            if_index: u32,
        },
    },
    next: ?*IpAdapterAddresses,
    /// Interface GUID string ("{...}"); the stable id on Windows.
    adapter_name: ?[*:0]const u8,
    first_unicast: ?*anyopaque,
    first_anycast: ?*anyopaque,
    first_multicast: ?*anyopaque,
    first_dns_server: ?*anyopaque,
    dns_suffix: ?[*:0]u16,
    description: ?[*:0]u16,
    friendly_name: ?[*:0]u16,
    physical_address: [8]u8,
    physical_address_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: u32,
    ipv6_if_index: u32,
    zone_indices: [16]u32,
    first_prefix: ?*anyopaque,
};

extern "iphlpapi" fn GetAdaptersAddresses(
    family: u32,
    flags: u32,
    reserved: ?*anyopaque,
    adapter_addresses: ?*IpAdapterAddresses,
    size_pointer: *u32,
) callconv(.winapi) u32;

fn listNicsWindows(allocator: std.mem.Allocator) !NicList {
    var size: u32 = 16 * 1024;
    var buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);

    const flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    var rc = GetAdaptersAddresses(0, flags, null, @ptrCast(@alignCast(buf.ptr)), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf = try allocator.realloc(buf, size);
        rc = GetAdaptersAddresses(0, flags, null, @ptrCast(@alignCast(buf.ptr)), &size);
    }
    if (rc != ERROR_SUCCESS) return error.EnumerationFailed;

    var list: std.ArrayList(NicInfo) = .{};
    errdefer {
        for (list.items) |item| allocator.free(item.name);
        list.deinit(allocator);
    }

    var node: ?*IpAdapterAddresses = @ptrCast(@alignCast(buf.ptr));
    while (node) |addr| : (node = addr.next) {
        if (addr.if_type == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        const guid = std.mem.span(addr.adapter_name orelse continue);
        var mac: ?[6]u8 = null;
        if (addr.physical_address_length >= 6) {
            mac = addr.physical_address[0..6].*;
        }
        try list.append(allocator, .{
            .name = try allocator.dupe(u8, guid),
            .mac = mac,
            .index = addr.head.fields.if_index,
        });
    }

    return .{ .items = try list.toOwnedSlice(allocator), .allocator = allocator };
}

// ============================================================================
// getifaddrs(3) path — macOS/iOS (AF_LINK) and Linux/Android (AF_PACKET)
// ============================================================================

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

extern "c" fn getifaddrs(ifap: *?*IfAddrs) c_int;
extern "c" fn freeifaddrs(ifa: *IfAddrs) void;

const IFF_LOOPBACK: c_uint = 0x8;

const is_bsd = builtin.os.tag == .macos or builtin.os.tag == .ios or
    builtin.os.tag == .tvos or builtin.os.tag == .watchos;

fn listNicsGetifaddrs(allocator: std.mem.Allocator) !NicList {
    var head: ?*IfAddrs = null;
    if (getifaddrs(&head) != 0) return error.EnumerationFailed;
    defer if (head) |h| freeifaddrs(h);

    var list: std.ArrayList(NicInfo) = .{};
    errdefer {
        for (list.items) |item| allocator.free(item.name);
        list.deinit(allocator);
    }

    // One entry per interface: only the hardware-address entry (AF_LINK on
    // BSD, AF_PACKET on Linux) carries name+mac+index; other entries are
    // filtered out, so each interface appears exactly once.
    var node = head;
    while (node) |entry| : (node = entry.ifa_next) {
        const addr = entry.ifa_addr orelse continue;
        if ((entry.ifa_flags & IFF_LOOPBACK) != 0) continue;
        if (!isHwFamily(addr)) continue;

        const name = std.mem.span(entry.ifa_name);
        const mac = extractMac(addr) catch null;
        try appendUnique(&list, allocator, name, mac, indexOf(addr));
    }

    return .{ .items = try list.toOwnedSlice(allocator), .allocator = allocator };
}

fn isHwFamily(addr: *const std.posix.sockaddr) bool {
    if (comptime is_bsd) {
        return addr.family == af_link_u8;
    }
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .android) {
        return addr.family == af_packet_u16;
    }
    return false;
}

const af_link_u8: u8 = 18; // macOS/BSD AF_LINK
const af_packet_u16: u16 = 17; // Linux AF_PACKET

/// Extract a 6-byte MAC from the hardware-address sockaddr.
/// Returns null for hardware entries without a MAC (e.g. utun on macOS).
fn extractMac(addr: *const std.posix.sockaddr) !?[6]u8 {
    if (comptime is_bsd) {
        // sockaddr_dl: len(1) family(1) index(2) type(1) nlen(1) alen(1) slen(1) data[12]
        // The kernel reports the real struct via sdl_len, which can exceed the
        // fixed 12-byte inline buffer (long ifnames) — walk the raw bytes
        // bounded by sdl_len instead of indexing the inline array.
        const dl: *const SockaddrDl = @ptrCast(@alignCast(addr));
        if (dl.sdl_alen < 6) return null;
        const raw: [*]const u8 = @ptrCast(addr);
        const data_base = 8; // header bytes before sdl_data
        const mac_off = data_base + dl.sdl_nlen;
        if (mac_off + 6 > dl.sdl_len or mac_off + 6 > 8 + dl.sdl_data.len) return null;
        var mac: [6]u8 = undefined;
        @memcpy(&mac, raw[mac_off .. mac_off + 6]);
        return mac;
    }
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .android) {
        // sockaddr_ll: family(2) protocol(2) ifindex(4) hatype(2) pkttype(1)
        // halen(1) addr[8]
        const ll: *const SockaddrLl = @ptrCast(@alignCast(addr));
        if (ll.sll_halen < 6) return null;
        var mac: [6]u8 = undefined;
        @memcpy(&mac, ll.sll_addr[0..6]);
        return mac;
    }
    return null;
}

fn indexOf(addr: *const std.posix.sockaddr) u32 {
    if (comptime is_bsd) {
        const dl: *const SockaddrDl = @ptrCast(@alignCast(addr));
        return dl.sdl_index;
    }
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .android) {
        const ll: *const SockaddrLl = @ptrCast(@alignCast(addr));
        return @intCast(ll.sll_ifindex);
    }
    return 0;
}

const SockaddrDl = extern struct {
    sdl_len: u8,
    sdl_family: u8,
    sdl_index: u16,
    sdl_type: u8,
    sdl_nlen: u8,
    sdl_alen: u8,
    sdl_slen: u8,
    sdl_data: [12]u8,
};

const SockaddrLl = extern struct {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [8]u8,
};

/// Append an interface entry unless the name is already present (dedupe).
fn appendUnique(
    list: *std.ArrayList(NicInfo),
    allocator: std.mem.Allocator,
    name: []const u8,
    mac: ?[6]u8,
    index: u32,
) !void {
    for (list.items) |*item| {
        if (std.mem.eql(u8, item.name, name)) {
            if (item.mac == null and mac != null) {
                item.mac = mac;
                item.index = index;
            }
            return;
        }
    }
    try list.append(allocator, .{
        .name = try allocator.dupe(u8, name),
        .mac = mac,
        .index = index,
    });
}

// ============================================================================
// Tests
// ============================================================================

test "listNics returns interface entries" {
    const allocator = std.testing.allocator;
    var list = try listNics(allocator);
    defer list.deinit();

    // The running host always has at least one non-loopback interface.
    try std.testing.expect(list.items.len >= 1);
    for (list.items) |item| {
        try std.testing.expect(item.name.len > 0);
        // Loopback must not appear after filtering.
        try std.testing.expect(!std.mem.eql(u8, item.name, "lo"));
    }
}

test "appendUnique deduplicates by name and fills missing mac" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(NicInfo) = .{};
    defer {
        for (list.items) |item| allocator.free(item.name);
        list.deinit(allocator);
    }

    try appendUnique(&list, allocator, "eth0", null, 1);
    try appendUnique(&list, allocator, "eth0", .{ 1, 2, 3, 4, 5, 6 }, 1);
    try appendUnique(&list, allocator, "eth1", .{ 9, 9, 9, 9, 9, 9 }, 2);

    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqualSlices(u8, "eth0", list.items[0].name);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6 }, &list.items[0].mac.?);
    try std.testing.expectEqual(@as(u32, 2), list.items[1].index);
}