// SoftEther VPN Client - Windows TUN Adapter
// Uses Wintun driver (modern WireGuard-compatible TUN) for packet I/O.
// Falls back to TAP-Windows6 NDIS driver if Wintun is unavailable.

const std = @import("std");
const builtin = @import("builtin");

pub const TUN_MTU: usize = 1500;
pub const MAX_PACKET_SIZE: usize = TUN_MTU + 14;
pub const RECV_QUEUE_MAX: usize = 64;

// ============================================
// Windows API types (kernel32 / advapi32)
// ============================================
const HANDLE = std.os.windows.HANDLE;
const INVALID_HANDLE_VALUE = std.os.windows.INVALID_HANDLE_VALUE;
const DWORD = std.os.windows.DWORD;
const BOOL = std.os.windows.BOOL;
const BYTE = u8;
const HMODULE = ?*anyopaque;
const LPCSTR = [*:0]const u8;
const LPCWSTR = [*:0]const u16;

const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

// ============================================
// Wintun API function pointer types
// ============================================

/// Wintun adapter handle (opaque)
const WINTUN_ADAPTER_HANDLE = *anyopaque;
/// Wintun session handle (opaque)
const WINTUN_SESSION_HANDLE = *anyopaque;

/// WintunCreateAdapter(Name, TunnelType, RequestedGUID) -> WINTUN_ADAPTER_HANDLE
const WintunCreateAdapterFn = *const fn (
    [*:0]const u16, // Name
    [*:0]const u16, // TunnelType
    ?*const GUID, // RequestedGUID (nullable)
) callconv(.c) ?WINTUN_ADAPTER_HANDLE;

/// WintunCloseAdapter(Adapter)
const WintunCloseAdapterFn = *const fn (WINTUN_ADAPTER_HANDLE) callconv(.c) void;

/// WintunStartSession(Adapter, Capacity) -> WINTUN_SESSION_HANDLE
const WintunStartSessionFn = *const fn (
    WINTUN_ADAPTER_HANDLE,
    DWORD, // ring capacity (must be power of 2, between 0x20000 and 0x4000000)
) callconv(.c) ?WINTUN_SESSION_HANDLE;

/// WintunEndSession(Session)
const WintunEndSessionFn = *const fn (WINTUN_SESSION_HANDLE) callconv(.c) void;

/// WintunGetReadWaitEvent(Session) -> HANDLE
const WintunGetReadWaitEventFn = *const fn (WINTUN_SESSION_HANDLE) callconv(.c) HANDLE;

/// WintunReceivePacket(Session, PacketSize) -> *BYTE
const WintunReceivePacketFn = *const fn (
    WINTUN_SESSION_HANDLE,
    *DWORD, // out: packet size
) callconv(.c) ?[*]const BYTE;

/// WintunReleaseReceivePacket(Session, Packet)
const WintunReleaseReceivePacketFn = *const fn (
    WINTUN_SESSION_HANDLE,
    [*]const BYTE,
) callconv(.c) void;

/// WintunAllocateSendPacket(Session, PacketSize) -> *BYTE
const WintunAllocateSendPacketFn = *const fn (
    WINTUN_SESSION_HANDLE,
    DWORD, // packet size
) callconv(.c) ?[*]BYTE;

/// WintunSendPacket(Session, Packet)
const WintunSendPacketFn = *const fn (
    WINTUN_SESSION_HANDLE,
    [*]const BYTE,
) callconv(.c) void;

/// WintunGetAdapterLUID(Adapter, Luid)
const WintunGetAdapterLUIDFn = *const fn (
    WINTUN_ADAPTER_HANDLE,
    *NET_LUID,
) callconv(.c) void;

const NET_LUID = extern struct {
    Value: u64,
};

// ============================================
// Wintun DLL wrapper
// ============================================
const WintunApi = struct {
    dll: HMODULE,
    createAdapter: WintunCreateAdapterFn,
    closeAdapter: WintunCloseAdapterFn,
    startSession: WintunStartSessionFn,
    endSession: WintunEndSessionFn,
    getReadWaitEvent: WintunGetReadWaitEventFn,
    receivePacket: WintunReceivePacketFn,
    releaseReceivePacket: WintunReleaseReceivePacketFn,
    allocateSendPacket: WintunAllocateSendPacketFn,
    sendPacket: WintunSendPacketFn,
    getAdapterLUID: WintunGetAdapterLUIDFn,

    fn load() !WintunApi {
        const kernel32 = @cImport(@cInclude("windows.h"));
        const dll = kernel32.LoadLibraryA("wintun.dll");
        if (dll == null) {
            std.log.err("Failed to load wintun.dll — Wintun driver not installed.", .{});
            std.log.err("Download from: https://www.wintun.net/ and place wintun.dll in the application directory or System32.", .{});
            return TapWindowsError.WintunNotFound;
        }

        return .{
            .dll = dll,
            .createAdapter = @ptrCast(kernel32.GetProcAddress(dll, "WintunCreateAdapter") orelse return TapWindowsError.WintunNotFound),
            .closeAdapter = @ptrCast(kernel32.GetProcAddress(dll, "WintunCloseAdapter") orelse return TapWindowsError.WintunNotFound),
            .startSession = @ptrCast(kernel32.GetProcAddress(dll, "WintunStartSession") orelse return TapWindowsError.WintunNotFound),
            .endSession = @ptrCast(kernel32.GetProcAddress(dll, "WintunEndSession") orelse return TapWindowsError.WintunNotFound),
            .getReadWaitEvent = @ptrCast(kernel32.GetProcAddress(dll, "WintunGetReadWaitEvent") orelse return TapWindowsError.WintunNotFound),
            .receivePacket = @ptrCast(kernel32.GetProcAddress(dll, "WintunReceivePacket") orelse return TapWindowsError.WintunNotFound),
            .releaseReceivePacket = @ptrCast(kernel32.GetProcAddress(dll, "WintunReleaseReceivePacket") orelse return TapWindowsError.WintunNotFound),
            .allocateSendPacket = @ptrCast(kernel32.GetProcAddress(dll, "WintunAllocateSendPacket") orelse return TapWindowsError.WintunNotFound),
            .sendPacket = @ptrCast(kernel32.GetProcAddress(dll, "WintunSendPacket") orelse return TapWindowsError.WintunNotFound),
            .getAdapterLUID = @ptrCast(kernel32.GetProcAddress(dll, "WintunGetAdapterLUID") orelse return TapWindowsError.WintunNotFound),
        };
    }

    fn unload(self: *WintunApi) void {
        const kernel32 = @cImport(@cInclude("windows.h"));
        if (self.dll) |dll| {
            _ = kernel32.FreeLibrary(@ptrCast(@alignCast(dll)));
            self.dll = null;
        }
    }
};

// ============================================
// Error types
// ============================================
pub const TapWindowsError = error{
    NotWindows,
    WintunNotFound,
    CreateAdapterFailed,
    StartSessionFailed,
    DeviceNotOpen,
    ReadFailed,
    WriteFailed,
    ConfigureFailed,
    OpenFailed,
};

// ============================================
// TUN Statistics (matches Linux TUN format)
// ============================================
pub const TunStats = struct {
    send_packets: u64 = 0,
    send_bytes: u64 = 0,
    recv_packets: u64 = 0,
    recv_bytes: u64 = 0,
};

// ============================================
// Windows TUN Device (Wintun-based)
// ============================================
pub const TapWindowsDevice = struct {
    allocator: std.mem.Allocator,

    // Wintun API handles
    api: WintunApi,
    adapter: ?WINTUN_ADAPTER_HANDLE,
    session: ?WINTUN_SESSION_HANDLE,
    read_event: ?HANDLE,

    // Device info
    device_name: [64]u8,
    device_name_len: usize,
    mac_address: [6]u8,
    luid: NET_LUID,

    // IP configuration
    ipv4_address: u32,
    ipv4_netmask: u32,
    ipv4_gateway: u32,

    // Statistics
    stats: TunStats,

    // State
    is_open: bool,
    is_configured: bool,
    halt: bool,

    connection_start_time: i64,

    // Wintun session ring capacity (4 MB)
    const RING_CAPACITY: DWORD = 0x400000;

    // Adapter name for Wintun
    const ADAPTER_NAME = toUtf16Literal("SoftEther VPN");
    const TUNNEL_TYPE = toUtf16Literal("SoftEther");

    /// Open a Windows TUN device via Wintun
    pub fn open(allocator: std.mem.Allocator) TapWindowsError!*TapWindowsDevice {
        if (builtin.os.tag != .windows) {
            return TapWindowsError.NotWindows;
        }

        // Load Wintun DLL
        var api = WintunApi.load() catch {
            std.log.err("Wintun initialization failed. VPN tunnel cannot be created.", .{});
            std.log.err("Ensure Wintun is installed: https://www.wintun.net/", .{});
            return TapWindowsError.WintunNotFound;
        };
        errdefer api.unload();

        // Create adapter
        const adapter = api.createAdapter(
            &ADAPTER_NAME,
            &TUNNEL_TYPE,
            null,
        ) orelse {
            std.log.err("WintunCreateAdapter failed", .{});
            return TapWindowsError.CreateAdapterFailed;
        };
        errdefer api.closeAdapter(adapter);

        // Get adapter LUID for IP configuration
        var luid: NET_LUID = .{ .Value = 0 };
        api.getAdapterLUID(adapter, &luid);

        // Start session
        const session = api.startSession(adapter, RING_CAPACITY) orelse {
            std.log.err("WintunStartSession failed", .{});
            return TapWindowsError.StartSessionFailed;
        };
        errdefer api.endSession(session);

        // Get the read wait event for WaitForSingleObject / poll
        const read_event = api.getReadWaitEvent(session);

        // Generate random MAC address
        var mac: [6]u8 = undefined;
        std.crypto.random.bytes(&mac);
        mac[0] = (mac[0] & 0xFC) | 0x02; // locally administered, unicast

        const device = allocator.create(TapWindowsDevice) catch {
            return TapWindowsError.OpenFailed;
        };

        const name_str = "SoftEther VPN";
        var name_buf: [64]u8 = [_]u8{0} ** 64;
        @memcpy(name_buf[0..name_str.len], name_str);

        device.* = .{
            .allocator = allocator,
            .api = api,
            .adapter = adapter,
            .session = session,
            .read_event = read_event,
            .device_name = name_buf,
            .device_name_len = name_str.len,
            .mac_address = mac,
            .luid = luid,
            .ipv4_address = 0,
            .ipv4_netmask = 0,
            .ipv4_gateway = 0,
            .stats = .{},
            .is_open = true,
            .is_configured = false,
            .halt = false,
            .connection_start_time = std.time.milliTimestamp(),
        };

        std.log.info("Wintun adapter created: {s}", .{name_str});
        return device;
    }

    /// Close the TUN device and release all Wintun resources
    pub fn close(self: *TapWindowsDevice) void {
        if (self.session) |session| {
            self.api.endSession(session);
            self.session = null;
        }
        if (self.adapter) |adapter| {
            self.api.closeAdapter(adapter);
            self.adapter = null;
        }
        self.api.unload();
        self.is_open = false;
        self.read_event = null;
        self.allocator.destroy(self);
    }

    /// Get device name
    pub fn getName(self: *const TapWindowsDevice) []const u8 {
        return self.device_name[0..self.device_name_len];
    }

    /// Get MAC address
    pub fn getMac(self: *const TapWindowsDevice) [6]u8 {
        return self.mac_address;
    }

    /// Get wait event handle for polling (Windows equivalent of fd for poll)
    pub fn getReadEvent(self: *const TapWindowsDevice) ?HANDLE {
        return self.read_event;
    }

    /// Check if device is open
    pub fn isOpen(self: *const TapWindowsDevice) bool {
        return self.is_open and self.session != null;
    }

    /// Configure IP address via netsh (Windows IP helper)
    pub fn configure(self: *TapWindowsDevice, ip: u32, mask: u32, gateway: u32) !void {
        self.ipv4_address = ip;
        self.ipv4_netmask = mask;
        self.ipv4_gateway = gateway;

        // Format IP strings
        var ip_buf: [16]u8 = undefined;
        var mask_buf: [16]u8 = undefined;
        var gw_buf: [16]u8 = undefined;

        const ip_str = formatIpv4(ip, &ip_buf);
        const mask_str = formatIpv4(mask, &mask_buf);
        const gw_str = formatIpv4(gateway, &gw_buf);

        // Use netsh to configure the adapter IP
        var cmd_buf: [512]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "netsh interface ip set address name=\"SoftEther VPN\" static {s} {s} {s}", .{
            ip_str,
            mask_str,
            gw_str,
        }) catch return TapWindowsError.ConfigureFailed;

        std.log.info("Running: {s}", .{cmd});

        var child = std.process.Child.init(
            &[_][]const u8{ "cmd.exe", "/C", cmd },
            self.allocator,
        );
        child.stdout_behavior = .Close;
        child.stderr_behavior = .Close;
        _ = child.spawnAndWait() catch {
            return TapWindowsError.ConfigureFailed;
        };

        self.is_configured = true;
    }

    /// Configure with temporary settings for DHCP phase
    /// On Windows with Wintun (L3), we skip this — the VPN tunnel performs its own
    /// DHCP negotiation and then configure() sets a static IP from the DHCP ACK.
    /// Set the MTU on this device. Not supported for Wintun (handled by driver).
    pub fn setMtu(self: *TapWindowsDevice, mtu: u16) !void {
        _ = self;
        _ = mtu;
        std.log.debug("setMtu not supported for Wintun", .{});
    }

    /// Running `netsh ... dhcp` here would trigger Windows' built-in DHCP client
    /// which races the tunnel DHCP and falls back to APIPA (169.254.x.x).
    pub fn configureTemporary(self: *TapWindowsDevice) !void {
        _ = self;
        // No-op on Windows — tunnel DHCP + configure() handles IP assignment
    }

    /// Read a packet from the Wintun session ring.
    /// Returns IP packet data (no Ethernet header — Wintun is L3).
    pub fn read(self: *TapWindowsDevice, buffer: []u8) !?usize {
        const session = self.session orelse return TapWindowsError.DeviceNotOpen;

        var pkt_size: DWORD = 0;
        const pkt_ptr = self.api.receivePacket(session, &pkt_size);

        if (pkt_ptr) |ptr| {
            defer self.api.releaseReceivePacket(session, ptr);

            const len = @min(@as(usize, pkt_size), buffer.len);
            @memcpy(buffer[0..len], ptr[0..len]);

            self.stats.recv_packets += 1;
            self.stats.recv_bytes += len;
            return len;
        }

        // No packet available (non-blocking)
        return null;
    }

    /// Write a packet to the Wintun session ring.
    /// Expects a raw IP packet (no Ethernet header).
    pub fn write(self: *TapWindowsDevice, data: []const u8) !usize {
        const session = self.session orelse return TapWindowsError.DeviceNotOpen;

        const pkt_ptr = self.api.allocateSendPacket(session, @intCast(data.len));
        if (pkt_ptr) |ptr| {
            @memcpy(ptr[0..data.len], data);
            self.api.sendPacket(session, ptr);

            self.stats.send_packets += 1;
            self.stats.send_bytes += data.len;
            return data.len;
        }

        return TapWindowsError.WriteFailed;
    }

    /// Get traffic statistics
    pub fn getStats(self: *const TapWindowsDevice) TunStats {
        return self.stats;
    }
};

// ============================================
// Helpers
// ============================================

/// Format a u32 IPv4 address to dotted decimal
fn formatIpv4(ip: u32, buf: []u8) []const u8 {
    const b0: u8 = @truncate((ip >> 24) & 0xFF);
    const b1: u8 = @truncate((ip >> 16) & 0xFF);
    const b2: u8 = @truncate((ip >> 8) & 0xFF);
    const b3: u8 = @truncate(ip & 0xFF);
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ b0, b1, b2, b3 }) catch return "";
    return result;
}

/// Comptime helper: convert ASCII to UTF-16LE null-terminated literal
fn toUtf16Literal(comptime ascii: []const u8) [ascii.len:0]u16 {
    var result: [ascii.len:0]u16 = undefined;
    for (ascii, 0..) |c, i| {
        result[i] = c;
    }
    return result;
}
