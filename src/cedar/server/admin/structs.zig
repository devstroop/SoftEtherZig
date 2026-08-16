//! Server admin RPC structs + Pack (de)serialization (issue #89).
//!
//! `RPC_*`-equivalent structs and their Pack field (de)serialization, used by
//! the admin dispatch endpoints (mirror C `Admin.h` / `Admin.c`). Implemented
//! in dispatch order (SERVER_PLAN.md §6.5): Core, Listeners, Hubs. Later
//! groups (Users, Sessions, Tables, Traffic/logging) add their structs here.
//!
//! C reference (4.44):
//! - Struct definitions: `Admin.h`, `Server.h` (`RPC_SESSION_STATUS`),
//!   `MayaType.h` (`OS_INFO`), `Kernel.h` (`MEMINFO`), `Cedar.h` (`TRAFFIC`,
//!   `TRAFFIC_ENTRY`), `Server.h` (`CAPS`/`CAPSLIST`)
//! - Serializers: `Admin.c` `InRpc*`/`OutRpc*`, `Client.c`
//!   `InRpcTraffic`/`OutRpcTraffic`, `Server.c` `InRpcCapsList`/`OutRpcCapsList`
//!
//! ## Ownership model
//!
//! `in*` functions allocate (strings + item arrays) from the given allocator;
//! the matching `free*` releases them. `out*` functions only read. Field
//! names and types match the C wire format exactly — that is the interop
//! contract with `vpncmd`/the C server.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const pack_mod = @import("../../protocol/pack.zig");
const Pack = pack_mod.Pack;
const types_mod = @import("../../../mayaqua/kernel/types.zig");
const IpAddress = types_mod.IpAddress;

// ============================================================================
// Length constants (C: Cedar.h / Mayaqua.h)
// ============================================================================

pub const MAX_HUBNAME_LEN = 255;
pub const MAX_HOST_NAME_LEN = 255;
pub const MAX_USERNAME_LEN = 255;
pub const MAX_SESSION_NAME_LEN = 255;
pub const MAX_SERVER_STR_LEN = 255;
pub const MAX_CLIENT_STR_LEN = 255;
pub const MAX_SIZE = 512;
pub const SHA1_SIZE = 20;

// ============================================================================
// Shared sub-structs
// ============================================================================

/// C `TRAFFIC_ENTRY` (Cedar.h:949) + `TRAFFIC` (Cedar.h:958).
/// `send`/`recv` are the two directions.
pub const Traffic = struct {
    send_broadcast_bytes: u64 = 0,
    send_broadcast_count: u64 = 0,
    send_unicast_bytes: u64 = 0,
    send_unicast_count: u64 = 0,
    recv_broadcast_bytes: u64 = 0,
    recv_broadcast_count: u64 = 0,
    recv_unicast_bytes: u64 = 0,
    recv_unicast_count: u64 = 0,

    /// C `InRpcTraffic` (Client.c:4193). Non-indexed element names.
    pub fn inRpc(self: *Traffic, p: *const Pack) void {
        self.* = .{};
        self.recv_broadcast_bytes = p.getInt64("Recv.BroadcastBytes") orelse 0;
        self.recv_broadcast_count = p.getInt64("Recv.BroadcastCount") orelse 0;
        self.recv_unicast_bytes = p.getInt64("Recv.UnicastBytes") orelse 0;
        self.recv_unicast_count = p.getInt64("Recv.UnicastCount") orelse 0;
        self.send_broadcast_bytes = p.getInt64("Send.BroadcastBytes") orelse 0;
        self.send_broadcast_count = p.getInt64("Send.BroadcastCount") orelse 0;
        self.send_unicast_bytes = p.getInt64("Send.UnicastBytes") orelse 0;
        self.send_unicast_count = p.getInt64("Send.UnicastCount") orelse 0;
    }

    /// C `OutRpcTraffic` (Client.c:4211).
    pub fn outRpc(self: *const Traffic, p: *Pack) !void {
        try p.addInt64("Recv.BroadcastBytes", self.recv_broadcast_bytes);
        try p.addInt64("Recv.BroadcastCount", self.recv_broadcast_count);
        try p.addInt64("Recv.UnicastBytes", self.recv_unicast_bytes);
        try p.addInt64("Recv.UnicastCount", self.recv_unicast_count);
        try p.addInt64("Send.BroadcastBytes", self.send_broadcast_bytes);
        try p.addInt64("Send.BroadcastCount", self.send_broadcast_count);
        try p.addInt64("Send.UnicastBytes", self.send_unicast_bytes);
        try p.addInt64("Send.UnicastCount", self.send_unicast_count);
    }
};

/// C `MEMINFO` (Kernel.h:106).
pub const MemInfo = struct {
    total_memory: u64 = 0,
    used_memory: u64 = 0,
    free_memory: u64 = 0,
    total_phys: u64 = 0,
    used_phys: u64 = 0,
    free_phys: u64 = 0,

    pub fn inRpc(self: *MemInfo, p: *const Pack) void {
        self.* = .{};
        self.total_memory = p.getInt64("TotalMemory") orelse 0;
        self.used_memory = p.getInt64("UsedMemory") orelse 0;
        self.free_memory = p.getInt64("FreeMemory") orelse 0;
        self.total_phys = p.getInt64("TotalPhys") orelse 0;
        self.used_phys = p.getInt64("UsedPhys") orelse 0;
        self.free_phys = p.getInt64("FreePhys") orelse 0;
    }

    pub fn outRpc(self: *const MemInfo, p: *Pack) !void {
        try p.addInt64("TotalMemory", self.total_memory);
        try p.addInt64("UsedMemory", self.used_memory);
        try p.addInt64("FreeMemory", self.free_memory);
        try p.addInt64("TotalPhys", self.total_phys);
        try p.addInt64("UsedPhys", self.used_phys);
        try p.addInt64("FreePhys", self.free_phys);
    }
};

/// C `OS_INFO` (MayaType.h:369). Variable-length strings are heap slices.
pub const OsInfo = struct {
    os_type: u32 = 0,
    os_service_pack: u32 = 0,
    os_system_name: []const u8 = "",
    os_product_name: []const u8 = "",
    os_vendor_name: []const u8 = "",
    os_version: []const u8 = "",
    kernel_name: []const u8 = "",
    kernel_version: []const u8 = "",

    /// C `InRpcOsInfo` (Admin.c:11396). Missing strings are left empty.
    pub fn inRpc(self: *OsInfo, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.os_type = p.getInt("OsType") orelse 0;
        self.os_service_pack = p.getInt("OsServicePack") orelse 0;
        self.os_system_name = try dupStr(allocator, p.getStr("OsSystemName"));
        self.os_product_name = try dupStr(allocator, p.getStr("OsProductName"));
        self.os_vendor_name = try dupStr(allocator, p.getStr("OsVendorName"));
        self.os_version = try dupStr(allocator, p.getStr("OsVersion"));
        self.kernel_name = try dupStr(allocator, p.getStr("KernelName"));
        self.kernel_version = try dupStr(allocator, p.getStr("KernelVersion"));
    }

    /// C `OutRpcOsInfo` (Admin.c:11433).
    pub fn outRpc(self: *const OsInfo, p: *Pack) !void {
        try p.addInt("OsType", self.os_type);
        try p.addInt("OsServicePack", self.os_service_pack);
        try p.addStr("OsSystemName", self.os_system_name);
        try p.addStr("OsProductName", self.os_product_name);
        try p.addStr("OsVendorName", self.os_vendor_name);
        try p.addStr("OsVersion", self.os_version);
        try p.addStr("KernelName", self.kernel_name);
        try p.addStr("KernelVersion", self.kernel_version);
    }

    /// C `FreeRpcOsInfo` (Admin.c:11451).
    pub fn free(self: *OsInfo, allocator: Allocator) void {
        allocator.free(self.os_system_name);
        allocator.free(self.os_product_name);
        allocator.free(self.os_vendor_name);
        allocator.free(self.os_version);
        allocator.free(self.kernel_name);
        allocator.free(self.kernel_version);
        self.* = .{};
    }
};

/// C `RPC_HUB_OPTION` (Admin.h:312).
pub const HubOption = struct {
    max_session: u32 = 0,
    no_enum: bool = false,

    pub fn inRpc(self: *HubOption, p: *const Pack) void {
        self.* = .{};
        self.max_session = p.getInt("MaxSession") orelse 0;
        self.no_enum = p.getBool("NoEnum") orelse false;
    }

    pub fn outRpc(self: *const HubOption, p: *Pack) !void {
        try p.addInt("MaxSession", self.max_session);
        try p.addBool("NoEnum", self.no_enum);
    }
};

/// C `CAPS` (Server.h:404) — one capability (name + int value).
pub const Caps = struct {
    name: []const u8 = "",
    value: u32 = 0,

    pub fn free(self: *Caps, allocator: Allocator) void {
        allocator.free(self.name);
        self.* = .{};
    }
};

/// C `CAPSLIST` (Server.h:408) — capabilities list (GetCaps / GetServerCaps).
/// `caps` mirrors C's `LIST *CapsList`; a "caps_" int element per capability.
pub const CapsList = struct {
    caps: []Caps = &.{},

    /// C `InRpcCapsList` (Server.c:1871): every `caps_*` INT element with a
    /// single value becomes one capability (name = element name minus the
    /// `caps_` prefix).
    pub fn inRpc(self: *CapsList, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        const prefix = "caps_";
        var items = std.ArrayListUnmanaged(Caps){};
        errdefer {
            for (items.items) |*c| c.free(allocator);
            items.deinit(allocator);
        }
        for (p.elements.items) |*elem| {
            if (elem.values.items.len != 1) continue;
            if (elem.value_type != .int) continue;
            if (!std.ascii.startsWithIgnoreCase(elem.name, prefix)) continue;
            const name = try allocator.dupe(u8, elem.name[prefix.len..]);
            errdefer allocator.free(name);
            try items.append(allocator, .{ .name = name, .value = elem.values.items[0].int });
        }
        self.caps = try items.toOwnedSlice(allocator);
    }

    /// C `OutRpcCapsList` (Server.c:1894): writes `caps_<name>` ints plus the
    /// indexed `CapsName`/`CapsValue`/`CapsDescrption` mirrors (description
    /// left as the plain name — no localization table in Zig).
    pub fn outRpc(self: *const CapsList, p: *Pack) !void {
        for (self.caps, 0..) |c, i| {
            var name_buf: [MAX_SIZE + 5]u8 = undefined;
            const caps_name = std.fmt.bufPrint(&name_buf, "caps_{s}", .{c.name}) catch
                return error.BufferTooSmall;
            try p.addInt(caps_name, c.value);
            try p.addStrEx("CapsName", c.name, i);
            try p.addIntEx("CapsValue", c.value, i);
            try p.addUniStrEx("CapsDescrption", c.name, i);
        }
    }

    pub fn free(self: *CapsList, allocator: Allocator) void {
        for (self.caps) |*c| c.free(allocator);
        allocator.free(self.caps);
        self.* = .{};
    }
};

// ============================================================================
// Core dispatch group (SERVER_PLAN.md §6.5 group 1)
// ============================================================================

/// C `RPC_TEST` (Admin.h:137) — `Test`, `RebootServer`, and other no-op/echo
/// endpoints.
pub const RpcTest = struct {
    int_value: u32 = 0,
    int64_value: u64 = 0,
    str_value: []const u8 = "",
    uni_str_value: []const u8 = "",

    pub fn inRpc(self: *RpcTest, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.int_value = p.getInt("IntValue") orelse 0;
        self.int64_value = p.getInt64("Int64Value") orelse 0;
        self.str_value = try dupStr(allocator, p.getStr("StrValue"));
        self.uni_str_value = try dupStr(allocator, p.getUniStr("UniStrValue"));
    }

    pub fn outRpc(self: *const RpcTest, p: *Pack) !void {
        try p.addInt("IntValue", self.int_value);
        try p.addInt64("Int64Value", self.int64_value);
        try p.addStr("StrValue", self.str_value);
        try p.addUniStr("UniStrValue", self.uni_str_value);
    }

    pub fn free(self: *RpcTest, allocator: Allocator) void {
        allocator.free(self.str_value);
        allocator.free(self.uni_str_value);
        self.* = .{};
    }
};

/// C `RPC_SERVER_INFO` (Admin.h:146) — `GetServerInfo`.
pub const RpcServerInfo = struct {
    server_product_name: []const u8 = "",
    server_version_string: []const u8 = "",
    server_build_info_string: []const u8 = "",
    server_ver_int: u32 = 0,
    server_build_int: u32 = 0,
    server_host_name: []const u8 = "",
    server_type: u32 = 0,
    server_build_date: u64 = 0,
    server_family_name: []const u8 = "",
    os_info: OsInfo = .{},

    pub fn inRpc(self: *RpcServerInfo, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.server_product_name = try dupStr(allocator, p.getStr("ServerProductName"));
        self.server_version_string = try dupStr(allocator, p.getStr("ServerVersionString"));
        self.server_build_info_string = try dupStr(allocator, p.getStr("ServerBuildInfoString"));
        self.server_ver_int = p.getInt("ServerVerInt") orelse 0;
        self.server_build_int = p.getInt("ServerBuildInt") orelse 0;
        self.server_host_name = try dupStr(allocator, p.getStr("ServerHostName"));
        self.server_type = p.getInt("ServerType") orelse 0;
        self.server_build_date = p.getInt64("ServerBuildDate") orelse 0;
        self.server_family_name = try dupStr(allocator, p.getStr("ServerFamilyName"));
        try self.os_info.inRpc(allocator, p);
    }

    pub fn outRpc(self: *const RpcServerInfo, p: *Pack) !void {
        try p.addStr("ServerProductName", self.server_product_name);
        try p.addStr("ServerVersionString", self.server_version_string);
        try p.addStr("ServerBuildInfoString", self.server_build_info_string);
        try p.addInt("ServerVerInt", self.server_ver_int);
        try p.addInt("ServerBuildInt", self.server_build_int);
        try p.addStr("ServerHostName", self.server_host_name);
        try p.addInt("ServerType", self.server_type);
        try p.addInt64("ServerBuildDate", self.server_build_date);
        try p.addStr("ServerFamilyName", self.server_family_name);
        try self.os_info.outRpc(p);
    }

    pub fn free(self: *RpcServerInfo, allocator: Allocator) void {
        allocator.free(self.server_product_name);
        allocator.free(self.server_version_string);
        allocator.free(self.server_build_info_string);
        allocator.free(self.server_host_name);
        allocator.free(self.server_family_name);
        self.os_info.free(allocator);
        self.* = .{};
    }
};

/// C `RPC_SERVER_STATUS` (Admin.h:161) — `GetServerStatus`.
pub const RpcServerStatus = struct {
    server_type: u32 = 0,
    num_tcp_connections: u32 = 0,
    num_tcp_connections_local: u32 = 0,
    num_tcp_connections_remote: u32 = 0,
    num_hub_total: u32 = 0,
    num_hub_standalone: u32 = 0,
    num_hub_static: u32 = 0,
    num_hub_dynamic: u32 = 0,
    num_sessions_total: u32 = 0,
    num_sessions_local: u32 = 0,
    num_sessions_remote: u32 = 0,
    num_mac_tables: u32 = 0,
    num_ip_tables: u32 = 0,
    num_users: u32 = 0,
    num_groups: u32 = 0,
    assigned_bridge_licenses: u32 = 0,
    assigned_client_licenses: u32 = 0,
    assigned_bridge_licenses_total: u32 = 0,
    assigned_client_licenses_total: u32 = 0,
    traffic: Traffic = .{},
    current_time: u64 = 0,
    current_tick: u64 = 0,
    start_time: u64 = 0,
    mem_info: MemInfo = .{},

    pub fn inRpc(self: *RpcServerStatus, p: *const Pack) void {
        self.* = .{};
        self.server_type = p.getInt("ServerType") orelse 0;
        self.num_tcp_connections = p.getInt("NumTcpConnections") orelse 0;
        self.num_tcp_connections_local = p.getInt("NumTcpConnectionsLocal") orelse 0;
        self.num_tcp_connections_remote = p.getInt("NumTcpConnectionsRemote") orelse 0;
        self.num_hub_total = p.getInt("NumHubTotal") orelse 0;
        self.num_hub_standalone = p.getInt("NumHubStandalone") orelse 0;
        self.num_hub_static = p.getInt("NumHubStatic") orelse 0;
        self.num_hub_dynamic = p.getInt("NumHubDynamic") orelse 0;
        self.num_sessions_total = p.getInt("NumSessionsTotal") orelse 0;
        self.num_sessions_local = p.getInt("NumSessionsLocal") orelse 0;
        self.num_sessions_remote = p.getInt("NumSessionsRemote") orelse 0;
        self.num_mac_tables = p.getInt("NumMacTables") orelse 0;
        self.num_ip_tables = p.getInt("NumIpTables") orelse 0;
        self.num_users = p.getInt("NumUsers") orelse 0;
        self.num_groups = p.getInt("NumGroups") orelse 0;
        self.current_time = p.getInt64("CurrentTime") orelse 0;
        self.current_tick = p.getInt64("CurrentTick") orelse 0;
        self.assigned_bridge_licenses = p.getInt("AssignedBridgeLicenses") orelse 0;
        self.assigned_client_licenses = p.getInt("AssignedClientLicenses") orelse 0;
        self.assigned_bridge_licenses_total = p.getInt("AssignedBridgeLicensesTotal") orelse 0;
        self.assigned_client_licenses_total = p.getInt("AssignedClientLicensesTotal") orelse 0;
        self.start_time = p.getInt64("StartTime") orelse 0;
        self.traffic.inRpc(p);
        self.mem_info.inRpc(p);
    }

    pub fn outRpc(self: *const RpcServerStatus, p: *Pack) !void {
        try p.addInt("ServerType", self.server_type);
        try p.addInt("NumHubTotal", self.num_hub_total);
        try p.addInt("NumHubStandalone", self.num_hub_standalone);
        try p.addInt("NumHubStatic", self.num_hub_static);
        try p.addInt("NumHubDynamic", self.num_hub_dynamic);
        try p.addInt("NumSessionsTotal", self.num_sessions_total);
        try p.addInt("NumSessionsLocal", self.num_sessions_local);
        try p.addInt("NumSessionsRemote", self.num_sessions_remote);
        try p.addInt("NumTcpConnections", self.num_tcp_connections);
        try p.addInt("NumTcpConnectionsLocal", self.num_tcp_connections_local);
        try p.addInt("NumTcpConnectionsRemote", self.num_tcp_connections_remote);
        try p.addInt("NumMacTables", self.num_mac_tables);
        try p.addInt("NumIpTables", self.num_ip_tables);
        try p.addInt("NumUsers", self.num_users);
        try p.addInt("NumGroups", self.num_groups);
        try p.addInt64("CurrentTime", self.current_time);
        try p.addInt64("CurrentTick", self.current_tick);
        try p.addInt("AssignedBridgeLicenses", self.assigned_bridge_licenses);
        try p.addInt("AssignedClientLicenses", self.assigned_client_licenses);
        try p.addInt("AssignedBridgeLicensesTotal", self.assigned_bridge_licenses_total);
        try p.addInt("AssignedClientLicensesTotal", self.assigned_client_licenses_total);
        try p.addInt64("StartTime", self.start_time);
        try self.traffic.outRpc(p);
        try self.mem_info.outRpc(p);
    }
};

/// C `RPC_SET_PASSWORD` (Admin.h:218) — `SetServerPassword`.
pub const RpcSetPassword = struct {
    hashed_password: []const u8 = "",
    plain_text_password: []const u8 = "",

    pub fn inRpc(self: *RpcSetPassword, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hashed_password = try dupData(allocator, p.getData("HashedPassword"));
        self.plain_text_password = try dupStr(allocator, p.getStr("PlainTextPassword"));
    }

    pub fn outRpc(self: *const RpcSetPassword, p: *Pack) !void {
        try p.addData("HashedPassword", self.hashed_password);
        try p.addStr("PlainTextPassword", self.plain_text_password);
    }

    pub fn free(self: *RpcSetPassword, allocator: Allocator) void {
        allocator.free(self.hashed_password);
        allocator.free(self.plain_text_password);
        self.* = .{};
    }
};

/// C `RPC_STR` (Admin.h:206) — single string (e.g. `GetServerCipher`).
pub const RpcStr = struct {
    string: []const u8 = "",

    pub fn inRpc(self: *RpcStr, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.string = try dupStr(allocator, p.getStr("String"));
    }

    pub fn outRpc(self: *const RpcStr, p: *Pack) !void {
        try p.addStr("String", self.string);
    }

    pub fn free(self: *RpcStr, allocator: Allocator) void {
        allocator.free(self.string);
        self.* = .{};
    }
};

/// C `RPC_INT` (Admin.h:212) — single int.
pub const RpcInt = struct {
    int_value: u32 = 0,

    pub fn inRpc(self: *RpcInt, p: *const Pack) void {
        self.* = .{};
        self.int_value = p.getInt("IntValue") orelse 0;
    }

    pub fn outRpc(self: *const RpcInt, p: *Pack) !void {
        try p.addInt("IntValue", self.int_value);
    }
};

// ============================================================================
// Listeners dispatch group (SERVER_PLAN.md §6.5 group 2)
// ============================================================================

/// C `RPC_LISTENER` (Admin.h:190) — `CreateListener` / `DeleteListener`.
pub const RpcListener = struct {
    port: u32 = 0,
    enable: bool = false,

    pub fn inRpc(self: *RpcListener, p: *const Pack) void {
        self.* = .{};
        self.port = p.getInt("Port") orelse 0;
        self.enable = p.getBool("Enable") orelse false;
    }

    pub fn outRpc(self: *const RpcListener, p: *Pack) !void {
        try p.addInt("Port", self.port);
        try p.addBool("Enable", self.enable);
    }
};

/// C `RPC_LISTENER_LIST` (Admin.h:197) — `EnumListener`. Three parallel
/// indexed arrays (ports, enables, errors) sharing the count of the first.
pub const RpcListenerList = struct {
    ports: []u32 = &.{},
    enables: []bool = &.{},
    errors: []bool = &.{},

    pub fn inRpc(self: *RpcListenerList, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        const count = p.getValueCount("Ports");
        self.ports = try allocator.alloc(u32, count);
        self.enables = try allocator.alloc(bool, count);
        self.errors = try allocator.alloc(bool, count);
        for (0..count) |i| {
            self.ports[i] = p.getIntEx("Ports", i) orelse 0;
            self.enables[i] = p.getBoolEx("Enables", i) orelse false;
            self.errors[i] = p.getBoolEx("Errors", i) orelse false;
        }
    }

    pub fn outRpc(self: *const RpcListenerList, p: *Pack) !void {
        for (self.ports, 0..) |port, i| {
            try p.addIntEx("Ports", port, i);
            try p.addBoolEx("Enables", self.enables[i], i);
            try p.addBoolEx("Errors", self.errors[i], i);
        }
    }

    pub fn free(self: *RpcListenerList, allocator: Allocator) void {
        allocator.free(self.ports);
        allocator.free(self.enables);
        allocator.free(self.errors);
        self.* = .{};
    }
};

// ============================================================================
// Hubs dispatch group (SERVER_PLAN.md §6.5 group 3)
// ============================================================================

/// C `RPC_CREATE_HUB` (Admin.h:335) — `CreateHub` / `SetHub` / `GetHub`.
pub const RpcCreateHub = struct {
    hub_name: []const u8 = "",
    hashed_password: []const u8 = "",
    secure_password: []const u8 = "",
    admin_password_plain_text: []const u8 = "",
    online: bool = false,
    hub_option: HubOption = .{},
    hub_type: u32 = 0,

    pub fn inRpc(self: *RpcCreateHub, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStr("HubName"));
        self.hashed_password = try dupData(allocator, p.getData("HashedPassword"));
        self.secure_password = try dupData(allocator, p.getData("SecurePassword"));
        self.admin_password_plain_text = try dupStr(allocator, p.getStr("AdminPasswordPlainText"));
        self.online = p.getBool("Online") orelse false;
        self.hub_option.inRpc(p);
        self.hub_type = p.getInt("HubType") orelse 0;
    }

    pub fn outRpc(self: *const RpcCreateHub, p: *Pack) !void {
        try p.addStr("HubName", self.hub_name);
        try p.addData("HashedPassword", self.hashed_password);
        try p.addData("SecurePassword", self.secure_password);
        try p.addBool("Online", self.online);
        try p.addStr("AdminPasswordPlainText", self.admin_password_plain_text);
        try self.hub_option.outRpc(p);
        try p.addInt("HubType", self.hub_type);
    }

    pub fn free(self: *RpcCreateHub, allocator: Allocator) void {
        allocator.free(self.hub_name);
        allocator.free(self.hashed_password);
        allocator.free(self.secure_password);
        allocator.free(self.admin_password_plain_text);
        self.* = .{};
    }
};

/// C `RPC_ENUM_HUB_ITEM` (Admin.h:347) — one row of `EnumHub`.
pub const EnumHubItem = struct {
    hub_name: []const u8 = "",
    online: bool = false,
    hub_type: u32 = 0,
    num_users: u32 = 0,
    num_groups: u32 = 0,
    num_sessions: u32 = 0,
    num_mac_tables: u32 = 0,
    num_ip_tables: u32 = 0,
    last_comm_time: u64 = 0,
    last_login_time: u64 = 0,
    created_time: u64 = 0,
    num_login: u32 = 0,
    is_traffic_filled: bool = false,
    traffic: Traffic = .{},

    pub fn inRpc(self: *EnumHubItem, allocator: Allocator, p: *const Pack, index: usize) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStrEx("HubName", index));
        self.online = p.getBoolEx("Online", index) orelse false;
        self.hub_type = p.getIntEx("HubType", index) orelse 0;
        self.num_sessions = p.getIntEx("NumSessions", index) orelse 0;
        self.num_users = p.getIntEx("NumUsers", index) orelse 0;
        self.num_groups = p.getIntEx("NumGroups", index) orelse 0;
        self.num_mac_tables = p.getIntEx("NumMacTables", index) orelse 0;
        self.num_ip_tables = p.getIntEx("NumIpTables", index) orelse 0;
        self.last_comm_time = p.getInt64Ex("LastCommTime", index) orelse 0;
        self.created_time = p.getInt64Ex("CreatedTime", index) orelse 0;
        self.last_login_time = p.getInt64Ex("LastLoginTime", index) orelse 0;
        self.num_login = p.getIntEx("NumLogin", index) orelse 0;
        self.is_traffic_filled = p.getBoolEx("IsTrafficFilled", index) orelse false;
        inRpcTrafficEx(&self.traffic, p, index);
    }

    pub fn outRpc(self: *const EnumHubItem, p: *Pack, index: usize) !void {
        try p.addStrEx("HubName", self.hub_name, index);
        try p.addBoolEx("Online", self.online, index);
        try p.addIntEx("HubType", self.hub_type, index);
        try p.addIntEx("NumSessions", self.num_sessions, index);
        try p.addIntEx("NumUsers", self.num_users, index);
        try p.addIntEx("NumGroups", self.num_groups, index);
        try p.addIntEx("NumMacTables", self.num_mac_tables, index);
        try p.addIntEx("NumIpTables", self.num_ip_tables, index);
        try p.addInt64Ex("LastCommTime", self.last_comm_time, index);
        try p.addInt64Ex("CreatedTime", self.created_time, index);
        try p.addInt64Ex("LastLoginTime", self.last_login_time, index);
        try p.addIntEx("NumLogin", self.num_login, index);
        try p.addBoolEx("IsTrafficFilled", self.is_traffic_filled, index);
        try outRpcTrafficEx(&self.traffic, p, index);
    }

    pub fn free(self: *EnumHubItem, allocator: Allocator) void {
        allocator.free(self.hub_name);
        self.* = .{};
    }
};

/// C `RPC_ENUM_HUB` (Admin.h:366) — `EnumHub`. The item count is the index
/// count of the "HubName" element (C: `PackGetIndexCount`).
pub const RpcEnumHub = struct {
    hubs: []EnumHubItem = &.{},

    pub fn inRpc(self: *RpcEnumHub, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        const count = p.getValueCount("HubName");
        self.hubs = try allocator.alloc(EnumHubItem, count);
        for (0..count) |i| {
            self.hubs[i] = .{};
            try self.hubs[i].inRpc(allocator, p, i);
        }
    }

    pub fn outRpc(self: *const RpcEnumHub, p: *Pack) !void {
        for (self.hubs, 0..) |*hub, i| {
            try hub.outRpc(p, i);
        }
    }

    pub fn free(self: *RpcEnumHub, allocator: Allocator) void {
        for (self.hubs) |*hub| hub.free(allocator);
        allocator.free(self.hubs);
        self.* = .{};
    }
};

/// C `RPC_DELETE_HUB` (Admin.h:373) — `DeleteHub`.
pub const RpcDeleteHub = struct {
    hub_name: []const u8 = "",

    pub fn inRpc(self: *RpcDeleteHub, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStr("HubName"));
    }

    pub fn outRpc(self: *const RpcDeleteHub, p: *Pack) !void {
        try p.addStr("HubName", self.hub_name);
    }

    pub fn free(self: *RpcDeleteHub, allocator: Allocator) void {
        allocator.free(self.hub_name);
        self.* = .{};
    }
};

/// C `RPC_HUB_STATUS` (Admin.h:427) — `GetHubStatus`.
pub const RpcHubStatus = struct {
    hub_name: []const u8 = "",
    online: bool = false,
    hub_type: u32 = 0,
    num_sessions: u32 = 0,
    num_sessions_client: u32 = 0,
    num_sessions_bridge: u32 = 0,
    num_access_lists: u32 = 0,
    num_users: u32 = 0,
    num_groups: u32 = 0,
    num_mac_tables: u32 = 0,
    num_ip_tables: u32 = 0,
    secure_nat_enabled: bool = false,
    traffic: Traffic = .{},
    last_comm_time: u64 = 0,
    created_time: u64 = 0,
    last_login_time: u64 = 0,
    num_login: u32 = 0,

    pub fn inRpc(self: *RpcHubStatus, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStr("HubName"));
        self.online = p.getBool("Online") orelse false;
        self.hub_type = p.getInt("HubType") orelse 0;
        self.num_sessions = p.getInt("NumSessions") orelse 0;
        self.num_sessions_client = p.getInt("NumSessionsClient") orelse 0;
        self.num_sessions_bridge = p.getInt("NumSessionsBridge") orelse 0;
        self.num_access_lists = p.getInt("NumAccessLists") orelse 0;
        self.num_users = p.getInt("NumUsers") orelse 0;
        self.num_groups = p.getInt("NumGroups") orelse 0;
        self.num_mac_tables = p.getInt("NumMacTables") orelse 0;
        self.num_ip_tables = p.getInt("NumIpTables") orelse 0;
        self.secure_nat_enabled = p.getBool("SecureNATEnabled") orelse false;
        self.traffic.inRpc(p);
        self.last_comm_time = p.getInt64("LastCommTime") orelse 0;
        self.created_time = p.getInt64("CreatedTime") orelse 0;
        self.last_login_time = p.getInt64("LastLoginTime") orelse 0;
        self.num_login = p.getInt("NumLogin") orelse 0;
    }

    pub fn outRpc(self: *const RpcHubStatus, p: *Pack) !void {
        try p.addStr("HubName", self.hub_name);
        try p.addBool("Online", self.online);
        try p.addInt("HubType", self.hub_type);
        try p.addInt("NumSessions", self.num_sessions);
        try p.addInt("NumSessionsClient", self.num_sessions_client);
        try p.addInt("NumSessionsBridge", self.num_sessions_bridge);
        try p.addInt("NumAccessLists", self.num_access_lists);
        try p.addInt("NumUsers", self.num_users);
        try p.addInt("NumGroups", self.num_groups);
        try p.addInt("NumMacTables", self.num_mac_tables);
        try p.addInt("NumIpTables", self.num_ip_tables);
        try p.addBool("SecureNATEnabled", self.secure_nat_enabled);
        try self.traffic.outRpc(p);
        try p.addInt64("LastCommTime", self.last_comm_time);
        try p.addInt64("CreatedTime", self.created_time);
        try p.addInt64("LastLoginTime", self.last_login_time);
        try p.addInt("NumLogin", self.num_login);
    }

    pub fn free(self: *RpcHubStatus, allocator: Allocator) void {
        allocator.free(self.hub_name);
        self.* = .{};
    }
};

// ============================================================================
// Sessions & connections (C: Admin.h RPC_ENUM_SESSION / RPC_SESSION_STATUS /
// RPC_DELETE_SESSION / RPC_ENUM_CONNECTION / RPC_DISCONNECT_CONNECTION)
// ============================================================================

/// C `RPC_ENUM_SESSION_ITEM` (Admin.h:651) — one row of `EnumSession`. The
/// `client_ip` union is serialized in the C `PackAddIpEx` four-element format
/// so vpncmd's `PackGetIpEx` round-trips it; `ip` carries the plain IPv4 u32.
pub const EnumSessionItem = struct {
    name: []const u8 = "",
    remote_session: bool = false,
    remote_hostname: []const u8 = "",
    username: []const u8 = "",
    ip: u32 = 0,
    client_ip: IpAddress = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    hostname: []const u8 = "",
    max_num_tcp: u32 = 0,
    current_num_tcp: u32 = 0,
    packet_size: u64 = 0,
    packet_num: u64 = 0,
    link_mode: bool = false,
    secure_nat_mode: bool = false,
    bridge_mode: bool = false,
    layer3_mode: bool = false,
    client_bridge_mode: bool = false,
    client_monitor_mode: bool = false,
    vlan_id: u32 = 0,
    unique_id: [16]u8 = [_]u8{0} ** 16,
    is_dormant_enabled: bool = false,
    is_dormant: bool = false,
    last_comm_dormant: u64 = 0,
    created_time: u64 = 0,
    last_comm_time: u64 = 0,

    pub fn inRpc(self: *EnumSessionItem, allocator: Allocator, p: *const Pack, index: usize) !void {
        self.* = .{};
        self.name = try dupStr(allocator, p.getStrEx("Name", index));
        self.remote_session = p.getBoolEx("RemoteSession", index) orelse false;
        self.remote_hostname = try dupStr(allocator, p.getStrEx("RemoteHostname", index));
        self.username = try dupStr(allocator, p.getStrEx("Username", index));
        self.ip = p.getIntEx("Ip", index) orelse 0;
        self.client_ip = getIpAddressEx(p, "ClientIP", index);
        self.hostname = try dupStr(allocator, p.getStrEx("Hostname", index));
        self.max_num_tcp = p.getIntEx("MaxNumTcp", index) orelse 0;
        self.current_num_tcp = p.getIntEx("CurrentNumTcp", index) orelse 0;
        self.packet_size = p.getInt64Ex("PacketSize", index) orelse 0;
        self.packet_num = p.getInt64Ex("PacketNum", index) orelse 0;
        self.link_mode = p.getBoolEx("LinkMode", index) orelse false;
        self.secure_nat_mode = p.getBoolEx("SecureNATMode", index) orelse false;
        self.bridge_mode = p.getBoolEx("BridgeMode", index) orelse false;
        self.layer3_mode = p.getBoolEx("Layer3Mode", index) orelse false;
        self.client_bridge_mode = p.getBoolEx("Client_BridgeMode", index) orelse false;
        self.client_monitor_mode = p.getBoolEx("Client_MonitorMode", index) orelse false;
        self.vlan_id = p.getIntEx("VLanId", index) orelse 0;
        if (p.getDataEx("UniqueId", index)) |d| {
            const n = @min(d.len, self.unique_id.len);
            @memcpy(self.unique_id[0..n], d[0..n]);
        }
        self.is_dormant_enabled = p.getBoolEx("IsDormantEnabled", index) orelse false;
        self.is_dormant = p.getBoolEx("IsDormant", index) orelse false;
        self.last_comm_dormant = p.getInt64Ex("LastCommDormant", index) orelse 0;
        self.created_time = p.getInt64Ex("CreatedTime", index) orelse 0;
        self.last_comm_time = p.getInt64Ex("LastCommTime", index) orelse 0;
    }

    pub fn outRpc(self: *const EnumSessionItem, p: *Pack, index: usize) !void {
        try p.addStrEx("Name", self.name, index);
        try p.addBoolEx("RemoteSession", self.remote_session, index);
        try p.addStrEx("RemoteHostname", self.remote_hostname, index);
        try p.addStrEx("Username", self.username, index);
        try p.addIntEx("Ip", self.ip, index);
        try addIpAddressEx(p, "ClientIP", self.client_ip, index);
        try p.addStrEx("Hostname", self.hostname, index);
        try p.addIntEx("MaxNumTcp", self.max_num_tcp, index);
        try p.addIntEx("CurrentNumTcp", self.current_num_tcp, index);
        try p.addInt64Ex("PacketSize", self.packet_size, index);
        try p.addInt64Ex("PacketNum", self.packet_num, index);
        try p.addBoolEx("LinkMode", self.link_mode, index);
        try p.addBoolEx("SecureNATMode", self.secure_nat_mode, index);
        try p.addBoolEx("BridgeMode", self.bridge_mode, index);
        try p.addBoolEx("Layer3Mode", self.layer3_mode, index);
        try p.addBoolEx("Client_BridgeMode", self.client_bridge_mode, index);
        try p.addBoolEx("Client_MonitorMode", self.client_monitor_mode, index);
        try p.addIntEx("VLanId", self.vlan_id, index);
        try p.addDataEx("UniqueId", &self.unique_id, index);
        try p.addBoolEx("IsDormantEnabled", self.is_dormant_enabled, index);
        try p.addBoolEx("IsDormant", self.is_dormant, index);
        try p.addInt64Ex("LastCommDormant", self.last_comm_dormant, index);
        try p.addInt64Ex("CreatedTime", self.created_time, index);
        try p.addInt64Ex("LastCommTime", self.last_comm_time, index);
    }

    pub fn free(self: *EnumSessionItem, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.remote_hostname);
        allocator.free(self.username);
        allocator.free(self.hostname);
        self.* = .{};
    }
};

/// C `RPC_ENUM_SESSION` (Admin.h:676) — `EnumSession`.
pub const RpcEnumSession = struct {
    hub_name: []const u8 = "",
    sessions: []EnumSessionItem = &.{},

    pub fn inRpc(self: *RpcEnumSession, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStr("HubName"));
        const count = p.getValueCount("Name");
        self.sessions = try allocator.alloc(EnumSessionItem, count);
        for (0..count) |i| {
            self.sessions[i] = .{};
            try self.sessions[i].inRpc(allocator, p, i);
        }
    }

    pub fn outRpc(self: *const RpcEnumSession, p: *Pack) !void {
        try p.addStr("HubName", self.hub_name);
        for (self.sessions, 0..) |*item, i| {
            try item.outRpc(p, i);
        }
    }

    pub fn free(self: *RpcEnumSession, allocator: Allocator) void {
        allocator.free(self.hub_name);
        for (self.sessions) |*item| item.free(allocator);
        allocator.free(self.sessions);
        self.* = .{};
    }
};

/// C `RPC_CLIENT_GET_CONNECTION_STATUS` (Client.h:409) subset, the `Status`
/// field of `GetSessionStatus`. Only the fields the standalone server can
/// fill are serialized; field names match C exactly.
pub const Connecting = struct {
    session_name: []const u8 = "",
    connection_name: []const u8 = "",
    active: bool = false,
    connected: bool = false,
    session_status: u32 = 0,
    half_connection: bool = false,
    qos: bool = false,
    max_tcp_connections: u32 = 0,
    num_tcp_connections: u32 = 0,
    use_encrypt: bool = false,
    cipher_name: []const u8 = "",
    use_compress: bool = false,
    is_udp_session: bool = false,
    underlay_protocol: []const u8 = "",
    is_bridge_mode: bool = false,
    is_monitor_mode: bool = false,
    start_time: u64 = 0,
    total_send_size: u64 = 0,
    total_recv_size: u64 = 0,
    vlan_id: u32 = 0,
    traffic: Traffic = .{},

    pub fn inRpc(self: *Connecting, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.session_name = try dupStr(allocator, p.getStr("SessionName"));
        self.connection_name = try dupStr(allocator, p.getStr("ConnectionName"));
        self.active = p.getBool("Active") orelse false;
        self.connected = p.getBool("Connected") orelse false;
        self.session_status = p.getInt("SessionStatus") orelse 0;
        self.half_connection = p.getBool("HalfConnection") orelse false;
        self.qos = p.getBool("QoS") orelse false;
        self.max_tcp_connections = p.getInt("MaxTcpConnections") orelse 0;
        self.num_tcp_connections = p.getInt("NumTcpConnections") orelse 0;
        self.use_encrypt = p.getBool("UseEncrypt") orelse false;
        self.cipher_name = try dupStr(allocator, p.getStr("CipherName"));
        self.use_compress = p.getBool("UseCompress") orelse false;
        self.is_udp_session = p.getBool("IsRUDPSession") orelse false;
        self.underlay_protocol = try dupStr(allocator, p.getStr("UnderlayProtocol"));
        self.is_bridge_mode = p.getBool("IsBridgeMode") orelse false;
        self.is_monitor_mode = p.getBool("IsMonitorMode") orelse false;
        self.start_time = p.getInt64("StartTime") orelse 0;
        self.total_send_size = p.getInt64("TotalSendSize") orelse 0;
        self.total_recv_size = p.getInt64("TotalRecvSize") orelse 0;
        self.vlan_id = p.getInt("VLanId") orelse 0;
        self.traffic.inRpc(p);
    }

    pub fn outRpc(self: *const Connecting, p: *Pack) !void {
        try p.addStr("SessionName", self.session_name);
        try p.addStr("ConnectionName", self.connection_name);
        try p.addBool("Active", self.active);
        try p.addBool("Connected", self.connected);
        try p.addInt("SessionStatus", self.session_status);
        try p.addBool("HalfConnection", self.half_connection);
        try p.addBool("QoS", self.qos);
        try p.addInt("MaxTcpConnections", self.max_tcp_connections);
        try p.addInt("NumTcpConnections", self.num_tcp_connections);
        try p.addBool("UseEncrypt", self.use_encrypt);
        try p.addStr("CipherName", self.cipher_name);
        try p.addBool("UseCompress", self.use_compress);
        try p.addBool("IsRUDPSession", self.is_udp_session);
        try p.addStr("UnderlayProtocol", self.underlay_protocol);
        try p.addBool("IsBridgeMode", self.is_bridge_mode);
        try p.addBool("IsMonitorMode", self.is_monitor_mode);
        try p.addInt64("StartTime", self.start_time);
        try p.addInt64("TotalSendSize", self.total_send_size);
        try p.addInt64("TotalRecvSize", self.total_recv_size);
        try p.addInt("VLanId", self.vlan_id);
        try self.traffic.outRpc(p);
    }

    pub fn free(self: *Connecting, allocator: Allocator) void {
        allocator.free(self.session_name);
        allocator.free(self.connection_name);
        allocator.free(self.cipher_name);
        allocator.free(self.underlay_protocol);
        self.* = .{};
    }
};

/// C `RPC_SESSION_STATUS` (Admin.h:660) — `GetSessionStatus`. `node_info`
/// (C `NODE_INFO`) is not modeled yet, so those pack fields are omitted.
pub const RpcSessionStatus = struct {
    hub_name: []const u8 = "",
    name: []const u8 = "",
    username: []const u8 = "",
    group_name: []const u8 = "",
    real_username: []const u8 = "",
    client_ip: u32 = 0,
    client_ip6: [16]u8 = [_]u8{0} ** 16,
    client_host_name: []const u8 = "",
    client_ip_address: IpAddress = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    status: Connecting = .{},

    pub fn inRpc(self: *RpcSessionStatus, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStr("HubName"));
        self.name = try dupStr(allocator, p.getStr("Name"));
        self.username = try dupStr(allocator, p.getStr("Username"));
        self.group_name = try dupStr(allocator, p.getStr("GroupName"));
        self.real_username = try dupStr(allocator, p.getStr("RealUsername"));
        self.client_ip = p.getInt("SessionStatus_ClientIp") orelse 0;
        if (p.getData("SessionStatus_ClientIp6")) |d| {
            const n = @min(d.len, self.client_ip6.len);
            @memcpy(self.client_ip6[0..n], d[0..n]);
        }
        self.client_host_name = try dupStr(allocator, p.getStr("SessionStatus_ClientHostName"));
        self.client_ip_address = getIpAddress(p, "Client_Ip_Address");
        try self.status.inRpc(allocator, p);
    }

    pub fn outRpc(self: *const RpcSessionStatus, p: *Pack) !void {
        try p.addStr("HubName", self.hub_name);
        try p.addStr("Name", self.name);
        try p.addStr("Username", self.username);
        try p.addStr("GroupName", self.group_name);
        try p.addStr("RealUsername", self.real_username);
        try p.addInt("SessionStatus_ClientIp", self.client_ip);
        try p.addData("SessionStatus_ClientIp6", &self.client_ip6);
        try p.addStr("SessionStatus_ClientHostName", self.client_host_name);
        try addIpAddress(p, "Client_Ip_Address", self.client_ip_address);
        try self.status.outRpc(p);
    }

    pub fn free(self: *RpcSessionStatus, allocator: Allocator) void {
        allocator.free(self.hub_name);
        allocator.free(self.name);
        allocator.free(self.username);
        allocator.free(self.group_name);
        allocator.free(self.real_username);
        allocator.free(self.client_host_name);
        self.status.free(allocator);
        self.* = .{};
    }
};

/// C `RPC_DELETE_SESSION` (Admin.h:680) — `DeleteSession`.
pub const RpcDeleteSession = struct {
    hub_name: []const u8 = "",
    name: []const u8 = "",

    pub fn inRpc(self: *RpcDeleteSession, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.hub_name = try dupStr(allocator, p.getStr("HubName"));
        self.name = try dupStr(allocator, p.getStr("Name"));
    }

    pub fn outRpc(self: *const RpcDeleteSession, p: *Pack) !void {
        try p.addStr("HubName", self.hub_name);
        try p.addStr("Name", self.name);
    }

    pub fn free(self: *RpcDeleteSession, allocator: Allocator) void {
        allocator.free(self.hub_name);
        allocator.free(self.name);
        self.* = .{};
    }
};

/// C `RPC_ENUM_CONNECTION_ITEM` (Admin.h:379) — one row of `EnumConnection`.
pub const EnumConnectionItem = struct {
    name: []const u8 = "",
    hostname: []const u8 = "",
    ip: u32 = 0,
    port: u32 = 0,
    connected_time: u64 = 0,
    connection_type: u32 = 0,

    pub fn inRpc(self: *EnumConnectionItem, allocator: Allocator, p: *const Pack, index: usize) !void {
        self.* = .{};
        self.name = try dupStr(allocator, p.getStrEx("Name", index));
        self.hostname = try dupStr(allocator, p.getStrEx("Hostname", index));
        self.ip = p.getIntEx("Ip", index) orelse 0;
        self.port = p.getIntEx("Port", index) orelse 0;
        self.connected_time = p.getInt64Ex("ConnectedTime", index) orelse 0;
        self.connection_type = p.getIntEx("Type", index) orelse 0;
    }

    pub fn outRpc(self: *const EnumConnectionItem, p: *Pack, index: usize) !void {
        try p.addStrEx("Name", self.name, index);
        try p.addStrEx("Hostname", self.hostname, index);
        try p.addIntEx("Ip", self.ip, index);
        try p.addIntEx("Port", self.port, index);
        try p.addInt64Ex("ConnectedTime", self.connected_time, index);
        try p.addIntEx("Type", self.connection_type, index);
    }

    pub fn free(self: *EnumConnectionItem, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.hostname);
        self.* = .{};
    }
};

/// C `RPC_ENUM_CONNECTION` (Admin.h:390) — `EnumConnection`. Server-wide (no
/// `HubName`); the item count is the index count of the "Name" element.
pub const RpcEnumConnection = struct {
    connections: []EnumConnectionItem = &.{},

    pub fn inRpc(self: *RpcEnumConnection, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        const count = p.getValueCount("Name");
        self.connections = try allocator.alloc(EnumConnectionItem, count);
        for (0..count) |i| {
            self.connections[i] = .{};
            try self.connections[i].inRpc(allocator, p, i);
        }
    }

    pub fn outRpc(self: *const RpcEnumConnection, p: *Pack) !void {
        for (self.connections, 0..) |*item, i| {
            try item.outRpc(p, i);
        }
    }

    pub fn free(self: *RpcEnumConnection, allocator: Allocator) void {
        for (self.connections) |*item| item.free(allocator);
        allocator.free(self.connections);
        self.* = .{};
    }
};

/// C `RPC_DISCONNECT_CONNECTION` (Admin.h:397) — `DisconnectConnection`.
pub const RpcDisconnectConnection = struct {
    name: []const u8 = "",

    pub fn inRpc(self: *RpcDisconnectConnection, allocator: Allocator, p: *const Pack) !void {
        self.* = .{};
        self.name = try dupStr(allocator, p.getStr("Name"));
    }

    pub fn outRpc(self: *const RpcDisconnectConnection, p: *Pack) !void {
        try p.addStr("Name", self.name);
    }

    pub fn free(self: *RpcDisconnectConnection, allocator: Allocator) void {
        allocator.free(self.name);
        self.* = .{};
    }
};

// ============================================================================
// IP helpers (C: PackAddIp32Ex2 / PackAddIpEx2 / PackGetIpEx wire format)
// ============================================================================

/// C `PackAddIpEx2`: an IP address spans four elements
/// (`name@ipv6_bool`, `name@ipv6_array`, `name@ipv6_scope_id`, `name`), so
/// `PackGetIpEx`/`PackGetIp32` read it back on the C side.
fn addIpAddress(p: *Pack, name: []const u8, ip: IpAddress) !void {
    var buf: [128]u8 = undefined;
    const v6_bool = std.fmt.bufPrint(&buf, "{s}@ipv6_bool", .{name}) catch return error.OutOfMemory;
    try p.addBool(v6_bool, ip == .ipv6);
    const v6_array = std.fmt.bufPrint(&buf, "{s}@ipv6_array", .{name}) catch return error.OutOfMemory;
    switch (ip) {
        .ipv6 => |a| try p.addData(v6_array, &a),
        .ipv4 => try p.addData(v6_array, &([_]u8{0} ** 16)),
    }
    const v6_scope = std.fmt.bufPrint(&buf, "{s}@ipv6_scope_id", .{name}) catch return error.OutOfMemory;
    try p.addInt(v6_scope, 0);
    const ip32 = ip.toU32() orelse 0;
    try p.addInt(name, ip32);
}

fn getIpAddress(p: *const Pack, name: []const u8) IpAddress {
    var buf: [128]u8 = undefined;
    const v6_bool = std.fmt.bufPrint(&buf, "{s}@ipv6_bool", .{name}) catch return IpAddress{ .ipv4 = .{ 0, 0, 0, 0 } };
    const is_v6 = p.getBool(v6_bool) orelse false;
    if (!is_v6) {
        const ip32 = p.getInt(name) orelse 0;
        return IpAddress.fromU32(ip32);
    }
    const v6_array = std.fmt.bufPrint(&buf, "{s}@ipv6_array", .{name}) catch return IpAddress{ .ipv4 = .{ 0, 0, 0, 0 } };
    if (p.getData(v6_array)) |d| {
        if (d.len == 16) {
            var a: [16]u8 = undefined;
            @memcpy(&a, d);
            return .{ .ipv6 = a };
        }
    }
    return IpAddress{ .ipv4 = .{ 0, 0, 0, 0 } };
}

/// Indexed variant of `addIpAddress` (C `PackAddIpEx2` with an index).
fn addIpAddressEx(p: *Pack, name: []const u8, ip: IpAddress, index: usize) !void {
    var buf: [128]u8 = undefined;
    const v6_bool = std.fmt.bufPrint(&buf, "{s}@ipv6_bool", .{name}) catch return error.OutOfMemory;
    try p.addBoolEx(v6_bool, ip == .ipv6, index);
    const v6_array = std.fmt.bufPrint(&buf, "{s}@ipv6_array", .{name}) catch return error.OutOfMemory;
    switch (ip) {
        .ipv6 => |a| try p.addDataEx(v6_array, &a, index),
        .ipv4 => try p.addDataEx(v6_array, &([_]u8{0} ** 16), index),
    }
    const v6_scope = std.fmt.bufPrint(&buf, "{s}@ipv6_scope_id", .{name}) catch return error.OutOfMemory;
    try p.addIntEx(v6_scope, 0, index);
    const ip32 = ip.toU32() orelse 0;
    try p.addIntEx(name, ip32, index);
}

fn getIpAddressEx(p: *const Pack, name: []const u8, index: usize) IpAddress {
    var buf: [128]u8 = undefined;
    const v6_bool = std.fmt.bufPrint(&buf, "{s}@ipv6_bool", .{name}) catch return IpAddress{ .ipv4 = .{ 0, 0, 0, 0 } };
    const is_v6 = p.getBoolEx(v6_bool, index) orelse false;
    if (!is_v6) {
        const ip32 = p.getIntEx(name, index) orelse 0;
        return IpAddress.fromU32(ip32);
    }
    const v6_array = std.fmt.bufPrint(&buf, "{s}@ipv6_array", .{name}) catch return IpAddress{ .ipv4 = .{ 0, 0, 0, 0 } };
    if (p.getDataEx(v6_array, index)) |d| {
        if (d.len == 16) {
            var a: [16]u8 = undefined;
            @memcpy(&a, d);
            return .{ .ipv6 = a };
        }
    }
    return IpAddress{ .ipv4 = .{ 0, 0, 0, 0 } };
}

// ============================================================================
// Indexed traffic helpers (C: Client.c InRpcTrafficEx / OutRpcTrafficEx)
// ============================================================================

/// C `InRpcTrafficEx` (Client.c:4156): traffic serialized at pack index `i`
/// with the `Ex.` element-name prefix.
fn inRpcTrafficEx(t: *Traffic, p: *const Pack, index: usize) void {
    t.* = .{};
    t.recv_broadcast_bytes = p.getInt64Ex("Ex.Recv.BroadcastBytes", index) orelse 0;
    t.recv_broadcast_count = p.getInt64Ex("Ex.Recv.BroadcastCount", index) orelse 0;
    t.recv_unicast_bytes = p.getInt64Ex("Ex.Recv.UnicastBytes", index) orelse 0;
    t.recv_unicast_count = p.getInt64Ex("Ex.Recv.UnicastCount", index) orelse 0;
    t.send_broadcast_bytes = p.getInt64Ex("Ex.Send.BroadcastBytes", index) orelse 0;
    t.send_broadcast_count = p.getInt64Ex("Ex.Send.BroadcastCount", index) orelse 0;
    t.send_unicast_bytes = p.getInt64Ex("Ex.Send.UnicastBytes", index) orelse 0;
    t.send_unicast_count = p.getInt64Ex("Ex.Send.UnicastCount", index) orelse 0;
}

/// C `OutRpcTrafficEx` (Client.c:4174).
fn outRpcTrafficEx(t: *const Traffic, p: *Pack, index: usize) !void {
    try p.addInt64Ex("Ex.Recv.BroadcastBytes", t.recv_broadcast_bytes, index);
    try p.addInt64Ex("Ex.Recv.BroadcastCount", t.recv_broadcast_count, index);
    try p.addInt64Ex("Ex.Recv.UnicastBytes", t.recv_unicast_bytes, index);
    try p.addInt64Ex("Ex.Recv.UnicastCount", t.recv_unicast_count, index);
    try p.addInt64Ex("Ex.Send.BroadcastBytes", t.send_broadcast_bytes, index);
    try p.addInt64Ex("Ex.Send.BroadcastCount", t.send_broadcast_count, index);
    try p.addInt64Ex("Ex.Send.UnicastBytes", t.send_unicast_bytes, index);
    try p.addInt64Ex("Ex.Send.UnicastCount", t.send_unicast_count, index);
}

// ============================================================================
// Helpers
// ============================================================================

/// Duplicate a Pack string, or return "" when the element is absent
/// (C `PackGetStr` leaves the destination zeroed → empty string).
fn dupStr(allocator: Allocator, s: ?[]const u8) ![]const u8 {
    return allocator.dupe(u8, s orelse "");
}

/// Duplicate a Pack data blob, or return "" when absent.
fn dupData(allocator: Allocator, d: ?[]const u8) ![]const u8 {
    return allocator.dupe(u8, d orelse "");
}

// ============================================================================
// Tests
// ============================================================================

fn roundTripStr(allocator: Allocator, comptime T: type, value: *const T, out: *T) !void {
    var p = Pack.init(allocator);
    defer p.deinit();
    try outRpcGeneric(T, value, &p);
    try inRpcGeneric(T, out, allocator, &p);
}

fn inRpcGeneric(comptime T: type, t: *T, allocator: Allocator, p: *const Pack) !void {
    switch (T) {
        RpcTest => try t.inRpc(allocator, p),
        RpcServerInfo => try t.inRpc(allocator, p),
        RpcSetPassword => try t.inRpc(allocator, p),
        RpcStr => try t.inRpc(allocator, p),
        RpcListenerList => try t.inRpc(allocator, p),
        RpcCreateHub => try t.inRpc(allocator, p),
        RpcDeleteHub => try t.inRpc(allocator, p),
        RpcHubStatus => try t.inRpc(allocator, p),
        RpcEnumSession => try t.inRpc(allocator, p),
        RpcSessionStatus => try t.inRpc(allocator, p),
        RpcDeleteSession => try t.inRpc(allocator, p),
        RpcEnumConnection => try t.inRpc(allocator, p),
        RpcDisconnectConnection => try t.inRpc(allocator, p),
        else => @compileError("no inRpc for " ++ @typeName(T)),
    }
}

fn outRpcGeneric(comptime T: type, t: *const T, p: *Pack) !void {
    switch (T) {
        RpcTest => try t.outRpc(p),
        RpcServerInfo => try t.outRpc(p),
        RpcSetPassword => try t.outRpc(p),
        RpcStr => try t.outRpc(p),
        RpcListenerList => try t.outRpc(p),
        RpcCreateHub => try t.outRpc(p),
        RpcDeleteHub => try t.outRpc(p),
        RpcHubStatus => try t.outRpc(p),
        RpcEnumSession => try t.outRpc(p),
        RpcSessionStatus => try t.outRpc(p),
        RpcDeleteSession => try t.outRpc(p),
        RpcEnumConnection => try t.outRpc(p),
        RpcDisconnectConnection => try t.outRpc(p),
        else => @compileError("no outRpc for " ++ @typeName(T)),
    }
}

test "server.admin_structs RpcTest round-trip" {
    const allocator = testing.allocator;
    var v = RpcTest{ .int_value = 7, .int64_value = 0x123456789, .str_value = "hello", .uni_str_value = "world" };

    var r = RpcTest{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcTest, &v, &r);

    try testing.expectEqual(@as(u32, 7), r.int_value);
    try testing.expectEqual(@as(u64, 0x123456789), r.int64_value);
    try testing.expectEqualStrings("hello", r.str_value);
    try testing.expectEqualStrings("world", r.uni_str_value);
}

test "server.admin_structs RpcServerInfo round-trip" {
    const allocator = testing.allocator;
    var v = RpcServerInfo{
        .server_product_name = "SoftEther VPN Server",
        .server_version_string = "4.44",
        .server_build_info_string = "build-info",
        .server_ver_int = 4440,
        .server_build_int = 9792,
        .server_host_name = "host.example.com",
        .server_type = 0,
        .server_build_date = 123456789,
        .server_family_name = "SoftEther VPN",
        .os_info = .{ .os_type = 1, .os_service_pack = 2, .os_product_name = "Linux", .kernel_name = "linux" },
    };

    var r = RpcServerInfo{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcServerInfo, &v, &r);

    try testing.expectEqualStrings("SoftEther VPN Server", r.server_product_name);
    try testing.expectEqualStrings("4.44", r.server_version_string);
    try testing.expectEqual(@as(u32, 4440), r.server_ver_int);
    try testing.expectEqual(@as(u64, 123456789), r.server_build_date);
    try testing.expectEqualStrings("host.example.com", r.server_host_name);
    try testing.expectEqual(@as(u32, 1), r.os_info.os_type);
    try testing.expectEqualStrings("Linux", r.os_info.os_product_name);
    try testing.expectEqualStrings("linux", r.os_info.kernel_name);
}

test "server.admin_structs RpcServerStatus round-trip" {
    const allocator = testing.allocator;
    var v = RpcServerStatus{
        .server_type = 1,
        .num_hub_total = 3,
        .num_sessions_total = 10,
        .current_time = 100,
        .start_time = 50,
        .traffic = .{ .recv_unicast_bytes = 42, .send_broadcast_count = 9 },
        .mem_info = .{ .total_memory = 1024, .free_phys = 512 },
    };
    var r = RpcServerStatus{};

    var p = Pack.init(allocator);
    defer p.deinit();
    try v.outRpc(&p);
    r.inRpc(&p);

    try testing.expectEqual(@as(u32, 3), r.num_hub_total);
    try testing.expectEqual(@as(u32, 10), r.num_sessions_total);
    try testing.expectEqual(@as(u64, 42), r.traffic.recv_unicast_bytes);
    try testing.expectEqual(@as(u64, 9), r.traffic.send_broadcast_count);
    try testing.expectEqual(@as(u64, 1024), r.mem_info.total_memory);
    try testing.expectEqual(@as(u64, 512), r.mem_info.free_phys);
}

test "server.admin_structs RpcSetPassword round-trip" {
    const allocator = testing.allocator;
    var v = RpcSetPassword{ .hashed_password = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 }, .plain_text_password = "test" };
    var r = RpcSetPassword{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcSetPassword, &v, &r);

    try testing.expectEqualSlices(u8, v.hashed_password, r.hashed_password);
    try testing.expectEqualStrings("test", r.plain_text_password);
}

test "server.admin_structs RpcStr round-trip" {
    const allocator = testing.allocator;
    var v = RpcStr{ .string = "AES128-SHA256" };
    var r = RpcStr{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcStr, &v, &r);
    try testing.expectEqualStrings("AES128-SHA256", r.string);
}

test "server.admin_structs RpcListenerList round-trip" {
    const allocator = testing.allocator;
    var v = RpcListenerList{
        .ports = try allocator.dupe(u32, &[_]u32{ 443, 992, 5555 }),
        .enables = try allocator.dupe(bool, &[_]bool{ true, false, true }),
        .errors = try allocator.dupe(bool, &[_]bool{ false, false, false }),
    };
    defer v.free(allocator);
    var r = RpcListenerList{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcListenerList, &v, &r);

    try testing.expectEqual(@as(usize, 3), r.ports.len);
    try testing.expectEqualSlices(u32, &[_]u32{ 443, 992, 5555 }, r.ports);
    try testing.expectEqualSlices(bool, &[_]bool{ true, false, true }, r.enables);
    try testing.expectEqualSlices(bool, &[_]bool{ false, false, false }, r.errors);
}

test "server.admin_structs RpcCreateHub round-trip" {
    const allocator = testing.allocator;
    var v = RpcCreateHub{
        .hub_name = "VPN",
        .hashed_password = &[_]u8{ 1, 2, 3 },
        .secure_password = &[_]u8{ 4, 5, 6 },
        .admin_password_plain_text = "admin",
        .online = true,
        .hub_option = .{ .max_session = 256, .no_enum = true },
        .hub_type = 1,
    };
    var r = RpcCreateHub{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcCreateHub, &v, &r);

    try testing.expectEqualStrings("VPN", r.hub_name);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, r.hashed_password);
    try testing.expect(r.online);
    try testing.expectEqual(@as(u32, 256), r.hub_option.max_session);
    try testing.expect(r.hub_option.no_enum);
    try testing.expectEqual(@as(u32, 1), r.hub_type);
}

test "server.admin_structs RpcEnumHub round-trip" {
    const allocator = testing.allocator;
    var v = RpcEnumHub{ .hubs = try allocator.alloc(EnumHubItem, 2) };
    v.hubs[0] = .{ .hub_name = try allocator.dupe(u8, "VPN"), .online = true, .hub_type = 0, .traffic = .{ .send_unicast_bytes = 11 } };
    v.hubs[1] = .{ .hub_name = try allocator.dupe(u8, "TEST"), .online = false, .hub_type = 1, .traffic = .{ .recv_unicast_count = 7 } };
    defer v.free(allocator);
    var r = RpcEnumHub{};
    defer r.free(allocator);

    var p = Pack.init(allocator);
    defer p.deinit();
    try v.outRpc(&p);
    try r.inRpc(allocator, &p);

    try testing.expectEqual(@as(usize, 2), r.hubs.len);
    try testing.expectEqualStrings("VPN", r.hubs[0].hub_name);
    try testing.expect(r.hubs[0].online);
    try testing.expectEqual(@as(u64, 11), r.hubs[0].traffic.send_unicast_bytes);
    try testing.expectEqualStrings("TEST", r.hubs[1].hub_name);
    try testing.expectEqual(@as(u32, 1), r.hubs[1].hub_type);
    try testing.expectEqual(@as(u64, 7), r.hubs[1].traffic.recv_unicast_count);
}

test "server.admin_structs RpcDeleteHub round-trip" {
    const allocator = testing.allocator;
    var v = RpcDeleteHub{ .hub_name = "VPN" };
    var r = RpcDeleteHub{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcDeleteHub, &v, &r);
    try testing.expectEqualStrings("VPN", r.hub_name);
}

test "server.admin_structs RpcHubStatus round-trip" {
    const allocator = testing.allocator;
    var v = RpcHubStatus{
        .hub_name = "VPN",
        .online = true,
        .num_sessions = 5,
        .num_users = 10,
        .traffic = .{ .recv_broadcast_bytes = 99 },
        .last_login_time = 1234,
    };
    var r = RpcHubStatus{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcHubStatus, &v, &r);

    try testing.expectEqualStrings("VPN", r.hub_name);
    try testing.expect(r.online);
    try testing.expectEqual(@as(u32, 5), r.num_sessions);
    try testing.expectEqual(@as(u32, 10), r.num_users);
    try testing.expectEqual(@as(u64, 99), r.traffic.recv_broadcast_bytes);
    try testing.expectEqual(@as(u64, 1234), r.last_login_time);
}

test "server.admin_structs CapsList round-trip" {
    const allocator = testing.allocator;
    var v = CapsList{ .caps = try allocator.alloc(Caps, 2) };
    v.caps[0] = .{ .name = try allocator.dupe(u8, "b_support_foo"), .value = 1 };
    v.caps[1] = .{ .name = try allocator.dupe(u8, "i_max_conn"), .value = 128 };
    defer v.free(allocator);

    var p = Pack.init(allocator);
    defer p.deinit();
    try v.outRpc(&p);

    // "caps_<name>" int elements exist.
    try testing.expectEqual(@as(u32, 1), p.getInt("caps_b_support_foo").?);
    try testing.expectEqual(@as(u32, 128), p.getInt("caps_i_max_conn").?);
    try testing.expectEqualStrings("b_support_foo", p.getStrEx("CapsName", 0).?);
    try testing.expectEqual(@as(u32, 128), p.getIntEx("CapsValue", 1).?);

    var r = CapsList{};
    defer r.free(allocator);
    try r.inRpc(allocator, &p);
    try testing.expectEqual(@as(usize, 2), r.caps.len);
    try testing.expectEqualStrings("b_support_foo", r.caps[0].name);
    try testing.expectEqual(@as(u32, 1), r.caps[0].value);
    try testing.expectEqualStrings("i_max_conn", r.caps[1].name);
    try testing.expectEqual(@as(u32, 128), r.caps[1].value);
}

test "server.admin_structs RpcEnumSession round-trip" {
    const allocator = testing.allocator;
    var v = RpcEnumSession{ .hub_name = try allocator.dupe(u8, "VPN") };
    v.sessions = try allocator.alloc(EnumSessionItem, 2);
    v.sessions[0] = .{
        .name = try allocator.dupe(u8, "SID-ALICE"),
        .username = try allocator.dupe(u8, "Alice"),
        .ip = 0x0A000001,
        .client_ip = IpAddress.fromU32(0x0A000001),
        .packet_size = 1000,
        .created_time = 111,
    };
    v.sessions[1] = .{
        .name = try allocator.dupe(u8, "SID-BOB"),
        .username = try allocator.dupe(u8, "Bob"),
        .ip = 0x0A000002,
        .client_ip = IpAddress.fromU32(0x0A000002),
        .vlan_id = 4,
        .last_comm_time = 222,
    };
    defer v.free(allocator);
    var r = RpcEnumSession{};
    defer r.free(allocator);

    var p = Pack.init(allocator);
    defer p.deinit();
    try v.outRpc(&p);
    try r.inRpc(allocator, &p);

    try testing.expectEqualStrings("VPN", r.hub_name);
    try testing.expectEqual(@as(usize, 2), r.sessions.len);
    try testing.expectEqualStrings("SID-ALICE", r.sessions[0].name);
    try testing.expectEqualStrings("Alice", r.sessions[0].username);
    try testing.expectEqual(@as(u32, 0x0A000001), r.sessions[0].ip);
    try testing.expectEqual(@as(u64, 1000), r.sessions[0].packet_size);
    try testing.expectEqual(@as(u64, 111), r.sessions[0].created_time);
    try testing.expectEqual(@as(u32, 0x0A000002), r.sessions[1].ip);
    try testing.expectEqual(@as(u32, 4), r.sessions[1].vlan_id);
    try testing.expectEqual(@as(u64, 222), r.sessions[1].last_comm_time);
}

test "server.admin_structs RpcSessionStatus round-trip" {
    const allocator = testing.allocator;
    var v = RpcSessionStatus{
        .hub_name = "VPN",
        .name = "SID-ALICE",
        .username = "Alice",
        .client_ip = 0x0A000001,
        .client_ip_address = IpAddress.fromU32(0x0A000001),
        .status = .{
            .session_name = "SID-ALICE",
            .connection_name = "CONN-0",
            .active = true,
            .connected = true,
            .session_status = 4,
            .start_time = 12345,
            .total_send_size = 500,
            .total_recv_size = 600,
            .traffic = .{ .send_unicast_bytes = 7 },
        },
    };
    var r = RpcSessionStatus{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcSessionStatus, &v, &r);

    try testing.expectEqualStrings("VPN", r.hub_name);
    try testing.expectEqualStrings("SID-ALICE", r.name);
    try testing.expectEqualStrings("Alice", r.username);
    try testing.expectEqual(@as(u32, 0x0A000001), r.client_ip);
    try testing.expectEqual(@as(u32, 0x0A000001), r.client_ip_address.toU32().?);
    try testing.expectEqualStrings("CONN-0", r.status.connection_name);
    try testing.expect(r.status.connected);
    try testing.expectEqual(@as(u64, 12345), r.status.start_time);
    try testing.expectEqual(@as(u64, 600), r.status.total_recv_size);
    try testing.expectEqual(@as(u64, 7), r.status.traffic.send_unicast_bytes);
}

test "server.admin_structs RpcDeleteSession round-trip" {
    const allocator = testing.allocator;
    var v = RpcDeleteSession{ .hub_name = "VPN", .name = "SID-ALICE" };
    var r = RpcDeleteSession{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcDeleteSession, &v, &r);
    try testing.expectEqualStrings("VPN", r.hub_name);
    try testing.expectEqualStrings("SID-ALICE", r.name);
}

test "server.admin_structs RpcEnumConnection round-trip" {
    const allocator = testing.allocator;
    var v = RpcEnumConnection{};
    v.connections = try allocator.alloc(EnumConnectionItem, 1);
    v.connections[0] = .{
        .name = try allocator.dupe(u8, "CONN-0"),
        .hostname = try allocator.dupe(u8, "client.example.com"),
        .ip = 0xC0A80101,
        .port = 40000,
        .connected_time = 999,
        .connection_type = 0,
    };
    defer v.free(allocator);
    var r = RpcEnumConnection{};
    defer r.free(allocator);

    var p = Pack.init(allocator);
    defer p.deinit();
    try v.outRpc(&p);
    try r.inRpc(allocator, &p);

    try testing.expectEqual(@as(usize, 1), r.connections.len);
    try testing.expectEqualStrings("CONN-0", r.connections[0].name);
    try testing.expectEqualStrings("client.example.com", r.connections[0].hostname);
    try testing.expectEqual(@as(u32, 0xC0A80101), r.connections[0].ip);
    try testing.expectEqual(@as(u32, 40000), r.connections[0].port);
    try testing.expectEqual(@as(u64, 999), r.connections[0].connected_time);
    try testing.expectEqual(@as(u32, 0), r.connections[0].connection_type);
}

test "server.admin_structs RpcDisconnectConnection round-trip" {
    const allocator = testing.allocator;
    var v = RpcDisconnectConnection{ .name = "CONN-0" };
    var r = RpcDisconnectConnection{};
    defer r.free(allocator);
    try roundTripStr(allocator, RpcDisconnectConnection, &v, &r);
    try testing.expectEqualStrings("CONN-0", r.name);
}
