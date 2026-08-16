//! Server admin RPC dispatch (issue #88).
//!
//! The server-side RPC dispatcher: maps a `function_name` to one of the St*
//! handler endpoints, running the C `AdminDispatch` / `DECLARE_RPC_EX`
//! semantics. The server state here is a self-contained admin-facing model
//! (`Server`), separate from the live `auth.Hub` / `hub.Hub` data plane; the
//! dispatch endpoints snapshot from it.
//!
//! Implemented in dispatch order (SERVER_PLAN.md §6.5 groups 1-3):
//! - Core: `Test`, `GetServerInfo`, `GetServerStatus`, `SetServerPassword`,
//!   `GetCaps`
//! - Listeners: `EnumListener`, `CreateListener`, `DeleteListener`
//! - Hubs: `EnumHub`, `CreateHub`, `SetHub`, `DeleteHub`, `GetHubStatus`
//!
//! C reference (4.44):
//! - `AdminDispatch` (Admin.c:1519) + `DECLARE_RPC_EX` (Admin.c:110) — the
//!   dispatch flow: InRpc → handler → OutRpc (only on success), `error` field
//!   with the raw error code, `ERR_NOT_SUPPORTED` for unknown functions
//! - `CHECK_RIGHT` / `SERVER_ADMIN_ONLY` / `NO_SUPPORT_FOR_BRIDGE`
//!   (Admin.c:181,186,189)
//! - The 13 `St*` handlers referenced in each endpoint below
//! - `GetServerCapsMain` (Server.c:1432) — the capabilities list
//! - `HashAdminPassword` (Server.h:379) — SHA-1 of the plain text
//! - `IsSafeStr` (Str.c:2654) — hub name character whitelist
//!
//! ## Error convention
//!
//! Mirrors C: every dispatch call returns a response Pack; on failure it
//! carries `error = <raw error code>` (the field C's `AdminDispatch` writes,
//! and what `getErrorFromPack` reads) plus `error_code = <raw error code>` so
//! the transport helpers `rpcIsOk`/`rpcGetError` (which read `error`/`error_code`)
//! also see the real code. An unknown `function_name` yields
//! `error = ERR_NOT_SUPPORTED`. The transport (`rpc.zig`) treats a null return
//! as "not supported" — that path is only a safety net (e.g. out-of-memory
//! while building the response Pack).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const pack_mod = @import("../../protocol/pack.zig");
const Pack = pack_mod.Pack;
const rpc_mod = @import("rpc.zig");
const structs = @import("structs.zig");
const hash_mod = @import("../../../mayaqua/encrypt/hash.zig");
const auth = @import("../auth.zig");

// ============================================================================
// Error codes (C: Cedar.h)
// ============================================================================

pub const err_no_error: u32 = 0;
pub const err_hub_not_found: u32 = 8;
pub const err_internal_error: u32 = 23;
pub const err_not_supported: u32 = 33;
pub const err_invalid_parameter: u32 = 38;
pub const err_not_farm_controller: u32 = 46;
pub const err_not_enough_right: u32 = 52;
pub const err_listener_not_found: u32 = 53;
pub const err_listener_already_exists: u32 = 54;
pub const err_hub_already_exists: u32 = 57;
pub const err_too_many_hubs: u32 = 58;

// ============================================================================
// Server type / hub type constants (C: Server.h:397, Cedar.h:411)
// ============================================================================

pub const server_type_standalone: u32 = 0;
pub const server_type_farm_controller: u32 = 1;
pub const server_type_farm_member: u32 = 2;

pub const hub_type_standalone: u32 = 0;
pub const hub_type_farm_static: u32 = 1;
pub const hub_type_farm_dynamic: u32 = 2;

// ============================================================================
// Capability constants (C: Cedar.h / MayaType.h)
// ============================================================================

pub const infinite: u32 = 0xFFFFFFFF;
pub const max_packet_size: u32 = 1600;
pub const server_max_sessions: u32 = 100000;
pub const server_max_hubs: u32 = 100000;
pub const max_users: u32 = 10000;
pub const max_groups: u32 = 10000;
pub const max_access_lists: u32 = 4096 * 8;
pub const max_mac_tables: u32 = 65536;
pub const max_ip_tables: u32 = 65536;
pub const nat_max_sessions: u32 = 4096;
pub const max_num_l3_switch: u32 = 4096;
pub const max_num_l3_if: u32 = 4096;
pub const max_num_l3_table: u32 = 4096;

const sha1_size = structs.SHA1_SIZE;

// ============================================================================
// Server state model (admin-facing snapshot; C `SERVER` / `SERVER_LISTENER`
// / `HUB` subsets)
// ============================================================================

pub const default_product_name = "SoftEther VPN Server";
pub const default_version_string = "4.44";
pub const default_family_name = "SoftEther VPN";
pub const default_host_name = "localhost";

/// C `SERVER_LISTENER` (Server.h:471) subset.
pub const ServerListener = struct {
    port: u32 = 0,
    enabled: bool = false,
    /// True when the port failed to bind (C `LISTENER_STATUS_TRYING`).
    has_error: bool = false,
    disable_dos: bool = false,
};

/// C `HUB` subset used by EnumHub / CreateHub / SetHub / GetHubStatus.
pub const ServerHub = struct {
    name: []const u8 = "",
    hub_type: u32 = hub_type_standalone,
    online: bool = false,
    hashed_password: [sha1_size]u8 = [_]u8{0} ** sha1_size,
    secure_password: [sha1_size]u8 = [_]u8{0} ** sha1_size,
    max_session: u32 = 0,
    no_enum: bool = false,
    num_users: u32 = 0,
    num_groups: u32 = 0,
    num_sessions: u32 = 0,
    num_mac_tables: u32 = 0,
    num_ip_tables: u32 = 0,
    last_comm_time: u64 = 0,
    last_login_time: u64 = 0,
    created_time: u64 = 0,
    num_login: u32 = 0,
    traffic: structs.Traffic = .{},
};

/// C `SERVER` subset covering the 13 dispatch endpoints. `param` of the RPC
/// session points at this (via `rpc.zig`'s `Rpc.param`).
pub const Server = struct {
    allocator: Allocator,
    /// Serializes access to the mutable collections (`hubs`/`listeners`,
    /// `config_revision`): the transport accept path is per-connection
    /// threaded, so concurrent admin connections share this state.
    mutex: std.Thread.Mutex = .{},

    hashed_password: [sha1_size]u8 = [_]u8{0} ** sha1_size,
    server_type: u32 = server_type_standalone,
    is_bridge: bool = false,

    product_name: []const u8 = "",
    version_string: []const u8 = "",
    build_info_string: []const u8 = "",
    version: u32 = 4440,
    build: u32 = 9792,
    family_name: []const u8 = "",
    host_name: []const u8 = "",
    build_date: u64 = 0,

    os_info: structs.OsInfo = .{},
    traffic: structs.Traffic = .{},
    mem_info: structs.MemInfo = .{},
    start_time: u64 = 0,
    config_revision: u32 = 0,

    listeners: std.ArrayListUnmanaged(ServerListener) = .{},
    hubs: std.ArrayListUnmanaged(ServerHub) = .{},

    /// Create a standalone server with default identity strings.
    pub fn init(allocator: Allocator) !Server {
        var s: Server = .{ .allocator = allocator };
        errdefer s.deinit();
        s.product_name = try allocator.dupe(u8, default_product_name);
        s.version_string = try allocator.dupe(u8, default_version_string);
        s.build_info_string = try allocator.dupe(u8, "");
        s.family_name = try allocator.dupe(u8, default_family_name);
        s.host_name = try allocator.dupe(u8, default_host_name);
        s.start_time = nowMs();
        return s;
    }

    pub fn deinit(self: *Server) void {
        const allocator = self.allocator;
        allocator.free(self.product_name);
        allocator.free(self.version_string);
        allocator.free(self.build_info_string);
        allocator.free(self.family_name);
        allocator.free(self.host_name);
        self.os_info.free(allocator);
        for (self.hubs.items) |hub| allocator.free(hub.name);
        self.hubs.deinit(allocator);
        self.listeners.deinit(allocator);
        self.* = .{ .allocator = allocator };
    }

    /// Append a listener (test/bootstrap helper).
    pub fn addListener(self: *Server, port: u32, enabled: bool) !void {
        try self.listeners.append(self.allocator, .{ .port = port, .enabled = enabled });
    }

    /// Append a hub (test/bootstrap helper).
    pub fn addHub(self: *Server, name: []const u8, hub_type: u32) !void {
        const owned = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned);
        try self.hubs.append(self.allocator, .{
            .name = owned,
            .hub_type = hub_type,
            .online = true,
            .created_time = nowMs(),
        });
    }
};

/// C `ADMIN` subset (Admin.h:90): the per-connection admin context.
pub const AdminCtx = struct {
    server: *Server,
    server_admin: bool = false,
    hub_name: []const u8 = "",
};

// ============================================================================
// Dispatcher
// ============================================================================

/// C `AdminDispatch` (Admin.c:1519). Matches `rpc.zig`'s `Rpc.Dispatcher`.
/// Always returns a response Pack; errors go in the `error` field.
pub fn adminDispatch(rpc: *anyopaque, function_name: []const u8, request: *Pack) ?*Pack {
    const rpc_self: *rpc_mod.Rpc = @ptrCast(@alignCast(rpc));
    const server: *Server = @ptrCast(@alignCast(rpc_self.param));
    const allocator = rpc_self.allocator;
    var a = AdminCtx{
        .server = server,
        .server_admin = rpc_self.server_admin_mode,
        .hub_name = rpc_self.hub_name,
    };

    // Serialize concurrent admin connections against the shared hub/listener
    // collections and `config_revision` (see `Server.mutex`).
    server.mutex.lock();
    defer server.mutex.unlock();

    const ret = allocator.create(Pack) catch return null;
    errdefer allocator.destroy(ret);
    ret.* = Pack.init(allocator);
    errdefer ret.deinit();

    var err: u32 = err_no_error;

    if (mem.eql(u8, function_name, "Test")) {
        err = dispatchCall(structs.RpcTest, &a, allocator, request, ret, stTest);
    } else if (mem.eql(u8, function_name, "GetServerInfo")) {
        err = dispatchCall(structs.RpcServerInfo, &a, allocator, request, ret, stGetServerInfo);
    } else if (mem.eql(u8, function_name, "GetServerStatus")) {
        err = dispatchCall(structs.RpcServerStatus, &a, allocator, request, ret, stGetServerStatus);
    } else if (mem.eql(u8, function_name, "SetServerPassword")) {
        err = dispatchCall(structs.RpcSetPassword, &a, allocator, request, ret, stSetServerPassword);
    } else if (mem.eql(u8, function_name, "GetCaps")) {
        err = dispatchCall(structs.CapsList, &a, allocator, request, ret, stGetCaps);
    } else if (mem.eql(u8, function_name, "EnumListener")) {
        err = dispatchCall(structs.RpcListenerList, &a, allocator, request, ret, stEnumListener);
    } else if (mem.eql(u8, function_name, "CreateListener")) {
        err = dispatchCall(structs.RpcListener, &a, allocator, request, ret, stCreateListener);
    } else if (mem.eql(u8, function_name, "DeleteListener")) {
        err = dispatchCall(structs.RpcListener, &a, allocator, request, ret, stDeleteListener);
    } else if (mem.eql(u8, function_name, "EnumHub")) {
        err = dispatchCall(structs.RpcEnumHub, &a, allocator, request, ret, stEnumHub);
    } else if (mem.eql(u8, function_name, "CreateHub")) {
        err = dispatchCall(structs.RpcCreateHub, &a, allocator, request, ret, stCreateHub);
    } else if (mem.eql(u8, function_name, "SetHub")) {
        err = dispatchCall(structs.RpcCreateHub, &a, allocator, request, ret, stSetHub);
    } else if (mem.eql(u8, function_name, "DeleteHub")) {
        err = dispatchCall(structs.RpcDeleteHub, &a, allocator, request, ret, stDeleteHub);
    } else if (mem.eql(u8, function_name, "GetHubStatus")) {
        err = dispatchCall(structs.RpcHubStatus, &a, allocator, request, ret, stGetHubStatus);
    } else {
        err = err_not_supported;
    }

    if (err != err_no_error) {
        ret.addInt("error", err) catch return null;
        ret.addInt("error_code", err) catch return null;
    }
    return ret;
}

/// C `DECLARE_RPC_EX` (Admin.c:110): InRpc → handler → OutRpc (only when the
/// handler succeeded). The InRpc/free variance between structs is handled by
/// `inRpcT` / `freeT` (e.g. `RpcServerStatus` has no-allocator InRpc and no
/// Free in C).
fn dispatchCall(
    comptime T: type,
    a: *AdminCtx,
    allocator: Allocator,
    request: *const Pack,
    ret: *Pack,
    handler: *const fn (a: *AdminCtx, t: *T, allocator: Allocator) u32,
) u32 {
    var t: T = .{};
    defer freeT(T, &t, allocator);
    inRpcT(T, &t, allocator, request) catch return err_internal_error;
    const err = handler(a, &t, allocator);
    if (err == err_no_error) {
        outRpcT(T, &t, ret) catch return err_internal_error;
    }
    return err;
}

fn inRpcT(comptime T: type, t: *T, allocator: Allocator, p: *const Pack) !void {
    switch (T) {
        structs.RpcServerStatus, structs.RpcListener => t.inRpc(p),
        else => try inRpcAlloc(T, t, allocator, p),
    }
}

fn inRpcAlloc(comptime T: type, t: *T, allocator: Allocator, p: *const Pack) !void {
    switch (T) {
        structs.RpcTest => try t.inRpc(allocator, p),
        structs.RpcServerInfo => try t.inRpc(allocator, p),
        structs.RpcSetPassword => try t.inRpc(allocator, p),
        structs.CapsList => try t.inRpc(allocator, p),
        structs.RpcListenerList => try t.inRpc(allocator, p),
        structs.RpcCreateHub => try t.inRpc(allocator, p),
        structs.RpcEnumHub => try t.inRpc(allocator, p),
        structs.RpcDeleteHub => try t.inRpc(allocator, p),
        structs.RpcHubStatus => try t.inRpc(allocator, p),
        else => @compileError("no InRpc for " ++ @typeName(T)),
    }
}

fn outRpcT(comptime T: type, t: *const T, p: *Pack) !void {
    switch (T) {
        structs.RpcTest => try t.outRpc(p),
        structs.RpcServerInfo => try t.outRpc(p),
        structs.RpcServerStatus => try t.outRpc(p),
        structs.RpcSetPassword => try t.outRpc(p),
        structs.CapsList => try t.outRpc(p),
        structs.RpcListener => try t.outRpc(p),
        structs.RpcListenerList => try t.outRpc(p),
        structs.RpcCreateHub => try t.outRpc(p),
        structs.RpcEnumHub => try t.outRpc(p),
        structs.RpcDeleteHub => try t.outRpc(p),
        structs.RpcHubStatus => try t.outRpc(p),
        else => @compileError("no OutRpc for " ++ @typeName(T)),
    }
}

fn freeT(comptime T: type, t: *T, allocator: Allocator) void {
    switch (T) {
        structs.RpcServerStatus, structs.RpcListener => {},
        else => freeAlloc(T, t, allocator),
    }
}

fn freeAlloc(comptime T: type, t: *T, allocator: Allocator) void {
    switch (T) {
        structs.RpcTest => t.free(allocator),
        structs.RpcServerInfo => t.free(allocator),
        structs.RpcSetPassword => t.free(allocator),
        structs.CapsList => t.free(allocator),
        structs.RpcListenerList => t.free(allocator),
        structs.RpcCreateHub => t.free(allocator),
        structs.RpcEnumHub => t.free(allocator),
        structs.RpcDeleteHub => t.free(allocator),
        structs.RpcHubStatus => t.free(allocator),
        else => @compileError("no Free for " ++ @typeName(T)),
    }
}

// ============================================================================
// Core endpoints
// ============================================================================

/// C `StTest` (Admin.c:14487): `StrValue` becomes the decimal form of
/// `IntValue`; the other fields are echoed unchanged.
fn stTest(a: *AdminCtx, t: *structs.RpcTest, allocator: Allocator) u32 {
    _ = a;
    allocator.free(t.str_value);
    t.str_value = std.fmt.allocPrint(allocator, "{d}", .{t.int_value}) catch return err_internal_error;
    return err_no_error;
}

/// C `StGetServerInfo` (Admin.c:10029). Re-fills the struct with the server
/// identity; `OsInfo` copied string-by-string.
fn stGetServerInfo(a: *AdminCtx, t: *structs.RpcServerInfo, allocator: Allocator) u32 {
    const s = a.server;
    t.free(allocator);
    t.* = .{};
    t.server_product_name = dupStr(allocator, s.product_name) catch return err_internal_error;
    t.server_version_string = dupStr(allocator, s.version_string) catch return err_internal_error;
    t.server_build_info_string = dupStr(allocator, s.build_info_string) catch return err_internal_error;
    t.server_ver_int = s.version;
    t.server_build_int = s.build;
    t.server_host_name = dupStr(allocator, s.host_name) catch return err_internal_error;
    t.server_type = s.server_type;
    t.server_build_date = s.build_date;
    t.server_family_name = dupStr(allocator, s.family_name) catch return err_internal_error;
    copyOsInfo(allocator, &t.os_info, &s.os_info) catch return err_internal_error;
    return err_no_error;
}

/// C `StGetServerStatus` (Admin.c:9923). Standalone snapshot: no farm members,
/// no active TCP connections, sessions are the sum over hubs.
fn stGetServerStatus(a: *AdminCtx, t: *structs.RpcServerStatus, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    t.* = .{};
    t.server_type = s.server_type;
    t.num_tcp_connections = 0;
    t.num_tcp_connections_local = 0;
    t.num_tcp_connections_remote = 0;

    var hub_total: u32 = 0;
    var hub_standalone: u32 = 0;
    var hub_static: u32 = 0;
    var hub_dynamic: u32 = 0;
    var sessions_total: u32 = 0;
    var mac_tables: u32 = 0;
    var ip_tables: u32 = 0;
    var users: u32 = 0;
    var groups: u32 = 0;

    for (s.hubs.items) |*hub| {
        hub_total += 1;
        switch (hub.hub_type) {
            hub_type_standalone => hub_standalone += 1,
            hub_type_farm_static => hub_static += 1,
            else => hub_dynamic += 1,
        }
        sessions_total +%= hub.num_sessions;
        mac_tables +%= hub.num_mac_tables;
        ip_tables +%= hub.num_ip_tables;
        users +%= hub.num_users;
        groups +%= hub.num_groups;
    }

    t.num_hub_total = hub_total;
    t.num_hub_standalone = hub_standalone;
    t.num_hub_static = hub_static;
    t.num_hub_dynamic = hub_dynamic;
    t.num_sessions_total = sessions_total;
    t.num_sessions_local = sessions_total;
    t.num_sessions_remote = 0;
    t.num_mac_tables = mac_tables;
    t.num_ip_tables = ip_tables;
    t.num_users = users;
    t.num_groups = groups;

    t.assigned_bridge_licenses = 0;
    t.assigned_client_licenses = 0;
    t.assigned_bridge_licenses_total = 0;
    t.assigned_client_licenses_total = 0;

    t.traffic = s.traffic;
    t.mem_info = s.mem_info;
    t.current_tick = nowMs();
    t.current_time = nowMs();
    t.start_time = s.start_time;
    return err_no_error;
}

/// C `StSetServerPassword` (Admin.c:9765): a zero `hashed_password` (or a
/// plain text password) is hashed with SHA-1 (`HashAdminPassword`), then the
/// 20-byte hash is stored and the config revision bumped. A non-empty hash
/// that is not exactly `SHA1_SIZE` bytes is rejected (no silent truncation).
fn stSetServerPassword(a: *AdminCtx, t: *structs.RpcSetPassword, allocator: Allocator) u32 {
    _ = allocator;
    if (!a.server_admin) return err_not_enough_right;
    if (!validHash(t.hashed_password)) return err_invalid_parameter;
    var hashed: [sha1_size]u8 = [_]u8{0} ** sha1_size;
    copyToFixed(&hashed, t.hashed_password);
    if (isZero(&hashed)) {
        hashed = hash_mod.sha1(t.plain_text_password);
    }
    a.server.hashed_password = hashed;
    a.server.config_revision +%= 1;
    return err_no_error;
}

/// C `StGetCaps` (Admin.c:4533) + `GetServerCapsMain` (Server.c:1432).
fn stGetCaps(a: *AdminCtx, t: *structs.CapsList, allocator: Allocator) u32 {
    t.free(allocator);
    t.* = .{};
    t.caps = buildServerCaps(allocator, a.server) catch return err_internal_error;
    return err_no_error;
}

// ============================================================================
// Listener endpoints
// ============================================================================

/// C `StEnumListener` (Admin.c:9854): parallel Ports/Enables/Errors arrays.
fn stEnumListener(a: *AdminCtx, t: *structs.RpcListenerList, allocator: Allocator) u32 {
    t.free(allocator);
    t.* = .{};
    const count = a.server.listeners.items.len;
    t.ports = allocator.alloc(u32, count) catch return err_internal_error;
    t.enables = allocator.alloc(bool, count) catch return err_internal_error;
    t.errors = allocator.alloc(bool, count) catch return err_internal_error;
    for (a.server.listeners.items, 0..) |*l, i| {
        t.ports[i] = l.port;
        t.enables[i] = l.enabled;
        t.errors[i] = if (l.enabled and l.has_error) true else false;
    }
    return err_no_error;
}

/// C `StCreateListener` (Admin.c:9890): port range check, server-admin-only,
/// duplicate detection, config revision bump.
fn stCreateListener(a: *AdminCtx, t: *structs.RpcListener, allocator: Allocator) u32 {
    if (t.port == 0 or t.port > 65535) return err_invalid_parameter;
    if (!a.server_admin) return err_not_enough_right;
    for (a.server.listeners.items) |*l| {
        if (l.port == t.port) return err_listener_already_exists;
    }
    a.server.listeners.append(allocator, .{
        .port = t.port,
        .enabled = t.enable,
        .has_error = false,
        .disable_dos = false,
    }) catch return err_internal_error;
    a.server.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteListener` (Admin.c:9828).
fn stDeleteListener(a: *AdminCtx, t: *structs.RpcListener, allocator: Allocator) u32 {
    _ = allocator;
    if (!a.server_admin) return err_not_enough_right;
    const index = findListenerIndex(a.server, t.port) orelse return err_listener_not_found;
    _ = a.server.listeners.swapRemove(index);
    a.server.config_revision +%= 1;
    return err_no_error;
}

// ============================================================================
// Hub endpoints
// ============================================================================

/// C `StEnumHub` (Admin.c:8895). A non-server-admin sees only the hub named by
/// `AdminCtx.hub_name` (the hub the connection is logged into).
fn stEnumHub(a: *AdminCtx, t: *structs.RpcEnumHub, allocator: Allocator) u32 {
    t.free(allocator);
    t.* = .{};

    var count: usize = 0;
    for (a.server.hubs.items) |*hub| {
        if (!a.server_admin and !std.ascii.eqlIgnoreCase(hub.name, a.hub_name)) continue;
        count += 1;
    }

    t.hubs = allocator.alloc(structs.EnumHubItem, count) catch return err_internal_error;
    var i: usize = 0;
    for (a.server.hubs.items) |*hub| {
        if (!a.server_admin and !std.ascii.eqlIgnoreCase(hub.name, a.hub_name)) continue;
        const e = &t.hubs[i];
        e.* = .{};
        e.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
        e.online = hub.online;
        e.hub_type = hub.hub_type;
        e.num_sessions = hub.num_sessions;
        e.num_mac_tables = hub.num_mac_tables;
        e.num_ip_tables = hub.num_ip_tables;
        e.num_users = hub.num_users;
        e.num_groups = hub.num_groups;
        e.last_comm_time = hub.last_comm_time;
        e.last_login_time = hub.last_login_time;
        e.num_login = hub.num_login;
        e.created_time = hub.created_time;
        e.traffic = hub.traffic;
        e.is_traffic_filled = true;
        i += 1;
    }
    return err_no_error;
}

/// C `StCreateHub` (Admin.c:9239). Validation order mirrors C exactly.
fn stCreateHub(a: *AdminCtx, t: *structs.RpcCreateHub, allocator: Allocator) u32 {
    const s = a.server;
    if (s.server_type == server_type_farm_member) return err_not_farm_controller;
    if (t.hub_name.len == 0 or !isSafeStr(t.hub_name)) return err_invalid_parameter;
    if (s.is_bridge) return err_not_supported;
    if (!a.server_admin) return err_not_enough_right;

    const name = std.mem.trim(u8, t.hub_name, " ");
    if (name.len == 0) return err_invalid_parameter;
    if (name[0] == '.' or name[name.len - 1] == '.') return err_invalid_parameter;

    if (s.server_type == server_type_standalone) {
        if (t.hub_type != hub_type_standalone) return err_invalid_parameter;
    } else if (t.hub_type != hub_type_farm_dynamic and t.hub_type != hub_type_farm_static) {
        return err_invalid_parameter;
    }

    if (s.hubs.items.len >= server_max_hubs) return err_too_many_hubs;
    if (findHub(s, name) != null) return err_hub_already_exists;
    if (!validHash(t.hashed_password) or !validHash(t.secure_password)) return err_invalid_parameter;

    var hashed: [sha1_size]u8 = [_]u8{0} ** sha1_size;
    var secure: [sha1_size]u8 = [_]u8{0} ** sha1_size;
    copyToFixed(&hashed, t.hashed_password);
    copyToFixed(&secure, t.secure_password);
    if ((isZero(&hashed) and isZero(&secure)) or t.admin_password_plain_text.len != 0) {
        hashed = hash_mod.sha1(t.admin_password_plain_text);
        secure = auth.hashPassword(t.admin_password_plain_text, auth.administrator_username);
    }

    const hub_name = dupStr(allocator, name) catch return err_internal_error;
    errdefer allocator.free(hub_name);
    s.hubs.append(allocator, .{
        .name = hub_name,
        .hub_type = t.hub_type,
        .online = t.online,
        .hashed_password = hashed,
        .secure_password = secure,
        .max_session = t.hub_option.max_session,
        .no_enum = t.hub_option.no_enum,
        .created_time = nowMs(),
    }) catch return err_internal_error;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StSetHub` (Admin.c:9092). Only a subset of the C validation is live for
/// the standalone model (no hub-admin options, no remote-IP distinction).
fn stSetHub(a: *AdminCtx, t: *structs.RpcCreateHub, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (s.server_type == server_type_farm_member) return err_not_farm_controller;
    if (t.hub_name.len == 0 or !isSafeStr(t.hub_name)) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_standalone and t.hub_type != hub_type_standalone) return err_invalid_parameter;
    if (s.server_type == server_type_farm_controller and t.hub_type == hub_type_standalone) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (hub.hub_type != t.hub_type) return err_not_supported;
    if (!validHash(t.hashed_password) or !validHash(t.secure_password)) return err_invalid_parameter;

    var hashed: [sha1_size]u8 = [_]u8{0} ** sha1_size;
    var secure: [sha1_size]u8 = [_]u8{0} ** sha1_size;
    copyToFixed(&hashed, t.hashed_password);
    copyToFixed(&secure, t.secure_password);
    if (t.admin_password_plain_text.len != 0) {
        hashed = hash_mod.sha1(t.admin_password_plain_text);
        secure = auth.hashPassword(t.admin_password_plain_text, auth.administrator_username);
    }

    // Refuse a blank hub-admin password from a non-server-admin (C: also
    // requires a remote address, which the direct-call model cannot see).
    const blank_hashed = hash_mod.sha1("");
    const blank_secure = auth.hashPassword(auth.administrator_username, "");
    const is_blank = mem.eql(u8, &hashed, &blank_hashed) or mem.eql(u8, &secure, &blank_secure);
    if (is_blank and !a.server_admin) return err_invalid_parameter;

    if (!a.server_admin and hub.hub_type != t.hub_type) return err_not_enough_right;
    hub.hub_type = t.hub_type;
    hub.max_session = t.hub_option.max_session;
    hub.no_enum = t.hub_option.no_enum;
    if (!isZero(&hashed) and !isZero(&secure)) {
        hub.hashed_password = hashed;
        hub.secure_password = secure;
    }
    hub.online = t.online;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteHub` (Admin.c:8850).
fn stDeleteHub(a: *AdminCtx, t: *structs.RpcDeleteHub, allocator: Allocator) u32 {
    const s = a.server;
    if (s.server_type == server_type_farm_member) return err_not_farm_controller;
    if (t.hub_name.len == 0 or !isSafeStr(t.hub_name)) return err_invalid_parameter;
    if (s.is_bridge) return err_not_supported;
    if (!a.server_admin) return err_not_enough_right;

    const index = findHubIndex(s, t.hub_name) orelse return err_hub_not_found;
    const removed = s.hubs.swapRemove(index);
    allocator.free(removed.name);
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StGetHubStatus` (Admin.c:7935). CHECK_RIGHT, then a snapshot of the hub.
fn stGetHubStatus(a: *AdminCtx, t: *structs.RpcHubStatus, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.online = hub.online;
    t.hub_type = hub.hub_type;
    t.num_sessions = hub.num_sessions;
    t.num_sessions_client = hub.num_sessions;
    t.num_sessions_bridge = 0;
    t.num_access_lists = 0;
    t.num_users = hub.num_users;
    t.num_groups = hub.num_groups;
    t.num_mac_tables = hub.num_mac_tables;
    t.num_ip_tables = hub.num_ip_tables;
    t.secure_nat_enabled = false;
    t.traffic = hub.traffic;
    t.last_comm_time = hub.last_comm_time;
    t.last_login_time = hub.last_login_time;
    t.num_login = hub.num_login;
    t.created_time = hub.created_time;
    return err_no_error;
}

// ============================================================================
// Capabilities (C `GetServerCapsMain`, Server.c:1432)
// ============================================================================

fn addCap(
    allocator: Allocator,
    list: *std.ArrayListUnmanaged(structs.Caps),
    name: []const u8,
    value: u32,
) !void {
    const owned = try allocator.dupe(u8, name);
    errdefer allocator.free(owned);
    try list.append(allocator, .{ .name = owned, .value = value });
}

/// Standalone-server capabilities in C order. The model pins the environment
/// flags: not restricted, not a VM, local bridge unsupported, not Windows.
fn buildServerCaps(allocator: Allocator, s: *const Server) ![]structs.Caps {
    var list = std.ArrayListUnmanaged(structs.Caps){};
    errdefer {
        for (list.items) |*c| c.free(allocator);
        list.deinit(allocator);
    }

    const standalone = s.server_type == server_type_standalone;
    const farm_controller = s.server_type == server_type_farm_controller;
    const farm_member = s.server_type == server_type_farm_member;
    const is_restricted = false;
    const is_in_vm = false;
    const bridge_supported = false;

    try addCap(allocator, &list, "i_max_packet_size", max_packet_size);

    if (!s.is_bridge) {
        const max_sessions: u32 = server_max_sessions;
        try addCap(allocator, &list, "i_max_hubs", server_max_sessions);
        try addCap(allocator, &list, "i_max_sessions", max_sessions);
        try addCap(allocator, &list, "i_max_user_creation", infinite);
        try addCap(allocator, &list, "i_max_clients", infinite);
        try addCap(allocator, &list, "i_max_bridges", infinite);
        try addCap(allocator, &list, "i_max_users_per_hub", if (farm_member) 0 else max_users);
        try addCap(allocator, &list, "i_max_groups_per_hub", if (farm_member) 0 else max_groups);
        try addCap(allocator, &list, "i_max_access_lists", if (farm_member) 0 else max_access_lists);
        try addCap(allocator, &list, "b_support_limit_multilogin", 1);
        try addCap(allocator, &list, "b_support_qos", 1);
        try addCap(allocator, &list, "b_support_syslog", 1);
        try addCap(allocator, &list, "b_support_ipsec", if (standalone) 1 else 0);
        try addCap(allocator, &list, "b_support_sstp", if (standalone) 1 else 0);
        try addCap(allocator, &list, "b_support_openvpn", if (standalone) 1 else 0);
        try addCap(allocator, &list, "b_support_ddns", 0);
        try addCap(allocator, &list, "b_support_special_listener", 1);
    } else {
        try addCap(allocator, &list, "i_max_hubs", 0);
        try addCap(allocator, &list, "i_max_sessions", 0);
        try addCap(allocator, &list, "i_max_clients", 0);
        try addCap(allocator, &list, "i_max_bridges", 0);
        try addCap(allocator, &list, "i_max_users_per_hub", 0);
        try addCap(allocator, &list, "i_max_groups_per_hub", 0);
        try addCap(allocator, &list, "i_max_access_lists", 0);
        try addCap(allocator, &list, "b_support_qos", 1);
        try addCap(allocator, &list, "b_support_syslog", 1);
        try addCap(allocator, &list, "b_support_ipsec", 0);
        try addCap(allocator, &list, "b_support_sstp", 0);
        try addCap(allocator, &list, "b_support_openvpn", 0);
        try addCap(allocator, &list, "b_support_ddns", 0);
        try addCap(allocator, &list, "b_support_special_listener", 0);
    }

    try addCap(allocator, &list, "b_cluster_hub_type_fixed", 1);
    try addCap(allocator, &list, "i_max_mac_tables", max_mac_tables);
    try addCap(allocator, &list, "i_max_ip_tables", max_ip_tables);
    try addCap(allocator, &list, "b_support_securenat", 1);
    try addCap(allocator, &list, "b_suppport_push_route", if (is_restricted) 0 else 1);
    try addCap(allocator, &list, "b_suppport_push_route_config", 1);
    if (!standalone) try addCap(allocator, &list, "b_virtual_nat_disabled", 1);
    try addCap(allocator, &list, "i_max_secnat_tables", nat_max_sessions);
    try addCap(allocator, &list, "b_support_cascade", if (standalone) 1 else 0);

    if (s.is_bridge) {
        try addCap(allocator, &list, "b_bridge", 1);
    } else if (standalone) {
        try addCap(allocator, &list, "b_standalone", 1);
    } else if (farm_controller) {
        try addCap(allocator, &list, "b_cluster_controller", 1);
    } else {
        try addCap(allocator, &list, "b_cluster_member", 1);
    }

    try addCap(allocator, &list, "b_support_config_hub", if (farm_member or s.is_bridge) 0 else 1);
    try addCap(allocator, &list, "b_vpn_client_connect", if (s.is_bridge) 0 else 1);
    try addCap(allocator, &list, "b_support_radius", if (farm_member or s.is_bridge) 0 else 1);
    try addCap(allocator, &list, "b_local_bridge", if (bridge_supported) 1 else 0);
    try addCap(allocator, &list, "b_must_install_pcap", 0);
    if (bridge_supported) try addCap(allocator, &list, "b_tap_supported", 0);
    try addCap(allocator, &list, "b_support_cascade_cert", 1);
    try addCap(allocator, &list, "b_support_config_log", if (farm_member) 0 else 1);
    try addCap(allocator, &list, "b_support_autodelete", 1);
    try addCap(allocator, &list, "b_support_config_rw", 1);
    try addCap(allocator, &list, "b_support_hub_admin_option", 1);
    try addCap(allocator, &list, "b_support_cascade_client_cert", 1);
    try addCap(allocator, &list, "b_support_hide_hub", 1);
    try addCap(allocator, &list, "b_support_cluster_admin", 1);
    try addCap(allocator, &list, "b_is_softether", 1);

    if (!s.is_bridge) {
        try addCap(allocator, &list, "b_support_layer3", 1);
        try addCap(allocator, &list, "i_max_l3_sw", max_num_l3_switch);
        try addCap(allocator, &list, "i_max_l3_if", max_num_l3_if);
        try addCap(allocator, &list, "i_max_l3_table", max_num_l3_table);
        try addCap(allocator, &list, "b_support_cluster", 1);
    } else {
        try addCap(allocator, &list, "b_support_layer3", 0);
        try addCap(allocator, &list, "i_max_l3_sw", 0);
        try addCap(allocator, &list, "i_max_l3_if", 0);
        try addCap(allocator, &list, "i_max_l3_table", 0);
        try addCap(allocator, &list, "b_support_cluster", 0);
    }

    if (!farm_member and !s.is_bridge) {
        try addCap(allocator, &list, "b_support_crl", 1);
        try addCap(allocator, &list, "b_support_ac", 1);
    }

    try addCap(allocator, &list, "b_support_read_log", 1);
    try addCap(allocator, &list, "b_support_rename_cascade", 1);
    try addCap(allocator, &list, "b_is_in_vm", if (is_in_vm) 1 else 0);
    try addCap(allocator, &list, "b_support_check_mac", 1);
    try addCap(allocator, &list, "b_support_check_tcp_state", 1);
    try addCap(allocator, &list, "b_support_radius_retry_interval_and_several_servers", if (farm_member or s.is_bridge) 0 else 1);
    try addCap(allocator, &list, "b_support_vlan", 1);
    try addCap(allocator, &list, "b_support_hub_ext_options", if ((!s.is_bridge) and (standalone or farm_controller)) 1 else 0);
    try addCap(allocator, &list, "b_support_policy_ver_3", 1);
    try addCap(allocator, &list, "b_support_ipv6_acl", 1);
    try addCap(allocator, &list, "b_support_ex_acl", 1);
    try addCap(allocator, &list, "b_support_redirect_url_acl", 1);
    try addCap(allocator, &list, "b_support_acl_group", 1);
    try addCap(allocator, &list, "b_support_ipv6_ac", 1);
    try addCap(allocator, &list, "b_support_eth_vlan", 0);
    try addCap(allocator, &list, "b_support_msg", 1);
    try addCap(allocator, &list, "b_support_udp_acceleration", 1);
    try addCap(allocator, &list, "b_support_intel_aes", 0);
    try addCap(allocator, &list, "b_support_azure", 0);
    try addCap(allocator, &list, "b_vpn3", 1);
    try addCap(allocator, &list, "b_vpn4", 1);

    return list.toOwnedSlice(allocator);
}

// ============================================================================
// Helpers
// ============================================================================

fn nowMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

fn dupStr(allocator: Allocator, s: []const u8) ![]const u8 {
    return allocator.dupe(u8, s);
}

fn isZero(bytes: *const [sha1_size]u8) bool {
    return mem.allEqual(u8, bytes, 0);
}

/// A packed password hash is either empty ("derive from plain text") or
/// exactly `SHA1_SIZE` bytes; anything else would be silently truncated.
fn validHash(s: []const u8) bool {
    return s.len == 0 or s.len == sha1_size;
}

fn copyToFixed(dst: *[sha1_size]u8, src: []const u8) void {
    @memset(dst, 0);
    const n = @min(src.len, sha1_size);
    @memcpy(dst[0..n], src[0..n]);
}

fn copyOsInfo(allocator: Allocator, dst: *structs.OsInfo, src: *const structs.OsInfo) !void {
    dst.* = .{};
    dst.os_type = src.os_type;
    dst.os_service_pack = src.os_service_pack;
    dst.os_system_name = try dupStr(allocator, src.os_system_name);
    dst.os_product_name = try dupStr(allocator, src.os_product_name);
    dst.os_vendor_name = try dupStr(allocator, src.os_vendor_name);
    dst.os_version = try dupStr(allocator, src.os_version);
    dst.kernel_name = try dupStr(allocator, src.kernel_name);
    dst.kernel_version = try dupStr(allocator, src.kernel_version);
}

const safe_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ()-_#%&.";

/// C `IsSafeStr` (Str.c:2654): whitelist characters, no leading/trailing
/// space. The empty string is considered safe (handlers check emptiness).
fn isSafeStr(s: []const u8) bool {
    for (s) |c| {
        if (std.mem.indexOfScalar(u8, safe_charset, c) == null) return false;
    }
    if (s.len != 0 and s[0] == ' ') return false;
    if (s.len != 0 and s[s.len - 1] == ' ') return false;
    return true;
}

fn findListenerIndex(s: *Server, port: u32) ?usize {
    for (s.listeners.items, 0..) |*l, i| {
        if (l.port == port) return i;
    }
    return null;
}

fn findHubIndex(s: *Server, name: []const u8) ?usize {
    for (s.hubs.items, 0..) |*hub, i| {
        if (std.ascii.eqlIgnoreCase(hub.name, name)) return i;
    }
    return null;
}

fn findHub(s: *Server, name: []const u8) ?*ServerHub {
    const index = findHubIndex(s, name) orelse return null;
    return &s.hubs.items[index];
}

// ============================================================================
// Tests
// ============================================================================

/// Build a request Pack carrying the `function_name` field (mirrors the wire).
fn makeRequest(allocator: Allocator, function_name: []const u8) !Pack {
    var p = Pack.init(allocator);
    try p.addStr("function_name", function_name);
    return p;
}

/// Call `adminDispatch` as if from the transport for the given session mode.
fn call(
    allocator: Allocator,
    server: *Server,
    server_admin: bool,
    hub_name: []const u8,
    function_name: []const u8,
    request: *Pack,
) !*Pack {
    var rpc = rpc_mod.Rpc{
        .allocator = allocator,
        .sock = undefined,
        .dispatch = adminDispatch,
        .param = @ptrCast(server),
        .server_admin_mode = server_admin,
        .hub_name = hub_name,
    };
    return adminDispatch(@ptrCast(&rpc), function_name, request) orelse return error.NoResponse;
}

fn assertOk(resp: *const Pack) !void {
    try testing.expectEqual(@as(u32, 0), resp.getInt("error") orelse 0);
}

fn assertErr(resp: *const Pack, expected: u32) !void {
    try testing.expectEqual(expected, resp.getInt("error") orelse 0);
    try testing.expectEqual(expected, resp.getInt("error_code") orelse 0);
}

test "server.admin_dispatch Test echoes IntValue into StrValue" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    var req = try makeRequest(allocator, "Test");
    defer req.deinit();
    try req.addInt("IntValue", 7);
    try req.addInt64("Int64Value", 1234);
    try req.addStr("StrValue", "old");
    try req.addUniStr("UniStrValue", "world");

    var resp = try call(allocator, &server, true, "", "Test", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(u32, 7), resp.getInt("IntValue").?);
    try testing.expectEqual(@as(u64, 1234), resp.getInt64("Int64Value").?);
    try testing.expectEqualStrings("7", resp.getStr("StrValue").?);
    try testing.expectEqualStrings("world", resp.getUniStr("UniStrValue").?);
}

test "server.admin_dispatch GetServerInfo fills the identity fields" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    server.server_type = server_type_standalone;
    server.version = 4440;
    server.build = 9792;
    server.build_date = 123456789;
    server.os_info = .{
        .os_type = 1,
        .os_service_pack = 2,
        .os_system_name = try allocator.dupe(u8, "linux"),
        .os_product_name = try allocator.dupe(u8, "Ubuntu"),
        .os_vendor_name = "",
        .os_version = "",
        .kernel_name = try allocator.dupe(u8, "linux"),
        .kernel_version = "",
    };

    var req = try makeRequest(allocator, "GetServerInfo");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "GetServerInfo", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqualStrings(default_product_name, resp.getStr("ServerProductName").?);
    try testing.expectEqualStrings(default_version_string, resp.getStr("ServerVersionString").?);
    try testing.expectEqualStrings(default_family_name, resp.getStr("ServerFamilyName").?);
    try testing.expectEqualStrings("localhost", resp.getStr("ServerHostName").?);
    try testing.expectEqual(@as(u32, 4440), resp.getInt("ServerVerInt").?);
    try testing.expectEqual(@as(u32, 9792), resp.getInt("ServerBuildInt").?);
    try testing.expectEqual(@as(u64, 123456789), resp.getInt64("ServerBuildDate").?);
    try testing.expectEqual(@as(u32, 0), resp.getInt("ServerType").?);
    try testing.expectEqualStrings("Ubuntu", resp.getStr("OsProductName").?);
    try testing.expectEqualStrings("linux", resp.getStr("KernelName").?);
}

test "server.admin_dispatch GetServerStatus counts hubs and sessions" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);
    server.hubs.items[0].num_sessions = 3;
    server.hubs.items[0].num_users = 10;
    server.hubs.items[1].num_sessions = 2;
    server.hubs.items[1].num_mac_tables = 4;
    server.start_time = 500;

    var req = try makeRequest(allocator, "GetServerStatus");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "GetServerStatus", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(u32, 2), resp.getInt("NumHubTotal").?);
    try testing.expectEqual(@as(u32, 2), resp.getInt("NumHubStandalone").?);
    try testing.expectEqual(@as(u32, 0), resp.getInt("NumHubStatic").?);
    try testing.expectEqual(@as(u32, 5), resp.getInt("NumSessionsTotal").?);
    try testing.expectEqual(@as(u32, 5), resp.getInt("NumSessionsLocal").?);
    try testing.expectEqual(@as(u32, 10), resp.getInt("NumUsers").?);
    try testing.expectEqual(@as(u32, 4), resp.getInt("NumMacTables").?);
    try testing.expectEqual(@as(u64, 500), resp.getInt64("StartTime").?);
}

test "server.admin_dispatch SetServerPassword hashes and bumps the revision" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    const initial = server.config_revision;

    var req = try makeRequest(allocator, "SetServerPassword");
    defer req.deinit();
    try req.addStr("PlainTextPassword", "secret");
    try req.addData("HashedPassword", "");

    var resp = try call(allocator, &server, true, "", "SetServerPassword", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    const expected = hash_mod.sha1("secret");
    try testing.expectEqualSlices(u8, &expected, &server.hashed_password);
    try testing.expectEqual(initial +% 1, server.config_revision);
}

test "server.admin_dispatch SetServerPassword keeps a provided hash" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    const provided = hash_mod.sha1("other");
    var req = try makeRequest(allocator, "SetServerPassword");
    defer req.deinit();
    try req.addData("HashedPassword", &provided);

    var resp = try call(allocator, &server, true, "", "SetServerPassword", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqualSlices(u8, &provided, &server.hashed_password);
}

test "server.admin_dispatch GetCaps lists standalone capabilities" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    var req = try makeRequest(allocator, "GetCaps");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "GetCaps", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(u32, max_packet_size), resp.getInt("caps_i_max_packet_size").?);
    try testing.expectEqual(@as(u32, server_max_sessions), resp.getInt("caps_i_max_hubs").?);
    try testing.expectEqual(@as(u32, infinite), resp.getInt("caps_i_max_clients").?);
    try testing.expectEqual(@as(u32, max_users), resp.getInt("caps_i_max_users_per_hub").?);
    try testing.expectEqual(@as(u32, 1), resp.getInt("caps_b_support_securenat").?);
    try testing.expectEqual(@as(u32, 1), resp.getInt("caps_b_standalone").?);
    try testing.expectEqual(@as(u32, 0), resp.getInt("caps_b_support_ddns").?);
    try testing.expectEqual(@as(u32, 1), resp.getInt("caps_b_support_cascade").?);
    try testing.expectEqual(@as(u32, 1), resp.getInt("caps_b_vpn4").?);
}

test "server.admin_dispatch EnumListener lists ports and flags" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addListener(443, true);
    try server.addListener(992, false);
    server.listeners.items[0].has_error = true;

    var req = try makeRequest(allocator, "EnumListener");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "EnumListener", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 2), resp.getValueCount("Ports"));
    try testing.expectEqual(@as(u32, 443), resp.getIntEx("Ports", 0).?);
    try testing.expect(resp.getBoolEx("Enables", 0).?);
    try testing.expect(resp.getBoolEx("Errors", 0).?);
    try testing.expectEqual(@as(u32, 992), resp.getIntEx("Ports", 1).?);
    try testing.expect(!resp.getBoolEx("Enables", 1).?);
}

test "server.admin_dispatch CreateListener appends and validates" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    const initial = server.config_revision;

    var req = try makeRequest(allocator, "CreateListener");
    defer req.deinit();
    try req.addInt("Port", 5555);
    try req.addBool("Enable", true);

    var resp = try call(allocator, &server, true, "", "CreateListener", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 1), server.listeners.items.len);
    try testing.expectEqual(@as(u32, 5555), server.listeners.items[0].port);
    try testing.expectEqual(initial +% 1, server.config_revision);

    // Duplicate port.
    var dup = try makeRequest(allocator, "CreateListener");
    defer dup.deinit();
    try dup.addInt("Port", 5555);
    var dup_resp = try call(allocator, &server, true, "", "CreateListener", &dup);
    defer {
        dup_resp.deinit();
        allocator.destroy(dup_resp);
    }
    try assertErr(dup_resp, err_listener_already_exists);

    // Invalid port.
    var bad = try makeRequest(allocator, "CreateListener");
    defer bad.deinit();
    try bad.addInt("Port", 0);
    var bad_resp = try call(allocator, &server, true, "", "CreateListener", &bad);
    defer {
        bad_resp.deinit();
        allocator.destroy(bad_resp);
    }
    try assertErr(bad_resp, err_invalid_parameter);
}

test "server.admin_dispatch DeleteListener removes and reports missing" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addListener(443, true);
    const initial = server.config_revision;

    var req = try makeRequest(allocator, "DeleteListener");
    defer req.deinit();
    try req.addInt("Port", 443);

    var resp = try call(allocator, &server, true, "", "DeleteListener", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 0), server.listeners.items.len);
    try testing.expectEqual(initial +% 1, server.config_revision);

    var miss = try makeRequest(allocator, "DeleteListener");
    defer miss.deinit();
    try miss.addInt("Port", 9999);
    var miss_resp = try call(allocator, &server, true, "", "DeleteListener", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_listener_not_found);
}

test "server.admin_dispatch EnumHub lists all hubs for a server admin" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);
    server.hubs.items[0].num_login = 7;
    server.hubs.items[0].traffic.recv_unicast_bytes = 42;

    var req = try makeRequest(allocator, "EnumHub");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "EnumHub", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 2), resp.getValueCount("HubName"));
    try testing.expectEqualStrings("VPN", resp.getStrEx("HubName", 0).?);
    try testing.expect(resp.getBoolEx("IsTrafficFilled", 0).?);
    try testing.expectEqual(@as(u32, 7), resp.getIntEx("NumLogin", 0).?);
    try testing.expectEqual(@as(u64, 42), resp.getInt64Ex("Ex.Recv.UnicastBytes", 0).?);
    try testing.expectEqualStrings("TEST", resp.getStrEx("HubName", 1).?);
}

test "server.admin_dispatch CreateHub adds a hub and validates input" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    const initial = server.config_revision;

    var req = try makeRequest(allocator, "CreateHub");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addInt("HubType", hub_type_standalone);
    try req.addBool("Online", true);
    try req.addStr("AdminPasswordPlainText", "hubadmin");
    try req.addInt("MaxSession", 256);
    try req.addBool("NoEnum", true);

    var resp = try call(allocator, &server, true, "", "CreateHub", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 1), server.hubs.items.len);
    const hub = &server.hubs.items[0];
    try testing.expectEqualStrings("VPN", hub.name);
    try testing.expectEqual(hub_type_standalone, hub.hub_type);
    try testing.expect(hub.online);
    try testing.expectEqual(@as(u32, 256), hub.max_session);
    try testing.expect(hub.no_enum);
    try testing.expectEqualSlices(u8, &hash_mod.sha1("hubadmin"), &hub.hashed_password);
    try testing.expectEqual(initial +% 1, server.config_revision);

    // Duplicate hub name.
    var dup = try makeRequest(allocator, "CreateHub");
    defer dup.deinit();
    try dup.addStr("HubName", "VPN");
    try dup.addInt("HubType", hub_type_standalone);
    var dup_resp = try call(allocator, &server, true, "", "CreateHub", &dup);
    defer {
        dup_resp.deinit();
        allocator.destroy(dup_resp);
    }
    try assertErr(dup_resp, err_hub_already_exists);

    // Duplicate that differs only by case is still rejected (StrCmpi).
    var case_req = try makeRequest(allocator, "CreateHub");
    defer case_req.deinit();
    try case_req.addStr("HubName", "vpn");
    try case_req.addInt("HubType", hub_type_standalone);
    var case_resp = try call(allocator, &server, true, "", "CreateHub", &case_req);
    defer {
        case_resp.deinit();
        allocator.destroy(case_resp);
    }
    try assertErr(case_resp, err_hub_already_exists);

    // Empty hub name.
    var bad = try makeRequest(allocator, "CreateHub");
    defer bad.deinit();
    try bad.addStr("HubName", "");
    try bad.addInt("HubType", hub_type_standalone);
    var bad_resp = try call(allocator, &server, true, "", "CreateHub", &bad);
    defer {
        bad_resp.deinit();
        allocator.destroy(bad_resp);
    }
    try assertErr(bad_resp, err_invalid_parameter);

    // Unsafe characters.
    var unsafe_req = try makeRequest(allocator, "CreateHub");
    defer unsafe_req.deinit();
    try unsafe_req.addStr("HubName", "VPN/");
    try unsafe_req.addInt("HubType", hub_type_standalone);
    var unsafe_resp = try call(allocator, &server, true, "", "CreateHub", &unsafe_req);
    defer {
        unsafe_resp.deinit();
        allocator.destroy(unsafe_resp);
    }
    try assertErr(unsafe_resp, err_invalid_parameter);
}

test "server.admin_dispatch SetHub updates a hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    const initial = server.config_revision;

    var req = try makeRequest(allocator, "SetHub");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addInt("HubType", hub_type_standalone);
    try req.addBool("Online", false);
    try req.addInt("MaxSession", 128);
    try req.addBool("NoEnum", true);

    var resp = try call(allocator, &server, true, "", "SetHub", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expect(!server.hubs.items[0].online);
    try testing.expectEqual(@as(u32, 128), server.hubs.items[0].max_session);
    try testing.expect(server.hubs.items[0].no_enum);
    try testing.expectEqual(initial +% 1, server.config_revision);

    // Missing hub.
    var miss = try makeRequest(allocator, "SetHub");
    defer miss.deinit();
    try miss.addStr("HubName", "NOPE");
    try miss.addInt("HubType", hub_type_standalone);
    var miss_resp = try call(allocator, &server, true, "", "SetHub", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_hub_not_found);
}

test "server.admin_dispatch DeleteHub removes and reports missing" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    const initial = server.config_revision;

    var req = try makeRequest(allocator, "DeleteHub");
    defer req.deinit();
    try req.addStr("HubName", "VPN");

    var resp = try call(allocator, &server, true, "", "DeleteHub", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 0), server.hubs.items.len);
    try testing.expectEqual(initial +% 1, server.config_revision);

    var miss = try makeRequest(allocator, "DeleteHub");
    defer miss.deinit();
    try miss.addStr("HubName", "NOPE");
    var miss_resp = try call(allocator, &server, true, "", "DeleteHub", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_hub_not_found);
}

test "server.admin_dispatch GetHubStatus returns a hub snapshot" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    server.hubs.items[0].num_sessions = 4;
    server.hubs.items[0].num_users = 9;
    server.hubs.items[0].num_login = 3;
    server.hubs.items[0].created_time = 1234;
    server.hubs.items[0].traffic.send_unicast_bytes = 77;

    var req = try makeRequest(allocator, "GetHubStatus");
    defer req.deinit();
    try req.addStr("HubName", "VPN");

    var resp = try call(allocator, &server, true, "", "GetHubStatus", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
    try testing.expect(resp.getBool("Online").?);
    try testing.expectEqual(@as(u32, 4), resp.getInt("NumSessions").?);
    try testing.expectEqual(@as(u32, 4), resp.getInt("NumSessionsClient").?);
    try testing.expectEqual(@as(u32, 9), resp.getInt("NumUsers").?);
    try testing.expectEqual(@as(u32, 3), resp.getInt("NumLogin").?);
    try testing.expectEqual(@as(u64, 1234), resp.getInt64("CreatedTime").?);
    try testing.expectEqual(@as(u64, 77), resp.getInt64("Send.UnicastBytes").?);
}

test "server.admin_dispatch rejects malformed credential hashes" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    // SetServerPassword: a non-empty hash that is not exactly 20 bytes.
    var pw = try makeRequest(allocator, "SetServerPassword");
    defer pw.deinit();
    try pw.addData("HashedPassword", &[_]u8{ 1, 2, 3 });
    var pw_resp = try call(allocator, &server, true, "", "SetServerPassword", &pw);
    defer {
        pw_resp.deinit();
        allocator.destroy(pw_resp);
    }
    try assertErr(pw_resp, err_invalid_parameter);

    // CreateHub: a malformed SecurePassword is rejected without storing it.
    var hub = try makeRequest(allocator, "CreateHub");
    defer hub.deinit();
    try hub.addStr("HubName", "VPN");
    try hub.addInt("HubType", hub_type_standalone);
    try hub.addData("SecurePassword", &[_]u8{ 4, 5, 6 });
    var hub_resp = try call(allocator, &server, true, "", "CreateHub", &hub);
    defer {
        hub_resp.deinit();
        allocator.destroy(hub_resp);
    }
    try assertErr(hub_resp, err_invalid_parameter);
    try testing.expectEqual(@as(usize, 0), server.hubs.items.len);
}

test "server.admin_dispatch unknown function replies ERR_NOT_SUPPORTED" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    var req = try makeRequest(allocator, "NoSuchFunction");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "NoSuchFunction", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertErr(resp, err_not_supported);
}

test "server.admin_dispatch non-server-admin is rejected for admin-only endpoints" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var req = try makeRequest(allocator, "CreateHub");
    defer req.deinit();
    try req.addStr("HubName", "OTHER");
    try req.addInt("HubType", hub_type_standalone);

    var resp = try call(allocator, &server, false, "VPN", "CreateHub", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertErr(resp, err_not_enough_right);
}
