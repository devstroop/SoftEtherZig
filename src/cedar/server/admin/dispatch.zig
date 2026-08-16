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
const session_registry = @import("../session_registry.zig");
const session_main = @import("../session_main.zig");
const types_mod = @import("../../../mayaqua/kernel/types.zig");

// ============================================================================
// Error codes (C: Cedar.h)
// ============================================================================

pub const err_no_error: u32 = 0;
pub const err_hub_not_found: u32 = 8;
pub const err_internal_error: u32 = 23;
pub const err_object_not_found: u32 = 29;
pub const err_not_supported: u32 = 33;
pub const err_invalid_parameter: u32 = 38;
pub const err_not_farm_controller: u32 = 46;
pub const err_not_enough_right: u32 = 52;
pub const err_listener_not_found: u32 = 53;
pub const err_listener_already_exists: u32 = 54;
pub const err_hub_already_exists: u32 = 57;
pub const err_too_many_hubs: u32 = 58;
pub const err_too_many_user: u32 = 63;
pub const err_user_already_exists: u32 = 66;
pub const err_not_supported_auth_on_opensource: u32 = 143;

// ============================================================================
// Server type / hub type constants (C: Server.h:397, Cedar.h:411)
// ============================================================================

pub const server_type_standalone: u32 = 0;
pub const server_type_farm_controller: u32 = 1;
pub const server_type_farm_member: u32 = 2;

pub const hub_type_standalone: u32 = 0;
pub const hub_type_farm_static: u32 = 1;
pub const hub_type_farm_dynamic: u32 = 2;

pub const connection_type_client: u32 = 0;
pub const connecting_connected: u32 = 4;
pub const connecting_disconnecting: u32 = 5;

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

/// C `USER` subset backing the user endpoints. All string fields are owned
/// (always duplicated on creation), so `free` may release them unconditionally.
pub const ServerUser = struct {
    name: []const u8 = "",
    group_name: []const u8 = "",
    realname: []const u8 = "",
    note: []const u8 = "",
    auth_type: auth.UserAuthType = .anonymous,
    /// `auth.hashPassword(password, name)` digest for `password` accounts
    /// (C `AUTHPASSWORD.HashedKey`). Null = no known password (login fails).
    password_hash: ?[auth.digest_length]u8 = null,
    created_time: u64 = 0,
    updated_time: u64 = 0,
    expire_time: u64 = 0,
    num_login: u32 = 0,
    last_login_time: u64 = 0,
    deny_access: bool = false,
    traffic: structs.Traffic = .{},

    fn free(self: *ServerUser, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.group_name);
        allocator.free(self.realname);
        allocator.free(self.note);
        self.* = .{};
    }
};

/// C `MAC_TABLE_ENTRY` (Hub.h:280) subset backing `EnumMacTable` /
/// `DeleteMacTable`. `session_name` is owned (duped at insert). C keys the
/// hash by the entry pointer (`POINTER_TO_KEY`); the model uses a monotonic
/// counter instead, which is stable per hub and distinct from the data
/// plane's own table records.
pub const MacTableEntry = struct {
    key: u32 = 0,
    session_name: []const u8 = "",
    mac_address: [6]u8 = .{0} ** 6,
    vlan_id: u32 = 0,
    created_time: u64 = 0,
    updated_time: u64 = 0,

    fn free(self: *MacTableEntry, allocator: Allocator) void {
        allocator.free(self.session_name);
        self.* = .{};
    }
};

/// C `IP_TABLE_ENTRY` (Hub.h:292) subset backing `EnumIpTable` /
/// `DeleteIpTable`. Same key scheme as `MacTableEntry`.
pub const IpTableEntry = struct {
    key: u32 = 0,
    session_name: []const u8 = "",
    ip: types_mod.IpAddress = .{ .ipv4 = .{ 0, 0, 0, 0 } },
    dhcp_allocated: bool = false,
    created_time: u64 = 0,
    updated_time: u64 = 0,

    fn free(self: *IpTableEntry, allocator: Allocator) void {
        allocator.free(self.session_name);
        self.* = .{};
    }
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
    users: std.ArrayListUnmanaged(ServerUser) = .{},
    mac_tables: std.ArrayListUnmanaged(MacTableEntry) = .{},
    ip_tables: std.ArrayListUnmanaged(IpTableEntry) = .{},
    /// Next `MacTableEntry` / `IpTableEntry` key (monotonic per hub).
    next_table_key: u32 = 1,
    /// C hub admin options consulted by the table endpoints
    /// (`GetHubAdminOption`, Admin.c): `no_delete_mactable` /
    /// `no_delete_iptable` deny hub admins table deletion.
    no_delete_mactable: bool = false,
    no_delete_iptable: bool = false,

    /// Look up a user by name, matching case-insensitively (C `SearchUser`
    /// with `StrCmpi`; account names are not case-sensitive).
    fn findUser(self: *ServerHub, name: []const u8) ?*ServerUser {
        for (self.users.items) |*user| {
            if (std.ascii.eqlIgnoreCase(user.name, name)) return user;
        }
        return null;
    }

    /// Append a user, keeping `num_users` in sync. `u` must already be owned
    /// by the caller (dup'd strings); ownership transfers to the hub.
    fn addUser(self: *ServerHub, allocator: Allocator, u: ServerUser) !void {
        try self.users.append(allocator, u);
        self.num_users +%= 1;
    }

    /// Remove a user by name, releasing it. Returns false when absent.
    fn removeUser(self: *ServerHub, allocator: Allocator, name: []const u8) bool {
        for (self.users.items, 0..) |*user, i| {
            if (std.ascii.eqlIgnoreCase(user.name, name)) {
                var removed = self.users.swapRemove(i);
                removed.free(allocator);
                self.num_users -%= 1;
                return true;
            }
        }
        return false;
    }

    fn deinitUsers(self: *ServerHub, allocator: Allocator) void {
        for (self.users.items) |*user| user.free(allocator);
        self.users.deinit(allocator);
    }

    /// Look up a MAC table entry by key (C `IsInHashListKey` +
    /// `HashListKeyToPointer` on `MacHashTable`).
    fn findMacTableEntry(self: *ServerHub, key: u32) ?*MacTableEntry {
        for (self.mac_tables.items) |*e| {
            if (e.key == key) return e;
        }
        return null;
    }

    /// Look up an IP table entry by key (C `IsInListKey` +
    /// `ListKeyToPointer` on `IpTable`).
    fn findIpTableEntry(self: *ServerHub, key: u32) ?*IpTableEntry {
        for (self.ip_tables.items) |*e| {
            if (e.key == key) return e;
        }
        return null;
    }

    /// Insert a MAC table entry, assigning the next monotonic key and
    /// keeping `num_mac_tables` in sync. `session_name` ownership transfers
    /// to the hub.
    fn addMacTableEntry(self: *ServerHub, allocator: Allocator, entry: MacTableEntry) !u32 {
        var e = entry;
        e.key = self.next_table_key;
        self.next_table_key +%= 1;
        try self.mac_tables.append(allocator, e);
        self.num_mac_tables +%= 1;
        return e.key;
    }

    /// Insert an IP table entry, assigning the next monotonic key and
    /// keeping `num_ip_tables` in sync.
    fn addIpTableEntry(self: *ServerHub, allocator: Allocator, entry: IpTableEntry) !u32 {
        var e = entry;
        e.key = self.next_table_key;
        self.next_table_key +%= 1;
        try self.ip_tables.append(allocator, e);
        self.num_ip_tables +%= 1;
        return e.key;
    }

    /// Remove a MAC table entry by key, releasing it. Returns false when
    /// absent (C `ERR_OBJECT_NOT_FOUND`).
    fn removeMacTableEntry(self: *ServerHub, allocator: Allocator, key: u32) bool {
        for (self.mac_tables.items, 0..) |*e, i| {
            if (e.key == key) {
                var removed = self.mac_tables.swapRemove(i);
                removed.free(allocator);
                self.num_mac_tables -%= 1;
                return true;
            }
        }
        return false;
    }

    /// Remove an IP table entry by key, releasing it. Returns false when
    /// absent (C `ERR_OBJECT_NOT_FOUND`).
    fn removeIpTableEntry(self: *ServerHub, allocator: Allocator, key: u32) bool {
        for (self.ip_tables.items, 0..) |*e, i| {
            if (e.key == key) {
                var removed = self.ip_tables.swapRemove(i);
                removed.free(allocator);
                self.num_ip_tables -%= 1;
                return true;
            }
        }
        return false;
    }

    fn deinitTables(self: *ServerHub, allocator: Allocator) void {
        for (self.mac_tables.items) |*e| e.free(allocator);
        self.mac_tables.deinit(allocator);
        for (self.ip_tables.items) |*e| e.free(allocator);
        self.ip_tables.deinit(allocator);
    }
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

    /// Live sessions (C `SERVER->SessionList` + `ConnectionList` subset).
    /// `accept.zig`'s data-plane sessions register into their own registry; the
    /// admin dispatch model keeps a standalone one so `EnumSession` &
    /// friends can run against `SessionMain`-backed test records.
    sessions: session_registry.SessionRegistry,

    /// Create a standalone server with default identity strings.
    pub fn init(allocator: Allocator) !Server {
        var s: Server = .{
            .allocator = allocator,
            .sessions = session_registry.SessionRegistry.init(allocator),
        };
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
        for (self.hubs.items) |*hub| {
            hub.deinitUsers(allocator);
            hub.deinitTables(allocator);
            allocator.free(hub.name);
        }
        self.hubs.deinit(allocator);
        self.listeners.deinit(allocator);
        self.sessions.deinit();
        self.* = .{
            .allocator = allocator,
            .sessions = session_registry.SessionRegistry.init(allocator),
        };
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
    } else if (mem.eql(u8, function_name, "EnumSession")) {
        err = dispatchCall(structs.RpcEnumSession, &a, allocator, request, ret, stEnumSession);
    } else if (mem.eql(u8, function_name, "GetSessionStatus")) {
        err = dispatchCall(structs.RpcSessionStatus, &a, allocator, request, ret, stGetSessionStatus);
    } else if (mem.eql(u8, function_name, "DeleteSession")) {
        err = dispatchCall(structs.RpcDeleteSession, &a, allocator, request, ret, stDeleteSession);
    } else if (mem.eql(u8, function_name, "EnumConnection")) {
        err = dispatchCall(structs.RpcEnumConnection, &a, allocator, request, ret, stEnumConnection);
    } else if (mem.eql(u8, function_name, "DisconnectConnection")) {
        err = dispatchCall(structs.RpcDisconnectConnection, &a, allocator, request, ret, stDisconnectConnection);
    } else if (mem.eql(u8, function_name, "EnumUser")) {
        err = dispatchCall(structs.RpcEnumUser, &a, allocator, request, ret, stEnumUser);
    } else if (mem.eql(u8, function_name, "CreateUser")) {
        err = dispatchCall(structs.RpcSetUser, &a, allocator, request, ret, stCreateUser);
    } else if (mem.eql(u8, function_name, "SetUser")) {
        err = dispatchCall(structs.RpcSetUser, &a, allocator, request, ret, stSetUser);
    } else if (mem.eql(u8, function_name, "DeleteUser")) {
        err = dispatchCall(structs.RpcDeleteUser, &a, allocator, request, ret, stDeleteUser);
    } else if (mem.eql(u8, function_name, "EnumMacTable")) {
        err = dispatchCall(structs.RpcEnumMacTable, &a, allocator, request, ret, stEnumMacTable);
    } else if (mem.eql(u8, function_name, "EnumIpTable")) {
        err = dispatchCall(structs.RpcEnumIpTable, &a, allocator, request, ret, stEnumIpTable);
    } else if (mem.eql(u8, function_name, "DeleteMacTable")) {
        err = dispatchCall(structs.RpcDeleteTable, &a, allocator, request, ret, stDeleteMacTable);
    } else if (mem.eql(u8, function_name, "DeleteIpTable")) {
        err = dispatchCall(structs.RpcDeleteTable, &a, allocator, request, ret, stDeleteIpTable);
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
        structs.RpcEnumSession => try t.inRpc(allocator, p),
        structs.RpcSessionStatus => try t.inRpc(allocator, p),
        structs.RpcDeleteSession => try t.inRpc(allocator, p),
        structs.RpcEnumConnection => try t.inRpc(allocator, p),
        structs.RpcDisconnectConnection => try t.inRpc(allocator, p),
        structs.RpcEnumUser => try t.inRpc(allocator, p),
        structs.RpcSetUser => try t.inRpc(allocator, p),
        structs.RpcDeleteUser => try t.inRpc(allocator, p),
        structs.RpcEnumMacTable => try t.inRpc(allocator, p),
        structs.RpcEnumIpTable => try t.inRpc(allocator, p),
        structs.RpcDeleteTable => try t.inRpc(allocator, p),
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
        structs.RpcEnumSession => try t.outRpc(p),
        structs.RpcSessionStatus => try t.outRpc(p),
        structs.RpcDeleteSession => try t.outRpc(p),
        structs.RpcEnumConnection => try t.outRpc(p),
        structs.RpcDisconnectConnection => try t.outRpc(p),
        structs.RpcEnumUser => try t.outRpc(p),
        structs.RpcSetUser => try t.outRpc(p),
        structs.RpcDeleteUser => try t.outRpc(p),
        structs.RpcEnumMacTable => try t.outRpc(p),
        structs.RpcEnumIpTable => try t.outRpc(p),
        structs.RpcDeleteTable => try t.outRpc(p),
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
        structs.RpcEnumSession => t.free(allocator),
        structs.RpcSessionStatus => t.free(allocator),
        structs.RpcDeleteSession => t.free(allocator),
        structs.RpcEnumConnection => t.free(allocator),
        structs.RpcDisconnectConnection => t.free(allocator),
        structs.RpcEnumUser => t.free(allocator),
        structs.RpcSetUser => t.free(allocator),
        structs.RpcDeleteUser => t.free(allocator),
        structs.RpcEnumMacTable => t.free(allocator),
        structs.RpcEnumIpTable => t.free(allocator),
        structs.RpcDeleteTable => t.free(allocator),
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
    var removed = s.hubs.swapRemove(index);
    removed.deinitUsers(allocator);
    removed.deinitTables(allocator);
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
// Sessions (C `StEnumSession`, Admin.c:5448)
// ============================================================================

/// C `StEnumSession`. CHECK_RIGHT first, then the hub must exist. A non-server
/// admin only ever sees sessions on the hub it authenticated against.
fn stEnumSession(a: *AdminCtx, t: *structs.RpcEnumSession, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;

    const req_hub = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = req_hub;

    const snaps = s.sessions.snapshot(allocator) catch return err_internal_error;
    defer session_registry.SessionRegistry.freeSnapshot(allocator, snaps);

    var count: usize = 0;
    for (snaps) |*snap| {
        if (std.ascii.eqlIgnoreCase(snap.hub_name, t.hub_name)) count += 1;
    }
    t.sessions = allocator.alloc(structs.EnumSessionItem, count) catch return err_internal_error;
    var i: usize = 0;
    for (snaps) |*snap| {
        if (!std.ascii.eqlIgnoreCase(snap.hub_name, t.hub_name)) continue;
        const e = &t.sessions[i];
        e.* = .{};
        e.name = dupStr(allocator, snap.session_name) catch return err_internal_error;
        e.username = dupStr(allocator, snap.username) catch return err_internal_error;
        e.ip = snap.peer_ip;
        e.client_ip = types_mod.IpAddress.fromU32(snap.peer_ip);
        e.max_num_tcp = 1;
        e.current_num_tcp = 1;
        // The registry does not track per-session traffic; report 0 rather
        // than fabricating counters. `last_comm_time` is the session's
        // initial value (a session that has not communicated yet).
        e.packet_size = 0;
        e.packet_num = 0;
        e.link_mode = false;
        e.secure_nat_mode = false;
        e.bridge_mode = false;
        e.layer3_mode = false;
        e.client_bridge_mode = false;
        e.client_monitor_mode = false;
        e.vlan_id = 0;
        e.is_dormant_enabled = false;
        e.is_dormant = false;
        e.created_time = @intCast(@max(snap.created_time, 0));
        e.last_comm_time = e.created_time;
        i += 1;
    }
    return err_no_error;
}

/// C `StGetSessionStatus` (Admin.c:5302). Same check order as
/// `StDeleteSession`: empty name, CHECK_RIGHT, hub, then session lookup.
fn stGetSessionStatus(a: *AdminCtx, t: *structs.RpcSessionStatus, allocator: Allocator) u32 {
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;

    const snaps = s.sessions.snapshot(allocator) catch return err_internal_error;
    defer session_registry.SessionRegistry.freeSnapshot(allocator, snaps);

    var found: ?*session_registry.SessionSnapshot = null;
    for (snaps) |*snap| {
        if (std.ascii.eqlIgnoreCase(snap.hub_name, t.hub_name) and
            std.ascii.eqlIgnoreCase(snap.session_name, t.name))
        {
            found = snap;
            break;
        }
    }
    const snap = found orelse return err_object_not_found;

    const req_hub = dupStr(allocator, t.hub_name) catch return err_internal_error;
    const req_name = dupStr(allocator, t.name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = req_hub;
    t.name = req_name;
    t.username = dupStr(allocator, snap.username) catch return err_internal_error;
    t.client_ip = snap.peer_ip;
    t.client_ip_address = types_mod.IpAddress.fromU32(snap.peer_ip);
    t.status.session_name = dupStr(allocator, snap.session_name) catch return err_internal_error;
    t.status.connection_name = dupStr(allocator, snap.connection_name) catch return err_internal_error;
    // A session whose stop was requested is mid-teardown (C `EndSession` only
    // flips the stop flag; the record remains until the session thread exits),
    // so report it as disconnecting instead of fully connected.
    t.status.active = !snap.stop_requested;
    t.status.connected = !snap.stop_requested;
    t.status.session_status = if (snap.stop_requested) connecting_disconnecting else connecting_connected;
    t.status.max_tcp_connections = 1;
    t.status.num_tcp_connections = 1;
    t.status.start_time = @intCast(@max(snap.created_time, 0));
    return err_no_error;
}

/// C `StDeleteSession` (Admin.c:5202). Empty name is checked before
/// CHECK_RIGHT; the session is looked up on the target hub and stopped.
fn stDeleteSession(a: *AdminCtx, t: *structs.RpcDeleteSession, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;
    if (!s.sessions.requestStopOnHub(t.hub_name, t.name)) return err_object_not_found;
    return err_no_error;
}

/// C `StEnumConnection` (Admin.c:8725). `SERVER_ADMIN_ONLY`; every live
/// connection in the registry is listed (the model only tracks sessions, so a
/// connection row exists per session).
fn stEnumConnection(a: *AdminCtx, t: *structs.RpcEnumConnection, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin) return err_not_enough_right;

    t.free(allocator);
    t.* = .{};
    const snaps = s.sessions.snapshot(allocator) catch return err_internal_error;
    defer session_registry.SessionRegistry.freeSnapshot(allocator, snaps);
    t.connections = allocator.alloc(structs.EnumConnectionItem, snaps.len) catch return err_internal_error;
    for (snaps, 0..) |*snap, i| {
        const e = &t.connections[i];
        e.* = .{};
        e.name = dupStr(allocator, snap.connection_name) catch return err_internal_error;
        e.hostname = dupStr(allocator, "") catch return err_internal_error;
        e.ip = snap.peer_ip;
        e.port = snap.peer_port;
        e.connected_time = @intCast(@max(snap.created_time, 0));
        e.connection_type = connection_type_client;
    }
    return err_no_error;
}

/// C `StDisconnectConnection` (Admin.c:8683). Empty name, then
/// `SERVER_ADMIN_ONLY`, then the server-wide connection lookup.
fn stDisconnectConnection(a: *AdminCtx, t: *structs.RpcDisconnectConnection, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;
    if (!a.server_admin) return err_not_enough_right;
    if (!s.sessions.requestStopByConnection(t.name)) return err_object_not_found;
    return err_no_error;
}

// ============================================================================
// Users (C `StEnumUser` / `StCreateUser` / `StSetUser` / `StDeleteUser`)
// ============================================================================

/// C `InRpcAuthData` AUTHTYPE_PASSWORD (Admin.c:13522): the client's
/// `HashedKey` (a 20-byte `HashPassword` digest) wins; a zero/absent key
/// falls back to hashing the optional `Auth_Password` plaintext against the
/// account name. Returns null when neither is present.
fn resolvePasswordHash(t: *const structs.RpcSetUser) ?[auth.digest_length]u8 {
    if (t.hashed_key) |key| {
        var nonzero = false;
        for (key) |byte| {
            if (byte != 0) {
                nonzero = true;
                break;
            }
        }
        if (nonzero) return key;
    }
    if (t.auth_password.len != 0) {
        return auth.hashPassword(t.auth_password, t.name);
    }
    return null;
}

/// Map a wire `AuthType` to the model's supported set. The opensource build
/// defines `GSF_DISABLE_RADIUS_AUTH`, so certificate / RADIUS / NT accounts
/// are rejected (C `StCreateUser` Admin.c:6262).
fn resolveAuthType(wire_auth_type: u32) ?auth.UserAuthType {
    return switch (wire_auth_type) {
        @intFromEnum(auth.UserAuthType.anonymous) => .anonymous,
        @intFromEnum(auth.UserAuthType.password) => .password,
        else => null,
    };
}

/// C `StEnumUser` (Admin.c:5911). Hub-scoped: server admins target the
/// requested hub, hub admins are locked to their own.
fn stEnumUser(a: *AdminCtx, t: *structs.RpcEnumUser, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    t.users = allocator.alloc(structs.EnumUserItem, hub.users.items.len) catch return err_internal_error;
    for (hub.users.items, 0..) |*user, i| {
        const e = &t.users[i];
        e.* = .{};
        e.name = dupStr(allocator, user.name) catch return err_internal_error;
        e.group_name = dupStr(allocator, user.group_name) catch return err_internal_error;
        e.realname = dupStr(allocator, user.realname) catch return err_internal_error;
        e.note = dupStr(allocator, user.note) catch return err_internal_error;
        e.auth_type = @intFromEnum(user.auth_type);
        e.last_login_time = user.last_login_time;
        e.num_login = user.num_login;
        e.deny_access = user.deny_access;
        e.is_traffic_filled = true;
        e.traffic = user.traffic;
        e.is_expires_filled = true;
        e.expires = user.expire_time;
    }
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StCreateUser` (Admin.c:6262).
fn stCreateUser(a: *AdminCtx, t: *structs.RpcSetUser, allocator: Allocator) u32 {
    const s = a.server;
    if (!isUserName(t.name)) return err_invalid_parameter;
    if (isWildcardName(t.name)) return err_invalid_parameter;
    if (!canonicalizeUserName(t, allocator)) return err_internal_error;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;

    const auth_type = resolveAuthType(t.auth_type) orelse return err_not_supported_auth_on_opensource;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (hub.findUser(t.name) != null) return err_user_already_exists;
    if (hub.users.items.len >= max_users) return err_too_many_user;

    const now = nowMs();
    var user = ServerUser{
        .name = dupStr(allocator, t.name) catch return err_internal_error,
        .group_name = dupStr(allocator, t.group_name) catch return err_internal_error,
        .realname = dupStr(allocator, t.realname) catch return err_internal_error,
        .note = dupStr(allocator, t.note) catch return err_internal_error,
        .auth_type = auth_type,
        .created_time = now,
        .updated_time = now,
        .expire_time = t.expire_time,
    };
    if (auth_type == .password) {
        user.password_hash = resolvePasswordHash(t);
    }
    hub.addUser(allocator, user) catch return err_internal_error;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StSetUser` (Admin.c:6129). Divergence from C: when a password account is
/// edited without new auth data the existing hash is kept (C randomizes it,
/// locking the account out).
fn stSetUser(a: *AdminCtx, t: *structs.RpcSetUser, allocator: Allocator) u32 {
    const s = a.server;
    if (!isUserName(t.name)) return err_invalid_parameter;
    if (isWildcardName(t.name)) return err_invalid_parameter;
    if (!canonicalizeUserName(t, allocator)) return err_internal_error;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;

    const auth_type = resolveAuthType(t.auth_type) orelse return err_not_supported_auth_on_opensource;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    const user = hub.findUser(t.name) orelse return err_object_not_found;

    const group_name = dupStr(allocator, t.group_name) catch return err_internal_error;
    const realname = dupStr(allocator, t.realname) catch return err_internal_error;
    const note = dupStr(allocator, t.note) catch return err_internal_error;

    allocator.free(user.group_name);
    allocator.free(user.realname);
    allocator.free(user.note);
    user.group_name = group_name;
    user.realname = realname;
    user.note = note;
    user.auth_type = auth_type;
    if (auth_type == .password) {
        if (resolvePasswordHash(t)) |hash| {
            user.password_hash = hash;
        }
    } else {
        user.password_hash = null;
    }
    user.expire_time = t.expire_time;
    user.num_login = t.num_login;
    user.traffic = t.traffic;
    user.updated_time = nowMs();
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteUser` (Admin.c:5992).
fn stDeleteUser(a: *AdminCtx, t: *structs.RpcDeleteUser, allocator: Allocator) u32 {
    const s = a.server;
    if (!isUserName(t.name)) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (!hub.removeUser(allocator, t.name)) return err_object_not_found;
    s.config_revision +%= 1;
    return err_no_error;
}

// ============================================================================
// Tables (C `StEnumMacTable` Admin.c:5152, `StEnumIpTable` Admin.c:4978,
//         `StDeleteMacTable` Admin.c:5028, `StDeleteIpTable` Admin.c:4854)
// ============================================================================

/// C `StEnumMacTable` (Admin.c:5152) via `SiEnumMacTable` (Admin.c:5224).
/// CHECK_RIGHT only — the MAC table is enumerable by hub admins of their own
/// hub. Divergence from C: the model holds a single MAC table list, so the
/// farm-controller fan-out (`SiCallEnumMacTable`) is not needed.
fn stEnumMacTable(a: *AdminCtx, t: *structs.RpcEnumMacTable, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    t.mac_tables = allocator.alloc(structs.EnumMacTableItem, hub.mac_tables.items.len) catch return err_internal_error;
    for (hub.mac_tables.items, 0..) |*m, i| {
        const e = &t.mac_tables[i];
        e.* = .{};
        e.key = m.key;
        e.session_name = dupStr(allocator, m.session_name) catch return err_internal_error;
        e.mac_address = m.mac_address;
        e.vlan_id = m.vlan_id;
        e.created_time = m.created_time;
        e.updated_time = m.updated_time;
        e.remote_item = false;
    }
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StEnumIpTable` (Admin.c:4978) via `SiEnumIpTable` (Admin.c:4930).
/// CHECK_RIGHT only; the IP table is enumerable by hub admins of their own
/// hub. Divergence from C: single local list, no farm-controller fan-out.
fn stEnumIpTable(a: *AdminCtx, t: *structs.RpcEnumIpTable, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    t.ip_tables = allocator.alloc(structs.EnumIpTableItem, hub.ip_tables.items.len) catch return err_internal_error;
    for (hub.ip_tables.items, 0..) |*entry, i| {
        const e = &t.ip_tables[i];
        e.* = .{};
        e.key = entry.key;
        e.session_name = dupStr(allocator, entry.session_name) catch return err_internal_error;
        e.ip = entry.ip.toU32() orelse 0;
        e.ip_v6 = entry.ip;
        e.ip_address = entry.ip;
        e.dhcp_allocated = entry.dhcp_allocated;
        e.created_time = entry.created_time;
        e.updated_time = entry.updated_time;
        e.remote_item = false;
    }
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteMacTable` (Admin.c:5028). Hub admins are blocked when the
/// `no_delete_mactable` hub option is set (C `GetHubAdminOption`);
/// server admins always pass (C returns early on `a->ServerAdmin`).
fn stDeleteMacTable(a: *AdminCtx, t: *structs.RpcDeleteTable, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (!a.server_admin and hub.no_delete_mactable) return err_not_enough_right;
    if (!hub.removeMacTableEntry(allocator, t.key)) return err_object_not_found;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteIpTable` (Admin.c:4854). Hub admins are blocked when the
/// `no_delete_iptable` hub option is set (C `GetHubAdminOption`).
fn stDeleteIpTable(a: *AdminCtx, t: *structs.RpcDeleteTable, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (!a.server_admin and hub.no_delete_iptable) return err_not_enough_right;
    if (!hub.removeIpTableEntry(allocator, t.key)) return err_object_not_found;
    s.config_revision +%= 1;
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

/// C `IsUserName` (Account.c:340): trimmed, then a safe, non-reserved account
/// name. `"*"` passes here but is reserved for RADIUS/NT wildcard accounts
/// (the handlers reject it for the supported auth types).
fn isUserName(s: []const u8) bool {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(t, "*")) return true;
    if (!isSafeStr(t)) return false;
    if (std.ascii.eqlIgnoreCase(t, "link") or
        std.ascii.eqlIgnoreCase(t, "Link") or
        std.ascii.eqlIgnoreCase(t, "securenat") or
        std.ascii.eqlIgnoreCase(t, "SecureNAT") or
        std.ascii.eqlIgnoreCase(t, "localbridge") or
        std.ascii.eqlIgnoreCase(t, "Local Bridge") or
        std.ascii.eqlIgnoreCase(t, "administrator")) return false;
    if (std.ascii.startsWithIgnoreCase(t, "L3SW_")) return false;
    return true;
}

/// True when the trimmed name is the RADIUS/NT wildcard `"*"`, which the
/// supported auth types can't back (C `StIsSafeName(name, false)` rejects the
/// trimmed wildcard too, since `IsUserName` trims in place).
fn isWildcardName(s: []const u8) bool {
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, s, " \t"), "*");
}

/// Replace the request name with its trimmed canonical form (C `IsUserName`
/// validates the trimmed name, so the stored/hashed identity must match).
/// The raw allocation is freed and the trimmed copy adopted, so padded names
/// like `" Alice "` can't create a distinct account from `Alice`.
fn canonicalizeUserName(t: *structs.RpcSetUser, allocator: Allocator) bool {
    const trimmed = std.mem.trim(u8, t.name, " \t");
    if (trimmed.len == t.name.len) return true;
    const owned = allocator.dupe(u8, trimmed) catch return false;
    allocator.free(t.name);
    t.name = owned;
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

test "server.admin_dispatch DeleteHub frees the hub's users" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var create = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    const hash = auth.hashPassword("s3cret", "Alice");
    try create.addData("HashedKey", &hash);
    try create.addInt("AuthType", 1);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

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

test "server.admin_dispatch isUserName accepts safe names and rejects reserved" {
    try testing.expect(isUserName("Alice"));
    try testing.expect(isUserName("user-1"));
    try testing.expect(isUserName("user name"));
    try testing.expect(isUserName("*"));

    try testing.expect(!isUserName(""));
    try testing.expect(!isUserName(" "));
    try testing.expect(!isUserName(" link"));
    try testing.expect(!isUserName("link"));
    try testing.expect(!isUserName("Link"));
    try testing.expect(!isUserName("securenat"));
    try testing.expect(!isUserName("SecureNAT"));
    try testing.expect(!isUserName("localbridge"));
    try testing.expect(!isUserName("Local Bridge"));
    try testing.expect(!isUserName("administrator"));
    try testing.expect(!isUserName("L3SW_foo"));
    try testing.expect(!isUserName("bad$char"));
}

/// Build a `CreateUser`/`SetUser` request carrying the full `RPC_SET_USER`
/// payload. Realname/Note default to `"Real {name}"` / `"note"`.
fn makeSetUserRequest(allocator: Allocator, hub_name: []const u8, name: []const u8) !Pack {
    var req = try makeRequest(allocator, "CreateUser");
    try req.addStr("HubName", hub_name);
    try req.addStr("Name", name);
    try req.addStr("GroupName", "Engineering");
    var buf: [256]u8 = undefined;
    const realname = std.fmt.bufPrint(&buf, "Real {s}", .{name}) catch "Real";
    try req.addUniStr("Realname", realname);
    try req.addUniStr("Note", "note");
    return req;
}

test "server.admin_dispatch CreateUser adds and validates a user" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    const revision_before = server.config_revision;

    // Password user with a client-computed hash.
    var create = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    const hash = auth.hashPassword("s3cret", "Alice");
    try create.addData("HashedKey", &hash);
    try create.addInt("AuthType", 1);

    var resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqual(revision_before + 1, server.config_revision);

    const hub = findHub(&server, "VPN").?;
    try testing.expectEqual(@as(u32, 1), hub.num_users);
    const alice = hub.findUser("Alice").?;
    try testing.expectEqual(auth.UserAuthType.password, alice.auth_type);
    try testing.expectEqualSlices(u8, &hash, &alice.password_hash.?);
    try testing.expectEqualStrings("Engineering", alice.group_name);
    try testing.expectEqualStrings("Real Alice", alice.realname);
    try testing.expectEqualStrings("note", alice.note);

    // Duplicate name.
    var dup = try makeSetUserRequest(allocator, "VPN", "alice");
    defer dup.deinit();
    try dup.addStr("function_name", "CreateUser");
    try dup.addInt("AuthType", 0);
    var dup_resp = try call(allocator, &server, true, "", "CreateUser", &dup);
    defer {
        dup_resp.deinit();
        allocator.destroy(dup_resp);
    }
    try assertErr(dup_resp, err_user_already_exists);
}

test "server.admin_dispatch CreateUser hashes a plaintext Auth_Password" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var create = try makeSetUserRequest(allocator, "VPN", "Bob");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    try create.addData("HashedKey", &([_]u8{0} ** 20));
    try create.addStr("Auth_Password", "hunter2");
    try create.addInt("AuthType", 1);

    var resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    const bob = findHub(&server, "VPN").?.findUser("Bob").?;
    try testing.expectEqualSlices(u8, &auth.hashPassword("hunter2", "Bob"), &bob.password_hash.?);
}

test "server.admin_dispatch CreateUser validates name, hub and auth type" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Invalid / reserved names.
    var bad_name = try makeSetUserRequest(allocator, "VPN", "administrator");
    defer bad_name.deinit();
    var bad_name_resp = try call(allocator, &server, true, "", "CreateUser", &bad_name);
    defer {
        bad_name_resp.deinit();
        allocator.destroy(bad_name_resp);
    }
    try assertErr(bad_name_resp, err_invalid_parameter);

    // Wildcard names need RADIUS/NT, which the opensource model rejects.
    var star = try makeSetUserRequest(allocator, "VPN", "*");
    defer star.deinit();
    var star_resp = try call(allocator, &server, true, "", "CreateUser", &star);
    defer {
        star_resp.deinit();
        allocator.destroy(star_resp);
    }
    try assertErr(star_resp, err_invalid_parameter);

    // A padded wildcard is the same reserved name after trimming.
    var padded_star = try makeSetUserRequest(allocator, "VPN", " * ");
    defer padded_star.deinit();
    var padded_star_resp = try call(allocator, &server, true, "", "CreateUser", &padded_star);
    defer {
        padded_star_resp.deinit();
        allocator.destroy(padded_star_resp);
    }
    try assertErr(padded_star_resp, err_invalid_parameter);

    // The L3SW_ namespace is reserved case-insensitively, matching the
    // case-insensitive user lookup.
    var l3sw = try makeSetUserRequest(allocator, "VPN", "l3sw_vlan10");
    defer l3sw.deinit();
    var l3sw_resp = try call(allocator, &server, true, "", "CreateUser", &l3sw);
    defer {
        l3sw_resp.deinit();
        allocator.destroy(l3sw_resp);
    }
    try assertErr(l3sw_resp, err_invalid_parameter);

    // Certificate auth is unavailable in the opensource model.
    var cert = try makeSetUserRequest(allocator, "VPN", "Carol");
    defer cert.deinit();
    try cert.addInt("AuthType", 2);
    var cert_resp = try call(allocator, &server, true, "", "CreateUser", &cert);
    defer {
        cert_resp.deinit();
        allocator.destroy(cert_resp);
    }
    try assertErr(cert_resp, err_not_supported_auth_on_opensource);

    // Unknown hub.
    var no_hub = try makeSetUserRequest(allocator, "NOPE", "Dana");
    defer no_hub.deinit();
    var no_hub_resp = try call(allocator, &server, true, "", "CreateUser", &no_hub);
    defer {
        no_hub_resp.deinit();
        allocator.destroy(no_hub_resp);
    }
    try assertErr(no_hub_resp, err_hub_not_found);

    // Hub admins are locked to their own hub.
    var locked = try makeSetUserRequest(allocator, "OTHER", "Eve");
    defer locked.deinit();
    var locked_resp = try call(allocator, &server, false, "VPN", "CreateUser", &locked);
    defer {
        locked_resp.deinit();
        allocator.destroy(locked_resp);
    }
    try assertErr(locked_resp, err_not_enough_right);
}

test "server.admin_dispatch CreateUser canonicalizes padded names" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // A padded name is stored trimmed, matching the validated identity.
    var padded = try makeSetUserRequest(allocator, "VPN", "  Frank  ");
    defer padded.deinit();
    var padded_resp = try call(allocator, &server, true, "", "CreateUser", &padded);
    defer {
        padded_resp.deinit();
        allocator.destroy(padded_resp);
    }
    try assertOk(padded_resp);

    var req = try makeRequest(allocator, "EnumUser");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    var resp = try call(allocator, &server, true, "", "EnumUser", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqual(@as(usize, 1), resp.getValueCount("Name"));
    try testing.expectEqualStrings("Frank", resp.getStrEx("Name", 0).?);

    // The trimmed identity is the same account: a second create collides.
    var dup = try makeSetUserRequest(allocator, "VPN", "Frank");
    defer dup.deinit();
    var dup_resp = try call(allocator, &server, true, "", "CreateUser", &dup);
    defer {
        dup_resp.deinit();
        allocator.destroy(dup_resp);
    }
    try assertErr(dup_resp, err_user_already_exists);
}

test "server.admin_dispatch EnumUser lists only the requested hub's users" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    var alice = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer alice.deinit();
    try alice.addStr("function_name", "CreateUser");
    try alice.addData("HashedKey", &auth.hashPassword("p", "Alice"));
    try alice.addInt("AuthType", 1);
    var a_resp = try call(allocator, &server, true, "", "CreateUser", &alice);
    defer {
        a_resp.deinit();
        allocator.destroy(a_resp);
    }
    try assertOk(a_resp);

    var bob = try makeSetUserRequest(allocator, "TEST", "Bob");
    defer bob.deinit();
    try bob.addStr("function_name", "CreateUser");
    try bob.addInt("AuthType", 0);
    var b_resp = try call(allocator, &server, true, "", "CreateUser", &bob);
    defer {
        b_resp.deinit();
        allocator.destroy(b_resp);
    }
    try assertOk(b_resp);

    var req = try makeRequest(allocator, "EnumUser");
    defer req.deinit();
    try req.addStr("HubName", "VPN");

    var resp = try call(allocator, &server, true, "", "EnumUser", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
    try testing.expectEqual(@as(usize, 1), resp.getValueCount("Name"));
    try testing.expectEqualStrings("Alice", resp.getStrEx("Name", 0).?);
    try testing.expectEqualStrings("Engineering", resp.getStrEx("GroupName", 0).?);
    try testing.expectEqualStrings("Real Alice", resp.getUniStrEx("Realname", 0).?);
    try testing.expectEqual(@as(u32, 1), resp.getIntEx("AuthType", 0).?);
    try testing.expectEqual(@as(bool, true), resp.getBoolEx("IsExpiresFilled", 0).?);
    try testing.expectEqual(@as(u64, 0), resp.getInt64Ex("Expires", 0).?);
}

test "server.admin_dispatch EnumUser is hub-scoped for non-server-admin" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    // Own hub is fine.
    var own = try makeRequest(allocator, "EnumUser");
    defer own.deinit();
    try own.addStr("HubName", "VPN");
    var own_resp = try call(allocator, &server, false, "VPN", "EnumUser", &own);
    defer {
        own_resp.deinit();
        allocator.destroy(own_resp);
    }
    try assertOk(own_resp);

    // Another hub is rejected.
    var other = try makeRequest(allocator, "EnumUser");
    defer other.deinit();
    try other.addStr("HubName", "TEST");
    var other_resp = try call(allocator, &server, false, "VPN", "EnumUser", &other);
    defer {
        other_resp.deinit();
        allocator.destroy(other_resp);
    }
    try assertErr(other_resp, err_not_enough_right);

    // Unknown hub.
    var missing = try makeRequest(allocator, "EnumUser");
    defer missing.deinit();
    try missing.addStr("HubName", "NOPE");
    var missing_resp = try call(allocator, &server, true, "", "EnumUser", &missing);
    defer {
        missing_resp.deinit();
        allocator.destroy(missing_resp);
    }
    try assertErr(missing_resp, err_hub_not_found);
}

test "server.admin_dispatch SetUser updates a user" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hash = auth.hashPassword("oldpass", "Alice");
    var create = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    try create.addData("HashedKey", &hash);
    try create.addInt("AuthType", 1);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

    // Change password + metadata.
    var set = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer set.deinit();
    try set.addStr("function_name", "SetUser");
    try set.addStrEx("GroupName", "Security", 0);
    try set.addUniStrEx("Realname", "Alice Smith", 0);
    try set.addUniStrEx("Note", "rotated", 0);
    const new_hash = auth.hashPassword("newpass", "Alice");
    try set.addData("HashedKey", &new_hash);
    try set.addInt("AuthType", 1);

    var set_resp = try call(allocator, &server, true, "", "SetUser", &set);
    defer {
        set_resp.deinit();
        allocator.destroy(set_resp);
    }
    try assertOk(set_resp);

    const alice = findHub(&server, "VPN").?.findUser("Alice").?;
    try testing.expectEqualStrings("Security", alice.group_name);
    try testing.expectEqualStrings("Alice Smith", alice.realname);
    try testing.expectEqualStrings("rotated", alice.note);
    try testing.expectEqualSlices(u8, &new_hash, &alice.password_hash.?);

    // Unknown user.
    var miss = try makeSetUserRequest(allocator, "VPN", "Nobody");
    defer miss.deinit();
    try miss.addStr("function_name", "SetUser");
    var miss_resp = try call(allocator, &server, true, "", "SetUser", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_object_not_found);
}

test "server.admin_dispatch SetUser switches auth type and keeps password" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hash = auth.hashPassword("s3cret", "Alice");
    var create = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    try create.addData("HashedKey", &hash);
    try create.addInt("AuthType", 1);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

    // Downgrade to anonymous.
    var anon = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer anon.deinit();
    try anon.addStr("function_name", "SetUser");
    try anon.addInt("AuthType", 0);
    var anon_resp = try call(allocator, &server, true, "", "SetUser", &anon);
    defer {
        anon_resp.deinit();
        allocator.destroy(anon_resp);
    }
    try assertOk(anon_resp);
    var alice = findHub(&server, "VPN").?.findUser("Alice").?;
    try testing.expectEqual(auth.UserAuthType.anonymous, alice.auth_type);
    try testing.expectEqual(@as(?[auth.digest_length]u8, null), alice.password_hash);

    // Upgrade back to password without auth data: the (null) existing hash is
    // kept rather than randomized (divergence from C's lockout behavior).
    var upgrade = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer upgrade.deinit();
    try upgrade.addStr("function_name", "SetUser");
    try upgrade.addInt("AuthType", 1);
    var upgrade_resp = try call(allocator, &server, true, "", "SetUser", &upgrade);
    defer {
        upgrade_resp.deinit();
        allocator.destroy(upgrade_resp);
    }
    try assertOk(upgrade_resp);
    alice = findHub(&server, "VPN").?.findUser("Alice").?;
    try testing.expectEqual(auth.UserAuthType.password, alice.auth_type);
    try testing.expectEqual(@as(?[auth.digest_length]u8, null), alice.password_hash);
}

test "server.admin_dispatch DeleteUser removes and reports missing" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var create = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    try create.addData("HashedKey", &auth.hashPassword("p", "Alice"));
    try create.addInt("AuthType", 1);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

    var del = try makeRequest(allocator, "DeleteUser");
    defer del.deinit();
    try del.addStr("HubName", "VPN");
    try del.addStr("Name", "alice");
    var del_resp = try call(allocator, &server, true, "", "DeleteUser", &del);
    defer {
        del_resp.deinit();
        allocator.destroy(del_resp);
    }
    try assertOk(del_resp);
    try testing.expectEqual(@as(u32, 0), findHub(&server, "VPN").?.num_users);
    try testing.expect(findHub(&server, "VPN").?.findUser("Alice") == null);

    // Deleting again reports the account is gone.
    var again = try makeRequest(allocator, "DeleteUser");
    defer again.deinit();
    try again.addStr("HubName", "VPN");
    try again.addStr("Name", "Alice");
    var again_resp = try call(allocator, &server, true, "", "DeleteUser", &again);
    defer {
        again_resp.deinit();
        allocator.destroy(again_resp);
    }
    try assertErr(again_resp, err_object_not_found);

    // Invalid name.
    var bad = try makeRequest(allocator, "DeleteUser");
    defer bad.deinit();
    try bad.addStr("HubName", "VPN");
    try bad.addStr("Name", "administrator");
    var bad_resp = try call(allocator, &server, true, "", "DeleteUser", &bad);
    defer {
        bad_resp.deinit();
        allocator.destroy(bad_resp);
    }
    try assertErr(bad_resp, err_invalid_parameter);
}
test "server.admin_dispatch EnumMacTable lists entries for the requested hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    const mac = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    _ = try hub.addMacTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-BOB"),
        .mac_address = mac,
        .vlan_id = 7,
        .created_time = 100,
        .updated_time = 200,
    });
    _ = try hub.addMacTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-ALICE"),
        .mac_address = .{ 1, 2, 3, 4, 5, 6 },
        .created_time = 300,
        .updated_time = 400,
    });
    _ = try findHub(&server, "TEST").?.addMacTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-CAROL"),
        .created_time = 500,
        .updated_time = 600,
    });

    var req = try makeRequest(allocator, "EnumMacTable");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    var resp = try call(allocator, &server, true, "", "EnumMacTable", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
    try testing.expectEqual(@as(usize, 2), resp.getValueCount("SessionName"));
    try testing.expectEqualStrings("SID-BOB", resp.getStrEx("SessionName", 0).?);
    try testing.expectEqualSlices(u8, &mac, resp.getDataEx("MacAddress", 0).?[0..6]);
    try testing.expectEqual(@as(u32, 7), resp.getIntEx("VlanId", 0).?);
    try testing.expectEqual(@as(u64, 100), resp.getInt64Ex("CreatedTime", 0).?);
    try testing.expectEqualStrings("SID-ALICE", resp.getStrEx("SessionName", 1).?);

    // Unknown hub.
    var nohub = try makeRequest(allocator, "EnumMacTable");
    defer nohub.deinit();
    try nohub.addStr("HubName", "NOPE");
    var nohub_resp = try call(allocator, &server, true, "", "EnumMacTable", &nohub);
    defer {
        nohub_resp.deinit();
        allocator.destroy(nohub_resp);
    }
    try assertErr(nohub_resp, err_hub_not_found);

    // Hub admin of another hub is denied.
    var other = try makeRequest(allocator, "EnumMacTable");
    defer other.deinit();
    try other.addStr("HubName", "TEST");
    var other_resp = try call(allocator, &server, false, "VPN", "EnumMacTable", &other);
    defer {
        other_resp.deinit();
        allocator.destroy(other_resp);
    }
    try assertErr(other_resp, err_not_enough_right);
}

test "server.admin_dispatch EnumIpTable lists entries for the requested hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    _ = try hub.addIpTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-BOB"),
        .ip = types_mod.IpAddress.fromU32(0x0A000001),
        .dhcp_allocated = true,
        .created_time = 100,
        .updated_time = 200,
    });

    var req = try makeRequest(allocator, "EnumIpTable");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    var resp = try call(allocator, &server, true, "", "EnumIpTable", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqual(@as(usize, 1), resp.getValueCount("SessionName"));
    try testing.expectEqualStrings("SID-BOB", resp.getStrEx("SessionName", 0).?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getIntEx("Ip", 0).?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getIntEx("IpAddress", 0).?);
    try testing.expect(resp.getBoolEx("DhcpAllocated", 0).?);
    try testing.expectEqual(@as(u64, 100), resp.getInt64Ex("CreatedTime", 0).?);
}

test "server.admin_dispatch DeleteMacTable and DeleteIpTable remove by key" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    const mac_key = try hub.addMacTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-BOB"),
        .created_time = 100,
        .updated_time = 100,
    });
    const ip_key = try hub.addIpTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-BOB"),
        .ip = types_mod.IpAddress.fromU32(0x0A000001),
        .created_time = 100,
        .updated_time = 100,
    });
    try testing.expectEqual(@as(u32, 2), hub.num_mac_tables + hub.num_ip_tables);

    // Remove the MAC entry.
    var mac_del = try makeRequest(allocator, "DeleteMacTable");
    defer mac_del.deinit();
    try mac_del.addStr("HubName", "VPN");
    try mac_del.addInt("Key", mac_key);
    var mac_resp = try call(allocator, &server, true, "", "DeleteMacTable", &mac_del);
    defer {
        mac_resp.deinit();
        allocator.destroy(mac_resp);
    }
    try assertOk(mac_resp);
    try testing.expect(hub.findMacTableEntry(mac_key) == null);
    try testing.expectEqual(@as(u32, 0), hub.num_mac_tables);

    // Missing entry reports ERR_OBJECT_NOT_FOUND.
    var again = try makeRequest(allocator, "DeleteMacTable");
    defer again.deinit();
    try again.addStr("HubName", "VPN");
    try again.addInt("Key", mac_key);
    var again_resp = try call(allocator, &server, true, "", "DeleteMacTable", &again);
    defer {
        again_resp.deinit();
        allocator.destroy(again_resp);
    }
    try assertErr(again_resp, err_object_not_found);

    // Remove the IP entry.
    var ip_del = try makeRequest(allocator, "DeleteIpTable");
    defer ip_del.deinit();
    try ip_del.addStr("HubName", "VPN");
    try ip_del.addInt("Key", ip_key);
    var ip_resp = try call(allocator, &server, true, "", "DeleteIpTable", &ip_del);
    defer {
        ip_resp.deinit();
        allocator.destroy(ip_resp);
    }
    try assertOk(ip_resp);
    try testing.expect(hub.findIpTableEntry(ip_key) == null);
    try testing.expectEqual(@as(u32, 0), hub.num_ip_tables);

    // Unknown hub.
    var nohub = try makeRequest(allocator, "DeleteMacTable");
    defer nohub.deinit();
    try nohub.addStr("HubName", "NOPE");
    try nohub.addInt("Key", mac_key);
    var nohub_resp = try call(allocator, &server, true, "", "DeleteMacTable", &nohub);
    defer {
        nohub_resp.deinit();
        allocator.destroy(nohub_resp);
    }
    try assertErr(nohub_resp, err_hub_not_found);
}

test "server.admin_dispatch table deletes honor hub options for hub admins" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    hub.no_delete_mactable = true;
    hub.no_delete_iptable = true;
    const mac_key = try hub.addMacTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-BOB"),
        .created_time = 100,
        .updated_time = 100,
    });
    const ip_key = try hub.addIpTableEntry(allocator, .{
        .session_name = try allocator.dupe(u8, "SID-BOB"),
        .ip = types_mod.IpAddress.fromU32(0x0A000001),
        .created_time = 100,
        .updated_time = 100,
    });

    // Hub admin is blocked by the option.
    var mac_del = try makeRequest(allocator, "DeleteMacTable");
    defer mac_del.deinit();
    try mac_del.addStr("HubName", "VPN");
    try mac_del.addInt("Key", mac_key);
    var mac_resp = try call(allocator, &server, false, "VPN", "DeleteMacTable", &mac_del);
    defer {
        mac_resp.deinit();
        allocator.destroy(mac_resp);
    }
    try assertErr(mac_resp, err_not_enough_right);

    var ip_del = try makeRequest(allocator, "DeleteIpTable");
    defer ip_del.deinit();
    try ip_del.addStr("HubName", "VPN");
    try ip_del.addInt("Key", ip_key);
    var ip_resp = try call(allocator, &server, false, "VPN", "DeleteIpTable", &ip_del);
    defer {
        ip_resp.deinit();
        allocator.destroy(ip_resp);
    }
    try assertErr(ip_resp, err_not_enough_right);

    // Server admin bypasses the option (C returns early on `a->ServerAdmin`).
    var adm = try makeRequest(allocator, "DeleteMacTable");
    defer adm.deinit();
    try adm.addStr("HubName", "VPN");
    try adm.addInt("Key", mac_key);
    var adm_resp = try call(allocator, &server, true, "", "DeleteMacTable", &adm);
    defer {
        adm_resp.deinit();
        allocator.destroy(adm_resp);
    }
    try assertOk(adm_resp);
    try testing.expect(hub.findMacTableEntry(mac_key) == null);
}

/// Stands in for `SessionMain` in admin tests: `requestStop` flips `halt`, and
/// the padding makes the store land in the fake's `halt` (same layout trick as
/// the session_registry tests).
const FakeMain = struct {
    _pad: [@offsetOf(session_main.SessionMain, "halt")]u8 = [_]u8{0} ** @offsetOf(session_main.SessionMain, "halt"),
    halt: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn wasStopped(self: *const FakeMain) bool {
        return self.halt.load(.acquire);
    }
};

/// Register a fake live session (mirrors `accept.zig`'s `runSession`
/// registration). `hub_name` is borrowed and must outlive the registry.
fn registerTestSession(
    allocator: Allocator,
    server: *Server,
    fake: *FakeMain,
    hub_name: []const u8,
    session_name: []const u8,
    connection_name: []const u8,
    username: []const u8,
) !void {
    const rec = try allocator.create(session_registry.SessionRecord);
    rec.* = .{
        .session_name = try allocator.dupe(u8, session_name),
        .connection_name = try allocator.dupe(u8, connection_name),
        .username = try allocator.dupe(u8, username),
        .hub_name = hub_name,
        .peer_ip = 0x0A000001,
        .peer_port = 40000,
        .created_time = 12345,
        .main = @ptrCast(@alignCast(fake)),
    };
    try server.sessions.register(rec);
}

test "server.admin_dispatch EnumSession lists only the requested hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");
    var carol: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &carol, "TEST", "SID-CAROL", "CONN-2", "Carol");
    var alice: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &alice, "VPN", "SID-ALICE", "CONN-3", "Alice");

    var req = try makeRequest(allocator, "EnumSession");
    defer req.deinit();
    try req.addStr("HubName", "VPN");

    var resp = try call(allocator, &server, true, "", "EnumSession", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
    try testing.expectEqual(@as(usize, 2), resp.getValueCount("Name"));
    try testing.expectEqualStrings("SID-BOB", resp.getStrEx("Name", 0).?);
    try testing.expectEqualStrings("Bob", resp.getStrEx("Username", 0).?);
    try testing.expectEqualStrings("SID-ALICE", resp.getStrEx("Name", 1).?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getIntEx("Ip", 0).?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getInt("ClientIP").?);
    try testing.expectEqual(@as(u64, 12345), resp.getInt64Ex("CreatedTime", 0).?);
}

test "server.admin_dispatch EnumSession is hub-scoped for non-server-admin" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    // A hub admin may enumerate its own hub...
    var own = try makeRequest(allocator, "EnumSession");
    defer own.deinit();
    try own.addStr("HubName", "VPN");
    var own_resp = try call(allocator, &server, false, "VPN", "EnumSession", &own);
    defer {
        own_resp.deinit();
        allocator.destroy(own_resp);
    }
    try assertOk(own_resp);

    // ...but not another hub (CHECK_RIGHT), and a missing hub still errors.
    var other = try makeRequest(allocator, "EnumSession");
    defer other.deinit();
    try other.addStr("HubName", "TEST");
    var other_resp = try call(allocator, &server, false, "VPN", "EnumSession", &other);
    defer {
        other_resp.deinit();
        allocator.destroy(other_resp);
    }
    try assertErr(other_resp, err_not_enough_right);

    var miss = try makeRequest(allocator, "EnumSession");
    defer miss.deinit();
    try miss.addStr("HubName", "NOPE");
    var miss_resp = try call(allocator, &server, true, "", "EnumSession", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_hub_not_found);
}

test "server.admin_dispatch GetSessionStatus returns a live session snapshot" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");

    var req = try makeRequest(allocator, "GetSessionStatus");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "SID-BOB");

    var resp = try call(allocator, &server, true, "", "GetSessionStatus", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
    try testing.expectEqualStrings("SID-BOB", resp.getStr("Name").?);
    try testing.expectEqualStrings("Bob", resp.getStr("Username").?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getInt("SessionStatus_ClientIp").?);
    try testing.expectEqualStrings("SID-BOB", resp.getStr("SessionName").?);
    try testing.expectEqualStrings("CONN-1", resp.getStr("ConnectionName").?);
    try testing.expectEqual(@as(u32, 1), resp.getInt("Active").?);
    try testing.expectEqual(@as(u32, 1), resp.getInt("Connected").?);
    try testing.expectEqual(@as(u32, connecting_connected), resp.getInt("SessionStatus").?);
    try testing.expectEqual(@as(u64, 12345), resp.getInt64("StartTime").?);
}

test "server.admin_dispatch GetSessionStatus validates name and membership" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");

    // Empty name is rejected before any rights/hub checks.
    var empty = try makeRequest(allocator, "GetSessionStatus");
    defer empty.deinit();
    try empty.addStr("HubName", "VPN");
    try empty.addStr("Name", "");
    var empty_resp = try call(allocator, &server, true, "", "GetSessionStatus", &empty);
    defer {
        empty_resp.deinit();
        allocator.destroy(empty_resp);
    }
    try assertErr(empty_resp, err_invalid_parameter);

    // Unknown session on an existing hub.
    var miss = try makeRequest(allocator, "GetSessionStatus");
    defer miss.deinit();
    try miss.addStr("HubName", "VPN");
    try miss.addStr("Name", "SID-NOPE");
    var miss_resp = try call(allocator, &server, true, "", "GetSessionStatus", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_object_not_found);

    // Missing hub.
    var nohub = try makeRequest(allocator, "GetSessionStatus");
    defer nohub.deinit();
    try nohub.addStr("HubName", "NOPE");
    try nohub.addStr("Name", "SID-BOB");
    var nohub_resp = try call(allocator, &server, true, "", "GetSessionStatus", &nohub);
    defer {
        nohub_resp.deinit();
        allocator.destroy(nohub_resp);
    }
    try assertErr(nohub_resp, err_hub_not_found);
}

test "server.admin_dispatch DeleteSession stops a session on its hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");
    var carol: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &carol, "TEST", "SID-CAROL", "CONN-2", "Carol");

    // The same session name on another hub is not stopped (C GetSessionByName).
    var wrong = try makeRequest(allocator, "DeleteSession");
    defer wrong.deinit();
    try wrong.addStr("HubName", "VPN");
    try wrong.addStr("Name", "SID-CAROL");
    var wrong_resp = try call(allocator, &server, true, "", "DeleteSession", &wrong);
    defer {
        wrong_resp.deinit();
        allocator.destroy(wrong_resp);
    }
    try assertErr(wrong_resp, err_object_not_found);
    try testing.expect(!carol.wasStopped());

    // Correct hub + name stops the session.
    var ok = try makeRequest(allocator, "DeleteSession");
    defer ok.deinit();
    try ok.addStr("HubName", "VPN");
    try ok.addStr("Name", "SID-BOB");
    var ok_resp = try call(allocator, &server, true, "", "DeleteSession", &ok);
    defer {
        ok_resp.deinit();
        allocator.destroy(ok_resp);
    }
    try assertOk(ok_resp);
    try testing.expect(bob.wasStopped());

    // A stopped session is mid-teardown: status reports it as disconnecting,
    // not fully connected, while the record is still registered.
    var status = try makeRequest(allocator, "GetSessionStatus");
    defer status.deinit();
    try status.addStr("HubName", "VPN");
    try status.addStr("Name", "SID-BOB");
    var status_resp = try call(allocator, &server, true, "", "GetSessionStatus", &status);
    defer {
        status_resp.deinit();
        allocator.destroy(status_resp);
    }
    try assertOk(status_resp);
    try testing.expectEqual(@as(u32, 0), status_resp.getInt("Active").?);
    try testing.expectEqual(@as(u32, 0), status_resp.getInt("Connected").?);
    try testing.expectEqual(@as(u32, connecting_disconnecting), status_resp.getInt("SessionStatus").?);

    // Empty name is checked before everything else.
    var empty = try makeRequest(allocator, "DeleteSession");
    defer empty.deinit();
    try empty.addStr("HubName", "VPN");
    try empty.addStr("Name", "");
    var empty_resp = try call(allocator, &server, true, "", "DeleteSession", &empty);
    defer {
        empty_resp.deinit();
        allocator.destroy(empty_resp);
    }
    try assertErr(empty_resp, err_invalid_parameter);

    // A stopped/missing session reports ERR_OBJECT_NOT_FOUND.
    var miss = try makeRequest(allocator, "DeleteSession");
    defer miss.deinit();
    try miss.addStr("HubName", "VPN");
    try miss.addStr("Name", "SID-NOPE");
    var miss_resp = try call(allocator, &server, true, "", "DeleteSession", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_object_not_found);
}

test "server.admin_dispatch EnumConnection lists connections for server admin" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");
    var alice: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &alice, "VPN", "SID-ALICE", "CONN-2", "Alice");

    var req = try makeRequest(allocator, "EnumConnection");
    defer req.deinit();

    var resp = try call(allocator, &server, true, "", "EnumConnection", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }

    try assertOk(resp);
    try testing.expectEqual(@as(usize, 2), resp.getValueCount("Name"));
    try testing.expectEqualStrings("CONN-1", resp.getStrEx("Name", 0).?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getIntEx("Ip", 0).?);
    try testing.expectEqual(@as(u32, 40000), resp.getIntEx("Port", 0).?);
    try testing.expectEqual(@as(u32, connection_type_client), resp.getIntEx("Type", 0).?);
    try testing.expectEqual(@as(u64, 12345), resp.getInt64Ex("ConnectedTime", 0).?);
}

test "server.admin_dispatch DisconnectConnection stops a connection" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");

    var ok = try makeRequest(allocator, "DisconnectConnection");
    defer ok.deinit();
    try ok.addStr("Name", "CONN-1");
    var ok_resp = try call(allocator, &server, true, "", "DisconnectConnection", &ok);
    defer {
        ok_resp.deinit();
        allocator.destroy(ok_resp);
    }
    try assertOk(ok_resp);
    try testing.expect(bob.wasStopped());

    // Unknown connection.
    var miss = try makeRequest(allocator, "DisconnectConnection");
    defer miss.deinit();
    try miss.addStr("Name", "CONN-9");
    var miss_resp = try call(allocator, &server, true, "", "DisconnectConnection", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_object_not_found);

    // Empty name, then SERVER_ADMIN_ONLY.
    var empty = try makeRequest(allocator, "DisconnectConnection");
    defer empty.deinit();
    try empty.addStr("Name", "");
    var empty_resp = try call(allocator, &server, true, "", "DisconnectConnection", &empty);
    defer {
        empty_resp.deinit();
        allocator.destroy(empty_resp);
    }
    try assertErr(empty_resp, err_invalid_parameter);

    var no_admin = try makeRequest(allocator, "DisconnectConnection");
    defer no_admin.deinit();
    try no_admin.addStr("Name", "CONN-1");
    var no_admin_resp = try call(allocator, &server, false, "VPN", "DisconnectConnection", &no_admin);
    defer {
        no_admin_resp.deinit();
        allocator.destroy(no_admin_resp);
    }
    try assertErr(no_admin_resp, err_not_enough_right);
}
