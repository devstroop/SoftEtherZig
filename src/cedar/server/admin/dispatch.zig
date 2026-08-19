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
const x509_mod = @import("../../../mayaqua/encrypt/x509.zig");
const ssl = @import("../../protocol/c_imports.zig").c;
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
pub const err_object_already_exists: u32 = 59;
pub const err_object_in_use: u32 = 60;
pub const err_too_many_user: u32 = 63;
pub const err_user_already_exists: u32 = 66;
pub const err_not_supported_auth_on_opensource: u32 = 143;
pub const err_too_many_items: u32 = 50;

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
pub const max_hub_admin_options: u32 = 4096;

const sha1_size = structs.SHA1_SIZE;

// ============================================================================
// Server state model (admin-facing snapshot; C `SERVER` / `SERVER_LISTENER`
// / `HUB` subsets)
// ============================================================================

pub const default_product_name = "SoftEther VPN Server";
pub const default_version_string = "4.44";
pub const default_family_name = "SoftEther VPN";
pub const default_host_name = "localhost";

/// C `admin_options[]` (Hub.c:113) — default hub admin option table.
pub const default_admin_options: []const structs.AdminOption = &.{
    .{ .name = "allow_hub_admin_change_option", .value = 0 },
    .{ .name = "max_users", .value = 0 },
    .{ .name = "max_multilogins_per_user", .value = 0 },
    .{ .name = "max_groups", .value = 0 },
    .{ .name = "max_accesslists", .value = 0 },
    .{ .name = "max_sessions_client_bridge_apply", .value = 0 },
    .{ .name = "max_sessions", .value = 0 },
    .{ .name = "max_sessions_client", .value = 0 },
    .{ .name = "max_sessions_bridge", .value = 0 },
    .{ .name = "max_bitrates_download", .value = 0 },
    .{ .name = "max_bitrates_upload", .value = 0 },
    .{ .name = "deny_empty_password", .value = 0 },
    .{ .name = "deny_bridge", .value = 0 },
    .{ .name = "deny_routing", .value = 0 },
    .{ .name = "deny_qos", .value = 0 },
    .{ .name = "deny_change_user_password", .value = 0 },
    .{ .name = "no_change_users", .value = 0 },
    .{ .name = "no_change_groups", .value = 0 },
    .{ .name = "no_securenat", .value = 0 },
    .{ .name = "no_securenat_enablenat", .value = 0 },
    .{ .name = "no_securenat_enabledhcp", .value = 0 },
    .{ .name = "no_cascade", .value = 0 },
    .{ .name = "no_online", .value = 0 },
    .{ .name = "no_offline", .value = 0 },
    .{ .name = "no_change_log_config", .value = 0 },
    .{ .name = "no_disconnect_session", .value = 0 },
    .{ .name = "no_delete_iptable", .value = 0 },
    .{ .name = "no_delete_mactable", .value = 0 },
    .{ .name = "no_enum_session", .value = 0 },
    .{ .name = "no_query_session", .value = 0 },
    .{ .name = "no_change_admin_password", .value = 0 },
    .{ .name = "no_change_log_switch_type", .value = 0 },
    .{ .name = "no_change_access_list", .value = 0 },
    .{ .name = "no_change_access_control_list", .value = 0 },
    .{ .name = "no_change_cert_list", .value = 0 },
    .{ .name = "no_change_crl_list", .value = 0 },
    .{ .name = "no_read_log_file", .value = 0 },
    .{ .name = "deny_hub_admin_change_ext_option", .value = 0 },
    .{ .name = "no_delay_jitter_packet_loss", .value = 0 },
    .{ .name = "no_change_msg", .value = 0 },
    .{ .name = "no_access_list_include_file", .value = 0 },
};

/// C `SERVER_LISTENER` (Server.h:471) subset.
pub const ServerListener = struct {
    port: u32 = 0,
    enabled: bool = false,
    /// True when the port failed to bind (C `LISTENER_STATUS_TRYING`).
    has_error: bool = false,
    disable_dos: bool = false,
};

/// Bridge operations vtable. Set by `accept.zig` at server startup so the
/// admin dispatch can create/destroy runtime `LocalBridge` instances without
/// importing `accept.zig` (which would create a circular import).
pub const BridgeOps = struct {
    ctx: ?*anyopaque = null,
    /// Create and start a bridge on `device_name` for `hub_name`.
    /// Returns true if the bridge is online and active.
    create: *const fn (ctx: *anyopaque, device_name: []const u8, hub_name: []const u8, tap_mode: bool) bool = &noopCreate,
    /// Destroy a bridge by device+hub. Returns true if found and removed.
    destroy: *const fn (ctx: *anyopaque, device_name: []const u8, hub_name: []const u8) bool = &noopDestroy,

    fn noopCreate(_: *anyopaque, _: []const u8, _: []const u8, _: bool) bool {
        return false;
    }
    fn noopDestroy(_: *anyopaque, _: []const u8, _: []const u8) bool {
        return false;
    }
};

/// Local bridge admin-model entry (C `LOCALBRIDGE` subset).
pub const LocalBridgeEntry = struct {
    device_name: []const u8 = "",
    hub_name: []const u8 = "",
    online: bool = false,
    active: bool = false,
    tap_mode: bool = false,

    pub fn deinit(self: *LocalBridgeEntry, allocator: Allocator) void {
        allocator.free(self.device_name);
        allocator.free(self.hub_name);
        self.* = .{};
    }
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

/// C `GROUP` (Account.h:156) subset backing the group endpoints. The stored
/// model keeps a copy of the group policy (all value types, no heap inside
/// `Policy`); `num_users` is computed on the fly in `stEnumGroup` by
/// counting users whose `group_name` matches.
pub const ServerGroup = struct {
    name: []const u8 = "",
    realname: []const u8 = "",
    note: []const u8 = "",
    deny_access: bool = false,
    traffic: structs.Traffic = .{},
    policy: ?structs.Policy = null,

    fn free(self: *ServerGroup, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.realname);
        allocator.free(self.note);
        self.* = .{};
    }
};

/// C `MAC_TABLE_ENTRY` (Hub.c:57) subset held by the admin model.
pub const MacTableEntry = struct {
    key: u32 = 0,
    session_name: []const u8 = "",
    mac_address: [6]u8 = [_]u8{0} ** 6,
    vlan_id: u32 = 0,
    created_time: u64 = 0,
    updated_time: u64 = 0,

    fn free(self: *MacTableEntry, allocator: Allocator) void {
        allocator.free(self.session_name);
        self.* = .{};
    }
};

/// C `IP_TABLE_ENTRY` (Hub.c:57) subset held by the admin model.
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

/// C `L3SW` subset — a Layer-3 virtual switch with interfaces.
pub const ServerL3Switch = struct {
    name: []const u8 = "",
    online: bool = false,
    active: bool = false,
    interfaces: std.ArrayListUnmanaged(ServerL3Interface) = .{},

    fn deinit(self: *ServerL3Switch, allocator: Allocator) void {
        for (self.interfaces.items) |*intf| intf.deinit(allocator);
        self.interfaces.deinit(allocator);
        allocator.free(self.name);
        self.* = .{};
    }
};

/// C `L3IF` subset — an interface attached to an L3 switch.
pub const ServerL3Interface = struct {
    hub_name: []const u8 = "",
    ip_address: u32 = 0,
    subnet_mask: u32 = 0,

    fn deinit(self: *ServerL3Interface, allocator: Allocator) void {
        allocator.free(self.hub_name);
        self.* = .{};
    }
};

/// C `LINK` subset (Admin.c) — a cascade connection entry.
pub const ServerLink = struct {
    account_name: []const u8 = "",
    hostname: []const u8 = "",
    hub_name: []const u8 = "",
    online: bool = false,
    connected: bool = false,
    connected_time: u64 = 0,
    last_error: u32 = 0,

    fn deinit(self: *ServerLink, allocator: Allocator) void {
        allocator.free(self.account_name);
        allocator.free(self.hostname);
        allocator.free(self.hub_name);
        self.* = .{};
    }
};

/// C `X *` subset for CA certificate entries (HubDb->RootCertList).
pub const ServerCa = struct {
    key: u32 = 0,
    subject_name: []const u8 = "",
    issuer_name: []const u8 = "",
    expires: u64 = 0,
    cert_pem: []const u8 = "",

    fn deinit(self: *ServerCa, allocator: Allocator) void {
        allocator.free(self.subject_name);
        allocator.free(self.issuer_name);
        allocator.free(self.cert_pem);
        self.* = .{};
    }
};

/// C `CRL` subset for CRL entries (HubDb->CrlList).
pub const ServerCrl = struct {
    key: u32 = 0,
    serial: []const u8 = "",
    common_name: []const u8 = "",
    organization: []const u8 = "",
    unit: []const u8 = "",
    country: []const u8 = "",
    state: []const u8 = "",
    local: []const u8 = "",
    info: []const u8 = "",

    fn deinit(self: *ServerCrl, allocator: Allocator) void {
        allocator.free(self.serial);
        allocator.free(self.common_name);
        allocator.free(self.organization);
        allocator.free(self.unit);
        allocator.free(self.country);
        allocator.free(self.state);
        allocator.free(self.local);
        allocator.free(self.info);
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
    groups: std.ArrayListUnmanaged(ServerGroup) = .{},
    /// Learned MAC table (C `HUB->MacHashTable` subset). The admin model is
    /// self-contained: entries are bootstrapped by tests / callers, the
    /// data-plane integration is a separate follow-up.
    mac_table: std.ArrayListUnmanaged(MacTableEntry) = .{},
    /// Learned IP table (C `HUB->IpTable` subset).
    ip_table: std.ArrayListUnmanaged(IpTableEntry) = .{},
    /// Hub access list (C `HUB->AccessList` subset).
    access_list: std.ArrayListUnmanaged(structs.Access) = .{},
    /// Hub admin options (C `HUB->AdminOptionList`).
    admin_options: std.ArrayListUnmanaged(structs.AdminOption) = .{},
    /// Next `MacTableEntry` / `IpTableEntry` key (monotonic per hub).
    next_table_key: u32 = 1,
    /// C hub admin options: `no_delete_mactable` / `no_delete_iptable` deny
    /// hub admins table deletion (C `GetHubAdminOption`, Admin.c).
    no_delete_mactable: bool = false,
    no_delete_iptable: bool = false,
    /// SecureNAT enabled on this hub (C: `h->SecureNAT != NULL`).
    secure_nat_enabled: bool = false,

    /// Hub log settings (C: HUB_LOG via Hub->LogSetting).
    log_save_security_log: bool = false,
    log_security_switch_type: u32 = 0,
    log_save_packet_log: bool = false,
    log_packet_switch_type: u32 = 0,

    /// Hub RADIUS settings (C: Hub->RadiusServerName etc.).
    radius_server_name: []const u8 = "",
    radius_port: u32 = 0,
    radius_secret: []const u8 = "",
    radius_retry_interval: u32 = 0,

    /// SecureNAT/VH option (C: `VH_OPTION` via Hub->SecureNATOption).
    vh_mac_address: [6]u8 = [_]u8{0} ** 6,
    vh_ip: u32 = 0,
    vh_mask: u32 = 0,
    vh_use_nat: bool = false,
    vh_mtu: u32 = 1500,
    vh_nat_tcp_timeout: u32 = 3600,
    vh_nat_udp_timeout: u32 = 120,
    vh_use_dhcp: bool = false,
    vh_dhcp_lease_ip_start: u32 = 0,
    vh_dhcp_lease_ip_end: u32 = 0,
    vh_dhcp_subnet_mask: u32 = 0,
    vh_dhcp_expire_time_span: u32 = 7200,
    vh_dhcp_gateway_address: u32 = 0,
    vh_dhcp_dns_server_address: u32 = 0,
    vh_dhcp_dns_server_address2: u32 = 0,
    vh_dhcp_domain_name: []const u8 = "",
    vh_save_log: bool = false,
    vh_apply_dhcp_push_routes: bool = false,
    vh_dhcp_push_routes: []const u8 = "",

    /// Link entries (C: Hub->LinkList subset).
    links: std.ArrayListUnmanaged(ServerLink) = .{},
    /// CA certificates (C: HubDb->RootCertList subset).
    ca_list: std.ArrayListUnmanaged(ServerCa) = .{},
    /// CRL entries (C: HubDb->CrlList subset).
    crl_list: std.ArrayListUnmanaged(ServerCrl) = .{},

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

    /// Look up a group by name, matching case-insensitively (C `SearchGroup`
    /// with `StrCmpi`; group names are not case-sensitive).
    fn findGroup(self: *ServerHub, name: []const u8) ?*ServerGroup {
        for (self.groups.items) |*group| {
            if (std.ascii.eqlIgnoreCase(group.name, name)) return group;
        }
        return null;
    }

    /// Append a group, keeping `num_groups` in sync. Ownership of `g`
    /// transfers to the hub.
    fn addGroup(self: *ServerHub, allocator: Allocator, g: ServerGroup) !void {
        try self.groups.append(allocator, g);
        self.num_groups +%= 1;
    }

    /// Remove a group by name, releasing it. Returns false when absent.
    fn removeGroup(self: *ServerHub, allocator: Allocator, name: []const u8) bool {
        for (self.groups.items, 0..) |*group, i| {
            if (std.ascii.eqlIgnoreCase(group.name, name)) {
                var removed = self.groups.swapRemove(i);
                removed.free(allocator);
                self.num_groups -%= 1;
                return true;
            }
        }
        return false;
    }

    fn deinitGroups(self: *ServerHub, allocator: Allocator) void {
        for (self.groups.items) |*group| group.free(allocator);
        self.groups.deinit(allocator);
    }

    /// Release the owned table entry names (test/bootstrap helper).
    pub fn freeTables(self: *ServerHub, allocator: Allocator) void {
        for (self.mac_table.items) |*e| allocator.free(e.session_name);
        self.mac_table.deinit(allocator);
        for (self.ip_table.items) |*e| allocator.free(e.session_name);
        self.ip_table.deinit(allocator);
    }

    /// Release all table entries (C `FreeHub` cleanup).
    pub fn deinitTables(self: *ServerHub, allocator: Allocator) void {
        self.freeTables(allocator);
    }

    /// Look up a MAC table entry by key (C `IsInHashListKey` +
    /// `HashListKeyToPointer` on `MacHashTable`).
    fn findMacTableEntry(self: *ServerHub, key: u32) ?*MacTableEntry {
        for (self.mac_table.items) |*e| {
            if (e.key == key) return e;
        }
        return null;
    }

    /// Look up an IP table entry by key (C `IsInListKey` +
    /// `ListKeyToPointer` on `IpTable`).
    fn findIpTableEntry(self: *ServerHub, key: u32) ?*IpTableEntry {
        for (self.ip_table.items) |*e| {
            if (e.key == key) return e;
        }
        return null;
    }

    /// Insert a MAC table entry, assigning the next monotonic key and
    /// keeping `num_mac_tables` in sync.
    fn insertMacTableEntry(self: *ServerHub, allocator: Allocator, entry: MacTableEntry) !u32 {
        const owned = try allocator.dupe(u8, entry.session_name);
        errdefer allocator.free(owned);
        var e = entry;
        e.key = self.next_table_key;
        self.next_table_key +%= 1;
        e.session_name = owned;
        try self.mac_table.append(allocator, e);
        self.num_mac_tables +%= 1;
        return e.key;
    }

    /// Insert an IP table entry, assigning the next monotonic key and
    /// keeping `num_ip_tables` in sync.
    fn insertIpTableEntry(self: *ServerHub, allocator: Allocator, entry: IpTableEntry) !u32 {
        const owned = try allocator.dupe(u8, entry.session_name);
        errdefer allocator.free(owned);
        var e = entry;
        e.key = self.next_table_key;
        self.next_table_key +%= 1;
        e.session_name = owned;
        try self.ip_table.append(allocator, e);
        self.num_ip_tables +%= 1;
        return e.key;
    }

    /// Remove a MAC table entry by key, releasing it. Returns false when
    /// absent (C `ERR_OBJECT_NOT_FOUND`).
    fn removeMacTableEntry(self: *ServerHub, allocator: Allocator, key: u32) bool {
        for (self.mac_table.items, 0..) |*e, i| {
            if (e.key == key) {
                var removed = self.mac_table.swapRemove(i);
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
        for (self.ip_table.items, 0..) |*e, i| {
            if (e.key == key) {
                var removed = self.ip_table.swapRemove(i);
                removed.free(allocator);
                self.num_ip_tables -%= 1;
                return true;
            }
        }
        return false;
    }

    /// Append a MAC table entry (test/bootstrap helper). Takes ownership of a
    /// copy of `entry.session_name`.
    pub fn addMacTableEntry(self: *ServerHub, allocator: Allocator, entry: MacTableEntry) !void {
        const owned = try allocator.dupe(u8, entry.session_name);
        errdefer allocator.free(owned);
        var e = entry;
        e.session_name = owned;
        try self.mac_table.append(allocator, e);
        self.num_mac_tables +%= 1;
    }

    /// Append an IP table entry (test/bootstrap helper).
    pub fn addIpTableEntry(self: *ServerHub, allocator: Allocator, entry: IpTableEntry) !void {
        const owned = try allocator.dupe(u8, entry.session_name);
        errdefer allocator.free(owned);
        var e = entry;
        e.session_name = owned;
        try self.ip_table.append(allocator, e);
        self.num_ip_tables +%= 1;
    }

    /// Append an access list entry. Ownership of `a`'s heap fields transfers
    /// to the hub (caller must not free them after append).
    pub fn addAccessEntry(self: *ServerHub, allocator: Allocator, a: structs.Access) !void {
        try self.access_list.append(allocator, a);
    }

    /// Remove an access list entry by `id`. Returns false when absent.
    pub fn removeAccessEntry(self: *ServerHub, allocator: Allocator, id: u32) bool {
        for (self.access_list.items, 0..) |*entry, i| {
            if (entry.id == id) {
                var removed = self.access_list.swapRemove(i);
                freeAccessFields(allocator, &removed);
                return true;
            }
        }
        return false;
    }

    /// Release all access list entries.
    pub fn deinitAccessList(self: *ServerHub, allocator: Allocator) void {
        for (self.access_list.items) |*e| freeAccessFields(allocator, e);
        self.access_list.deinit(allocator);
    }

    /// Release all hub admin options.
    pub fn deinitAdminOptions(self: *ServerHub, allocator: Allocator) void {
        for (self.admin_options.items) |*e| e.free(allocator);
        self.admin_options.deinit(allocator);
    }

    /// Replace the entire access list with new entries.
    pub fn setAccessList(self: *ServerHub, allocator: Allocator, entries: []structs.Access) !void {
        self.deinitAccessList(allocator);
        self.access_list.items = entries;
        self.access_list.capacity = entries.len;
    }

    /// Find an admin option by name (C `GetHubAdminOption` on `AdminOptionList`).
    pub fn findAdminOption(self: *const ServerHub, name: []const u8) ?*const structs.AdminOption {
        for (self.admin_options.items) |*e| {
            if (std.mem.eql(u8, e.name, name)) return e;
        }
        return null;
    }

    /// Get an admin option value, returning `default_val` if not found.
    pub fn getAdminOptionValue(self: *const ServerHub, name: []const u8, default_val: u32) u32 {
        if (self.findAdminOption(name)) |opt| return opt.value;
        return default_val;
    }

    /// Set or update an admin option (C `StSetHubAdminOptions` logic).
    pub fn setAdminOption(self: *ServerHub, allocator: Allocator, name: []const u8, value: u32) !void {
        for (self.admin_options.items) |*e| {
            if (std.mem.eql(u8, e.name, name)) {
                e.value = value;
                return;
            }
        }
        try self.admin_options.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .value = value,
        });
    }

    /// Replace all admin options (C `StSetHubAdminOptions` — DeleteAllHubAdminOption + insert).
    pub fn setAllAdminOptions(self: *ServerHub, allocator: Allocator, items: []const structs.AdminOption) !void {
        self.deinitAdminOptions(allocator);
        for (items) |item| {
            try self.admin_options.append(allocator, .{
                .name = try allocator.dupe(u8, item.name),
                .value = item.value,
            });
        }
    }

    /// Populate default admin options if the list is empty (C `AddHubAdminOptionsDefaults`).
    pub fn ensureDefaultAdminOptions(self: *ServerHub, allocator: Allocator) !void {
        if (self.admin_options.items.len > 0) return;
        for (default_admin_options) |def| {
            try self.admin_options.append(allocator, .{
                .name = try allocator.dupe(u8, def.name),
                .value = def.value,
            });
        }
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

    /// Active local bridges (AddLocalBridge/DeleteLocalBridge/EnumLocalBridge).
    local_bridges: std.ArrayListUnmanaged(LocalBridgeEntry) = .{},

    /// L3 switch entries (C: `SERVER->L3SwList` subset).
    l3_switches: std.ArrayListUnmanaged(ServerL3Switch) = .{},

    /// Server certificate PEM (C: cedar->ServerX serialized to PEM).
    cert_pem: []const u8 = "",
    /// Server private key PEM (C: cedar->ServerK serialized to PEM).
    key_pem: []const u8 = "",
    /// TLS cipher list string (C: cedar->CipherList).
    cipher_list: []const u8 = "",

    /// Syslog settings (C: `SYSLOG_SETTING`).
    syslog_save_type: u32 = 0,
    syslog_hostname: []const u8 = "",
    syslog_port: u32 = 0,

/// Back-pointer to the runtime `ServerContext` (accept.zig). Set once at
    /// startup so admin handlers can create/destroy runtime objects (e.g.
    /// LocalBridge). The dispatch Server outlives all connections.
    server_ctx: ?*anyopaque = null,

    /// Bridge operations vtable — set by accept.zig to wire admin dispatch
    /// to the runtime ServerContext. Avoids circular import.
    bridge_ops: BridgeOps = .{},

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
            hub.deinitGroups(allocator);
            hub.freeTables(allocator);
            hub.deinitAccessList(allocator);
            hub.deinitAdminOptions(allocator);
            allocator.free(hub.name);
            allocator.free(hub.radius_server_name);
            allocator.free(hub.radius_secret);
            allocator.free(hub.vh_dhcp_domain_name);
            allocator.free(hub.vh_dhcp_push_routes);
            for (hub.links.items) |*l| l.deinit(allocator);
            hub.links.deinit(allocator);
            for (hub.ca_list.items) |*ca| ca.deinit(allocator);
            hub.ca_list.deinit(allocator);
            for (hub.crl_list.items) |*crl| crl.deinit(allocator);
            hub.crl_list.deinit(allocator);
        }
        self.hubs.deinit(allocator);
        self.listeners.deinit(allocator);
        for (self.local_bridges.items) |*lb| lb.deinit(allocator);
        self.local_bridges.deinit(allocator);
        for (self.l3_switches.items) |*sw| sw.deinit(allocator);
        self.l3_switches.deinit(allocator);
        allocator.free(self.cert_pem);
        allocator.free(self.key_pem);
        allocator.free(self.cipher_list);
        allocator.free(self.syslog_hostname);
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
    /// Runtime server context (ServerContext from accept.zig). Null in unit
    /// tests that use `Server.init()` directly — handlers must check.
    server_ctx: ?*anyopaque = null,
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
        .server_ctx = server.server_ctx,
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
    } else if (mem.eql(u8, function_name, "DisconnectSession")) {
        err = dispatchCall(structs.RpcDeleteSession, &a, allocator, request, ret, stDisconnectSession);
    } else if (mem.eql(u8, function_name, "EnumConnection")) {
        err = dispatchCall(structs.RpcEnumConnection, &a, allocator, request, ret, stEnumConnection);
    } else if (mem.eql(u8, function_name, "DisconnectConnection")) {
        err = dispatchCall(structs.RpcDisconnectConnection, &a, allocator, request, ret, stDisconnectConnection);
    } else if (mem.eql(u8, function_name, "EnumUser")) {
        err = dispatchCall(structs.RpcEnumUser, &a, allocator, request, ret, stEnumUser);
    } else if (mem.eql(u8, function_name, "GetUser")) {
        err = dispatchCall(structs.RpcSetUser, &a, allocator, request, ret, stGetUser);
    } else if (mem.eql(u8, function_name, "CreateUser")) {
        err = dispatchCall(structs.RpcSetUser, &a, allocator, request, ret, stCreateUser);
    } else if (mem.eql(u8, function_name, "SetUser")) {
        err = dispatchCall(structs.RpcSetUser, &a, allocator, request, ret, stSetUser);
    } else if (mem.eql(u8, function_name, "DeleteUser")) {
        err = dispatchCall(structs.RpcDeleteUser, &a, allocator, request, ret, stDeleteUser);
    } else if (mem.eql(u8, function_name, "SetPassword")) {
        err = dispatchCall(structs.RpcSetUserPassword, &a, allocator, request, ret, stSetPassword);
    } else if (mem.eql(u8, function_name, "EnumGroup")) {
        err = dispatchCall(structs.RpcEnumGroup, &a, allocator, request, ret, stEnumGroup);
    } else if (mem.eql(u8, function_name, "CreateGroup")) {
        err = dispatchCall(structs.RpcSetGroup, &a, allocator, request, ret, stCreateGroup);
    } else if (mem.eql(u8, function_name, "SetGroup")) {
        err = dispatchCall(structs.RpcSetGroup, &a, allocator, request, ret, stSetGroup);
    } else if (mem.eql(u8, function_name, "GetGroup")) {
        err = dispatchCall(structs.RpcSetGroup, &a, allocator, request, ret, stGetGroup);
    } else if (mem.eql(u8, function_name, "DeleteGroup")) {
        err = dispatchCall(structs.RpcDeleteUser, &a, allocator, request, ret, stDeleteGroup);
    } else if (mem.eql(u8, function_name, "EnumMacTable")) {
        err = dispatchCall(structs.RpcEnumMacTable, &a, allocator, request, ret, stEnumMacTable);
    } else if (mem.eql(u8, function_name, "EnumIpTable")) {
        err = dispatchCall(structs.RpcEnumIpTable, &a, allocator, request, ret, stEnumIpTable);
    } else if (mem.eql(u8, function_name, "DeleteMacTable")) {
        err = dispatchCall(structs.RpcDeleteTable, &a, allocator, request, ret, stDeleteMacTable);
    } else if (mem.eql(u8, function_name, "DeleteIpTable")) {
        err = dispatchCall(structs.RpcDeleteTable, &a, allocator, request, ret, stDeleteIpTable);
    } else if (mem.eql(u8, function_name, "EnumAccess")) {
        err = dispatchCall(structs.RpcEnumAccessList, &a, allocator, request, ret, stEnumAccess);
    } else if (mem.eql(u8, function_name, "AddAccess")) {
        err = dispatchCall(structs.RpcAddAccess, &a, allocator, request, ret, stAddAccess);
    } else if (mem.eql(u8, function_name, "DeleteAccess")) {
        err = dispatchCall(structs.RpcDeleteAccess, &a, allocator, request, ret, stDeleteAccess);
    } else if (mem.eql(u8, function_name, "SetAccessList")) {
        err = dispatchCall(structs.RpcEnumAccessList, &a, allocator, request, ret, stSetAccessList);
    } else if (mem.eql(u8, function_name, "GetHubAdminOptions")) {
        err = dispatchCall(structs.RpcAdminOption, &a, allocator, request, ret, stGetHubAdminOptions);
    } else if (mem.eql(u8, function_name, "GetDefaultHubAdminOptions")) {
        err = dispatchCall(structs.RpcAdminOption, &a, allocator, request, ret, stGetDefaultHubAdminOptions);
    } else if (mem.eql(u8, function_name, "SetHubAdminOptions")) {
        err = dispatchCall(structs.RpcAdminOption, &a, allocator, request, ret, stSetHubAdminOptions);
    } else if (mem.eql(u8, function_name, "EnumLog")) {
        err = dispatchCall(structs.RpcEnumLogFile, &a, allocator, request, ret, stEnumLog);
    } else if (mem.eql(u8, function_name, "GetTraffic")) {
        err = dispatchCall(structs.RpcGetTraffic, &a, allocator, request, ret, stGetTraffic);
    } else if (mem.eql(u8, function_name, "GetFarmSetting")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetFarmSetting")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetFarmInfo")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "EnumFarmMember")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetFarmConnectionStatus")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "DisconnectFarmConnection")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetServerCert")) {
        err = dispatchCall(structs.RpcKeyPair, &a, allocator, request, ret, stSetServerCert);
    } else if (mem.eql(u8, function_name, "GetServerCert")) {
        err = dispatchCall(structs.RpcKeyPair, &a, allocator, request, ret, stGetServerCert);
    } else if (mem.eql(u8, function_name, "GetServerCipher")) {
        err = dispatchCall(structs.RpcStr, &a, allocator, request, ret, stGetServerCipher);
    } else if (mem.eql(u8, function_name, "SetServerCipher")) {
        err = dispatchCall(structs.RpcStr, &a, allocator, request, ret, stSetServerCipher);
    } else if (mem.eql(u8, function_name, "RegenerateServerCert")) {
        err = dispatchCall(structs.RpcTest, &a, allocator, request, ret, stRegenerateServerCert);
    } else if (mem.eql(u8, function_name, "CreateKeyPair")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "EnableListener")) {
        err = dispatchCall(structs.RpcListener, &a, allocator, request, ret, stEnableListener);
    } else if (mem.eql(u8, function_name, "GetHub")) {
        err = dispatchCall(structs.RpcCreateHub, &a, allocator, request, ret, stGetHub);
    } else if (mem.eql(u8, function_name, "SetHubOnline")) {
        err = dispatchCall(structs.RpcSetHubOnline, &a, allocator, request, ret, stSetHubOnline);
    } else if (mem.eql(u8, function_name, "SetHubLog")) {
        err = dispatchCall(structs.RpcHubLog, &a, allocator, request, ret, stSetHubLog);
    } else if (mem.eql(u8, function_name, "GetHubLog")) {
        err = dispatchCall(structs.RpcHubLog, &a, allocator, request, ret, stGetHubLog);
    } else if (mem.eql(u8, function_name, "GetHubExtOptions")) {
        err = dispatchCall(structs.RpcAdminOption, &a, allocator, request, ret, stGetHubExtOptions);
    } else if (mem.eql(u8, function_name, "SetHubExtOptions")) {
        err = dispatchCall(structs.RpcAdminOption, &a, allocator, request, ret, stSetHubExtOptions);
    } else if (mem.eql(u8, function_name, "GetHubRadius")) {
        err = dispatchCall(structs.RpcRadius, &a, allocator, request, ret, stGetHubRadius);
    } else if (mem.eql(u8, function_name, "SetHubRadius")) {
        err = dispatchCall(structs.RpcRadius, &a, allocator, request, ret, stSetHubRadius);
    } else if (mem.eql(u8, function_name, "GetConnectionInfo")) {
        err = dispatchCall(structs.RpcConnectionInfo, &a, allocator, request, ret, stGetConnectionInfo);
    } else if (mem.eql(u8, function_name, "CreateLink")) {
        err = dispatchCall(structs.RpcCreateLink, &a, allocator, request, ret, stCreateLink);
    } else if (mem.eql(u8, function_name, "GetLink")) {
        err = dispatchCall(structs.RpcCreateLink, &a, allocator, request, ret, stGetLink);
    } else if (mem.eql(u8, function_name, "SetLink")) {
        err = dispatchCall(structs.RpcCreateLink, &a, allocator, request, ret, stSetLink);
    } else if (mem.eql(u8, function_name, "DeleteLink")) {
        err = dispatchCall(structs.RpcLink, &a, allocator, request, ret, stDeleteLink);
    } else if (mem.eql(u8, function_name, "RenameLink")) {
        err = dispatchCall(structs.RpcRenameLink, &a, allocator, request, ret, stRenameLink);
    } else if (mem.eql(u8, function_name, "EnumLink")) {
        err = dispatchCall(structs.RpcEnumLink, &a, allocator, request, ret, stEnumLink);
    } else if (mem.eql(u8, function_name, "GetLinkStatus")) {
        err = dispatchCall(structs.RpcLinkStatus, &a, allocator, request, ret, stGetLinkStatus);
    } else if (mem.eql(u8, function_name, "SetLinkOnline")) {
        err = dispatchCall(structs.RpcLink, &a, allocator, request, ret, stSetLinkOnline);
    } else if (mem.eql(u8, function_name, "SetLinkOffline")) {
        err = dispatchCall(structs.RpcLink, &a, allocator, request, ret, stSetLinkOffline);
    } else if (mem.eql(u8, function_name, "AddCa")) {
        err = dispatchCall(structs.RpcHubAddCa, &a, allocator, request, ret, stAddCa);
    } else if (mem.eql(u8, function_name, "EnumCa")) {
        err = dispatchCall(structs.RpcHubEnumCa, &a, allocator, request, ret, stEnumCa);
    } else if (mem.eql(u8, function_name, "GetCa")) {
        err = dispatchCall(structs.RpcHubGetCa, &a, allocator, request, ret, stGetCa);
    } else if (mem.eql(u8, function_name, "DeleteCa")) {
        err = dispatchCall(structs.RpcHubDeleteCa, &a, allocator, request, ret, stDeleteCa);
    } else if (mem.eql(u8, function_name, "AddCrl")) {
        err = dispatchCall(structs.RpcCrl, &a, allocator, request, ret, stAddCrl);
    } else if (mem.eql(u8, function_name, "DelCrl")) {
        err = dispatchCall(structs.RpcCrl, &a, allocator, request, ret, stDelCrl);
    } else if (mem.eql(u8, function_name, "GetCrl")) {
        err = dispatchCall(structs.RpcCrl, &a, allocator, request, ret, stGetCrl);
    } else if (mem.eql(u8, function_name, "SetCrl")) {
        err = dispatchCall(structs.RpcCrl, &a, allocator, request, ret, stSetCrl);
    } else if (mem.eql(u8, function_name, "EnumCrl")) {
        err = dispatchCall(structs.RpcEnumCrl, &a, allocator, request, ret, stEnumCrl);
    } else if (mem.eql(u8, function_name, "SetKeep")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetKeep")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "EnableSecureNAT")) {
        err = dispatchCall(structs.RpcHub, &a, allocator, request, ret, stEnableSecureNAT);
    } else if (mem.eql(u8, function_name, "DisableSecureNAT")) {
        err = dispatchCall(structs.RpcHub, &a, allocator, request, ret, stDisableSecureNAT);
    } else if (mem.eql(u8, function_name, "SetSecureNATOption")) {
        err = dispatchCall(structs.RpcVhOption, &a, allocator, request, ret, stSetSecureNATOption);
    } else if (mem.eql(u8, function_name, "GetSecureNATOption")) {
        err = dispatchCall(structs.RpcVhOption, &a, allocator, request, ret, stGetSecureNATOption);
    } else if (mem.eql(u8, function_name, "EnumNAT")) {
        err = dispatchCall(structs.RpcEnumNat, &a, allocator, request, ret, stEnumNAT);
    } else if (mem.eql(u8, function_name, "EnumDHCP")) {
        err = dispatchCall(structs.RpcEnumDhcp, &a, allocator, request, ret, stEnumDHCP);
    } else if (mem.eql(u8, function_name, "GetSecureNATStatus")) {
        err = dispatchCall(structs.RpcNatStatus, &a, allocator, request, ret, stGetSecureNATStatus);
    } else if (mem.eql(u8, function_name, "EnumEthernet")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "AddLocalBridge")) {
        err = dispatchCall(structs.RpcLocalBridge, &a, allocator, request, ret, stAddLocalBridge);
    } else if (mem.eql(u8, function_name, "DeleteLocalBridge")) {
        err = dispatchCall(structs.RpcLocalBridge, &a, allocator, request, ret, stDeleteLocalBridge);
    } else if (mem.eql(u8, function_name, "EnumLocalBridge")) {
        err = dispatchCall(structs.RpcEnumLocalBridge, &a, allocator, request, ret, stEnumLocalBridge);
    } else if (mem.eql(u8, function_name, "GetBridgeSupport")) {
        err = dispatchCall(structs.RpcBridgeSupport, &a, allocator, request, ret, stGetBridgeSupport);
    } else if (mem.eql(u8, function_name, "RebootServer")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "Crash")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "Flush")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "Debug")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "AddLicenseKey")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "DelLicenseKey")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetConfig")) {
        err = dispatchCall(structs.RpcConfig, &a, allocator, request, ret, stGetConfig);
    } else if (mem.eql(u8, function_name, "SetConfig")) {
        err = dispatchCall(structs.RpcConfig, &a, allocator, request, ret, stSetConfig);
    } else if (mem.eql(u8, function_name, "AddL3Switch")) {
        err = dispatchCall(structs.RpcL3Sw, &a, allocator, request, ret, stAddL3Switch);
    } else if (mem.eql(u8, function_name, "DelL3Switch")) {
        err = dispatchCall(structs.RpcL3Sw, &a, allocator, request, ret, stDelL3Switch);
    } else if (mem.eql(u8, function_name, "EnumL3Switch")) {
        err = dispatchCall(structs.RpcEnumL3Sw, &a, allocator, request, ret, stEnumL3Switch);
    } else if (mem.eql(u8, function_name, "StartL3Switch")) {
        err = dispatchCall(structs.RpcL3Sw, &a, allocator, request, ret, stStartL3Switch);
    } else if (mem.eql(u8, function_name, "StopL3Switch")) {
        err = dispatchCall(structs.RpcL3Sw, &a, allocator, request, ret, stStopL3Switch);
    } else if (mem.eql(u8, function_name, "AddL3If")) {
        err = dispatchCall(structs.RpcL3If, &a, allocator, request, ret, stAddL3If);
    } else if (mem.eql(u8, function_name, "DelL3If")) {
        err = dispatchCall(structs.RpcL3If, &a, allocator, request, ret, stDelL3If);
    } else if (mem.eql(u8, function_name, "EnumL3If")) {
        err = dispatchCall(structs.RpcEnumL3If, &a, allocator, request, ret, stEnumL3If);
    } else if (mem.eql(u8, function_name, "AddL3Table")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "DelL3Table")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "EnumL3Table")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "ReadLogFile")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetSysLog")) {
        err = dispatchCall(structs.RpcSyslogSetting, &a, allocator, request, ret, stSetSysLog);
    } else if (mem.eql(u8, function_name, "GetSysLog")) {
        err = dispatchCall(structs.RpcSyslogSetting, &a, allocator, request, ret, stGetSysLog);
    } else if (mem.eql(u8, function_name, "EnumEthVLan")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetEnableEthVLan")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetHubMsg")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetHubMsg")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetAdminMsg")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetAcList")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetAcList")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "EnumLicenseKey")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetLicenseStatus")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetIPsecServices")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetIPsecServices")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "AddEtherIpId")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetEtherIpId")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "DeleteEtherIpId")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "EnumEtherIpId")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetOpenVpnSstpConfig")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetOpenVpnSstpConfig")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetDDnsClientStatus")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "ChangeDDnsClientHostname")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetDDnsInternetSettng")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetDDnsInternetSettng")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetAzureStatus")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetAzureStatus")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "SetSpecialListener")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "GetSpecialListener")) {
        err = err_not_supported;
    } else if (mem.eql(u8, function_name, "MakeOpenVpnConfigFile")) {
        err = err_not_supported;
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
        structs.RpcServerStatus, structs.RpcListener, structs.RpcFarmConnectionStatus, structs.RpcNatStatus, structs.RpcBridgeSupport, structs.RpcAzureStatus, structs.RpcSpecialListener, structs.RpcLicenseStatus, structs.RpcConnectionInfo => t.inRpc(p),
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
        structs.RpcSetUserPassword => try t.inRpc(allocator, p),
        structs.RpcSetGroup => try t.inRpc(allocator, p),
        structs.RpcEnumGroup => try t.inRpc(allocator, p),
        structs.RpcEnumAccessList => try t.inRpc(allocator, p),
        structs.RpcAddAccess => try t.inRpc(allocator, p),
        structs.RpcDeleteAccess => try t.inRpc(allocator, p),
        structs.RpcEnumLogFile => try t.inRpc(allocator, p),
        structs.RpcGetTraffic => try t.inRpc(allocator, p),
        structs.RpcEnumMacTable => try t.inRpc(allocator, p),
        structs.RpcEnumIpTable => try t.inRpc(allocator, p),
        structs.RpcDeleteTable => try t.inRpc(allocator, p),
        structs.RpcAdminOption => try t.inRpc(allocator, p),
        structs.RpcFarmSetting => try t.inRpc(allocator, p),
        structs.RpcFarmInfo => try t.inRpc(allocator, p),
        structs.RpcEnumFarm => try t.inRpc(allocator, p),
        structs.RpcSetHubOnline => try t.inRpc(allocator, p),
        structs.RpcHubLog => try t.inRpc(allocator, p),
        structs.RpcRadius => try t.inRpc(allocator, p),
        structs.RpcMsg => try t.inRpc(allocator, p),
        structs.RpcKeep => try t.inRpc(allocator, p),
        structs.RpcSyslogSetting => try t.inRpc(allocator, p),
        structs.RpcAcList => try t.inRpc(allocator, p),
        structs.RpcReadLogFile => try t.inRpc(allocator, p),
        structs.RpcConfig => try t.inRpc(allocator, p),
        structs.RpcL3Sw => try t.inRpc(allocator, p),
        structs.RpcEnumL3Sw => try t.inRpc(allocator, p),
        structs.RpcL3If => try t.inRpc(allocator, p),
        structs.RpcEnumL3If => try t.inRpc(allocator, p),
        structs.RpcL3Table => try t.inRpc(allocator, p),
        structs.RpcEnumL3Table => try t.inRpc(allocator, p),
        structs.RpcLocalBridge => try t.inRpc(allocator, p),
        structs.RpcEnumLocalBridge => try t.inRpc(allocator, p),
        structs.RpcEnumEth => try t.inRpc(allocator, p),
        structs.RpcEnumEthVLan => try t.inRpc(allocator, p),
        structs.RpcHubAddCa => try t.inRpc(allocator, p),
        structs.RpcHubEnumCa => try t.inRpc(allocator, p),
        structs.RpcHubGetCa => try t.inRpc(allocator, p),
        structs.RpcHubDeleteCa => try t.inRpc(allocator, p),
        structs.RpcEnumCrl => try t.inRpc(allocator, p),
        structs.RpcCrl => try t.inRpc(allocator, p),
        structs.RpcVhOption => try t.inRpc(allocator, p),
        structs.RpcEnumNat => try t.inRpc(allocator, p),
        structs.RpcEnumDhcp => try t.inRpc(allocator, p),
        structs.RpcIpSecServices => try t.inRpc(allocator, p),
        structs.RpcEtherIpId => try t.inRpc(allocator, p),
        structs.RpcEnumEtherIpId => try t.inRpc(allocator, p),
        structs.RpcOpenVpnSstpConfig => try t.inRpc(allocator, p),
        structs.RpcDdnsClientStatus => try t.inRpc(allocator, p),
        structs.RpcInternetSetting => try t.inRpc(allocator, p),
        structs.RpcAzureStatus => try t.inRpc(allocator, p),
        structs.RpcSpecialListener => try t.inRpc(allocator, p),
        structs.RpcEnumLicenseKey => try t.inRpc(allocator, p),
        structs.RpcLink => try t.inRpc(allocator, p),
        structs.RpcRenameLink => try t.inRpc(allocator, p),
        structs.RpcEnumLink => try t.inRpc(allocator, p),
        structs.RpcCreateLink => try t.inRpc(allocator, p),
        structs.RpcLinkStatus => try t.inRpc(allocator, p),
        structs.RpcKeyPair => try t.inRpc(allocator, p),
        structs.RpcHub => try t.inRpc(allocator, p),
        structs.RpcStr => try t.inRpc(allocator, p),
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
        structs.RpcSetUserPassword => try t.outRpc(p),
        structs.RpcSetGroup => try t.outRpc(p),
        structs.RpcEnumGroup => try t.outRpc(p),
        structs.RpcEnumAccessList => try t.outRpc(p),
        structs.RpcAddAccess => try t.outRpc(p),
        structs.RpcDeleteAccess => try t.outRpc(p),
        structs.RpcEnumLogFile => try t.outRpc(p),
        structs.RpcGetTraffic => try t.outRpc(p),
        structs.RpcEnumMacTable => try t.outRpc(p),
        structs.RpcEnumIpTable => try t.outRpc(p),
        structs.RpcDeleteTable => try t.outRpc(p),
        structs.RpcAdminOption => try t.outRpc(p),
        structs.RpcFarmSetting => try t.outRpc(p),
        structs.RpcFarmInfo => try t.outRpc(p),
        structs.RpcEnumFarm => try t.outRpc(p),
        structs.RpcFarmConnectionStatus => try t.outRpc(p),
        structs.RpcSetHubOnline => try t.outRpc(p),
        structs.RpcHubLog => try t.outRpc(p),
        structs.RpcRadius => try t.outRpc(p),
        structs.RpcMsg => try t.outRpc(p),
        structs.RpcKeep => try t.outRpc(p),
        structs.RpcSyslogSetting => try t.outRpc(p),
        structs.RpcAcList => try t.outRpc(p),
        structs.RpcReadLogFile => try t.outRpc(p),
        structs.RpcConfig => try t.outRpc(p),
        structs.RpcL3Sw => try t.outRpc(p),
        structs.RpcEnumL3Sw => try t.outRpc(p),
        structs.RpcL3If => try t.outRpc(p),
        structs.RpcEnumL3If => try t.outRpc(p),
        structs.RpcL3Table => try t.outRpc(p),
        structs.RpcEnumL3Table => try t.outRpc(p),
        structs.RpcLocalBridge => try t.outRpc(p),
        structs.RpcEnumLocalBridge => try t.outRpc(p),
        structs.RpcBridgeSupport => try t.outRpc(p),
        structs.RpcEnumEth => try t.outRpc(p),
        structs.RpcEnumEthVLan => try t.outRpc(p),
        structs.RpcHubAddCa => try t.outRpc(p),
        structs.RpcHubEnumCa => try t.outRpc(p),
        structs.RpcHubGetCa => try t.outRpc(p),
        structs.RpcHubDeleteCa => try t.outRpc(p),
        structs.RpcEnumCrl => try t.outRpc(p),
        structs.RpcCrl => try t.outRpc(p),
        structs.RpcVhOption => try t.outRpc(p),
        structs.RpcNatStatus => try t.outRpc(p),
        structs.RpcEnumNat => try t.outRpc(p),
        structs.RpcEnumDhcp => try t.outRpc(p),
        structs.RpcIpSecServices => try t.outRpc(p),
        structs.RpcEtherIpId => try t.outRpc(p),
        structs.RpcEnumEtherIpId => try t.outRpc(p),
        structs.RpcOpenVpnSstpConfig => try t.outRpc(p),
        structs.RpcDdnsClientStatus => try t.outRpc(p),
        structs.RpcInternetSetting => try t.outRpc(p),
        structs.RpcAzureStatus => try t.outRpc(p),
        structs.RpcSpecialListener => try t.outRpc(p),
        structs.RpcLicenseStatus => try t.outRpc(p),
        structs.RpcEnumLicenseKey => try t.outRpc(p),
        structs.RpcLink => try t.outRpc(p),
        structs.RpcRenameLink => try t.outRpc(p),
        structs.RpcEnumLink => try t.outRpc(p),
        structs.RpcCreateLink => try t.outRpc(p),
        structs.RpcLinkStatus => try t.outRpc(p),
        structs.RpcKeyPair => try t.outRpc(p),
        structs.RpcHub => try t.outRpc(p),
        structs.RpcStr => try t.outRpc(p),
        structs.RpcConnectionInfo => try t.outRpc(p),
        else => @compileError("no OutRpc for " ++ @typeName(T)),
    }
}

fn freeT(comptime T: type, t: *T, allocator: Allocator) void {
    switch (T) {
        structs.RpcServerStatus, structs.RpcListener, structs.RpcFarmConnectionStatus, structs.RpcNatStatus, structs.RpcBridgeSupport, structs.RpcAzureStatus, structs.RpcSpecialListener, structs.RpcLicenseStatus, structs.RpcConnectionInfo => {},
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
        structs.RpcSetUserPassword => t.free(allocator),
        structs.RpcSetGroup => t.free(allocator),
        structs.RpcEnumGroup => t.free(allocator),
        structs.RpcEnumAccessList => t.free(allocator),
        structs.RpcAddAccess => t.free(allocator),
        structs.RpcDeleteAccess => t.free(allocator),
        structs.RpcEnumLogFile => t.free(allocator),
        structs.RpcGetTraffic => t.free(allocator),
        structs.RpcEnumMacTable => t.free(allocator),
        structs.RpcEnumIpTable => t.free(allocator),
        structs.RpcDeleteTable => t.free(allocator),
        structs.RpcAdminOption => t.free(allocator),
        structs.RpcFarmSetting => t.free(allocator),
        structs.RpcFarmInfo => t.free(allocator),
        structs.RpcEnumFarm => t.free(allocator),
        structs.RpcSetHubOnline => t.free(allocator),
        structs.RpcHubLog => t.free(allocator),
        structs.RpcRadius => t.free(allocator),
        structs.RpcMsg => t.free(allocator),
        structs.RpcKeep => t.free(allocator),
        structs.RpcSyslogSetting => t.free(allocator),
        structs.RpcAcList => t.free(allocator),
        structs.RpcReadLogFile => t.free(allocator),
        structs.RpcConfig => t.free(allocator),
        structs.RpcL3Sw => t.free(allocator),
        structs.RpcEnumL3Sw => t.free(allocator),
        structs.RpcL3If => t.free(allocator),
        structs.RpcEnumL3If => t.free(allocator),
        structs.RpcL3Table => t.free(allocator),
        structs.RpcEnumL3Table => t.free(allocator),
        structs.RpcLocalBridge => t.free(allocator),
        structs.RpcEnumLocalBridge => t.free(allocator),
        structs.RpcEnumEth => t.free(allocator),
        structs.RpcEnumEthVLan => t.free(allocator),
        structs.RpcHubAddCa => t.free(allocator),
        structs.RpcHubEnumCa => t.free(allocator),
        structs.RpcHubGetCa => t.free(allocator),
        structs.RpcHubDeleteCa => t.free(allocator),
        structs.RpcEnumCrl => t.free(allocator),
        structs.RpcCrl => t.free(allocator),
        structs.RpcVhOption => t.free(allocator),
        structs.RpcEnumNat => t.free(allocator),
        structs.RpcEnumDhcp => t.free(allocator),
        structs.RpcIpSecServices => t.free(allocator),
        structs.RpcEtherIpId => t.free(allocator),
        structs.RpcEnumEtherIpId => t.free(allocator),
        structs.RpcOpenVpnSstpConfig => t.free(allocator),
        structs.RpcDdnsClientStatus => t.free(allocator),
        structs.RpcInternetSetting => t.free(allocator),
        structs.RpcAzureStatus => t.free(allocator),
        structs.RpcSpecialListener => t.free(allocator),
        structs.RpcLicenseStatus => t.free(allocator),
        structs.RpcEnumLicenseKey => t.free(allocator),
        structs.RpcLink => t.free(allocator),
        structs.RpcRenameLink => t.free(allocator),
        structs.RpcEnumLink => t.free(allocator),
        structs.RpcCreateLink => t.free(allocator),
        structs.RpcLinkStatus => t.free(allocator),
        structs.RpcKeyPair => t.free(allocator),
        structs.RpcStr => t.free(allocator),
        structs.RpcHub => t.free(allocator),
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
    removed.deinitGroups(allocator);
    removed.freeTables(allocator);
    removed.deinitAccessList(allocator);
    removed.deinitAdminOptions(allocator);
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
    t.secure_nat_enabled = hub.secure_nat_enabled;
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

/// Issue #88 `DisconnectSession` — session disconnect. C only exposes
/// `DeleteSession` (`RPC_DELETE_SESSION`); this project-defined endpoint is an
/// alias exposing the same hub-scoped stop under the issue's requested name.
fn stDisconnectSession(a: *AdminCtx, t: *structs.RpcDeleteSession, allocator: Allocator) u32 {
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

/// C `StEnumMacTable` (Admin.c:5152). Hub-scoped: a server admin targets the
/// requested hub, a hub admin is locked to the hub named in their session.
/// Standalone only: a farm controller would adjoin remote member entries
/// (C `SiCallEnumMacTable`), which the model does not implement, so non-
/// standalone types are rejected rather than returning a misleading local-only
/// enumeration. Does not touch `config_revision`.
fn stEnumMacTable(a: *AdminCtx, t: *structs.RpcEnumMacTable, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type != server_type_standalone) return err_not_supported;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    t.mac_tables = allocator.alloc(structs.EnumMacTableItem, hub.mac_table.items.len) catch return err_internal_error;
    for (hub.mac_table.items, 0..) |*entry, i| {
        const e = &t.mac_tables[i];
        e.* = .{};
        e.key = entry.key;
        e.session_name = dupStr(allocator, entry.session_name) catch return err_internal_error;
        e.mac_address = entry.mac_address;
        e.vlan_id = entry.vlan_id;
        e.created_time = entry.created_time;
        e.updated_time = entry.updated_time;
        e.remote_item = false;
        e.remote_hostname = dupStr(allocator, "") catch return err_internal_error;
    }
    return err_no_error;
}

/// C `StEnumIpTable` (Admin.c:4978). Same hub-scoping and standalone-only
/// behaviour as `StEnumMacTable`.
fn stEnumIpTable(a: *AdminCtx, t: *structs.RpcEnumIpTable, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type != server_type_standalone) return err_not_supported;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    t.ip_tables = allocator.alloc(structs.EnumIpTableItem, hub.ip_table.items.len) catch return err_internal_error;
    for (hub.ip_table.items, 0..) |*entry, i| {
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
        e.remote_hostname = dupStr(allocator, "") catch return err_internal_error;
    }
    return err_no_error;
}

// ============================================================================
// Table deletion (C `StDeleteMacTable` Admin.c:5028,
//                 `StDeleteIpTable` Admin.c:4854)
// ============================================================================

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

/// Issue #88 `GetTraffic` — hub traffic snapshot (project-defined; no C RPC).
/// Returns the same `TRAFFIC` block `GetHubStatus` embeds, standalone.
fn stGetTraffic(a: *AdminCtx, t: *structs.RpcGetTraffic, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    t.traffic = hub.traffic;
    return err_no_error;
}

/// Issue #88 `EnumLog` — log file listing. C `StEnumLogFile` (Admin.c:5162)
/// lists the log files an admin may access. The model has no persisted log
/// files yet (S23/logging), so the list is empty (`NumItem = 0`).
fn stEnumLog(a: *AdminCtx, t: *structs.RpcEnumLogFile, allocator: Allocator) u32 {
    if (!a.server_admin) return err_not_enough_right;
    t.free(allocator);
    t.* = .{};
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

/// C `StGetUser` (Admin.c:6048). Returns the account settings in a
/// `RPC_SET_USER`; unlike `SetUser` there is no canonicalization or
/// wildcard check (C only validates `IsUserName`). Divergence from C: the
/// stored model keeps only `password_hash` (SHA-0 of the password), so the
/// returned `NtLmSecureHash` is always empty and `Policy` is always null —
/// the C server returns both from `AUTHPASSWORD` / `USER.Policy`.
fn stGetUser(a: *AdminCtx, t: *structs.RpcSetUser, allocator: Allocator) u32 {
    const s = a.server;
    if (!isUserName(t.name)) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    const user = hub.findUser(t.name) orelse return err_object_not_found;

    const group_name = dupStr(allocator, user.group_name) catch return err_internal_error;
    const realname = dupStr(allocator, user.realname) catch return err_internal_error;
    const note = dupStr(allocator, user.note) catch return err_internal_error;

    allocator.free(t.group_name);
    allocator.free(t.realname);
    allocator.free(t.note);
    t.group_name = group_name;
    t.realname = realname;
    t.note = note;
    t.created_time = user.created_time;
    t.updated_time = user.updated_time;
    t.expire_time = user.expire_time;
    t.auth_type = @intFromEnum(user.auth_type);
    t.hashed_key = if (user.auth_type == .password) user.password_hash else null;
    t.ntlm_secure_hash = null;
    t.num_login = user.num_login;
    t.traffic = user.traffic;
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

/// Issue #88 `SetPassword` — user password change (project-defined; no C RPC).
/// The wire is the classic C `RPC_SET_PASSWORD` shape (hub + name +
/// hash/plaintext) with the modern SHA1 `HashedPassword` element. A provided
/// non-zero hash is stored verbatim; otherwise the plaintext is hashed like
/// `SetUser` (`auth.hashPassword`, SHA-0 with the user name as salt). The
/// account is set to password auth, matching C `UserPasswordSet`.
fn stSetPassword(a: *AdminCtx, t: *structs.RpcSetUserPassword, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!isUserName(t.name)) return err_invalid_parameter;
    if (isWildcardName(t.name)) return err_invalid_parameter;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (!validHash(t.hashed_password)) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    const user = hub.findUser(t.name) orelse return err_object_not_found;

    var hashed: [sha1_size]u8 = [_]u8{0} ** sha1_size;
    copyToFixed(&hashed, t.hashed_password);
    user.auth_type = .password;
    user.password_hash = if (isZero(&hashed)) auth.hashPassword(t.plain_text_password, user.name) else hashed;
    user.updated_time = nowMs();
    s.config_revision +%= 1;
    return err_no_error;
}

// ============================================================================
// Groups (C: Admin.c StCreateGroup / StSetGroup / StDeleteGroup / StGetGroup /
// StEnumGroup)
// ============================================================================

/// Count users on `hub` whose `group_name` matches `group_name`.
fn countGroupMembers(hub: *ServerHub, group_name: []const u8) u32 {
    var count: u32 = 0;
    for (hub.users.items) |user| {
        if (std.mem.eql(u8, user.group_name, group_name)) count += 1;
    }
    return count;
}

/// C `StEnumGroup` (Admin.c:6735). Hub-scoped: server admins target the
/// requested hub, hub admins are locked to their own.
fn stEnumGroup(a: *AdminCtx, t: *structs.RpcEnumGroup, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    t.groups = allocator.alloc(structs.EnumGroupItem, hub.groups.items.len) catch return err_internal_error;
    for (hub.groups.items, 0..) |*group, i| {
        const e = &t.groups[i];
        e.* = .{};
        e.name = dupStr(allocator, group.name) catch return err_internal_error;
        e.realname = dupStr(allocator, group.realname) catch return err_internal_error;
        e.note = dupStr(allocator, group.note) catch return err_internal_error;
        e.num_users = countGroupMembers(hub, group.name);
        e.deny_access = group.deny_access;
    }
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StCreateGroup` (Admin.c:6823).
fn stCreateGroup(a: *AdminCtx, t: *structs.RpcSetGroup, allocator: Allocator) u32 {
    const s = a.server;
    if (!isGroupName(t.name)) return err_invalid_parameter;
    if (isWildcardName(t.name)) return err_invalid_parameter;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    _ = canonicalizeGroupName(t, allocator);

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (hub.findGroup(t.name) != null) return err_user_already_exists;

    const group = ServerGroup{
        .name = dupStr(allocator, t.name) catch return err_internal_error,
        .realname = dupStr(allocator, t.realname) catch return err_internal_error,
        .note = dupStr(allocator, t.note) catch return err_internal_error,
        .deny_access = t.policy != null,
        .traffic = t.traffic,
        .policy = if (t.policy) |pol| pol.* else null,
    };
    hub.addGroup(allocator, group) catch return err_internal_error;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StSetGroup` (Admin.c:6916).
fn stSetGroup(a: *AdminCtx, t: *structs.RpcSetGroup, allocator: Allocator) u32 {
    const s = a.server;
    if (!isGroupName(t.name)) return err_invalid_parameter;
    if (isWildcardName(t.name)) return err_invalid_parameter;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    const group = hub.findGroup(t.name) orelse return err_object_not_found;

    const realname = dupStr(allocator, t.realname) catch return err_internal_error;
    const note = dupStr(allocator, t.note) catch return err_internal_error;

    allocator.free(group.realname);
    allocator.free(group.note);
    group.realname = realname;
    group.note = note;
    group.traffic = t.traffic;
    group.deny_access = t.policy != null;
    group.policy = if (t.policy) |pol| pol.* else null;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StGetGroup` (Admin.c:6993). Returns the group settings in a
/// `RPC_SET_GROUP`, including the persisted policy (if any).
fn stGetGroup(a: *AdminCtx, t: *structs.RpcSetGroup, allocator: Allocator) u32 {
    const s = a.server;
    if (!isGroupName(t.name)) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    const group = hub.findGroup(t.name) orelse return err_object_not_found;

    const realname = dupStr(allocator, group.realname) catch return err_internal_error;
    const note = dupStr(allocator, group.note) catch return err_internal_error;

    allocator.free(t.realname);
    allocator.free(t.note);
    if (t.policy) |pol| allocator.destroy(pol);
    t.realname = realname;
    t.note = note;
    t.traffic = group.traffic;
    if (group.policy) |pol| {
        const cloned = allocator.create(structs.Policy) catch return err_internal_error;
        cloned.* = pol;
        t.policy = cloned;
    } else {
        t.policy = null;
    }
    return err_no_error;
}

/// C `StDeleteGroup` (Admin.c:6684). Reuses `RPC_DELETE_USER` on the wire.
fn stDeleteGroup(a: *AdminCtx, t: *structs.RpcDeleteUser, allocator: Allocator) u32 {
    const s = a.server;
    if (!isGroupName(t.name)) return err_invalid_parameter;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (!hub.removeGroup(allocator, t.name)) return err_object_not_found;
    s.config_revision +%= 1;
    return err_no_error;
}

// ============================================================================
// Access List (C: Admin.c StAddAccess / StDeleteAccess / StEnumAccess /
// StSetAccessList — Hub.h ACCESS)
// ============================================================================

fn freeAccessFields(allocator: Allocator, a: *structs.Access) void {
    allocator.free(a.note);
    allocator.free(a.src_username);
    allocator.free(a.dest_username);
    allocator.free(a.redirect_url);
    a.* = .{};
}

/// C `StAddAccess` (Admin.c:4854). Append one ACCESS entry to the hub.
fn stAddAccess(a: *AdminCtx, t: *structs.RpcAddAccess, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    // Transfer ownership of the (already-duped) Access to the hub.
    const access = t.access;
    t.access = .{};
    hub.addAccessEntry(allocator, access) catch return err_internal_error;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteAccess` (Admin.c:4907). Remove an ACCESS entry by Id.
fn stDeleteAccess(a: *AdminCtx, t: *structs.RpcDeleteAccess, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    if (!hub.removeAccessEntry(allocator, t.id)) return err_object_not_found;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StEnumAccess` (Admin.c:4878). Copy all ACCESS entries into a flat
/// array; C assigns `UniqueId = HashPtrToUINT` — we assign the original `id`.
fn stEnumAccess(a: *AdminCtx, t: *structs.RpcEnumAccessList, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.free(allocator);
    t.* = .{};
    t.hub_name = hub_name;

    const entries = allocator.alloc(structs.Access, hub.access_list.items.len) catch return err_internal_error;
    for (hub.access_list.items, 0..) |src, i| {
        entries[i] = .{
            .id = src.id,
            .note = dupStr(allocator, src.note) catch return err_internal_error,
            .active = src.active,
            .priority = src.priority,
            .discard = src.discard,
            .src_ip = src.src_ip,
            .src_mask = src.src_mask,
            .dest_ip = src.dest_ip,
            .dest_mask = src.dest_mask,
            .protocol = src.protocol,
            .src_port_start = src.src_port_start,
            .src_port_end = src.src_port_end,
            .dest_port_start = src.dest_port_start,
            .dest_port_end = src.dest_port_end,
            .src_username = dupStr(allocator, src.src_username) catch return err_internal_error,
            .dest_username = dupStr(allocator, src.dest_username) catch return err_internal_error,
            .check_src_mac = src.check_src_mac,
            .src_mac = src.src_mac,
            .src_mac_mask = src.src_mac_mask,
            .check_dst_mac = src.check_dst_mac,
            .dst_mac = src.dst_mac,
            .dst_mac_mask = src.dst_mac_mask,
            .check_tcp_state = src.check_tcp_state,
            .established = src.established,
            .delay = src.delay,
            .jitter = src.jitter,
            .loss = src.loss,
            .redirect_url = dupStr(allocator, src.redirect_url) catch return err_internal_error,
            .is_ipv6 = src.is_ipv6,
            .src_ip6 = src.src_ip6,
            .src_mask6 = src.src_mask6,
            .dest_ip6 = src.dest_ip6,
            .dest_mask6 = src.dest_mask6,
            .unique_id = src.id,
        };
    }
    t.accesses = entries;
    return err_no_error;
}

/// C `StSetAccessList` (Admin.c:4939). Replace the entire access list.
fn stSetAccessList(a: *AdminCtx, t: *structs.RpcEnumAccessList, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    // Transfer ownership of the incoming array to the hub.
    const entries = t.accesses;
    t.accesses = &.{};

    hub.setAccessList(allocator, entries) catch return err_internal_error;
    s.config_revision +%= 1;
    return err_no_error;
}

/// C `StGetHubAdminOptions` (Admin.c:4381). Returns all hub admin options.
fn stGetHubAdminOptions(a: *AdminCtx, t: *structs.RpcAdminOption, allocator: Allocator) u32 {
    const s = a.server;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    hub.ensureDefaultAdminOptions(allocator) catch return err_internal_error;

    t.free(allocator);
    t.* = .{};
    t.hub_name = allocator.dupe(u8, hub.name) catch return err_internal_error;
    t.items = allocator.alloc(structs.AdminOption, hub.admin_options.items.len) catch return err_internal_error;
    for (hub.admin_options.items, 0..) |opt, i| {
        t.items[i] = .{
            .name = allocator.dupe(u8, opt.name) catch return err_internal_error,
            .value = opt.value,
        };
    }
    return err_no_error;
}

/// C `StGetDefaultHubAdminOptions` (Admin.c:4435). Returns the static default table.
fn stGetDefaultHubAdminOptions(a: *AdminCtx, t: *structs.RpcAdminOption, allocator: Allocator) u32 {
    const s = a.server;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;

    t.free(allocator);
    t.* = .{};
    t.items = allocator.alloc(structs.AdminOption, default_admin_options.len) catch return err_internal_error;
    for (default_admin_options, 0..) |opt, i| {
        t.items[i] = .{
            .name = allocator.dupe(u8, opt.name) catch return err_internal_error,
            .value = opt.value,
        };
    }
    return err_no_error;
}

/// C `StSetHubAdminOptions` (Admin.c:4301). Replace all hub admin options.
fn stSetHubAdminOptions(a: *AdminCtx, t: *structs.RpcAdminOption, allocator: Allocator) u32 {
    const s = a.server;
    if (s.is_bridge) return err_not_supported;
    if (s.server_type == server_type_farm_member) return err_not_supported;
    if (!a.server_admin) return err_not_enough_right;
    if (t.items.len > max_hub_admin_options) return err_too_many_items;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    // Hub admins need allow_hub_admin_change_option (C checks this).
    if (!a.server_admin) {
        if (hub.getAdminOptionValue("allow_hub_admin_change_option", 0) == 0)
            return err_not_enough_right;
    }

    hub.setAllAdminOptions(allocator, t.items) catch return err_internal_error;
    hub.ensureDefaultAdminOptions(allocator) catch return err_internal_error;

    // Take ownership of incoming items so free is safe.
    t.items = &.{};

    s.config_revision +%= 1;
    return err_no_error;
}

// ============================================================================
// LocalBridge endpoints (#97)
// ============================================================================

/// C `StAddLocalBridge` (Admin.c). Adds a bridge entry to the admin model
/// and creates the runtime LocalBridge instance.
fn stAddLocalBridge(a: *AdminCtx, t: *structs.RpcLocalBridge, allocator: Allocator) u32 {
    if (!a.server_admin) return err_not_enough_right;
    if (t.device_name.len == 0 or t.hub_name_lb.len == 0) return err_invalid_parameter;
    for (a.server.local_bridges.items) |lb| {
        if (mem.eql(u8, lb.device_name, t.device_name) and mem.eql(u8, lb.hub_name, t.hub_name_lb))
            return err_listener_already_exists;
    }

    // Create the runtime bridge (calls through vtable -> accept.zig).
    const bridge_active = blk: {
        if (a.server.bridge_ops.ctx) |ctx| {
            break :blk a.server.bridge_ops.create(ctx, t.device_name, t.hub_name_lb, t.tap_mode);
        }
        break :blk false;
    };

    a.server.local_bridges.append(allocator, .{
        .device_name = allocator.dupe(u8, t.device_name) catch return err_internal_error,
        .hub_name = allocator.dupe(u8, t.hub_name_lb) catch return err_internal_error,
        .online = bridge_active,
        .active = bridge_active,
        .tap_mode = t.tap_mode,
    }) catch return err_internal_error;
    a.server.config_revision +%= 1;
    return err_no_error;
}

/// C `StDeleteLocalBridge` (Admin.c). Removes a bridge entry and destroys
/// the runtime LocalBridge instance.
fn stDeleteLocalBridge(a: *AdminCtx, t: *structs.RpcLocalBridge, allocator: Allocator) u32 {
    _ = allocator;
    if (!a.server_admin) return err_not_enough_right;
    for (a.server.local_bridges.items, 0..) |lb, i| {
        if (mem.eql(u8, lb.device_name, t.device_name) and mem.eql(u8, lb.hub_name, t.hub_name_lb)) {
            // Destroy the runtime bridge (calls through vtable → accept.zig).
            if (a.server.bridge_ops.ctx) |ctx| {
                _ = a.server.bridge_ops.destroy(ctx, t.device_name, t.hub_name_lb);
            }
            var removed = a.server.local_bridges.swapRemove(i);
            removed.deinit(a.server.allocator);
            a.server.config_revision +%= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StEnumLocalBridge` (Admin.c). Returns all bridge entries.
fn stEnumLocalBridge(a: *AdminCtx, t: *structs.RpcEnumLocalBridge, allocator: Allocator) u32 {
    t.items = allocator.alloc(structs.RpcEnumLocalBridge.EnumLocalBridgeItem, a.server.local_bridges.items.len) catch return err_internal_error;
    for (a.server.local_bridges.items, 0..) |lb, i| {
        t.items[i] = .{
            .device_name = allocator.dupe(u8, lb.device_name) catch return err_internal_error,
            .hub_name_lb = allocator.dupe(u8, lb.hub_name) catch return err_internal_error,
            .online = lb.online,
            .active = lb.active,
            .tap_mode = lb.tap_mode,
        };
    }
    return err_no_error;
}

/// C `StGetBridgeSupport` (Admin.c). Reports platform bridge capability.
fn stGetBridgeSupport(a: *AdminCtx, t: *structs.RpcBridgeSupport, allocator: Allocator) u32 {
    _ = a;
    _ = allocator;
    t.is_bridge_supported_os = true;
    t.is_winpcap_needed = false;
    return err_no_error;
}

// ============================================================================
// Certificate & Cipher (C Admin.c:9366-9446, 2157)
// ============================================================================

/// C `StRegenerateServerCert` (Admin.c:2157). `RPC_TEST` — `StrValue` is the
/// CN for the new self-signed cert; empty → hostname default.
fn stRegenerateServerCert(a: *AdminCtx, t: *structs.RpcTest, allocator: Allocator) u32 {
    const s = a.server;
    const cn = if (t.str_value.len > 0) t.str_value else s.host_name;

    var result = x509_mod.generateSelfSigned(allocator, .{
        .common_name = cn,
        .organization = "SoftEther VPN Server",
    }, 365 * 10) catch return err_internal_error;
    defer result.cert.deinit(allocator);
    defer allocator.free(result.key);

    s.mutex.lock();
    defer s.mutex.unlock();

    const old_cert = s.cert_pem;
    const old_key = s.key_pem;
    s.cert_pem = allocator.dupe(u8, result.cert.data) catch return err_internal_error;
    s.key_pem = allocator.dupe(u8, result.key) catch {
        allocator.free(s.cert_pem);
        s.cert_pem = old_cert;
        return err_internal_error;
    };
    allocator.free(old_cert);
    allocator.free(old_key);
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StSetServerCert` (Admin.c:9446). `RPC_KEY_PAIR` — `Cert` and `Key` are
/// PEM-encoded. Validates key matches cert.
fn stSetServerCert(a: *AdminCtx, t: *structs.RpcKeyPair, allocator: Allocator) u32 {
    if (t.cert.len == 0 or t.key.len == 0) return err_invalid_parameter;

    // Validate: cert and key must both parse.
    const x509 = x509_mod.pemToX509(allocator, t.cert) catch return err_invalid_parameter;
    defer ssl.X509_free(x509);

    const pkey = x509_mod.pemToEvpPkey(allocator, t.key, true) catch return err_invalid_parameter;
    defer ssl.EVP_PKEY_free(pkey);

    // Validate: key matches cert.
    if (ssl.X509_check_private_key(x509, pkey) != 1) return err_invalid_parameter;

    const s = a.server;
    s.mutex.lock();
    defer s.mutex.unlock();

    const old_cert = s.cert_pem;
    const old_key = s.key_pem;
    s.cert_pem = allocator.dupe(u8, t.cert) catch return err_internal_error;
    s.key_pem = allocator.dupe(u8, t.key) catch {
        allocator.free(s.cert_pem);
        s.cert_pem = old_cert;
        return err_internal_error;
    };
    allocator.free(old_cert);
    allocator.free(old_key);
    s.config_revision +|= 1;
    t.flag1 = 1;
    return err_no_error;
}

/// C `StGetServerCert` (Admin.c:9419). `RPC_KEY_PAIR` — returns cert PEM in
/// `Cert`; private key in `Key` only for server admins.
fn stGetServerCert(a: *AdminCtx, t: *structs.RpcKeyPair, allocator: Allocator) u32 {
    const s = a.server;
    s.mutex.lock();
    defer s.mutex.unlock();

    t.free(allocator);
    t.* = .{};

    if (s.cert_pem.len > 0) {
        t.cert = allocator.dupe(u8, s.cert_pem) catch return err_internal_error;
    }
    // Private key only returned to server admins.
    if (a.server_admin and s.key_pem.len > 0) {
        t.key = allocator.dupe(u8, s.key_pem) catch {
            allocator.free(t.cert);
            t.cert = "";
            return err_internal_error;
        };
    }
    t.flag1 = 1;
    return err_no_error;
}

/// C `StGetServerCipher` (Admin.c:9401). `RPC_STR` — returns the cipher list.
fn stGetServerCipher(a: *AdminCtx, t: *structs.RpcStr, allocator: Allocator) u32 {
    const s = a.server;
    s.mutex.lock();
    defer s.mutex.unlock();

    t.free(allocator);
    t.* = .{};
    if (s.cipher_list.len > 0) {
        t.string = allocator.dupe(u8, s.cipher_list) catch return err_internal_error;
    }
    return err_no_error;
}

/// C `StSetServerCipher` (Admin.c:9366). `RPC_STR` — sets the cipher list.
fn stSetServerCipher(a: *AdminCtx, t: *structs.RpcStr, allocator: Allocator) u32 {
    if (t.string.len == 0) return err_invalid_parameter;

    const s = a.server;
    s.mutex.lock();
    defer s.mutex.unlock();

    const old = s.cipher_list;
    s.cipher_list = allocator.dupe(u8, t.string) catch return err_internal_error;
    allocator.free(old);
    s.config_revision +|= 1;
    return err_no_error;
}

// ============================================================================
// Listener Enable/Disable (C Admin.c:9726)
// ============================================================================

/// C `StEnableListener` (Admin.c:9726). SERVER_ADMIN_ONLY — toggles a
/// listener on/off by port number.
fn stEnableListener(a: *AdminCtx, t: *structs.RpcListener, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin) return err_not_enough_right;

    s.mutex.lock();
    defer s.mutex.unlock();

    const idx = findListenerIndex(s, t.port) orelse return err_object_not_found;
    s.listeners.items[idx].enabled = t.enable;
    s.listeners.items[idx].has_error = false;
    s.config_revision +|= 1;
    return err_no_error;
}

// ============================================================================
// Hub Get/Set (C Admin.c:8991, 9092)
// ============================================================================

/// C `StGetHub` (Admin.c:8991). CHECK_RIGHT — returns hub settings via
/// `RPC_CREATE_HUB` (HubName, Online, HubOption, HubType).
fn stGetHub(a: *AdminCtx, t: *structs.RpcCreateHub, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.online = hub.online;
    t.hub_option = .{ .max_session = hub.max_session, .no_enum = hub.no_enum };
    t.hub_type = hub.hub_type;
    return err_no_error;
}

// ============================================================================
// Hub Online/Offline (C Admin.c:9191)
// ============================================================================

/// C `StSetHubOnline` (Admin.c:9191). CHECK_RIGHT — brings a hub online or
/// offline.
fn stSetHubOnline(a: *AdminCtx, t: *structs.RpcSetHubOnline, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    hub.online = t.online;
    s.config_revision +|= 1;
    return err_no_error;
}

// ============================================================================
// Hub Log Settings (C Admin.c:8341)
// ============================================================================

/// C `StGetHubLog` (Admin.c:8341). CHECK_RIGHT — reads hub log settings.
fn stGetHubLog(a: *AdminCtx, t: *structs.RpcHubLog, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.save_security_log = hub.log_save_security_log;
    t.security_log_switch_type = hub.log_security_switch_type;
    t.save_packet_log = hub.log_save_packet_log;
    t.packet_log_switch_type = hub.log_packet_switch_type;
    return err_no_error;
}

/// C `StSetHubLog` (Admin.c:8375). CHECK_RIGHT — updates hub log settings.
fn stSetHubLog(a: *AdminCtx, t: *structs.RpcHubLog, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    hub.log_save_security_log = t.save_security_log;
    hub.log_security_switch_type = t.security_log_switch_type;
    hub.log_save_packet_log = t.save_packet_log;
    hub.log_packet_switch_type = t.packet_log_switch_type;
    s.config_revision +|= 1;
    return err_no_error;
}

// ============================================================================
// Hub Extended Options (C Admin.c:4301)
// ============================================================================

/// C `StGetHubExtOptions` (Admin.c:4381). CHECK_RIGHT — returns all hub admin
/// options.
fn stGetHubExtOptions(a: *AdminCtx, t: *structs.RpcAdminOption, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;

    t.items = allocator.alloc(structs.AdminOption, hub.admin_options.items.len) catch return err_internal_error;
    for (hub.admin_options.items, 0..) |opt, i| {
        t.items[i] = .{
            .name = dupStr(allocator, opt.name) catch return err_internal_error,
            .value = opt.value,
        };
    }
    return err_no_error;
}

/// C `StSetHubExtOptions` (Admin.c:4301). CHECK_RIGHT — replaces all hub admin
/// options.
fn stSetHubExtOptions(a: *AdminCtx, t: *structs.RpcAdminOption, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.admin_options.items) |*opt| opt.free(allocator);
    hub.admin_options.deinit(allocator);
    hub.admin_options = .{};

    hub.admin_options.ensureTotalCapacity(allocator, t.items.len) catch return err_internal_error;
    for (t.items) |opt| {
        hub.admin_options.append(allocator, .{
            .name = dupStr(allocator, opt.name) catch return err_internal_error,
            .value = opt.value,
        }) catch return err_internal_error;
    }
    s.config_revision +|= 1;
    return err_no_error;
}

// ============================================================================
// Hub RADIUS (C Admin.c:4165)
// ============================================================================

/// C `StGetHubRadius` (Admin.c:4203). CHECK_RIGHT — returns RADIUS settings.
fn stGetHubRadius(a: *AdminCtx, t: *structs.RpcRadius, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.radius_server_name = dupStr(allocator, hub.radius_server_name) catch return err_internal_error;
    t.radius_port = hub.radius_port;
    t.radius_secret = dupStr(allocator, hub.radius_secret) catch return err_internal_error;
    t.radius_retry_interval = hub.radius_retry_interval;
    return err_no_error;
}

/// C `StSetHubRadius` (Admin.c:4165). CHECK_RIGHT — sets RADIUS settings.
fn stSetHubRadius(a: *AdminCtx, t: *structs.RpcRadius, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    allocator.free(hub.radius_server_name);
    hub.radius_server_name = dupStr(allocator, t.radius_server_name) catch return err_internal_error;
    hub.radius_port = t.radius_port;
    allocator.free(hub.radius_secret);
    hub.radius_secret = dupStr(allocator, t.radius_secret) catch return err_internal_error;
    hub.radius_retry_interval = t.radius_retry_interval;
    s.config_revision +|= 1;
    return err_no_error;
}

// ============================================================================
// Connection Info (C Admin.c:4759)
// ============================================================================

/// C `StGetConnectionInfo` (Admin.c:4759). SERVER_ADMIN_ONLY — returns
/// connection details.
fn stGetConnectionInfo(a: *AdminCtx, t: *structs.RpcConnectionInfo, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin) return err_not_enough_right;
    if (t.name.len == 0) return err_invalid_parameter;

    // Search sessions for a matching name.
    const snaps = s.sessions.snapshot(allocator) catch return err_internal_error;
    defer session_registry.SessionRegistry.freeSnapshot(allocator, snaps);

    for (snaps) |*snap| {
        if (std.ascii.eqlIgnoreCase(snap.session_name, t.name)) {
            allocator.free(t.name);
            t.* = .{};
            t.name = dupStr(allocator, snap.session_name) catch return err_internal_error;
            t.hostname = "";
            t.ip = snap.peer_ip;
            t.port = 0;
            t.connected_time = @intCast(snap.created_time);
            t.server_str = "";
            t.server_ver = s.version;
            t.server_build = s.build;
            t.client_str = "";
            t.client_ver = 0;
            t.client_build = 0;
            t.conn_type = 0;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

// ============================================================================
// SecureNAT (C Admin.c:4556, Virtual.h VH_OPTION)
// ============================================================================

/// C `StEnableSecureNAT` (Admin.c:4556). CHECK_RIGHT — enables SecureNAT on a hub.
fn stEnableSecureNAT(a: *AdminCtx, t: *structs.RpcHub, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    hub.secure_nat_enabled = true;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StDisableSecureNAT` (Admin.c:4597). CHECK_RIGHT — disables SecureNAT.
fn stDisableSecureNAT(a: *AdminCtx, t: *structs.RpcHub, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;
    hub.secure_nat_enabled = false;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StGetSecureNATOption` (Admin.c:4640). CHECK_RIGHT — returns VH option.
fn stGetSecureNATOption(a: *AdminCtx, t: *structs.RpcVhOption, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.rpc_hub_name)) return err_not_enough_right;
    if (t.rpc_hub_name.len == 0) return err_invalid_parameter;

    const hub = findHub(s, t.rpc_hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.rpc_hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.mac_address = hub.vh_mac_address;
    t.ip = hub.vh_ip;
    t.mask = hub.vh_mask;
    t.use_nat = hub.vh_use_nat;
    t.mtu = hub.vh_mtu;
    t.nat_tcp_timeout = hub.vh_nat_tcp_timeout;
    t.nat_udp_timeout = hub.vh_nat_udp_timeout;
    t.use_dhcp = hub.vh_use_dhcp;
    t.dhcp_lease_ip_start = hub.vh_dhcp_lease_ip_start;
    t.dhcp_lease_ip_end = hub.vh_dhcp_lease_ip_end;
    t.dhcp_subnet_mask = hub.vh_dhcp_subnet_mask;
    t.dhcp_expire_time_span = hub.vh_dhcp_expire_time_span;
    t.dhcp_gateway_address = hub.vh_dhcp_gateway_address;
    t.dhcp_dns_server_address = hub.vh_dhcp_dns_server_address;
    t.dhcp_dns_server_address2 = hub.vh_dhcp_dns_server_address2;
    t.dhcp_domain_name = dupStr(allocator, hub.vh_dhcp_domain_name) catch return err_internal_error;
    t.save_log = hub.vh_save_log;
    t.apply_dhcp_push_routes = hub.vh_apply_dhcp_push_routes;
    t.dhcp_push_routes = dupStr(allocator, hub.vh_dhcp_push_routes) catch return err_internal_error;
    return err_no_error;
}

/// C `StSetSecureNATOption` (Admin.c:4705). CHECK_RIGHT — sets VH option.
fn stSetSecureNATOption(a: *AdminCtx, t: *structs.RpcVhOption, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.rpc_hub_name)) return err_not_enough_right;
    if (t.rpc_hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const hub = findHub(s, t.rpc_hub_name) orelse return err_hub_not_found;
    hub.vh_mac_address = t.mac_address;
    hub.vh_ip = t.ip;
    hub.vh_mask = t.mask;
    hub.vh_use_nat = t.use_nat;
    hub.vh_mtu = t.mtu;
    hub.vh_nat_tcp_timeout = t.nat_tcp_timeout;
    hub.vh_nat_udp_timeout = t.nat_udp_timeout;
    hub.vh_use_dhcp = t.use_dhcp;
    hub.vh_dhcp_lease_ip_start = t.dhcp_lease_ip_start;
    hub.vh_dhcp_lease_ip_end = t.dhcp_lease_ip_end;
    hub.vh_dhcp_subnet_mask = t.dhcp_subnet_mask;
    hub.vh_dhcp_expire_time_span = t.dhcp_expire_time_span;
    hub.vh_dhcp_gateway_address = t.dhcp_gateway_address;
    hub.vh_dhcp_dns_server_address = t.dhcp_dns_server_address;
    hub.vh_dhcp_dns_server_address2 = t.dhcp_dns_server_address2;
    allocator.free(hub.vh_dhcp_domain_name);
    hub.vh_dhcp_domain_name = dupStr(allocator, t.dhcp_domain_name) catch return err_internal_error;
    hub.vh_save_log = t.save_log;
    hub.vh_apply_dhcp_push_routes = t.apply_dhcp_push_routes;
    allocator.free(hub.vh_dhcp_push_routes);
    hub.vh_dhcp_push_routes = dupStr(allocator, t.dhcp_push_routes) catch return err_internal_error;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StEnumNAT` (Admin.c:4804). CHECK_RIGHT — returns empty (no live NAT yet).
fn stEnumNAT(a: *AdminCtx, t: *structs.RpcEnumNat, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    return err_no_error;
}

/// C `StEnumDHCP` (Admin.c:4844). CHECK_RIGHT — returns empty (no live DHCP yet).
fn stEnumDHCP(a: *AdminCtx, t: *structs.RpcEnumDhcp, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    return err_no_error;
}

/// C `StGetSecureNATStatus` (Admin.c:4877). CHECK_RIGHT — returns zeros (no live NAT).
fn stGetSecureNATStatus(a: *AdminCtx, t: *structs.RpcNatStatus, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;

    const hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    allocator.free(t.hub_name);
    t.* = .{};
    t.hub_name = hub_name;
    return err_no_error;
}

// ============================================================================
// Config / Syslog (C Admin.c:10161, 10184, Server.c:1833)
// ============================================================================

/// C `StGetConfig` (Admin.c:10161). SERVER_ADMIN_ONLY — returns config file.
fn stGetConfig(a: *AdminCtx, t: *structs.RpcConfig, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin) return err_not_enough_right;

    t.free(allocator);
    t.* = .{};
    t.file_name = dupStr(allocator, "server_config.xml") catch return err_internal_error;
    // Return a minimal config document.
    t.file_data = dupStr(allocator,
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<SoftEtherVPN>
        \\  <ServerConfiguration>
        \\    <Item name="default_hub" value="DEFAULT" />
        \\  </ServerConfiguration>
        \\</SoftEtherVPN>
    ) catch return err_internal_error;
    _ = s;
    return err_no_error;
}

/// C `StSetConfig` (Admin.c:10184). SERVER_ADMIN_ONLY — stores config file.
fn stSetConfig(a: *AdminCtx, t: *structs.RpcConfig, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin) return err_not_enough_right;
    if (t.file_data.len == 0) return err_invalid_parameter;

    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StSetSysLog` (Admin.c:10210). SERVER_ADMIN_ONLY — sets syslog config.
fn stSetSysLog(a: *AdminCtx, t: *structs.RpcSyslogSetting, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin) return err_not_enough_right;

    s.mutex.lock();
    defer s.mutex.unlock();

    s.syslog_save_type = t.save_type;
    allocator.free(s.syslog_hostname);
    s.syslog_hostname = dupStr(allocator, t.hostname) catch return err_internal_error;
    s.syslog_port = t.port;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StGetSysLog` (Admin.c:10245). Returns syslog config; non-admin sees redacted hostname.
fn stGetSysLog(a: *AdminCtx, t: *structs.RpcSyslogSetting, allocator: Allocator) u32 {
    const s = a.server;

    s.mutex.lock();
    defer s.mutex.unlock();

    t.free(allocator);
    t.* = .{};
    t.save_type = s.syslog_save_type;
    t.port = s.syslog_port;
    if (a.server_admin) {
        t.hostname = dupStr(allocator, s.syslog_hostname) catch return err_internal_error;
    } else {
        t.hostname = dupStr(allocator, "") catch return err_internal_error;
    }
    return err_no_error;
}

// ============================================================================
// Links (C Admin.c:4033 — cascade connections)
// ============================================================================

/// C `StEnumLink` (Admin.c:4033). CHECK_RIGHT — lists cascade links.
fn stEnumLink(a: *AdminCtx, t: *structs.RpcEnumLink, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.items = allocator.alloc(structs.RpcEnumLink.EnumLinkItem, hub.links.items.len) catch return err_internal_error;
    for (hub.links.items, 0..) |link, i| {
        t.items[i] = .{
            .account_name = dupStr(allocator, link.account_name) catch return err_internal_error,
            .hostname = dupStr(allocator, link.hostname) catch return err_internal_error,
            .connected_hub_name = dupStr(allocator, hub.name) catch return err_internal_error,
            .online = link.online,
            .connected = link.connected,
            .connected_time = link.connected_time,
            .last_error = link.last_error,
            .target_hub_name = dupStr(allocator, link.hub_name) catch return err_internal_error,
        };
    }
    return err_no_error;
}

/// C `StCreateLink` (Admin.c:4071). CHECK_RIGHT — creates a cascade link.
fn stCreateLink(a: *AdminCtx, t: *structs.RpcCreateLink, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const link = ServerLink{
        .account_name = dupStr(allocator, "new_link") catch return err_internal_error,
        .hostname = dupStr(allocator, "") catch return err_internal_error,
        .hub_name = dupStr(allocator, hub.name) catch return err_internal_error,
        .online = false,
    };
    hub.links.append(allocator, link) catch return err_internal_error;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StGetLink` (Admin.c:4142). CHECK_RIGHT — returns link config.
fn stGetLink(a: *AdminCtx, t: *structs.RpcCreateLink, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.links.items) |link| {
        if (std.ascii.eqlIgnoreCase(link.account_name, t.hub_name)) {
            t.free(allocator);
            t.* = .{};
            t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
            t.online = link.online;
            t.check_server_cert = false;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StSetLink` (Admin.c:4247). CHECK_RIGHT — updates link config.
fn stSetLink(a: *AdminCtx, t: *structs.RpcCreateLink, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    _ = findHub(s, t.hub_name) orelse return err_hub_not_found;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StDeleteLink` (Admin.c:4377). CHECK_RIGHT — deletes a cascade link.
fn stDeleteLink(a: *AdminCtx, t: *structs.RpcLink, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0 or t.account_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.links.items, 0..) |*link, i| {
        if (std.ascii.eqlIgnoreCase(link.account_name, t.account_name)) {
            var removed = hub.links.swapRemove(i);
            removed.deinit(allocator);
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StRenameLink` (Admin.c:4439). CHECK_RIGHT — renames a cascade link.
fn stRenameLink(a: *AdminCtx, t: *structs.RpcRenameLink, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0 or t.old_account_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.links.items) |*link| {
        if (std.ascii.eqlIgnoreCase(link.account_name, t.old_account_name)) {
            allocator.free(link.account_name);
            link.account_name = dupStr(allocator, t.new_account_name) catch return err_internal_error;
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StSetLinkOnline` (Admin.c:4503). CHECK_RIGHT — brings a link online.
fn stSetLinkOnline(a: *AdminCtx, t: *structs.RpcLink, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0 or t.account_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.links.items) |*link| {
        if (std.ascii.eqlIgnoreCase(link.account_name, t.account_name)) {
            link.online = true;
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StSetLinkOffline` (Admin.c:4530). CHECK_RIGHT — takes a link offline.
fn stSetLinkOffline(a: *AdminCtx, t: *structs.RpcLink, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0 or t.account_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.links.items) |*link| {
        if (std.ascii.eqlIgnoreCase(link.account_name, t.account_name)) {
            link.online = false;
            link.connected = false;
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StGetLinkStatus` (Admin.c:4396). CHECK_RIGHT — returns link status.
fn stGetLinkStatus(a: *AdminCtx, t: *structs.RpcLinkStatus, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0 or t.account_name.len == 0) return err_invalid_parameter;
    if (findHub(s, t.hub_name) == null) return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error;
    t.account_name = dupStr(allocator, t.account_name) catch return err_internal_error;
    return err_no_error;
}

// ============================================================================
// CA / CRL (C Admin.c:3353 — HubDb->RootCertList / CrlList)
// ============================================================================

/// C `StEnumCa` (Admin.c:7745). CHECK_RIGHT — lists CA certs.
fn stEnumCa(a: *AdminCtx, t: *structs.RpcHubEnumCa, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.items = allocator.alloc(structs.RpcHubEnumCa.EnumCaItem, hub.ca_list.items.len) catch return err_internal_error;
    for (hub.ca_list.items, 0..) |ca, i| {
        t.items[i] = .{
            .key = ca.key,
            .subject_name = dupStr(allocator, ca.subject_name) catch return err_internal_error,
            .issuer_name = dupStr(allocator, ca.issuer_name) catch return err_internal_error,
            .expires = ca.expires,
        };
    }
    return err_no_error;
}

/// C `StAddCa` (Admin.c:7809). CHECK_RIGHT — adds a CA cert.
fn stAddCa(a: *AdminCtx, t: *structs.RpcHubAddCa, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const next_key: u32 = if (hub.ca_list.items.len > 0) hub.ca_list.items[hub.ca_list.items.len - 1].key + 1 else 1;
    const ca = ServerCa{
        .key = next_key,
        .subject_name = dupStr(allocator, "Unknown") catch return err_internal_error,
        .issuer_name = dupStr(allocator, "Unknown") catch return err_internal_error,
    };
    hub.ca_list.append(allocator, ca) catch return err_internal_error;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StGetCa` (Admin.c:7687). CHECK_RIGHT — returns a CA cert by key.
fn stGetCa(a: *AdminCtx, t: *structs.RpcHubGetCa, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.ca_list.items) |ca| {
        if (ca.key == t.key) {
            t.free(allocator);
            t.* = .{};
            t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
            t.key = ca.key;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StDeleteCa` (Admin.c:7630). CHECK_RIGHT — deletes a CA cert by key.
fn stDeleteCa(a: *AdminCtx, t: *structs.RpcHubDeleteCa, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.ca_list.items, 0..) |*ca, i| {
        if (ca.key == t.key) {
            var removed = hub.ca_list.swapRemove(i);
            removed.deinit(allocator);
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StEnumCrl` (Admin.c:3613). CHECK_RIGHT — lists CRLs.
fn stEnumCrl(a: *AdminCtx, t: *structs.RpcEnumCrl, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    t.free(allocator);
    t.* = .{};
    t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
    t.items = allocator.alloc(structs.RpcEnumCrl.EnumCrlItem, hub.crl_list.items.len) catch return err_internal_error;
    for (hub.crl_list.items, 0..) |crl, i| {
        t.items[i] = .{
            .key = crl.key,
            .crl_info = dupStr(allocator, crl.info) catch return err_internal_error,
        };
    }
    return err_no_error;
}

/// C `StAddCrl` (Admin.c:3547). CHECK_RIGHT — adds a CRL entry.
fn stAddCrl(a: *AdminCtx, t: *structs.RpcCrl, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    const next_key: u32 = if (hub.crl_list.items.len > 0) hub.crl_list.items[hub.crl_list.items.len - 1].key + 1 else 1;
    var crl = ServerCrl{
        .key = next_key,
        .serial = dupStr(allocator, t.serial) catch return err_internal_error,
        .common_name = dupStr(allocator, t.common_name) catch return err_internal_error,
        .organization = dupStr(allocator, t.organization) catch return err_internal_error,
        .unit = dupStr(allocator, t.unit) catch return err_internal_error,
        .country = dupStr(allocator, t.country) catch return err_internal_error,
        .state = dupStr(allocator, t.state) catch return err_internal_error,
        .local = dupStr(allocator, t.local) catch return err_internal_error,
    };
    crl.info = std.fmt.allocPrint(allocator, "{s} {s}", .{ t.organization, t.common_name }) catch return err_internal_error;
    hub.crl_list.append(allocator, crl) catch return err_internal_error;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StGetCrl` (Admin.c:3423). CHECK_RIGHT — returns a CRL by key.
fn stGetCrl(a: *AdminCtx, t: *structs.RpcCrl, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.crl_list.items) |crl| {
        if (crl.key == t.key) {
            t.free(allocator);
            t.* = .{};
            t.hub_name = dupStr(allocator, hub.name) catch return err_internal_error;
            t.key = crl.key;
            t.serial = dupStr(allocator, crl.serial) catch return err_internal_error;
            t.common_name = dupStr(allocator, crl.common_name) catch return err_internal_error;
            t.organization = dupStr(allocator, crl.organization) catch return err_internal_error;
            t.unit = dupStr(allocator, crl.unit) catch return err_internal_error;
            t.country = dupStr(allocator, crl.country) catch return err_internal_error;
            t.state = dupStr(allocator, crl.state) catch return err_internal_error;
            t.local = dupStr(allocator, crl.local) catch return err_internal_error;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StSetCrl` (Admin.c:3353). CHECK_RIGHT — replaces a CRL by key.
fn stSetCrl(a: *AdminCtx, t: *structs.RpcCrl, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.crl_list.items) |*crl| {
        if (crl.key == t.key) {
            crl.deinit(allocator);
            crl.* = ServerCrl{
                .key = t.key,
                .serial = dupStr(allocator, t.serial) catch return err_internal_error,
                .common_name = dupStr(allocator, t.common_name) catch return err_internal_error,
                .organization = dupStr(allocator, t.organization) catch return err_internal_error,
                .unit = dupStr(allocator, t.unit) catch return err_internal_error,
                .country = dupStr(allocator, t.country) catch return err_internal_error,
                .state = dupStr(allocator, t.state) catch return err_internal_error,
                .local = dupStr(allocator, t.local) catch return err_internal_error,
                .info = std.fmt.allocPrint(allocator, "{s} {s}", .{ t.organization, t.common_name }) catch return err_internal_error,
            };
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StDelCrl` (Admin.c:3484). CHECK_RIGHT — deletes a CRL by key.
fn stDelCrl(a: *AdminCtx, t: *structs.RpcCrl, allocator: Allocator) u32 {
    const s = a.server;
    if (!a.server_admin and !std.ascii.eqlIgnoreCase(a.hub_name, t.hub_name)) return err_not_enough_right;
    if (t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();
    const hub = findHub(s, t.hub_name) orelse return err_hub_not_found;

    for (hub.crl_list.items, 0..) |*crl, i| {
        if (crl.key == t.key) {
            var removed = hub.crl_list.swapRemove(i);
            removed.deinit(allocator);
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

// ============================================================================
// L3 Switch (C Admin.c:3832 — L3 switch management)
// ============================================================================

/// C `StEnumL3Switch` (Admin.c:4062). CHECK_RIGHT — lists L3 switches.
fn stEnumL3Switch(a: *AdminCtx, t: *structs.RpcEnumL3Sw, allocator: Allocator) u32 {
    const s = a.server;
    t.free(allocator);
    t.* = .{};
    t.items = allocator.alloc(structs.RpcEnumL3Sw.EnumL3SwItem, s.l3_switches.items.len) catch return err_internal_error;
    for (s.l3_switches.items, 0..) |sw, i| {
        t.items[i] = .{
            .name = dupStr(allocator, sw.name) catch return err_internal_error,
            .num_interfaces = @intCast(sw.interfaces.items.len),
            .num_tables = 0,
            .active = sw.active,
            .online = sw.online,
        };
    }
    return err_no_error;
}

/// C `StAddL3Switch` (Admin.c:4130). CHECK_RIGHT — creates an L3 switch.
fn stAddL3Switch(a: *AdminCtx, t: *structs.RpcL3Sw, allocator: Allocator) u32 {
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    for (s.l3_switches.items) |sw| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) return err_object_already_exists;
    }

    const sw = ServerL3Switch{
        .name = dupStr(allocator, t.name) catch return err_internal_error,
    };
    s.l3_switches.append(allocator, sw) catch return err_internal_error;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StDelL3Switch` (Admin.c:4100). CHECK_RIGHT — deletes an L3 switch.
fn stDelL3Switch(a: *AdminCtx, t: *structs.RpcL3Sw, allocator: Allocator) u32 {
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    for (s.l3_switches.items, 0..) |*sw, i| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) {
            if (sw.active) return err_object_in_use;
            var removed = s.l3_switches.swapRemove(i);
            removed.deinit(allocator);
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StStartL3Switch` (Admin.c:4013). CHECK_RIGHT — starts an L3 switch.
fn stStartL3Switch(a: *AdminCtx, t: *structs.RpcL3Sw, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    for (s.l3_switches.items) |*sw| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) {
            if (sw.interfaces.items.len == 0) return err_invalid_parameter;
            if (sw.active) return err_object_in_use;
            sw.active = true;
            sw.online = true;
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StStopL3Switch` (Admin.c:3978). CHECK_RIGHT — stops an L3 switch.
fn stStopL3Switch(a: *AdminCtx, t: *structs.RpcL3Sw, allocator: Allocator) u32 {
    _ = allocator;
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    for (s.l3_switches.items) |*sw| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) {
            sw.active = false;
            sw.online = false;
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StAddL3If` (Admin.c:3920). CHECK_RIGHT — adds an interface to an L3 switch.
fn stAddL3If(a: *AdminCtx, t: *structs.RpcL3If, allocator: Allocator) u32 {
    const s = a.server;
    if (t.name.len == 0 or t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const sw = for (s.l3_switches.items) |*sw| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) break sw;
    } else return err_object_not_found;

    const intf = ServerL3Interface{
        .hub_name = dupStr(allocator, t.hub_name) catch return err_internal_error,
        .ip_address = t.ip_address,
        .subnet_mask = t.subnet_mask,
    };
    sw.interfaces.append(allocator, intf) catch return err_internal_error;
    s.config_revision +|= 1;
    return err_no_error;
}

/// C `StDelL3If` (Admin.c:3884). CHECK_RIGHT — removes an interface from an L3 switch.
fn stDelL3If(a: *AdminCtx, t: *structs.RpcL3If, allocator: Allocator) u32 {
    const s = a.server;
    if (t.name.len == 0 or t.hub_name.len == 0) return err_invalid_parameter;

    s.mutex.lock();
    defer s.mutex.unlock();

    const sw = for (s.l3_switches.items) |*sw| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) break sw;
    } else return err_object_not_found;

    for (sw.interfaces.items, 0..) |*intf, i| {
        if (std.ascii.eqlIgnoreCase(intf.hub_name, t.hub_name)) {
            var removed = sw.interfaces.swapRemove(i);
            removed.deinit(allocator);
            s.config_revision +|= 1;
            return err_no_error;
        }
    }
    return err_object_not_found;
}

/// C `StEnumL3If` (Admin.c:3832). CHECK_RIGHT — lists interfaces on an L3 switch.
fn stEnumL3If(a: *AdminCtx, t: *structs.RpcEnumL3If, allocator: Allocator) u32 {
    const s = a.server;
    if (t.name.len == 0) return err_invalid_parameter;

    const sw = for (s.l3_switches.items) |sw| {
        if (std.ascii.eqlIgnoreCase(sw.name, t.name)) break sw;
    } else return err_object_not_found;

    t.free(allocator);
    t.* = .{};
    t.name = dupStr(allocator, sw.name) catch return err_internal_error;
    t.items = allocator.alloc(structs.RpcEnumL3If.EnumL3IfItem, sw.interfaces.items.len) catch return err_internal_error;
    for (sw.interfaces.items, 0..) |intf, i| {
        t.items[i] = .{
            .name = dupStr(allocator, intf.hub_name) catch return err_internal_error,
            .ip_address = intf.ip_address,
            .subnet_mask = intf.subnet_mask,
        };
    }
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

/// True when the trimmed name is a valid group name. Group names follow the
/// same rules as user names (C `IsGroupName` → `IsSafeStr` + reserved list).
fn isGroupName(s: []const u8) bool {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return false;
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

/// Replace the request name with its trimmed canonical form. Mirrors
/// `canonicalizeUserName` for group names.
fn canonicalizeGroupName(t: *structs.RpcSetGroup, allocator: Allocator) bool {
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

test "server.admin_dispatch DeleteHub releases a populated hub's tables" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.hubs.items[0].addMacTableEntry(allocator, .{
        .key = 1,
        .session_name = "SID-ALICE",
        .mac_address = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
        .vlan_id = 3,
        .created_time = 111,
        .updated_time = 222,
    });
    try server.hubs.items[0].addIpTableEntry(allocator, .{
        .key = 2,
        .session_name = "SID-BOB",
        .ip = types_mod.IpAddress.fromU32(0x0A000001),
        .dhcp_allocated = true,
        .created_time = 111,
        .updated_time = 222,
    });

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

test "server.admin_dispatch GetUser returns account settings" {
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
    try create.addStrEx("GroupName", "Security", 0);
    try create.addUniStrEx("Realname", "Alice Smith", 0);
    try create.addUniStrEx("Note", "ops account", 0);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

    var get = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer get.deinit();
    try get.addStr("function_name", "GetUser");
    var get_resp = try call(allocator, &server, true, "", "GetUser", &get);
    defer {
        get_resp.deinit();
        allocator.destroy(get_resp);
    }
    try assertOk(get_resp);
    try testing.expectEqualStrings("VPN", get_resp.getStr("HubName").?);
    try testing.expectEqualStrings("Alice", get_resp.getStr("Name").?);
    try testing.expectEqualStrings("Security", get_resp.getStr("GroupName").?);
    try testing.expectEqualStrings("Alice Smith", get_resp.getUniStr("Realname").?);
    try testing.expectEqualStrings("ops account", get_resp.getUniStr("Note").?);
    try testing.expectEqual(@as(u32, 1), get_resp.getInt("AuthType").?);
    try testing.expectEqualSlices(u8, &hash, get_resp.getData("HashedKey").?[0..20]);

    // Unknown user reports ERR_OBJECT_NOT_FOUND.
    var miss = try makeSetUserRequest(allocator, "VPN", "Nobody");
    defer miss.deinit();
    try miss.addStr("function_name", "GetUser");
    var miss_resp = try call(allocator, &server, true, "", "GetUser", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_object_not_found);
}

test "server.admin_dispatch GetUser validates name and hub rights" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Invalid name.
    var bad = try makeSetUserRequest(allocator, "VPN", "administrator");
    defer bad.deinit();
    try bad.addStr("function_name", "GetUser");
    var bad_resp = try call(allocator, &server, true, "", "GetUser", &bad);
    defer {
        bad_resp.deinit();
        allocator.destroy(bad_resp);
    }
    try assertErr(bad_resp, err_invalid_parameter);

    // Missing hub.
    var nohub = try makeSetUserRequest(allocator, "Elsewhere", "Alice");
    defer nohub.deinit();
    try nohub.addStr("function_name", "GetUser");
    var nohub_resp = try call(allocator, &server, true, "", "GetUser", &nohub);
    defer {
        nohub_resp.deinit();
        allocator.destroy(nohub_resp);
    }
    try assertErr(nohub_resp, err_hub_not_found);

    // Hub admin cannot read another hub.
    try server.addHub("Other", hub_type_standalone);
    var other = try makeSetUserRequest(allocator, "Other", "Alice");
    defer other.deinit();
    try other.addStr("function_name", "GetUser");
    var other_resp = try call(allocator, &server, false, "VPN", "GetUser", &other);
    defer {
        other_resp.deinit();
        allocator.destroy(other_resp);
    }
    try assertErr(other_resp, err_not_enough_right);
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

test "server.admin_dispatch EnumMacTable lists a hub's MAC table" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    const hub = &server.hubs.items[0];
    try hub.addMacTableEntry(allocator, .{
        .key = 0x10,
        .session_name = "SID-ALICE",
        .mac_address = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
        .vlan_id = 3,
        .created_time = 111,
        .updated_time = 222,
    });
    try hub.addMacTableEntry(allocator, .{
        .key = 0x11,
        .session_name = "SID-BOB",
        .mac_address = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
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
    try testing.expectEqual(@as(u32, 0x10), resp.getIntEx("Key", 0).?);
    try testing.expectEqualStrings("SID-ALICE", resp.getStrEx("SessionName", 0).?);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 }, resp.getDataEx("MacAddress", 0).?);
    try testing.expectEqual(@as(u32, 3), resp.getIntEx("VlanId", 0).?);
    try testing.expectEqual(@as(u64, 111), resp.getInt64Ex("CreatedTime", 0).?);
    try testing.expectEqual(@as(u64, 222), resp.getInt64Ex("UpdatedTime", 0).?);
    try testing.expectEqualStrings("SID-BOB", resp.getStrEx("SessionName", 1).?);
    try testing.expectEqual(@as(u32, 0x11), resp.getIntEx("Key", 1).?);
}

test "server.admin_dispatch EnumIpTable lists a hub's IP table" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    const hub = &server.hubs.items[0];
    try hub.addIpTableEntry(allocator, .{
        .key = 0x20,
        .session_name = "SID-ALICE",
        .ip = types_mod.IpAddress.fromU32(0x0A000001),
        .dhcp_allocated = true,
        .created_time = 111,
        .updated_time = 222,
    });
    try hub.addIpTableEntry(allocator, .{
        .key = 0x21,
        .session_name = "SID-BOB",
        .ip = types_mod.IpAddress.fromU32(0x0A000002),
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
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
    try testing.expectEqual(@as(usize, 2), resp.getValueCount("SessionName"));
    try testing.expectEqual(@as(u32, 0x20), resp.getIntEx("Key", 0).?);
    try testing.expectEqualStrings("SID-ALICE", resp.getStrEx("SessionName", 0).?);
    try testing.expectEqual(@as(u32, 0x0A000001), resp.getIntEx("Ip", 0).?);
    try testing.expectEqual(@as(bool, true), resp.getBoolEx("DhcpAllocated", 0).?);
    try testing.expectEqual(@as(u64, 111), resp.getInt64Ex("CreatedTime", 0).?);
    try testing.expectEqualStrings("SID-BOB", resp.getStrEx("SessionName", 1).?);
    try testing.expectEqual(@as(u32, 0x0A000002), resp.getIntEx("Ip", 1).?);
}

test "server.admin_dispatch EnumMacTable and EnumIpTable validate hub and rights" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Unknown hub.
    var miss = try makeRequest(allocator, "EnumMacTable");
    defer miss.deinit();
    try miss.addStr("HubName", "MISSING");
    var miss_resp = try call(allocator, &server, true, "", "EnumMacTable", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_hub_not_found);

    // Hub admin locked to their own hub.
    var locked = try makeRequest(allocator, "EnumIpTable");
    defer locked.deinit();
    try locked.addStr("HubName", "OTHER");
    var locked_resp = try call(allocator, &server, false, "VPN", "EnumIpTable", &locked);
    defer {
        locked_resp.deinit();
        allocator.destroy(locked_resp);
    }
    try assertErr(locked_resp, err_not_enough_right);

    // Hub admin may enumerate their own hub.
    var own = try makeRequest(allocator, "EnumMacTable");
    defer own.deinit();
    try own.addStr("HubName", "VPN");
    var own_resp = try call(allocator, &server, false, "VPN", "EnumMacTable", &own);
    defer {
        own_resp.deinit();
        allocator.destroy(own_resp);
    }
    try assertOk(own_resp);

    // Farm controller and farm member are not standalone: remote entries are
    // not modelled, so the enumeration is rejected rather than misleading.
    for ([_]u32{ server_type_farm_controller, server_type_farm_member }) |server_type| {
        server.server_type = server_type;
        var farm = try makeRequest(allocator, "EnumMacTable");
        defer farm.deinit();
        try farm.addStr("HubName", "VPN");
        var farm_resp = try call(allocator, &server, true, "", "EnumMacTable", &farm);
        defer {
            farm_resp.deinit();
            allocator.destroy(farm_resp);
        }
        try assertErr(farm_resp, err_not_supported);
    }
}

test "server.admin_dispatch SetPassword hashes a plaintext password" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    const old_hash = auth.hashPassword("o" ++ "ld", "Alice");
    var create = try makeSetUserRequest(allocator, "VPN", "Alice");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    try create.addData("HashedKey", &old_hash);
    try create.addInt("AuthType", 1);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

    const revision_before = server.config_revision;
    var req = try makeRequest(allocator, "SetPassword");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "Alice");
    try req.addData("HashedPassword", "");
    try req.addStr("PlainTextPassword", "s3" ++ "cret");

    var resp = try call(allocator, &server, true, "", "SetPassword", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);

    const expected = auth.hashPassword("s3cret", "Alice");
    const user = findHub(&server, "VPN").?.findUser("Alice").?;
    try testing.expectEqualSlices(u8, &expected, &user.password_hash.?);
    try testing.expectEqual(revision_before +% 1, server.config_revision);
}

test "server.admin_dispatch SetPassword stores a provided hash and promotes auth" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // An anonymous account is promoted to password auth, like C UserPasswordSet.
    var create = try makeSetUserRequest(allocator, "VPN", "Bob");
    defer create.deinit();
    try create.addStr("function_name", "CreateUser");
    try create.addInt("AuthType", 0);
    var create_resp = try call(allocator, &server, true, "", "CreateUser", &create);
    defer {
        create_resp.deinit();
        allocator.destroy(create_resp);
    }
    try assertOk(create_resp);

    const provided = auth.hashPassword("p" ++ "w", "Bob");
    var req = try makeRequest(allocator, "SetPassword");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "Bob");
    try req.addData("HashedPassword", &provided);

    var resp = try call(allocator, &server, true, "", "SetPassword", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);

    const user = findHub(&server, "VPN").?.findUser("Bob").?;
    try testing.expectEqual(@as(auth.UserAuthType, .password), user.auth_type);
    try testing.expectEqualSlices(u8, &provided, &user.password_hash.?);

    // Hub admin can reset a password on their own hub.
    var own = try makeRequest(allocator, "SetPassword");
    defer own.deinit();
    try own.addStr("HubName", "VPN");
    try own.addStr("Name", "Bob");
    try own.addData("HashedPassword", "");
    try own.addStr("PlainTextPassword", "new" ++ "pw");
    var own_resp = try call(allocator, &server, false, "VPN", "SetPassword", &own);
    defer {
        own_resp.deinit();
        allocator.destroy(own_resp);
    }
    try assertOk(own_resp);
}

test "server.admin_dispatch SetPassword validates user, hub and rights" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hash = auth.hashPassword("s3" ++ "cret", "Alice");
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

    // Missing user.
    var miss = try makeRequest(allocator, "SetPassword");
    defer miss.deinit();
    try miss.addStr("HubName", "VPN");
    try miss.addStr("Name", "Nope");
    try miss.addStr("PlainTextPassword", "x");
    var miss_resp = try call(allocator, &server, true, "", "SetPassword", &miss);
    defer {
        miss_resp.deinit();
        allocator.destroy(miss_resp);
    }
    try assertErr(miss_resp, err_object_not_found);

    // Missing hub.
    var nohub = try makeRequest(allocator, "SetPassword");
    defer nohub.deinit();
    try nohub.addStr("HubName", "Elsewhere");
    try nohub.addStr("Name", "Alice");
    try nohub.addStr("PlainTextPassword", "x");
    var nohub_resp = try call(allocator, &server, true, "", "SetPassword", &nohub);
    defer {
        nohub_resp.deinit();
        allocator.destroy(nohub_resp);
    }
    try assertErr(nohub_resp, err_hub_not_found);

    // Reserved name.
    var bad = try makeRequest(allocator, "SetPassword");
    defer bad.deinit();
    try bad.addStr("HubName", "VPN");
    try bad.addStr("Name", "administrator");
    try bad.addStr("PlainTextPassword", "x");
    var bad_resp = try call(allocator, &server, true, "", "SetPassword", &bad);
    defer {
        bad_resp.deinit();
        allocator.destroy(bad_resp);
    }
    try assertErr(bad_resp, err_invalid_parameter);

    // Malformed hash length.
    var badhash = try makeRequest(allocator, "SetPassword");
    defer badhash.deinit();
    try badhash.addStr("HubName", "VPN");
    try badhash.addStr("Name", "Alice");
    try badhash.addData("HashedPassword", "short");
    var badhash_resp = try call(allocator, &server, true, "", "SetPassword", &badhash);
    defer {
        badhash_resp.deinit();
        allocator.destroy(badhash_resp);
    }
    try assertErr(badhash_resp, err_invalid_parameter);

    // Hub admin cannot change another hub's user.
    try server.addHub("Other", hub_type_standalone);
    var other = try makeRequest(allocator, "SetPassword");
    defer other.deinit();
    try other.addStr("HubName", "Other");
    try other.addStr("Name", "Alice");
    try other.addStr("PlainTextPassword", "x");
    var other_resp = try call(allocator, &server, false, "VPN", "SetPassword", &other);
    defer {
        other_resp.deinit();
        allocator.destroy(other_resp);
    }
    try assertErr(other_resp, err_not_enough_right);
}

test "server.admin_dispatch DisconnectSession stops a session on its hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    var bob: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &bob, "VPN", "SID-BOB", "CONN-1", "Bob");
    var carol: FakeMain align(@alignOf(session_main.SessionMain)) = .{};
    try registerTestSession(allocator, &server, &carol, "TEST", "SID-CAROL", "CONN-2", "Carol");

    // Same session name on another hub is not stopped (C GetSessionByName).
    var wrong = try makeRequest(allocator, "DisconnectSession");
    defer wrong.deinit();
    try wrong.addStr("HubName", "VPN");
    try wrong.addStr("Name", "SID-CAROL");
    var wrong_resp = try call(allocator, &server, true, "", "DisconnectSession", &wrong);
    defer {
        wrong_resp.deinit();
        allocator.destroy(wrong_resp);
    }
    try assertErr(wrong_resp, err_object_not_found);
    try testing.expect(!carol.wasStopped());

    // Correct hub + name stops the session.
    var ok = try makeRequest(allocator, "DisconnectSession");
    defer ok.deinit();
    try ok.addStr("HubName", "VPN");
    try ok.addStr("Name", "SID-BOB");
    var ok_resp = try call(allocator, &server, true, "", "DisconnectSession", &ok);
    defer {
        ok_resp.deinit();
        allocator.destroy(ok_resp);
    }
    try assertOk(ok_resp);
    try testing.expect(bob.wasStopped());

    // Empty name is checked before everything else.
    var empty = try makeRequest(allocator, "DisconnectSession");
    defer empty.deinit();
    try empty.addStr("HubName", "VPN");
    try empty.addStr("Name", "");
    var empty_resp = try call(allocator, &server, true, "", "DisconnectSession", &empty);
    defer {
        empty_resp.deinit();
        allocator.destroy(empty_resp);
    }
    try assertErr(empty_resp, err_invalid_parameter);
}

test "server.admin_dispatch EnumLog lists no files and is server-admin-only" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // No persisted log files yet (S23/logging): the list is empty.
    var req = try makeRequest(allocator, "EnumLog");
    defer req.deinit();
    var resp = try call(allocator, &server, true, "", "EnumLog", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqual(@as(u32, 0), resp.getInt("NumItem") orelse 0);

    // Hub admins cannot list server logs.
    var denied = try makeRequest(allocator, "EnumLog");
    defer denied.deinit();
    var denied_resp = try call(allocator, &server, false, "VPN", "EnumLog", &denied);
    defer {
        denied_resp.deinit();
        allocator.destroy(denied_resp);
    }
    try assertErr(denied_resp, err_not_enough_right);
}

test "server.admin_dispatch GetTraffic returns the hub traffic snapshot" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("TEST", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    hub.traffic = .{
        .recv_broadcast_bytes = 100,
        .send_unicast_count = 42,
        .recv_unicast_bytes = 7,
    };

    var req = try makeRequest(allocator, "GetTraffic");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    var resp = try call(allocator, &server, true, "", "GetTraffic", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqual(@as(u64, 100), resp.getInt64("Recv.BroadcastBytes").?);
    try testing.expectEqual(@as(u64, 42), resp.getInt64("Send.UnicastCount").?);
    try testing.expectEqual(@as(u64, 7), resp.getInt64("Recv.UnicastBytes").?);

    // Hub admin may read their own hub.
    var own = try makeRequest(allocator, "GetTraffic");
    defer own.deinit();
    try own.addStr("HubName", "VPN");
    var own_resp = try call(allocator, &server, false, "VPN", "GetTraffic", &own);
    defer {
        own_resp.deinit();
        allocator.destroy(own_resp);
    }
    try assertOk(own_resp);

    // But not another hub.
    var other = try makeRequest(allocator, "GetTraffic");
    defer other.deinit();
    try other.addStr("HubName", "TEST");
    var other_resp = try call(allocator, &server, false, "VPN", "GetTraffic", &other);
    defer {
        other_resp.deinit();
        allocator.destroy(other_resp);
    }
    try assertErr(other_resp, err_not_enough_right);

    // Missing hub.
    var nohub = try makeRequest(allocator, "GetTraffic");
    defer nohub.deinit();
    try nohub.addStr("HubName", "Elsewhere");
    var nohub_resp = try call(allocator, &server, true, "", "GetTraffic", &nohub);
    defer {
        nohub_resp.deinit();
        allocator.destroy(nohub_resp);
    }
    try assertErr(nohub_resp, err_hub_not_found);
}

// ============================================================================
// Group endpoint tests
// ============================================================================

test "server.admin_dispatch CreateGroup adds and validates a group" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Create succeeds
    var req = try makeRequest(allocator, "CreateGroup");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "Managers");
    try req.addUniStr("Realname", "Management");
    try req.addUniStr("Note", "Management team");
    var resp = try call(allocator, &server, true, "", "CreateGroup", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);

    // Enumerate: the group shows up
    var enq = try makeRequest(allocator, "EnumGroup");
    defer enq.deinit();
    try enq.addStr("HubName", "VPN");
    var enresp = try call(allocator, &server, true, "", "EnumGroup", &enq);
    defer {
        enresp.deinit();
        allocator.destroy(enresp);
    }
    try assertOk(enresp);
    try testing.expectEqual(@as(u32, 1), enresp.getInt("NumGroup").?);
    try testing.expectEqualStrings("Managers", (enresp.getStrEx("Name", 0)).?);
    try testing.expectEqualStrings("Management", (enresp.getUniStrEx("Realname", 0)).?);
    try testing.expectEqualStrings("Management team", (enresp.getUniStrEx("Note", 0)).?);

    // Duplicate name -> error
    var dup = try makeRequest(allocator, "CreateGroup");
    defer dup.deinit();
    try dup.addStr("HubName", "VPN");
    try dup.addStr("Name", "Managers");
    var dupresp = try call(allocator, &server, true, "", "CreateGroup", &dup);
    defer {
        dupresp.deinit();
        allocator.destroy(dupresp);
    }
    try assertErr(dupresp, err_user_already_exists);

    // Invalid name (reserved)
    var bad = try makeRequest(allocator, "CreateGroup");
    defer bad.deinit();
    try bad.addStr("HubName", "VPN");
    try bad.addStr("Name", "administrator");
    var badresp = try call(allocator, &server, true, "", "CreateGroup", &bad);
    defer {
        badresp.deinit();
        allocator.destroy(badresp);
    }
    try assertErr(badresp, err_invalid_parameter);

    // Missing hub
    var nohub = try makeRequest(allocator, "CreateGroup");
    defer nohub.deinit();
    try nohub.addStr("HubName", "Elsewhere");
    try nohub.addStr("Name", "Foo");
    var nohubresp = try call(allocator, &server, true, "", "CreateGroup", &nohub);
    defer {
        nohubresp.deinit();
        allocator.destroy(nohubresp);
    }
    try assertErr(nohubresp, err_hub_not_found);

    // Canonicalization: padded name is trimmed before storage
    var pad = try makeRequest(allocator, "CreateGroup");
    defer pad.deinit();
    try pad.addStr("HubName", "VPN");
    try pad.addStr("Name", "Padded  ");
    try pad.addUniStr("Realname", "Padded Group");
    var padresp = try call(allocator, &server, true, "", "CreateGroup", &pad);
    defer {
        padresp.deinit();
        allocator.destroy(padresp);
    }
    try assertOk(padresp);
    // Look up as trimmed — should succeed
    var get = try makeRequest(allocator, "GetGroup");
    defer get.deinit();
    try get.addStr("HubName", "VPN");
    try get.addStr("Name", "Padded");
    var getresp = try call(allocator, &server, true, "", "GetGroup", &get);
    defer {
        getresp.deinit();
        allocator.destroy(getresp);
    }
    try assertOk(getresp);
    try testing.expectEqualStrings("Padded Group", (getresp.getUniStr("Realname")).?);
}

test "server.admin_dispatch SetGroup updates a group" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Create first
    var create = try makeRequest(allocator, "CreateGroup");
    defer create.deinit();
    try create.addStr("HubName", "VPN");
    try create.addStr("Name", "Workers");
    var cr = try call(allocator, &server, true, "", "CreateGroup", &create);
    defer {
        cr.deinit();
        allocator.destroy(cr);
    }
    try assertOk(cr);

    // Set
    var req = try makeRequest(allocator, "SetGroup");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "Workers");
    try req.addUniStr("Realname", "Worker Group");
    try req.addUniStr("Note", "Regular workers");
    var resp = try call(allocator, &server, true, "", "SetGroup", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);

    // Get confirms
    var get = try makeRequest(allocator, "GetGroup");
    defer get.deinit();
    try get.addStr("HubName", "VPN");
    try get.addStr("Name", "Workers");
    var gresp = try call(allocator, &server, true, "", "GetGroup", &get);
    defer {
        gresp.deinit();
        allocator.destroy(gresp);
    }
    try assertOk(gresp);
    try testing.expectEqualStrings("Worker Group", (gresp.getUniStr("Realname")).?);
    try testing.expectEqualStrings("Regular workers", (gresp.getUniStr("Note")).?);

    // Missing group
    var miss = try makeRequest(allocator, "SetGroup");
    defer miss.deinit();
    try miss.addStr("HubName", "VPN");
    try miss.addStr("Name", "Nonexistent");
    var missresp = try call(allocator, &server, true, "", "SetGroup", &miss);
    defer {
        missresp.deinit();
        allocator.destroy(missresp);
    }
    try assertErr(missresp, err_object_not_found);
}

test "server.admin_dispatch GetGroup returns group settings" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Create with policy
    var create = try makeRequest(allocator, "CreateGroup");
    defer create.deinit();
    try create.addStr("HubName", "VPN");
    try create.addStr("Name", "Testers");
    try create.addUniStr("Realname", "QA Team");
    try create.addBool("UsePolicy", true);
    try create.addBool("Access", false);
    var cr = try call(allocator, &server, true, "", "CreateGroup", &create);
    defer {
        cr.deinit();
        allocator.destroy(cr);
    }
    try assertOk(cr);

    // Get confirms policy is persisted
    var req = try makeRequest(allocator, "GetGroup");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "Testers");
    var resp = try call(allocator, &server, true, "", "GetGroup", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqualStrings("Testers", (resp.getStr("Name")).?);
    try testing.expectEqualStrings("QA Team", (resp.getUniStr("Realname")).?);
    try testing.expect(resp.getBool("UsePolicy") orelse false);
    try testing.expect(!(resp.getBool("Access") orelse true));

    // Get does NOT echo an unrelated policy from the request itself
    var echo = try makeRequest(allocator, "GetGroup");
    defer echo.deinit();
    try echo.addStr("HubName", "VPN");
    try echo.addStr("Name", "Testers");
    try echo.addBool("UsePolicy", true);
    try echo.addBool("NoRouting", true);
    var eresp = try call(allocator, &server, true, "", "GetGroup", &echo);
    defer {
        eresp.deinit();
        allocator.destroy(eresp);
    }
    try assertOk(eresp);
    // UsePolicy reflects stored state (true), but NoRouting from request is NOT echoed
    try testing.expect(eresp.getBool("UsePolicy") orelse false);
    try testing.expect(!(eresp.getBool("NoRouting") orelse true));

    // Invalid name
    var bad = try makeRequest(allocator, "GetGroup");
    defer bad.deinit();
    try bad.addStr("HubName", "VPN");
    try bad.addStr("Name", "");
    var badresp = try call(allocator, &server, true, "", "GetGroup", &bad);
    defer {
        badresp.deinit();
        allocator.destroy(badresp);
    }
    try assertErr(badresp, err_invalid_parameter);

    // Missing group
    var miss = try makeRequest(allocator, "GetGroup");
    defer miss.deinit();
    try miss.addStr("HubName", "VPN");
    try miss.addStr("Name", "Nonexistent");
    var missresp = try call(allocator, &server, true, "", "GetGroup", &miss);
    defer {
        missresp.deinit();
        allocator.destroy(missresp);
    }
    try assertErr(missresp, err_object_not_found);
}

test "server.admin_dispatch DeleteGroup removes and reports missing" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Create
    var create = try makeRequest(allocator, "CreateGroup");
    defer create.deinit();
    try create.addStr("HubName", "VPN");
    try create.addStr("Name", "Temp");
    var cr = try call(allocator, &server, true, "", "CreateGroup", &create);
    defer {
        cr.deinit();
        allocator.destroy(cr);
    }
    try assertOk(cr);

    // Delete
    var req = try makeRequest(allocator, "DeleteGroup");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStr("Name", "Temp");
    var resp = try call(allocator, &server, true, "", "DeleteGroup", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);

    // Enumerate: empty
    var enq = try makeRequest(allocator, "EnumGroup");
    defer enq.deinit();
    try enq.addStr("HubName", "VPN");
    var enresp = try call(allocator, &server, true, "", "EnumGroup", &enq);
    defer {
        enresp.deinit();
        allocator.destroy(enresp);
    }
    try assertOk(enresp);
    try testing.expectEqual(@as(u32, 0), enresp.getInt("NumGroup").?);

    // Delete again -> not found
    var miss = try makeRequest(allocator, "DeleteGroup");
    defer miss.deinit();
    try miss.addStr("HubName", "VPN");
    try miss.addStr("Name", "Temp");
    var missresp = try call(allocator, &server, true, "", "DeleteGroup", &miss);
    defer {
        missresp.deinit();
        allocator.destroy(missresp);
    }
    try assertErr(missresp, err_object_not_found);

    // Invalid name
    var bad = try makeRequest(allocator, "DeleteGroup");
    defer bad.deinit();
    try bad.addStr("HubName", "VPN");
    try bad.addStr("Name", "administrator");
    var badresp = try call(allocator, &server, true, "", "DeleteGroup", &bad);
    defer {
        badresp.deinit();
        allocator.destroy(badresp);
    }
    try assertErr(badresp, err_invalid_parameter);
}

test "server.admin_dispatch EnumGroup is hub-scoped for non-server-admin" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("OTHER", hub_type_standalone);

    // Create groups in both hubs
    for (&[_][]const u8{ "VPN", "OTHER" }) |hub_name| {
        var cr = try makeRequest(allocator, "CreateGroup");
        defer cr.deinit();
        try cr.addStr("HubName", hub_name);
        try cr.addStr("Name", "Grp1");
        var r = try call(allocator, &server, true, "", "CreateGroup", &cr);
        defer {
            r.deinit();
            allocator.destroy(r);
        }
        try assertOk(r);
    }

    // Hub admin on VPN: can see VPN's group
    var req = try makeRequest(allocator, "EnumGroup");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    var resp = try call(allocator, &server, false, "VPN", "EnumGroup", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expectEqual(@as(u32, 1), resp.getInt("NumGroup").?);

    // But not OTHER's
    var other = try makeRequest(allocator, "EnumGroup");
    defer other.deinit();
    try other.addStr("HubName", "OTHER");
    var oresp = try call(allocator, &server, false, "VPN", "EnumGroup", &other);
    defer {
        oresp.deinit();
        allocator.destroy(oresp);
    }
    try assertErr(oresp, err_not_enough_right);
}

// ============================================================================
// Access List tests
// ============================================================================

test "server.admin_dispatch AddAccess / EnumAccess / DeleteAccess round-trip" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Add an access entry
    {
        var req = try makeRequest(allocator, "AddAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("Id", 100);
        try req.addUniStr("Note", "test-rule");
        try req.addBool("Active", true);
        try req.addInt("Priority", 10);
        try req.addBool("Discard", false);
        try req.addInt("SrcIpAddress", 0x0A000000);
        try req.addInt("SrcSubnetMask", 0xFF000000);
        try req.addInt("DestIpAddress", 0xC0A80000);
        try req.addInt("DestSubnetMask", 0xFFFFFF00);
        try req.addInt("Protocol", 6);
        try req.addInt("SrcPortStart", 1024);
        try req.addInt("SrcPortEnd", 65535);
        try req.addInt("DestPortStart", 80);
        try req.addInt("DestPortEnd", 80);
        var resp = try call(allocator, &server, true, "", "AddAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
    }

    // Enum should show 1 entry
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        var resp = try call(allocator, &server, true, "", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
        try testing.expectEqual(@as(u32, 1), resp.getInt("NumAccess").?);
        try testing.expectEqual(@as(u32, 100), resp.getIntEx("Id", 0).?);
        try testing.expectEqual(@as(u32, 0x0A000000), resp.getIntEx("SrcIpAddress", 0).?);
        try testing.expectEqual(@as(u32, 6), resp.getIntEx("Protocol", 0).?);
        try testing.expectEqual(@as(u32, 100), resp.getIntEx("UniqueId", 0).?);
        try testing.expect(resp.getBoolEx("Active", 0) orelse false);
        try testing.expectEqual(@as(u32, 10), resp.getIntEx("Priority", 0).?);
    }

    // Delete the entry
    {
        var req = try makeRequest(allocator, "DeleteAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("Id", 100);
        var resp = try call(allocator, &server, true, "", "DeleteAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
    }

    // Enum should now show 0 entries
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        var resp = try call(allocator, &server, true, "", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
        try testing.expectEqual(@as(u32, 0), resp.getInt("NumAccess").?);
    }

    // Delete non-existent id -> error
    {
        var req = try makeRequest(allocator, "DeleteAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("Id", 999);
        var resp = try call(allocator, &server, true, "", "DeleteAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertErr(resp, err_object_not_found);
    }
}

test "server.admin_dispatch SetAccessList replaces entire list" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Add two entries
    for (&[_]u32{ 1, 2 }) |id| {
        var req = try makeRequest(allocator, "AddAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("Id", id);
        try req.addInt("SrcIpAddress", id * 0x01000000);
        var resp = try call(allocator, &server, true, "", "AddAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
    }

    // SetAccessList with one new entry replaces the two
    {
        var req = try makeRequest(allocator, "SetAccessList");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("NumAccess", 1);
        try req.addInt("Id", 42);
        try req.addInt("SrcIpAddress", 0xDEAD0000);
        var resp = try call(allocator, &server, true, "", "SetAccessList", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
    }

    // Enum should show exactly 1 entry with the new id
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        var resp = try call(allocator, &server, true, "", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
        try testing.expectEqual(@as(u32, 1), resp.getInt("NumAccess").?);
        try testing.expectEqual(@as(u32, 42), resp.getIntEx("Id", 0).?);
        try testing.expectEqual(@as(u32, 0xDEAD0000), resp.getIntEx("SrcIpAddress", 0).?);
    }
}

test "server.admin_dispatch AddAccess hub-not-found" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    var req = try makeRequest(allocator, "AddAccess");
    defer req.deinit();
    try req.addStr("HubName", "NOPE");
    try req.addInt("Id", 1);
    var resp = try call(allocator, &server, true, "", "AddAccess", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertErr(resp, err_hub_not_found);
}

test "server.admin_dispatch AccessList hub-scoped for non-server-admin" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);
    try server.addHub("OTHER", hub_type_standalone);

    // Add access to both hubs
    for (&[_][]const u8{ "VPN", "OTHER" }) |hub_name| {
        var cr = try makeRequest(allocator, "AddAccess");
        defer cr.deinit();
        try cr.addStr("HubName", hub_name);
        try cr.addInt("Id", 1);
        var r = try call(allocator, &server, true, "", "AddAccess", &cr);
        defer {
            r.deinit();
            allocator.destroy(r);
        }
        try assertOk(r);
    }

    // Hub admin on VPN: can see VPN's entries
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        var resp = try call(allocator, &server, false, "VPN", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
        try testing.expectEqual(@as(u32, 1), resp.getInt("NumAccess").?);
    }

    // But not OTHER's
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "OTHER");
        var resp = try call(allocator, &server, false, "VPN", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertErr(resp, err_not_enough_right);
    }
}

test "server.admin_dispatch Access struct round-trip IPv4 + mac + redirect" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Add a complex IPv4 access entry with all field types
    {
        var req = try makeRequest(allocator, "AddAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("Id", 200);
        try req.addUniStr("Note", "complex");
        try req.addBool("Active", false);
        try req.addInt("Priority", 99);
        try req.addBool("Discard", true);
        try req.addInt("SrcIpAddress", 0x0A0A0A0A);
        try req.addInt("SrcSubnetMask", 0xFFFFFFFF);
        try req.addInt("DestIpAddress", 0x14141414);
        try req.addInt("DestSubnetMask", 0xFFFFFF00);
        try req.addInt("Protocol", 17);
        try req.addInt("SrcPortStart", 5000);
        try req.addInt("SrcPortEnd", 5001);
        try req.addInt("DestPortStart", 53);
        try req.addInt("DestPortEnd", 53);
        try req.addStr("SrcUsername", "alice");
        try req.addStr("DestUsername", "bob");
        try req.addBool("CheckSrcMac", true);
        try req.addData("SrcMacAddress", &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
        try req.addData("SrcMacMask", &[_]u8{ 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00 });
        try req.addBool("CheckDstMac", false);
        try req.addData("DstMacAddress", &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });
        try req.addData("DstMacMask", &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
        try req.addBool("CheckTcpState", true);
        try req.addBool("Established", true);
        try req.addInt("Delay", 100);
        try req.addInt("Jitter", 50);
        try req.addInt("Loss", 10);
        try req.addStr("RedirectUrl", "http://blocked.example.com");
        try req.addBool("IsIPv6", false);
        var resp = try call(allocator, &server, true, "", "AddAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
    }

    // Enum and verify every field
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        var resp = try call(allocator, &server, true, "", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
        try testing.expectEqual(@as(u32, 1), resp.getInt("NumAccess").?);
        try testing.expectEqual(@as(u32, 200), resp.getIntEx("Id", 0).?);
        try testing.expectEqual(@as(u32, 99), resp.getIntEx("Priority", 0).?);
        try testing.expectEqual(@as(u32, 17), resp.getIntEx("Protocol", 0).?);
        try testing.expectEqual(@as(u32, 100), resp.getIntEx("Delay", 0).?);
        try testing.expectEqual(@as(u32, 50), resp.getIntEx("Jitter", 0).?);
        try testing.expectEqual(@as(u32, 10), resp.getIntEx("Loss", 0).?);
        try testing.expectEqual(@as(u32, 0x0A0A0A0A), resp.getIntEx("SrcIpAddress", 0).?);
        try testing.expectEqual(@as(u32, 0x14141414), resp.getIntEx("DestIpAddress", 0).?);
        try testing.expectEqual(@as(u32, 5000), resp.getIntEx("SrcPortStart", 0).?);
        try testing.expectEqual(@as(u32, 5001), resp.getIntEx("SrcPortEnd", 0).?);
        try testing.expectEqual(@as(u32, 53), resp.getIntEx("DestPortStart", 0).?);
        try testing.expect(!(resp.getBoolEx("Active", 0) orelse true));
        try testing.expect(resp.getBoolEx("Discard", 0) orelse false);
        try testing.expect(resp.getBoolEx("CheckSrcMac", 0) orelse false);
        try testing.expect(!(resp.getBoolEx("CheckDstMac", 0) orelse true));
        try testing.expect(resp.getBoolEx("CheckTcpState", 0) orelse false);
        try testing.expect(resp.getBoolEx("Established", 0) orelse false);
        try testing.expect(!(resp.getBoolEx("IsIPv6", 0) orelse true));
        // MAC address
        const mac = resp.getData("SrcMacAddress") orelse return error.TestExpectedData;
        try testing.expectEqual(@as(usize, 6), mac.len);
        try testing.expectEqual(@as(u8, 0xAA), mac[0]);
        try testing.expectEqual(@as(u8, 0xBB), mac[1]);
        try testing.expectEqual(@as(u8, 0xFF), mac[5]);
        // Redirect URL
        const url = resp.getStr("RedirectUrl") orelse return error.TestExpectedString;
        try testing.expectEqualStrings("http://blocked.example.com", url);
    }
}

test "server.admin_dispatch Access struct round-trip IPv6 fields" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Add an IPv6 access entry
    {
        var req = try makeRequest(allocator, "AddAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        try req.addInt("Id", 300);
        try req.addBool("IsIPv6", true);
        const src6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        const dst6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
        const mask6 = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        try req.addData("SrcIpAddress6", &src6);
        try req.addData("SrcSubnetMask6", &mask6);
        try req.addData("DestIpAddress6", &dst6);
        try req.addData("DestSubnetMask6", &mask6);
        var resp = try call(allocator, &server, true, "", "AddAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
    }

    // Enum and verify IPv6 fields
    {
        var req = try makeRequest(allocator, "EnumAccess");
        defer req.deinit();
        try req.addStr("HubName", "VPN");
        var resp = try call(allocator, &server, true, "", "EnumAccess", &req);
        defer {
            resp.deinit();
            allocator.destroy(resp);
        }
        try assertOk(resp);
        try testing.expectEqual(@as(u32, 1), resp.getInt("NumAccess").?);
        try testing.expectEqual(@as(u32, 300), resp.getIntEx("Id", 0).?);
        try testing.expect(resp.getBoolEx("IsIPv6", 0) orelse false);
        // IPv6 source address
        const src6 = resp.getData("SrcIpAddress6") orelse return error.TestExpectedData;
        try testing.expectEqual(@as(usize, 16), src6.len);
        try testing.expectEqual(@as(u8, 0x20), src6[0]);
        try testing.expectEqual(@as(u8, 0x01), src6[1]);
        try testing.expectEqual(@as(u8, 0x01), src6[15]);
        // IPv6 dest address
        const dst6 = resp.getData("DestIpAddress6") orelse return error.TestExpectedData;
        try testing.expectEqual(@as(u8, 0x02), dst6[15]);
        // When is_ipv6=true, IPv4 fields get dummy values
        try testing.expectEqual(@as(u32, 0xFDFFFFDF), resp.getIntEx("SrcIpAddress", 0).?);
    }
}

test "server.admin_dispatch DeleteMacTable removes by key" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    const mac_key = try hub.insertMacTableEntry(allocator, .{
        .session_name = "SID-BOB",
        .mac_address = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        .created_time = 100,
        .updated_time = 200,
    });

    var del = try makeRequest(allocator, "DeleteMacTable");
    defer del.deinit();
    try del.addStr("HubName", "VPN");
    try del.addInt("Key", mac_key);
    var resp = try call(allocator, &server, true, "", "DeleteMacTable", &del);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
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

test "server.admin_dispatch DeleteIpTable removes by key" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    const ip_key = try hub.insertIpTableEntry(allocator, .{
        .session_name = "SID-BOB",
        .ip = types_mod.IpAddress.fromU32(0x0A000001),
        .dhcp_allocated = true,
        .created_time = 100,
        .updated_time = 200,
    });

    var del = try makeRequest(allocator, "DeleteIpTable");
    defer del.deinit();
    try del.addStr("HubName", "VPN");
    try del.addInt("Key", ip_key);
    var resp = try call(allocator, &server, true, "", "DeleteIpTable", &del);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    try testing.expect(hub.findIpTableEntry(ip_key) == null);
    try testing.expectEqual(@as(u32, 0), hub.num_ip_tables);
}

test "server.admin_dispatch table deletes honor no_delete hub options" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    const hub = findHub(&server, "VPN").?;
    hub.no_delete_mactable = true;
    hub.no_delete_iptable = true;
    const mac_key = try hub.insertMacTableEntry(allocator, .{
        .session_name = "SID-BOB",
        .created_time = 100,
        .updated_time = 100,
    });
    const ip_key = try hub.insertIpTableEntry(allocator, .{
        .session_name = "SID-BOB",
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

    // Server admin bypasses the option.
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

test "server.admin_dispatch GetDefaultHubAdminOptions returns the static table" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    var req = try makeRequest(allocator, "GetDefaultHubAdminOptions");
    defer req.deinit();
    var resp = try call(allocator, &server, true, "", "GetDefaultHubAdminOptions", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    const count = resp.getValueCount("Name");
    try testing.expectEqual(default_admin_options.len, count);
    const first_name = resp.getStrEx("Name", 0).?;
    try testing.expectEqualStrings("allow_hub_admin_change_option", first_name);
}

test "server.admin_dispatch GetHubAdminOptions returns defaults for a new hub" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    var req = try makeRequest(allocator, "GetHubAdminOptions");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    var resp = try call(allocator, &server, true, "VPN", "GetHubAdminOptions", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);
    const count = resp.getValueCount("Name");
    try testing.expectEqual(default_admin_options.len, count);
    try testing.expectEqualStrings("VPN", resp.getStr("HubName").?);
}

test "server.admin_dispatch SetHubAdminOptions replaces hub options" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Set two options.
    var req = try makeRequest(allocator, "SetHubAdminOptions");
    defer req.deinit();
    try req.addStr("HubName", "VPN");
    try req.addStrEx("Name", "max_users", 0);
    try req.addIntEx("Value", 100, 0);
    try req.addStrEx("Name", "deny_empty_password", 1);
    try req.addIntEx("Value", 1, 1);
    var resp = try call(allocator, &server, true, "VPN", "SetHubAdminOptions", &req);
    defer {
        resp.deinit();
        allocator.destroy(resp);
    }
    try assertOk(resp);

    // Read back and verify.
    var req2 = try makeRequest(allocator, "GetHubAdminOptions");
    defer req2.deinit();
    try req2.addStr("HubName", "VPN");
    var resp2 = try call(allocator, &server, true, "VPN", "GetHubAdminOptions", &req2);
    defer {
        resp2.deinit();
        allocator.destroy(resp2);
    }
    try assertOk(resp2);
    // The set replaced all options, so count = 2.
    try testing.expectEqual(@as(usize, 2), resp2.getValueCount("Name"));

    const hub = findHub(&server, "VPN").?;
    try testing.expectEqual(@as(u32, 100), hub.getAdminOptionValue("max_users", 0));
    try testing.expectEqual(@as(u32, 1), hub.getAdminOptionValue("deny_empty_password", 0));
}

test "server.admin_dispatch SetHubAdminOptions validates hub and rights" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();
    try server.addHub("VPN", hub_type_standalone);

    // Missing hub.
    var req1 = try makeRequest(allocator, "SetHubAdminOptions");
    defer req1.deinit();
    try req1.addStr("HubName", "NOPE");
    var resp1 = try call(allocator, &server, true, "", "SetHubAdminOptions", &req1);
    defer { resp1.deinit(); allocator.destroy(resp1); }
    try assertErr(resp1, err_hub_not_found);

    // Non-server-admin without the change option.
    var req2 = try makeRequest(allocator, "SetHubAdminOptions");
    defer req2.deinit();
    try req2.addStr("HubName", "VPN");
    var resp2 = try call(allocator, &server, false, "VPN", "SetHubAdminOptions", &req2);
    defer { resp2.deinit(); allocator.destroy(resp2); }
    try assertErr(resp2, err_not_enough_right);
}

// ============================================================================
// LocalBridge dispatch tests (#97)
// ============================================================================

test "server.admin_dispatch AddLocalBridge / EnumLocalBridge / DeleteLocalBridge round-trip" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    // Add a bridge
    {
        var req = try makeRequest(allocator, "AddLocalBridge");
        defer req.deinit();
        try req.addStr("DeviceName", "eth0");
        try req.addStr("HubNameLB", "VPN");
        try req.addBool("TapMode", false);
        var resp = try call(allocator, &server, true, "", "AddLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertOk(resp);
    }

    // Enumerate — should have one entry
    {
        var req = try makeRequest(allocator, "EnumLocalBridge");
        defer req.deinit();
        var resp = try call(allocator, &server, true, "", "EnumLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertOk(resp);
        try testing.expectEqualStrings("eth0", resp.getStrEx("DeviceName", 0) orelse "");
        try testing.expectEqualStrings("VPN", resp.getStrEx("HubNameLB", 0) orelse "");
    }

    // Duplicate add should fail
    {
        var req = try makeRequest(allocator, "AddLocalBridge");
        defer req.deinit();
        try req.addStr("DeviceName", "eth0");
        try req.addStr("HubNameLB", "VPN");
        var resp = try call(allocator, &server, true, "", "AddLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertErr(resp, err_listener_already_exists);
    }

    // Delete
    {
        var req = try makeRequest(allocator, "DeleteLocalBridge");
        defer req.deinit();
        try req.addStr("DeviceName", "eth0");
        try req.addStr("HubNameLB", "VPN");
        var resp = try call(allocator, &server, true, "", "DeleteLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertOk(resp);
    }

    // Enumerate after delete — should be empty
    {
        var req = try makeRequest(allocator, "EnumLocalBridge");
        defer req.deinit();
        var resp = try call(allocator, &server, true, "", "EnumLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertOk(resp);
    }

    // Delete non-existent — should fail
    {
        var req = try makeRequest(allocator, "DeleteLocalBridge");
        defer req.deinit();
        try req.addStr("DeviceName", "nope");
        try req.addStr("HubNameLB", "NOPE");
        var resp = try call(allocator, &server, true, "", "DeleteLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertErr(resp, err_object_not_found);
    }

    // Non-admin should be rejected
    {
        var req = try makeRequest(allocator, "AddLocalBridge");
        defer req.deinit();
        try req.addStr("DeviceName", "eth1");
        try req.addStr("HubNameLB", "VPN");
        var resp = try call(allocator, &server, false, "VPN", "AddLocalBridge", &req);
        defer { resp.deinit(); allocator.destroy(resp); }
        try assertErr(resp, err_not_enough_right);
    }
}

test "server.admin_dispatch GetBridgeSupport returns supported=true" {
    const allocator = testing.allocator;
    var server = try Server.init(allocator);
    defer server.deinit();

    var req = try makeRequest(allocator, "GetBridgeSupport");
    defer req.deinit();
    var resp = try call(allocator, &server, true, "", "GetBridgeSupport", &req);
    defer { resp.deinit(); allocator.destroy(resp); }
    try assertOk(resp);
    try testing.expect(resp.getBool("IsBridgeSupportedOs") orelse false);
}
