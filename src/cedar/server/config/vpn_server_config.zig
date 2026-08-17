//! Server configuration file — load, save and autosave (C: Cedar/Server.c
//! `SiLoadConfiguration`/`SiWriteConfiguration`/`SiSaverThread`).
//!
//! `vpn_server.config` is the on-disk form of the server's configuration. C
//! models it as the `SERVER` struct plus a `CFG_RW` that maps it to the Cfg
//! text format; this module is the Zig equivalent for the parts the server
//! actually uses:
//!
//! ```text
//! declare ServerConfiguration { ... }   -- server-wide settings (#86)
//! declare ListenerList { Listener0 { uint Port ... } ... }
//! declare VirtualHUB { DEFAULT { Option {...} SecurityAccountDatabase {
//!     UserList { administrator { uint AuthType ... } } } } }
//! ```
//!
//! ## Load / save
//!
//! - `initDefault` builds the first-run configuration (C `SiLoadInitial
//!   Configuration` + `SiInitDefaultHubList`): hub `DEFAULT` with the virtual
//!   `Administrator` account (empty admin password), the four default
//!   listeners (443/992/1194/5555) and C's default `ServerConfiguration`
//!   items.
//! - `load` parses an existing file into a `ServerConfig`. A missing or
//!   unreadable file, a syntax error, or a file without a
//!   `ServerConfiguration` folder (C `LS_BAD_CONFIG`) all surface as errors —
//!   the caller falls back to `initDefault` exactly like C.
//! - `save` serializes the model back to the Cfg text format via
//!   `Cfg.saveToFile` (CFG_RW: backup to `<path>~` + atomic temp-file rename).
//!
//! ## Autosave
//!
//! `Autosaver` mirrors C's `SiSaverThread`: a background thread that writes
//! the file whenever the config was modified since the last write, on a
//! `AutoSaveConfigSpan` cadence. `markModified` is the equivalent of C's
//! `SiSetServerConfigRevision`; `stop` does the final write (C
//! `SiFreeConfiguration`) and joins the thread. Config mutations are
//! serialized against the write under the saver's mutex: callers wrap a
//! mutation in `Autosaver.lock`/`unlock` before `markModified`.
//!
//! ## Scope / fidelity
//!
//! Item and folder names match C byte-for-byte (including the `DisableDos
//! Proction` typo) so a `vpn_server.config` written here is readable by the
//! C server for the modeled subset, and vice versa. Unknown folders/items in
//! an existing file are ignored on load and not re-emitted on save — C
//! rebuilds the tree from the `SERVER` struct, and the Zig server does not
//! yet own those subsystems (SecureNAT, links, access lists, DDNS, ...).
//! HUB `Option` covers the fields with non-trivial defaults; the remaining
//! ~50 C options default on load and are written as defaults.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const cfg = @import("cfg.zig");
const auth = @import("../auth.zig");
const listener = @import("../listener.zig");

const log = std.log.scoped(.cedar_server);

// ============================================================================
// Constants (Cedar.h / Server.h)
// ============================================================================

/// On-disk configuration file name, next to the binary (C
/// `SERVER_CONFIG_FILE_NAME` = "vpn_server.config").
pub const default_config_file_name = "vpn_server.config";
/// Default virtual hub name (C `SERVER_DEFAULT_HUB_NAME`).
pub const default_hub_name = "DEFAULT";
/// Hub administrator account name (C `ADMINISTRATOR_USERNAME`).
pub const administrator_username = auth.administrator_username;
/// Autosave interval (C `SERVER_FILE_SAVE_INTERVAL_DEFAULT` = 5 min).
pub const save_interval_ms_default: u32 = 5 * 60 * 1000;
/// Autosave interval floor/ceiling (C `SERVER_FILE_SAVE_INTERVAL_MIN/MAX`).
pub const save_interval_ms_min: u32 = 5 * 1000;
pub const save_interval_ms_max: u32 = 3600 * 1000;
/// Keep-alive server default (C `CLIENT_DEFAULT_KEEPALIVE_HOST`,
/// `CONNECTION_UDP`, `KEEP_INTERVAL_DEFAULT`).
pub const keep_connect_default_host = "keepalive.softether.org";
pub const keep_connect_default_port: u32 = 80;
pub const keep_connect_default_protocol: u32 = 1;
pub const keep_connect_default_interval_ms: u32 = 50 * 1000;
/// Cluster weight default (C `FARM_DEFAULT_WEIGHT`).
pub const default_weight: u32 = 100;
/// Server type: stand-alone (C `SERVER_TYPE_STANDALONE`).
pub const server_type_standalone: u32 = 0;
/// Hub type: stand-alone (C `HUB_TYPE_STANDALONE`).
pub const hub_type_standalone: u32 = 0;
/// C `SERVER_TYPE_FARM_CONTROLLER`.
pub const server_type_farm_controller: u32 = 1;
/// C `SERVER_TYPE_FARM_MEMBER`.
pub const server_type_farm_member: u32 = 2;
/// C `MAX_HOST_NAME_LEN` (Cedar.h:59).
pub const max_host_name_len: usize = 255;
/// C `MAX_PUBLIC_PORT_NUM` (Server.h:287).
pub const max_public_port_num: usize = 128;
/// Default cipher list (C `SERVER_DEFAULT_CIPHER_NAME`).
pub const default_cipher_name = "AES128-SHA";

const DigestLength = auth.digest_length;

// ============================================================================
// Model
// ============================================================================

/// A configured listener (C `SERVER_LISTENER`, Server.c `SiLoadListenerCfg`).
pub const ListenerConfig = struct {
    port: u16,
    enabled: bool = true,
    disable_dos: bool = false,
};

/// `ServerConfiguration` folder fields (C `SiLoadServerCfg`/
/// `SiWriteServerCfg`, Server.c:5831/6313).
pub const ServerConfiguration = struct {
    /// Persisted as `AutoSaveConfigSpan` in seconds (C stores ms in the
    /// struct, seconds on disk).
    auto_save_span_ms: u32 = save_interval_ms_default,
    /// Skip the file write when nothing changed (C
    /// `BackupConfigOnlyWhenModified`).
    backup_config_only_when_modified: bool = true,
    dont_backup_config: bool = false,
    use_keep_connect: bool = true,
    keep_connect_host: []u8, // owned
    keep_connect_port: u32 = keep_connect_default_port,
    keep_connect_protocol: u32 = keep_connect_default_protocol,
    /// Persisted as `KeepConnectInterval` in seconds.
    keep_connect_interval_ms: u32 = keep_connect_default_interval_ms,
    /// Note the C spelling `DisableDosProction` (typo, kept for fidelity).
    disable_dos_protection: bool = false,
    disable_nat_traversal: bool = false,
    disable_sstp_server: bool = false,
    disable_openvpn_server: bool = false,
    enable_vpn_over_icmp: bool = false,
    enable_vpn_over_dns: bool = false,
    enable_vpn_azure: bool = true,
    server_type: u32 = server_type_standalone,
    weight: u32 = default_weight,
    // ── Farm member config (persisted when ServerType == FARM_MEMBER) ──
    /// C `Server.ControllerName`.
    controller_name: []u8, // owned
    /// C `Server.ControllerPort`.
    controller_port: u32 = 0,
    /// C `Server.MemberPassword` — raw 20-byte SHA-1 hash.
    member_password: [20]u8 = .{0} ** 20,
    /// C `Server.PublicIp` (host byte order).
    public_ip: u32 = 0,
    /// CSV of public port numbers.
    public_ports_str: []u8, // owned
    /// C `Server.ControllerOnly` — controller-only mode.
    controller_only: bool = false,
    cipher_name: []u8, // owned
    accept_only_tls: bool = true,
    /// Server admin password hash — SHA-0 of the empty string by default
    /// (C `Hash(s->HashedPassword, "", 0, true)`).
    hashed_password: [DigestLength]u8 = .{0} ** DigestLength,

    fn initDefault(allocator: Allocator) !ServerConfiguration {
        var s: ServerConfiguration = .{
            .keep_connect_host = try allocator.dupe(u8, keep_connect_default_host),
            .cipher_name = undefined,
            .hashed_password = auth.hashPassword("", ""),
            .controller_name = try allocator.dupe(u8, ""),
            .public_ports_str = try allocator.dupe(u8, ""),
        };
        errdefer allocator.free(s.keep_connect_host);
        s.cipher_name = try allocator.dupe(u8, default_cipher_name);
        return s;
    }

    fn deinit(self: *ServerConfiguration, allocator: Allocator) void {
        allocator.free(self.keep_connect_host);
        allocator.free(self.cipher_name);
        allocator.free(self.controller_name);
        allocator.free(self.public_ports_str);
    }
};

/// Virtual HUB `Option` folder — the fields with non-trivial defaults (C
/// `SiSetDefaultHubOption` + a representative subset of
/// `SiLoadHubOptionCfg`/`SiWriteHubOptionCfg`).
pub const HubOption = struct {
    max_session: u32 = 0,
    no_arp_polling: bool = false,
    no_enum: bool = false,
    no_ip_table: bool = false,
    /// C default true (SiSetDefaultHubOption).
    no_ipv6_default_router_in_ra_when_ipv6: bool = true,
    no_mac_address_log: bool = true,
    no_dhcp_packet_log_outside_hub: bool = true,
    manage_only_private_ip: bool = true,
    manage_only_local_unicast_ipv6: bool = true,
    remove_def_gw_on_dhcp_for_localhost: bool = true,
    /// C `DEFAULT_FLOODING_QUEUE_LENGTH` = 32 MiB.
    flooding_send_queue_buffer_quota: u32 = 32 * 1024 * 1024,
    /// C `ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME` = 30 s.
    access_list_include_file_cache_lifetime: u32 = 30,

    // -- SecureNAT / VH_OPTION (C: hub.SecureNATOption) --
    /// Enable SecureNAT on this hub (C: `HUB_OPTION.UseSecureNAT`).
    use_secure_nat: bool = false,
    /// Virtual host gateway IP (host byte order).
    vh_host_ip: u32 = 0xC0A8_1E01, // 192.168.30.1
    /// Virtual host subnet mask.
    vh_host_mask: u32 = 0xFFFF_FF00, // 255.255.255.0
    /// Enable outbound NAT.
    vh_use_nat: bool = true,
    /// NAT TCP timeout (seconds).
    vh_nat_tcp_timeout_s: u32 = 1800,
    /// NAT UDP timeout (seconds).
    vh_nat_udp_timeout_s: u32 = 60,
    /// Enable virtual DHCP server.
    vh_use_dhcp: bool = true,
    /// DHCP range start (host byte order).
    vh_dhcp_start: u32 = 0xC0A8_1E0A, // 192.168.30.10
    /// DHCP range end.
    vh_dhcp_end: u32 = 0xC0A8_1EC8, // 192.168.30.200
    /// DHCP lease time (seconds).
    vh_dhcp_lease_s: u32 = 7200,
    /// DNS server 1 (handed to DHCP clients).
    vh_dns1: u32 = 0xC0A8_1E01, // 192.168.30.1
    /// DNS server 2.
    vh_dns2: u32 = 0x0808_0808, // 8.8.8.8
};

/// A user account as persisted (C `SiWriteUserCfg`/`SiLoadUserCfg`). The
/// folder name is the account name; `AuthPassword` holds the SHA-0 hash.
pub const UserConfig = struct {
    name: []u8, // owned
    /// C `AUTHTYPE_ANONYMOUS` = 0, `AUTHTYPE_PASSWORD` = 1.
    auth_type: u8 = 0,
    auth_password: ?[DigestLength]u8 = null,

    fn deinit(self: *UserConfig, allocator: Allocator) void {
        allocator.free(self.name);
    }
};

/// A hub group as persisted (C `SiWriteGroupCfg`/`SiLoadGroupCfg` subset).
pub const GroupConfig = struct {
    name: []u8, // owned
    realname: []u8 = "", // owned
    note: []u8 = "", // owned

    fn deinit(self: *GroupConfig, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.realname);
        allocator.free(self.note);
    }
};

/// A virtual hub as persisted (C `SiWriteHubCfg`/`SiLoadHubCfg` subset).
pub const HubConfig = struct {
    name: []u8, // owned
    hashed_password: [DigestLength]u8 = .{0} ** DigestLength,
    /// Hub admin secure password — `hashPassword("", administrator)` by
    /// default (C `HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME,
    /// "")`).
    secure_password: [DigestLength]u8 = .{0} ** DigestLength,
    online: bool = true,
    hub_type: u32 = hub_type_standalone,
    created_time: u64 = 0,
    option: HubOption = .{},
    users: std.ArrayListUnmanaged(UserConfig) = .{},
    groups: std.ArrayListUnmanaged(GroupConfig) = .{},

    fn deinit(self: *HubConfig, allocator: Allocator) void {
        for (self.users.items) |*u| u.deinit(allocator);
        self.users.deinit(allocator);
        for (self.groups.items) |*g| g.deinit(allocator);
        self.groups.deinit(allocator);
        allocator.free(self.name);
    }

    /// Load a hub folder (C `SiLoadHubCfg`, Server.c:5193).
    fn fromFolder(allocator: Allocator, folder: *const cfg.Folder) !HubConfig {
        var hub = HubConfig{ .name = try allocator.dupe(u8, folder.name) };
        errdefer hub.deinit(allocator);

        // Passwords: keep the file value when present (20 bytes), otherwise
        // fall back to C's per-case defaults.
        if (folder.getBytes("HashedPassword")) |b| {
            if (b.len == DigestLength) @memcpy(&hub.hashed_password, b);
        } else {
            hub.hashed_password = auth.hashPassword("", "");
        }
        if (folder.getBytes("SecurePassword")) |b| {
            if (b.len == DigestLength) @memcpy(&hub.secure_password, b);
        } else {
            hub.secure_password = auth.hashPassword("", administrator_username);
        }

        hub.online = folder.getBool("Online", true);
        hub.hub_type = folder.getUint("Type", hub_type_standalone);
        hub.created_time = folder.getUint64("CreatedTime", 0);

        if (folder.getFolder("Option")) |of| try loadHubOption(&hub.option, of);

        // SecurityAccountDatabase → UserList → <username> folders.
        if (folder.getFolder("SecurityAccountDatabase")) |db| {
            if (db.getFolder("UserList")) |user_list| {
                for (user_list.folders.items) |uf| {
                    const t = uf.getUint("AuthType", 0);
                    const password = if (uf.getBytes("AuthPassword")) |b| blk: {
                        if (b.len == DigestLength) {
                            var h: [DigestLength]u8 = undefined;
                            @memcpy(&h, b);
                            break :blk h;
                        }
                        break :blk null;
                    } else null;
                    try hub.users.append(allocator, .{
                        .name = try allocator.dupe(u8, uf.name),
                        // Clamp: the Zig server only supports anonymous (0)
                        // and password (1); unknown values load as anonymous.
                        .auth_type = if (t > 1) 0 else @intCast(t),
                        .auth_password = password,
                    });
                }
            }
            // SecurityAccountDatabase → GroupList → <groupname> folders.
            if (db.getFolder("GroupList")) |group_list| {
                for (group_list.folders.items) |gf| {
                    const realname = gf.getStr("RealName", "");
                    const note = gf.getStr("Note", "");
                    try hub.groups.append(allocator, .{
                        .name = try allocator.dupe(u8, gf.name),
                        .realname = try allocator.dupe(u8, realname),
                        .note = try allocator.dupe(u8, note),
                    });
                }
            }
        }
        return hub;
    }
};

/// Complete server configuration (C `SERVER` persisted form).
pub const ServerConfig = struct {
    allocator: Allocator,
    /// Root item `Region` (C `SiGetCurrentRegion`; empty when not set).
    region: []u8, // owned
    config_revision: u32 = 1,
    /// Config revision that produced the current `<path>~` backup (used to
    /// implement `BackupConfigOnlyWhenModified`).
    last_backup_revision: u32 = 0,
    server: ServerConfiguration,
    listeners: std.ArrayListUnmanaged(ListenerConfig) = .{},
    hubs: std.ArrayListUnmanaged(HubConfig) = .{},

    /// First-run configuration (C `SiLoadInitialConfiguration` +
    /// `SiInitDefaultHubList` + `SiInitListenerList`).
    pub fn initDefault(allocator: Allocator) !ServerConfig {
        var self = ServerConfig{
            .allocator = allocator,
            .region = try allocator.dupe(u8, ""),
            .server = try ServerConfiguration.initDefault(allocator),
        };
        errdefer self.deinit();

        for (listener.default_ports) |port| {
            try self.listeners.append(allocator, .{ .port = port });
        }
        try self.hubs.append(allocator, .{
            .name = try allocator.dupe(u8, default_hub_name),
            .hashed_password = auth.hashPassword("", ""),
            .secure_password = auth.hashPassword("", administrator_username),
            .created_time = @intCast(std.time.timestamp()),
        });
        return self;
    }

    pub fn deinit(self: *ServerConfig) void {
        self.server.deinit(self.allocator);
        for (self.hubs.items) |*hub| hub.deinit(self.allocator);
        self.hubs.deinit(self.allocator);
        self.listeners.deinit(self.allocator);
        self.allocator.free(self.region);
    }

    /// Load from a parsed Cfg tree (C `SiLoadConfigurationCfg`, Server.c:
    /// 2965). Returns `error.InvalidConfig` when the `ServerConfiguration`
    /// folder is absent (C `LS_BAD_CONFIG` → fall back to defaults).
    pub fn fromCfg(allocator: Allocator, root: *const cfg.Folder) !ServerConfig {
        const sc_folder = root.getFolder("ServerConfiguration") orelse
            return error.InvalidConfig;

        var self = try initDefault(allocator);
        errdefer self.deinit();

        // The file, when present, is authoritative: replace the first-run
        // default listeners and hub (C builds these lists fresh).
        self.listeners.clearRetainingCapacity();
        for (self.hubs.items) |*hub| hub.deinit(allocator);
        self.hubs.clearRetainingCapacity();

        const region = try allocator.dupe(u8, root.getStr("Region", ""));
        allocator.free(self.region);
        self.region = region;
        self.config_revision = root.getUint("ConfigRevision", 1);

        try loadServerCfg(allocator, &self.server, sc_folder);

        if (root.getFolder("ListenerList")) |ll| {
            for (ll.folders.items) |sub| {
                const port = sub.getUint("Port", 0);
                if (port == 0 or port > 0xffff) continue; // C skips port 0
                try self.listeners.append(allocator, .{
                    .port = @intCast(port),
                    .enabled = sub.getBool("Enabled", true),
                    .disable_dos = sub.getBool("DisableDos", false),
                });
            }
        }

        if (root.getFolder("VirtualHUB")) |vh| {
            for (vh.folders.items) |hub_folder| {
                try self.hubs.append(allocator, try HubConfig.fromFolder(allocator, hub_folder));
            }
        }
        return self;
    }

    /// Serialize the model into `root` (C `SiWriteConfigurationToCfg`,
    /// Server.c:3367).
    pub fn toCfg(self: *const ServerConfig, root: *cfg.Folder) !void {
        try root.setStr("Region", self.region);
        try root.setUint("ConfigRevision", self.config_revision);

        const ll = try root.addFolder("ListenerList");
        for (self.listeners.items, 0..) |l, i| {
            const name = try std.fmt.allocPrint(self.allocator, "Listener{d}", .{i});
            defer self.allocator.free(name);
            const f = try ll.addFolder(name);
            try f.setBool("Enabled", l.enabled);
            try f.setUint("Port", l.port);
            try f.setBool("DisableDos", l.disable_dos);
        }

        try writeServerCfg(try root.addFolder("ServerConfiguration"), &self.server);

        const vh = try root.addFolder("VirtualHUB");
        for (self.hubs.items) |*hub| {
            const hf = try vh.addFolder(hub.name);
            try hf.setBytes("HashedPassword", &hub.hashed_password);
            try hf.setBytes("SecurePassword", &hub.secure_password);
            try hf.setBool("Online", hub.online);
            try hf.setUint("Type", hub.hub_type);
            try hf.setUint64("CreatedTime", hub.created_time);
            try writeHubOption(try hf.addFolder("Option"), &hub.option);
            const db = try hf.addFolder("SecurityAccountDatabase");
            const ul = try db.addFolder("UserList");
            for (hub.users.items) |*u| {
                const uf = try ul.addFolder(u.name);
                try uf.setUint("AuthType", u.auth_type);
                if (u.auth_password) |h| try uf.setBytes("AuthPassword", &h);
            }
            const gl = try db.addFolder("GroupList");
            for (hub.groups.items) |*g| {
                const gf = try gl.addFolder(g.name);
                if (g.realname.len > 0) try gf.setStr("RealName", g.realname);
                if (g.note.len > 0) try gf.setStr("Note", g.note);
            }
        }
    }

    /// Read and parse a configuration file (C `SiLoadConfigurationFile`).
    /// Any failure — missing file, syntax error, missing
    /// `ServerConfiguration` — is surfaced to the caller, which falls back to
    /// `initDefault` exactly like C does.
    pub fn load(allocator: Allocator, dir: std.fs.Dir, path: []const u8) !ServerConfig {
        const c = try cfg.Cfg.loadFromFile(allocator, dir, path);
        defer c.deinit();
        return fromCfg(allocator, c.root);
    }

    /// Write the configuration with CFG_RW semantics (C
    /// `SiWriteConfigurationFile` → `SaveCfgRwEx`). The previous file is
    /// backed up to `<path>~` unless the policy says otherwise:
    /// - `DontBackupConfig` disables the backup entirely (C sets
    ///   `CfgRw->DontBackup`).
    /// - `BackupConfigOnlyWhenModified` backs up only when the config revision
    ///   changed since the last backup (C names backups after the revision and
    ///   skips existing ones).
    pub fn save(self: *ServerConfig, dir: std.fs.Dir, path: []const u8) !void {
        const c = try cfg.Cfg.init(self.allocator);
        defer c.deinit();
        try self.toCfg(c.root);

        const backup = !self.server.dont_backup_config and
            (!self.server.backup_config_only_when_modified or self.config_revision != self.last_backup_revision);
        try c.saveToFileEx(dir, path, backup);
        if (backup) self.last_backup_revision = self.config_revision;
    }
};

// ============================================================================
// ServerConfiguration load/write
// ============================================================================

fn loadServerCfg(allocator: Allocator, s: *ServerConfiguration, f: *const cfg.Folder) !void {
    // AutoSaveConfigSpan is persisted in seconds (C stores ms in struct).
    // Clamp in seconds first: the on-disk value is unbounded and `* 1000`
    // could overflow u32 for a hostile file.
    const span_sec = f.getUint("AutoSaveConfigSpan", save_interval_ms_default / 1000);
    const span_sec_clamped = std.math.clamp(span_sec, save_interval_ms_min / 1000, save_interval_ms_max / 1000);
    s.auto_save_span_ms = if (span_sec == 0)
        save_interval_ms_default
    else
        span_sec_clamped * 1000;

    s.backup_config_only_when_modified = f.getBool("BackupConfigOnlyWhenModified", true);
    s.dont_backup_config = f.getBool("DontBackupConfig", false);

    s.use_keep_connect = f.getBool("UseKeepConnect", true);
    const host = f.getStr("KeepConnectHost", keep_connect_default_host);
    if (!mem.eql(u8, host, s.keep_connect_host)) {
        const duped = try allocator.dupe(u8, host);
        allocator.free(s.keep_connect_host);
        s.keep_connect_host = duped;
    }
    const keep_port = f.getUint("KeepConnectPort", 0);
    s.keep_connect_port = if (keep_port == 0) keep_connect_default_port else keep_port;
    s.keep_connect_protocol = f.getUint("KeepConnectProtocol", keep_connect_default_protocol);
    // `KeepConnectInterval` is unbounded on disk; clamp the seconds value so
    // the `* 1000` conversion below cannot overflow (C's `UINT` multiplies
    // unchecked, wrapping on a hostile file).
    const keep_sec = std.math.clamp(
        f.getUint("KeepConnectInterval", keep_connect_default_interval_ms / 1000),
        0,
        std.math.maxInt(u32) / 1000,
    );
    s.keep_connect_interval_ms = keep_sec * 1000;

    s.disable_dos_protection = f.getBool("DisableDosProction", false);
    s.disable_nat_traversal = f.getBool("DisableNatTraversal", false);
    s.disable_sstp_server = f.getBool("DisableSSTPServer", false);
    s.disable_openvpn_server = f.getBool("DisableOpenVPNServer", false);
    s.enable_vpn_over_icmp = f.getBool("EnableVpnOverIcmp", false);
    s.enable_vpn_over_dns = f.getBool("EnableVpnOverDns", false);
    s.enable_vpn_azure = f.getBool("EnableVpnAzure", true);
    s.server_type = f.getUint("ServerType", server_type_standalone);
    const weight = f.getUint("Weight", 0);
    s.weight = if (weight == 0) default_weight else weight;

    // Farm member fields (C SiLoadServerCfg, line 6495).
    const cname = f.getStr("ControllerName", "");
    if (!mem.eql(u8, cname, s.controller_name)) {
        const duped = try allocator.dupe(u8, cname);
        allocator.free(s.controller_name);
        s.controller_name = duped;
    }
    s.controller_port = f.getUint("ControllerPort", 0);
    if (f.getBytes("MemberPassword")) |b| {
        if (b.len == 20) @memcpy(&s.member_password, b);
    }
    s.public_ip = f.getUint("PublicIp", 0);
    const pports = f.getStr("PublicPorts", "");
    if (!mem.eql(u8, pports, s.public_ports_str)) {
        const duped = try allocator.dupe(u8, pports);
        allocator.free(s.public_ports_str);
        s.public_ports_str = duped;
    }
    s.controller_only = f.getBool("ControllerOnly", false);
    s.accept_only_tls = f.getBool("AcceptOnlyTls", true);

    const cipher = f.getStr("CipherName", default_cipher_name);
    if (!mem.eql(u8, cipher, s.cipher_name)) {
        const duped = try allocator.dupe(u8, cipher);
        allocator.free(s.cipher_name);
        s.cipher_name = duped;
    }

    if (f.getBytes("HashedPassword")) |b| {
        if (b.len == DigestLength) @memcpy(&s.hashed_password, b);
    }
}

fn writeServerCfg(f: *cfg.Folder, s: *const ServerConfiguration) !void {
    try f.setUint("AutoSaveConfigSpan", s.auto_save_span_ms / 1000);
    try f.setBool("BackupConfigOnlyWhenModified", s.backup_config_only_when_modified);
    try f.setBool("DontBackupConfig", s.dont_backup_config);
    try f.setBool("UseKeepConnect", s.use_keep_connect);
    try f.setStr("KeepConnectHost", s.keep_connect_host);
    try f.setUint("KeepConnectPort", s.keep_connect_port);
    try f.setUint("KeepConnectProtocol", s.keep_connect_protocol);
    try f.setUint("KeepConnectInterval", s.keep_connect_interval_ms / 1000);
    try f.setBool("DisableDosProction", s.disable_dos_protection);
    try f.setBool("DisableNatTraversal", s.disable_nat_traversal);
    try f.setBool("DisableSSTPServer", s.disable_sstp_server);
    try f.setBool("DisableOpenVPNServer", s.disable_openvpn_server);
    try f.setBool("EnableVpnOverIcmp", s.enable_vpn_over_icmp);
    try f.setBool("EnableVpnOverDns", s.enable_vpn_over_dns);
    try f.setBool("EnableVpnAzure", s.enable_vpn_azure);
    try f.setUint("ServerType", s.server_type);
    // Weight is only persisted for non-standalone servers (C).
    if (s.server_type != server_type_standalone) {
        try f.setUint("Weight", s.weight);
    }
    // Farm member fields (C SiWriteServerCfg, line 6495).
    if (s.server_type == server_type_farm_member) {
        try f.setStr("ControllerName", s.controller_name);
        try f.setUint("ControllerPort", s.controller_port);
        try f.setBytes("MemberPassword", &s.member_password);
        try f.setUint("PublicIp", s.public_ip);
        try f.setStr("PublicPorts", s.public_ports_str);
    }
    if (s.server_type == server_type_farm_controller) {
        try f.setBool("ControllerOnly", s.controller_only);
    }
    try f.setStr("CipherName", s.cipher_name);
    try f.setBool("AcceptOnlyTls", s.accept_only_tls);
    try f.setBytes("HashedPassword", &s.hashed_password);
}

fn loadHubOption(o: *HubOption, f: *const cfg.Folder) !void {
    o.max_session = f.getUint("MaxSession", 0);
    o.no_arp_polling = f.getBool("NoArpPolling", false);
    o.no_enum = f.getBool("NoEnum", false);
    o.no_ip_table = f.getBool("NoIpTable", false);
    o.no_ipv6_default_router_in_ra_when_ipv6 = f.getBool("NoIPv6DefaultRouterInRAWhenIPv6", true);
    o.no_mac_address_log = f.getBool("NoMacAddressLog", true);
    o.no_dhcp_packet_log_outside_hub = f.getBool("NoDhcpPacketLogOutsideHub", true);
    o.manage_only_private_ip = f.getBool("ManageOnlyPrivateIP", true);
    o.manage_only_local_unicast_ipv6 = f.getBool("ManageOnlyLocalUnicastIPv6", true);
    o.remove_def_gw_on_dhcp_for_localhost = f.getBool("RemoveDefGwOnDhcpForLocalhost", true);
    o.flooding_send_queue_buffer_quota = f.getUint("FloodingSendQueueBufferQuota", 32 * 1024 * 1024);
    o.access_list_include_file_cache_lifetime = f.getUint("AccessListIncludeFileCacheLifetime", 30);

    // SecureNAT / VH_OPTION (C: VirtualHost / VirtualRouter / VirtualDhcpServer subfolders).
    o.use_secure_nat = f.getBool("UseSecureNAT", false);
    o.vh_host_ip = f.getUint("VirtualHostIP", 0xC0A8_1E01);
    o.vh_host_mask = f.getUint("VirtualHostMask", 0xFFFF_FF00);
    o.vh_use_nat = f.getBool("UseVirtualNAT", true);
    o.vh_nat_tcp_timeout_s = f.getUint("NatTcpTimeout", 1800);
    o.vh_nat_udp_timeout_s = f.getUint("NatUdpTimeout", 60);
    o.vh_use_dhcp = f.getBool("UseVirtualDhcp", true);
    o.vh_dhcp_start = f.getUint("DhcpLeaseIPStart", 0xC0A8_1E0A);
    o.vh_dhcp_end = f.getUint("DhcpLeaseIPEnd", 0xC0A8_1EC8);
    o.vh_dhcp_lease_s = f.getUint("DhcpExpireTimeSpan", 7200);
    o.vh_dns1 = f.getUint("DhcpDnsServerAddress", 0xC0A8_1E01);
    o.vh_dns2 = f.getUint("DhcpDnsServerAddress2", 0x0808_0808);
}

fn writeHubOption(f: *cfg.Folder, o: *const HubOption) !void {
    try f.setUint("MaxSession", o.max_session);
    try f.setBool("NoArpPolling", o.no_arp_polling);
    try f.setBool("NoEnum", o.no_enum);
    try f.setBool("NoIpTable", o.no_ip_table);
    try f.setBool("NoIPv6DefaultRouterInRAWhenIPv6", o.no_ipv6_default_router_in_ra_when_ipv6);
    try f.setBool("NoMacAddressLog", o.no_mac_address_log);
    try f.setBool("NoDhcpPacketLogOutsideHub", o.no_dhcp_packet_log_outside_hub);
    try f.setBool("ManageOnlyPrivateIP", o.manage_only_private_ip);
    try f.setBool("ManageOnlyLocalUnicastIPv6", o.manage_only_local_unicast_ipv6);
    try f.setBool("RemoveDefGwOnDhcpForLocalhost", o.remove_def_gw_on_dhcp_for_localhost);
    try f.setUint("FloodingSendQueueBufferQuota", o.flooding_send_queue_buffer_quota);
    try f.setUint("AccessListIncludeFileCacheLifetime", o.access_list_include_file_cache_lifetime);

    // SecureNAT / VH_OPTION.
    try f.setBool("UseSecureNAT", o.use_secure_nat);
    try f.setUint("VirtualHostIP", o.vh_host_ip);
    try f.setUint("VirtualHostMask", o.vh_host_mask);
    try f.setBool("UseVirtualNAT", o.vh_use_nat);
    try f.setUint("NatTcpTimeout", o.vh_nat_tcp_timeout_s);
    try f.setUint("NatUdpTimeout", o.vh_nat_udp_timeout_s);
    try f.setBool("UseVirtualDhcp", o.vh_use_dhcp);
    try f.setUint("DhcpLeaseIPStart", o.vh_dhcp_start);
    try f.setUint("DhcpLeaseIPEnd", o.vh_dhcp_end);
    try f.setUint("DhcpExpireTimeSpan", o.vh_dhcp_lease_s);
    try f.setUint("DhcpDnsServerAddress", o.vh_dns1);
    try f.setUint("DhcpDnsServerAddress2", o.vh_dns2);
}

// ============================================================================
// Autosave (C `SiSaverThread` / `SiWriteConfigurationFile`)
// ============================================================================

/// Background saver thread. The owning server keeps the `ServerConfig` alive
/// and calls `markModified` on any configuration change; the thread writes the
/// file on the next tick. `stop` performs the final write and joins the
/// thread (C `SiFreeConfiguration`).
///
/// Concurrency contract: config mutations are serialized against the write
/// under `mutex`. Callers must wrap a mutation in `lock`/`unlock` and then call
/// `markModified`; the saver thread performs the serialization (`toCfg` → file)
/// while holding the same lock, so a write never observes a torn config.
pub const Autosaver = struct {
    config: *ServerConfig,
    dir: std.fs.Dir,
    path: []const u8,
    interval_ms: u64,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    halt: bool = false,
    modified: bool = false,
    thread: ?std.Thread = null,

    /// Initialize and spawn the saver thread. The caller owns `self` and must
    /// keep it alive until `stop` (which joins the thread).
    pub fn start(
        self: *Autosaver,
        config: *ServerConfig,
        dir: std.fs.Dir,
        path: []const u8,
        interval_ms: u64,
    ) !void {
        self.* = .{
            .config = config,
            .dir = dir,
            .path = path,
            .interval_ms = interval_ms,
        };
        self.thread = try std.Thread.spawn(.{}, saverLoop, .{self});
    }

    /// Acquire the lock for a config mutation. Pair with `unlock`.
    pub fn lock(self: *Autosaver) void {
        self.mutex.lock();
    }

    /// Release the lock after a config mutation.
    pub fn unlock(self: *Autosaver) void {
        self.mutex.unlock();
    }

    /// Record a configuration change so the next tick writes the file.
    /// Must be called without the lock held (it takes the lock itself).
    pub fn markModified(self: *Autosaver) void {
        self.mutex.lock();
        self.modified = true;
        self.mutex.unlock();
    }

    /// Final save, then halt and join the saver thread.
    pub fn stop(self: *Autosaver) void {
        self.mutex.lock();
        self.halt = true;
        self.cond.signal();
        self.mutex.unlock();

        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.config.save(self.dir, self.path) catch |err| {
            log.warn("final config save failed: {s}", .{@errorName(err)});
        };
    }

    fn saverLoop(self: *Autosaver) void {
        while (true) {
            self.mutex.lock();
            const do_save = self.modified and !self.halt;
            self.modified = false;
            if (do_save) {
                self.config.save(self.dir, self.path) catch |err| {
                    log.warn("config autosave failed: {s}", .{@errorName(err)});
                };
            }

            if (self.halt) {
                self.mutex.unlock();
                return;
            }
            self.cond.timedWait(&self.mutex, self.interval_ms * std.time.ns_per_ms) catch {};
            self.mutex.unlock();
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "server.vpn_server_config default config has DEFAULT hub and listeners" {
    const allocator = testing.allocator;
    var config = try ServerConfig.initDefault(allocator);
    defer config.deinit();

    try testing.expectEqualStrings(default_hub_name, config.hubs.items[0].name);
    try testing.expect(config.hubs.items[0].secure_password.len == DigestLength);
    try testing.expectEqual(@as(usize, 4), config.listeners.items.len);
    try testing.expectEqual(@as(u16, 443), config.listeners.items[0].port);
    try testing.expectEqual(save_interval_ms_default, config.server.auto_save_span_ms);
    try testing.expectEqualStrings(keep_connect_default_host, config.server.keep_connect_host);
    try testing.expectEqualStrings(default_cipher_name, config.server.cipher_name);
}

test "server.vpn_server_config save/load round-trips the default config" {
    const allocator = testing.allocator;
    var config = try ServerConfig.initDefault(allocator);
    defer config.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try config.save(tmp.dir, default_config_file_name);
    var reloaded = try ServerConfig.load(allocator, tmp.dir, default_config_file_name);
    defer reloaded.deinit();

    try testing.expectEqual(config.config_revision, reloaded.config_revision);
    try testing.expectEqual(config.server.auto_save_span_ms, reloaded.server.auto_save_span_ms);
    try testing.expectEqualStrings(config.server.keep_connect_host, reloaded.server.keep_connect_host);
    try testing.expectEqualStrings(config.server.cipher_name, reloaded.server.cipher_name);
    try testing.expectEqual(config.listeners.items.len, reloaded.listeners.items.len);
    try testing.expectEqualSlices(u16, &.{ 443, 992, 1194, 5555 }, &.{
        reloaded.listeners.items[0].port,
        reloaded.listeners.items[1].port,
        reloaded.listeners.items[2].port,
        reloaded.listeners.items[3].port,
    });
    try testing.expectEqualStrings(config.hubs.items[0].name, reloaded.hubs.items[0].name);
    try testing.expectEqualSlices(u8, &config.hubs.items[0].secure_password, &reloaded.hubs.items[0].secure_password);
    try testing.expectEqualSlices(u8, &config.server.hashed_password, &reloaded.server.hashed_password);
}

test "server.vpn_server_config writes a byte-stable C-layout file" {
    const allocator = testing.allocator;
    var config = try ServerConfig.initDefault(allocator);
    defer config.deinit();

    const c = try cfg.Cfg.init(allocator);
    defer c.deinit();
    try config.toCfg(c.root);
    const out = try c.toOwnedText(allocator);
    defer allocator.free(out);

    // Top-level structure matches C `SiWriteConfigurationToCfg`.
    try testing.expect(std.mem.indexOf(u8, out, "declare ServerConfiguration\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "declare ListenerList\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "declare VirtualHUB\r\n") != null);
    // C item names, including the `DisableDosProction` spelling.
    try testing.expect(std.mem.indexOf(u8, out, "bool DisableDosProction false\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "string KeepConnectHost keepalive.softether.org\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "uint AutoSaveConfigSpan 300\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "uint Port 443\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "declare DEFAULT\r\n") != null);
}

test "server.vpn_server_config load tolerates unknown folders and items" {
    const allocator = testing.allocator;
    const text =
        "declare ServerConfiguration\r\n" ++
        "{\r\n" ++
        "\tstring KeepConnectHost my.keep.example\r\n" ++
        "\tuint AutoSaveConfigSpan 60\r\n" ++
        "\tbyte HashedPassword AQIDBAUGBwgJCgsMDQ4PEA==\r\n" ++
        "\tdeclare GlobalParams\r\n" ++
        "\t{\r\n" ++
        "\t\tuint Whatever 1\r\n" ++
        "\t}\r\n" ++
        "}\r\n" ++
        "declare ListenerList\r\n" ++
        "{\r\n" ++
        "\tdeclare Listener0\r\n" ++
        "\t{\r\n" ++
        "\t\tuint Port 1194\r\n" ++
        "\t\tbool Enabled false\r\n" ++
        "\t\tbool DisableDos true\r\n" ++
        "\t}\r\n" ++
        "}\r\n" ++
        "declare VirtualHUB\r\n" ++
        "{\r\n" ++
        "\tdeclare DEFAULT\r\n" ++
        "\t{\r\n" ++
        "\t\tbool Online true\r\n" ++
        "\t\tuint Type 0\r\n" ++
        "\t\tdeclare Option\r\n" ++
        "\t\t{\r\n" ++
        "\t\t\tuint MaxSession 5\r\n" ++
        "\t\t}\r\n" ++
        "\t\tdeclare SecurityAccountDatabase\r\n" ++
        "\t\t{\r\n" ++
        "\t\t\tdeclare UserList\r\n" ++
        "\t\t\t{\r\n" ++
        "\t\t\t\tdeclare alice\r\n" ++
        "\t\t\t\t{\r\n" ++
        "\t\t\t\t\tuint AuthType 1\r\n" ++
        "\t\t\t\t\tbyte AuthPassword AQIDBAUGBwgJCgsMDQ4PEBESExQ=\r\n" ++
        "\t\t\t\t}\r\n" ++
        "\t\t\t}\r\n" ++
        "\t\t}\r\n" ++
        "\t}\r\n" ++
        "}\r\n";

    const parsed = try cfg.parse(allocator, text);
    defer parsed.deinit();
    var config = try ServerConfig.fromCfg(allocator, parsed.root);
    defer config.deinit();

    try testing.expectEqual(@as(u32, 60 * 1000), config.server.auto_save_span_ms);
    try testing.expectEqualStrings("my.keep.example", config.server.keep_connect_host);
    try testing.expectEqual(@as(usize, 1), config.listeners.items.len);
    try testing.expectEqual(@as(u16, 1194), config.listeners.items[0].port);
    try testing.expect(!config.listeners.items[0].enabled);
    try testing.expect(config.listeners.items[0].disable_dos);
    try testing.expectEqual(@as(usize, 1), config.hubs.items.len);
    try testing.expectEqualStrings("DEFAULT", config.hubs.items[0].name);
    try testing.expectEqual(@as(u32, 5), config.hubs.items[0].option.max_session);
    try testing.expectEqual(@as(usize, 1), config.hubs.items[0].users.items.len);
    try testing.expectEqualStrings("alice", config.hubs.items[0].users.items[0].name);
    try testing.expectEqual(@as(u8, 1), config.hubs.items[0].users.items[0].auth_type);
    try testing.expect(config.hubs.items[0].users.items[0].auth_password != null);
}

test "server.vpn_server_config rejects a file without ServerConfiguration" {
    const allocator = testing.allocator;
    const parsed = try cfg.parse(allocator, "declare VirtualHUB\n{\n\tdeclare DEFAULT\n\t{\n\t}\n}\n");
    defer parsed.deinit();
    try testing.expectError(error.InvalidConfig, ServerConfig.fromCfg(allocator, parsed.root));
}

test "server.vpn_server_config backup policy is honored" {
    const allocator = testing.allocator;
    var config = try ServerConfig.initDefault(allocator);
    defer config.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = "policy_test.config";

    // With `backup_config_only_when_modified`, a save at an unchanged
    // revision must not produce a `<path>~` backup.
    try config.save(tmp.dir, path);
    try testing.expectError(error.FileNotFound, tmp.dir.openFile("policy_test.config~", .{}));

    // Bump the revision: the next save backs the previous file up.
    config.config_revision = 2;
    try config.save(tmp.dir, path);
    _ = try tmp.dir.openFile("policy_test.config~", .{});

    // `dont_backup_config` disables backups entirely, even on revision change.
    config.server.dont_backup_config = true;
    config.config_revision = 3;
    try config.save(tmp.dir, path);
    tmp.dir.deleteFile("policy_test.config~") catch {};
    config.config_revision = 4;
    try config.save(tmp.dir, path);
    try testing.expectError(error.FileNotFound, tmp.dir.openFile("policy_test.config~", .{}));
}

test "server.vpn_server_config load missing file falls back to defaults" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try testing.expectError(error.FileNotFound, ServerConfig.load(allocator, tmp.dir, "nope.config"));
}

test "server.vpn_server_config autosave writes on markModified and stops" {
    const allocator = testing.allocator;
    var config = try ServerConfig.initDefault(allocator);
    defer config.deinit();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = default_config_file_name;

    // Save the baseline once (so the file exists before the saver runs).
    try config.save(tmp.dir, path);

    var saver: Autosaver = undefined;
    try saver.start(&config, tmp.dir, path, 10);
    // Change the config under the saver's lock, flag it, and give the 10ms
    // tick time to fire.
    saver.lock();
    allocator.free(config.server.keep_connect_host);
    config.server.keep_connect_host = try allocator.dupe(u8, "changed.example");
    saver.unlock();
    saver.markModified();
    std.Thread.sleep(50 * std.time.ns_per_ms);

    var reloaded = try ServerConfig.load(allocator, tmp.dir, path);
    defer reloaded.deinit();
    try testing.expectEqualStrings("changed.example", reloaded.server.keep_connect_host);

    saver.stop();
}

test "server.vpn_server_config save/load round-trips groups" {
    const allocator = testing.allocator;
    var config = try ServerConfig.initDefault(allocator);
    defer config.deinit();

    const hub = &config.hubs.items[0];
    try hub.groups.append(allocator, .{
        .name = try allocator.dupe(u8, "engineers"),
        .realname = try allocator.dupe(u8, "Engineering Team"),
        .note = try allocator.dupe(u8, "Core developers"),
    });
    try hub.groups.append(allocator, .{
        .name = try allocator.dupe(u8, "admins"),
        .realname = try allocator.dupe(u8, ""),
        .note = try allocator.dupe(u8, ""),
    });

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try config.save(tmp.dir, default_config_file_name);

    var reloaded = try ServerConfig.load(allocator, tmp.dir, default_config_file_name);
    defer reloaded.deinit();

    const rhub = &reloaded.hubs.items[0];
    try testing.expectEqual(@as(usize, 2), rhub.groups.items.len);
    try testing.expectEqualStrings("engineers", rhub.groups.items[0].name);
    try testing.expectEqualStrings("Engineering Team", rhub.groups.items[0].realname);
    try testing.expectEqualStrings("Core developers", rhub.groups.items[0].note);
    try testing.expectEqualStrings("admins", rhub.groups.items[1].name);
    try testing.expectEqualStrings("", rhub.groups.items[1].realname);
}
