//! Configuration Manager
//!
//! Phase 8: JSON configuration file management with validation

const std = @import("std");
const Allocator = std.mem.Allocator;
const args_mod = @import("args.zig");

// ============================================================================
// Configuration Structure
// ============================================================================

/// Full configuration file structure
pub const ConfigFile = struct {
    // Server settings
    server: ?[]const u8 = null,
    port: ?u16 = null,
    hub: ?[]const u8 = null,

    // Authentication
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    password_hash: ?[]const u8 = null,

    // Connection options
    skip_tls_verify: ?bool = null,
    use_compress: ?bool = null,
    use_encrypt: ?bool = null,
    half_connection: ?bool = null,
    qos: ?bool = null,
    udp_accel: ?bool = null,
    max_connections: ?u8 = null,
    mtu: ?u16 = null,
    ip_version: ?[]const u8 = null,

    // Reconnection
    reconnect: ?ReconnectConfig = null,

    // IP configuration
    static_ip: ?StaticIpConfig = null,

    // Routing
    routing: ?RoutingConfig = null,

    // Proxy
    proxy: ?[]const u8 = null,

    /// TCP_NODELAY (disable Nagle's algorithm)
    tcp_nodelay: ?bool = null,

    // Timeouts (milliseconds)
    connect_timeout_ms: ?u32 = null,
    read_timeout_ms: ?u32 = null,
    keepalive_interval_ms: ?u32 = null,
    garp_interval_ms: ?u32 = null,

    // Logging
    log_level: ?[]const u8 = null,
    /// Emit non-standard diagnostic logs (DIAG throughput/queue stats,
    /// per-connection RX state). Equivalent to the --verbose CLI flag.
    verbose: ?bool = null,
};

pub const ReconnectConfig = struct {
    enabled: ?bool = null,
    max_attempts: ?u32 = null,
};

pub const StaticIpConfig = struct {
    ipv4_address: ?[]const u8 = null,
    ipv4_netmask: ?[]const u8 = null,
    ipv4_gateway: ?[]const u8 = null,
    ipv6_address: ?[]const u8 = null,
    ipv6_prefix: ?u8 = null,
    ipv6_gateway: ?[]const u8 = null,
    dns_servers: ?[]const []const u8 = null,
};

pub const RoutingConfig = struct {
    default_route: ?bool = null,
    accept_pushed_routes: ?bool = null,
    enable_custom_routes: ?bool = null,
    ipv4_include: ?[]const u8 = null,
    ipv4_exclude: ?[]const u8 = null,
    ipv6_include: ?[]const u8 = null,
    ipv6_exclude: ?[]const u8 = null,
};

// ============================================================================
// Configuration Manager
// ============================================================================

pub const ConfigManager = struct {
    allocator: Allocator,
    config: ConfigFile,
    config_path: ?[]const u8,
    json_source: ?[]const u8,
    parsed: ?std.json.Parsed(ConfigFile) = null,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .config = .{},
            .config_path = null,
            .json_source = null,
            .parsed = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.json_source) |src| {
            self.allocator.free(src);
        }
        if (self.config_path) |path| {
            self.allocator.free(path);
        }
        if (self.parsed) |p| {
            p.deinit();
            self.parsed = null;
        }
        self.config = .{};
    }

    /// Load configuration from file
    pub fn loadFromFile(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const stat = try file.stat();
        if (stat.size > 1024 * 1024) { // 1MB limit
            return error.ConfigFileTooLarge;
        }

        const content = try self.allocator.alloc(u8, stat.size);
        errdefer self.allocator.free(content);

        const bytes_read = try file.readAll(content);
        if (bytes_read != stat.size) {
            return error.IncompleteRead;
        }

        try self.parseJson(content);
        self.config_path = try self.allocator.dupe(u8, path);
        self.json_source = content;
    }

    /// Load from JSON string
    pub fn loadFromString(self: *Self, json: []const u8) !void {
        if (self.parsed) |p| {
            p.deinit();
        }
        try self.parseJson(json);
    }

    fn parseJson(self: *Self, json: []const u8) !void {
        if (self.parsed) |p| {
            p.deinit();
            self.parsed = null;
        }
        self.parsed = std.json.parseFromSlice(ConfigFile, self.allocator, json, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch {
            return error.InvalidJson;
        };
        self.config = self.parsed.?.value;
    }

    /// Get default configuration file path
    pub fn getDefaultPath(allocator: Allocator) ![]const u8 {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.NoHomeDir;
        defer allocator.free(home);
        return try std.fmt.allocPrint(allocator, "{s}/.config/softether-zig/config.json", .{home});
    }

    /// Check if default config file exists
    pub fn defaultConfigExists() bool {
        const allocator = std.heap.page_allocator;
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch return false;
        defer allocator.free(home);

        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/.config/softether-zig/config.json", .{home}) catch return false;

        std.fs.cwd().access(path, .{}) catch return false;
        return true;
    }

    /// Merge CLI args with config file (CLI takes priority).
    /// Deep-copies all string fields so the ConfigManager can be freed afterward.
    pub fn mergeWithArgs(self: *const Self, cli_args: *args_mod.CliArgs) !void {
        const alloc = cli_args.allocator orelse return;

        // Server settings
        if (cli_args.server == null) {
            if (self.config.server) |s| cli_args.server = try alloc.dupe(u8, s);
        }
        if (cli_args.port == 443 and self.config.port != null) cli_args.port = self.config.port.?;
        if (cli_args.hub == null) {
            if (self.config.hub) |s| cli_args.hub = try alloc.dupe(u8, s);
        }

        // Authentication
        if (cli_args.username == null) {
            if (self.config.username) |s| cli_args.username = try alloc.dupe(u8, s);
        }
        if (cli_args.password == null) {
            if (self.config.password) |s| cli_args.password = try alloc.dupe(u8, s);
        }
        if (cli_args.password_hash == null) {
            if (self.config.password_hash) |s| cli_args.password_hash = try alloc.dupe(u8, s);
        }

        // Connection options
        if (self.config.skip_tls_verify) |stv| cli_args.skip_tls_verify = stv;
        if (self.config.use_compress) |comp| cli_args.use_compress = comp;
        if (self.config.use_encrypt) |v| cli_args.use_encrypt = v;
        if (self.config.half_connection) |v| cli_args.half_connection = v;
        if (self.config.qos) |v| cli_args.qos = v;
        if (self.config.udp_accel) |accel| cli_args.udp_accel = accel;
        if (self.config.max_connections) |max| cli_args.max_connections = max;
        if (self.config.mtu) |m| cli_args.mtu = m;
        if (self.config.ip_version) |v| {
            if (cli_args.ip_version == null) {
                if (args_mod.IpVersion.fromString(v)) |iv| cli_args.ip_version = iv;
            }
        }

        // Reconnection
        if (self.config.reconnect) |rc| {
            if (rc.enabled) |en| cli_args.reconnect = en;
            if (rc.max_attempts) |ma| cli_args.max_retries = ma;
        }

        // Static IP
        if (self.config.static_ip) |sip| {
            if (cli_args.static_ipv4 == null) {
                if (sip.ipv4_address) |s| cli_args.static_ipv4 = try alloc.dupe(u8, s);
            }
            if (cli_args.static_ipv4_netmask == null) {
                if (sip.ipv4_netmask) |s| cli_args.static_ipv4_netmask = try alloc.dupe(u8, s);
            }
            if (cli_args.static_ipv4_gateway == null) {
                if (sip.ipv4_gateway) |s| cli_args.static_ipv4_gateway = try alloc.dupe(u8, s);
            }
            if (cli_args.static_ipv6 == null) {
                if (sip.ipv6_address) |s| cli_args.static_ipv6 = try alloc.dupe(u8, s);
            }
            if (sip.ipv6_prefix) |pf| cli_args.static_ipv6_prefix = pf;
            if (cli_args.static_ipv6_gateway == null) {
                if (sip.ipv6_gateway) |s| cli_args.static_ipv6_gateway = try alloc.dupe(u8, s);
            }
            if (sip.dns_servers) |dns| {
                if (cli_args.dns_servers.len == 0) {
                    const duped = try alloc.alloc([]const u8, dns.len);
                    for (dns, 0..) |server, j| duped[j] = try alloc.dupe(u8, server);
                    cli_args.dns_servers = duped;
                }
            }
        }

        // Routing
        if (self.config.routing) |rt| {
            if (rt.default_route) |dr| cli_args.default_route = dr;
            if (rt.accept_pushed_routes) |apr| cli_args.accept_pushed_routes = apr;
            if (rt.enable_custom_routes) |ecr| cli_args.enable_custom_routes = ecr;
            if (cli_args.ipv4_include == null) {
                if (rt.ipv4_include) |s| cli_args.ipv4_include = try alloc.dupe(u8, s);
            }
            if (cli_args.ipv4_exclude == null) {
                if (rt.ipv4_exclude) |s| cli_args.ipv4_exclude = try alloc.dupe(u8, s);
            }
            if (cli_args.ipv6_include == null) {
                if (rt.ipv6_include) |s| cli_args.ipv6_include = try alloc.dupe(u8, s);
            }
            if (cli_args.ipv6_exclude == null) {
                if (rt.ipv6_exclude) |s| cli_args.ipv6_exclude = try alloc.dupe(u8, s);
            }
        }

        // Proxy
        if (cli_args.proxy == null) {
            if (self.config.proxy) |s| cli_args.proxy = try alloc.dupe(u8, s);
        }

        // TCP_NODELAY
        if (self.config.tcp_nodelay) |v| cli_args.tcp_nodelay = v;

        // Timeouts
        if (self.config.connect_timeout_ms) |v| cli_args.connect_timeout_ms = v;
        if (self.config.read_timeout_ms) |v| cli_args.read_timeout_ms = v;
        if (self.config.keepalive_interval_ms) |v| cli_args.keepalive_interval_ms = v;
        if (self.config.garp_interval_ms) |v| cli_args.garp_interval_ms = v;

        // Log level
        if (self.config.log_level) |ll| {
            if (args_mod.LogLevel.fromString(ll)) |l| cli_args.log_level = l;
        }

        // Verbose diagnostics
        if (self.config.verbose) |v| cli_args.verbose = v;
    }

    /// Save current config to file
    pub fn saveToFile(self: *Self, path: []const u8) !void {
        var file = try std.fs.cwd().createFile(path, .{});
        defer file.close();

        try std.json.stringify(self.config, .{ .whitespace = .indent_2 }, file.writer());
    }

    /// Create config from CLI args
    pub fn fromArgs(allocator: Allocator, cli_args: *const args_mod.CliArgs) ConfigFile {
        _ = allocator;
        var cfg = ConfigFile{};

        cfg.server = cli_args.server;
        cfg.port = cli_args.port;
        cfg.hub = cli_args.hub;
        cfg.username = cli_args.username;
        cfg.password = cli_args.password;
        cfg.password_hash = cli_args.password_hash;
        cfg.skip_tls_verify = cli_args.skip_tls_verify;
        cfg.use_compress = cli_args.use_compress;
        cfg.use_encrypt = cli_args.use_encrypt;
        cfg.half_connection = cli_args.half_connection;
        cfg.qos = cli_args.qos;
        cfg.udp_accel = cli_args.udp_accel;
        cfg.max_connections = cli_args.max_connections;
        cfg.mtu = cli_args.mtu;
    cfg.proxy = cli_args.proxy;
    cfg.tcp_nodelay = cli_args.tcp_nodelay;
    cfg.connect_timeout_ms = cli_args.connect_timeout_ms;
        cfg.read_timeout_ms = cli_args.read_timeout_ms;
        cfg.keepalive_interval_ms = cli_args.keepalive_interval_ms;
        cfg.garp_interval_ms = cli_args.garp_interval_ms;

        cfg.reconnect = .{
            .enabled = cli_args.reconnect,
            .max_attempts = cli_args.max_retries,
        };

        if (cli_args.static_ipv4 != null or cli_args.static_ipv6 != null or cli_args.dns_servers.len > 0) {
            cfg.static_ip = .{
                .ipv4_address = cli_args.static_ipv4,
                .ipv4_netmask = cli_args.static_ipv4_netmask,
                .ipv4_gateway = cli_args.static_ipv4_gateway,
                .ipv6_address = cli_args.static_ipv6,
                .ipv6_prefix = cli_args.static_ipv6_prefix,
                .ipv6_gateway = cli_args.static_ipv6_gateway,
                .dns_servers = if (cli_args.dns_servers.len > 0) cli_args.dns_servers else null,
            };
        }

        cfg.routing = .{
            .default_route = cli_args.default_route,
            .accept_pushed_routes = cli_args.accept_pushed_routes,
            .enable_custom_routes = cli_args.enable_custom_routes,
            .ipv4_include = cli_args.ipv4_include,
            .ipv4_exclude = cli_args.ipv4_exclude,
            .ipv6_include = cli_args.ipv6_include,
            .ipv6_exclude = cli_args.ipv6_exclude,
        };

        return cfg;
    }
};

// ============================================================================
// Validation
// ============================================================================

pub const ValidationError = struct {
    field: []const u8,
    message: []const u8,
};

pub fn validateConfig(cfg: *const ConfigFile, allocator: Allocator) ![]ValidationError {
    var errors = std.ArrayListUnmanaged(ValidationError){};
    defer errors.deinit(allocator);

    // Port validation
    if (cfg.port) |p| {
        if (p == 0) {
            try errors.append(allocator, .{ .field = "port", .message = "Port cannot be 0" });
        }
    }

    // Max connections validation
    if (cfg.max_connections) |mc| {
        if (mc > 32) {
            try errors.append(allocator, .{ .field = "max_connections", .message = "Max connections must be <= 32" });
        }
    }

    // IPv6 prefix validation
    if (cfg.static_ip) |sip| {
        if (sip.ipv6_prefix) |pf| {
            if (pf > 128) {
                try errors.append(allocator, .{
                    .field = "static_ip.ipv6_prefix",
                    .message = "IPv6 prefix must be <= 128",
                });
            }
        }
    }

    return try allocator.dupe(ValidationError, errors.items);
}

// ============================================================================
// Tests
// ============================================================================

test "ConfigManager init" {
    var mgr = ConfigManager.init(std.testing.allocator);
    defer mgr.deinit();

    try std.testing.expect(mgr.config.server == null);
    try std.testing.expect(mgr.config_path == null);
}

test "ConfigManager loadFromString" {
    var mgr = ConfigManager.init(std.testing.allocator);
    defer mgr.deinit();

    const json =
        \\{
        \\  "server": "vpn.example.com",
        \\  "port": 8443,
        \\  "hub": "VPN",
        \\  "username": "testuser"
        \\}
    ;

    try mgr.loadFromString(json);

    try std.testing.expectEqualStrings("vpn.example.com", mgr.config.server.?);
    try std.testing.expectEqual(@as(u16, 8443), mgr.config.port.?);
    try std.testing.expectEqualStrings("VPN", mgr.config.hub.?);
    try std.testing.expectEqualStrings("testuser", mgr.config.username.?);
}

test "ConfigManager loadFromString with reconnect" {
    var mgr = ConfigManager.init(std.testing.allocator);
    defer mgr.deinit();

    const json =
        \\{
        \\  "server": "test.com",
        \\  "reconnect": {
        \\    "enabled": true,
        \\    "max_attempts": 5
        \\  }
        \\}
    ;

    try mgr.loadFromString(json);

    try std.testing.expect(mgr.config.reconnect != null);
    try std.testing.expectEqual(@as(bool, true), mgr.config.reconnect.?.enabled.?);
    try std.testing.expectEqual(@as(u32, 5), mgr.config.reconnect.?.max_attempts.?);
}

test "ConfigManager mergeWithArgs" {
    var mgr = ConfigManager.init(std.testing.allocator);
    defer mgr.deinit();

    const json =
        \\{
        \\  "server": "config-server.com",
        \\  "port": 8443,
        \\  "hub": "ConfigHub"
        \\}
    ;
    try mgr.loadFromString(json);

    var cli_args = args_mod.CliArgs{
        .server = try std.testing.allocator.dupe(u8, "cli-server.com"), // CLI should take priority
        .port = 443, // Default, should be overridden
        .allocator = std.testing.allocator,
    };
    defer cli_args.deinit();

    try mgr.mergeWithArgs(&cli_args);

    // CLI takes priority
    try std.testing.expectEqualStrings("cli-server.com", cli_args.server.?);
    // Config file value used since CLI was default
    try std.testing.expectEqual(@as(u16, 8443), cli_args.port);
    // Config file value used
    try std.testing.expectEqualStrings("ConfigHub", cli_args.hub.?);
}

test "ConfigManager fromArgs" {
    var cli_args = args_mod.CliArgs{
        .server = "test.com",
        .port = 443,
        .hub = "TEST",
        .reconnect = true,
        .max_retries = 10,
    };

    const cfg = ConfigManager.fromArgs(std.testing.allocator, &cli_args);

    try std.testing.expectEqualStrings("test.com", cfg.server.?);
    try std.testing.expect(cfg.reconnect.?.enabled.?);
    try std.testing.expectEqual(@as(u32, 10), cfg.reconnect.?.max_attempts.?);
}

test "validateConfig valid" {
    const cfg = ConfigFile{
        .server = "test.com",
        .port = 443,
        .max_connections = 4,
    };

    const errors = try validateConfig(&cfg, std.testing.allocator);
    defer std.testing.allocator.free(errors);

    try std.testing.expectEqual(@as(usize, 0), errors.len);
}

test "validateConfig invalid port" {
    const cfg = ConfigFile{
        .port = 0,
    };

    const errors = try validateConfig(&cfg, std.testing.allocator);
    defer std.testing.allocator.free(errors);

    try std.testing.expect(errors.len > 0);
    try std.testing.expectEqualStrings("port", errors[0].field);
}

test "validateConfig invalid max_connections" {
    const cfg = ConfigFile{
        .max_connections = 100,
    };

    const errors = try validateConfig(&cfg, std.testing.allocator);
    defer std.testing.allocator.free(errors);

    try std.testing.expect(errors.len > 0);
}

test "getDefaultPath" {
    // Only run if HOME is set
    if (std.process.hasEnvVar(std.testing.allocator, "HOME") catch false) {
        const path = try ConfigManager.getDefaultPath(std.testing.allocator);
        defer std.testing.allocator.free(path);

        try std.testing.expect(std.mem.endsWith(u8, path, "/config.json"));
    }
}
