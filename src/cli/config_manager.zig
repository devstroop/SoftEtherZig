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
    udp_accel: ?bool = null,
    max_connection: ?u8 = null,
    mtu: ?u16 = null, // Parsed from JSON, defaults applied later

    // Reconnection
    reconnect: ?ReconnectConfig = null,

    // IP configuration
    static_ip: ?StaticIpConfig = null,

    // Routing
    routing: ?RoutingConfig = null,

    // Logging
    log_level: ?[]const u8 = null,
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
    ipv4_include: ?[]const []const u8 = null,
    ipv4_exclude: ?[]const []const u8 = null,
    ipv6_include: ?[]const []const u8 = null,
    ipv6_exclude: ?[]const []const u8 = null,
};

// ============================================================================
// Configuration Manager
// ============================================================================

pub const ConfigManager = struct {
    allocator: Allocator,
    config: ConfigFile,
    config_path: ?[]const u8,
    json_source: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .config = .{},
            .config_path = null,
            .json_source = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.json_source) |src| {
            self.allocator.free(src);
        }
        if (self.config_path) |path| {
            self.allocator.free(path);
        }
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
        self.json_source = content;
        self.config_path = try self.allocator.dupe(u8, path);
    }

    /// Load from JSON string
    pub fn loadFromString(self: *Self, json: []const u8) !void {
        try self.parseJson(json);
    }

    fn parseJson(self: *Self, json: []const u8) !void {
        const parsed = std.json.parseFromSlice(ConfigFile, self.allocator, json, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always, // Allocate copies of strings
        }) catch {
            return error.InvalidJson;
        };
        // Don't deinit - we keep the parsed strings
        // The parsed.value contains slices pointing to allocated memory
        // that we need to keep alive

        self.config = parsed.value;
        // Note: The parsed arena will be kept alive with the strings
        // In production, we'd want to manage this more carefully
    }

    /// Get default configuration file path
    pub fn getDefaultPath(allocator: Allocator) ![]const u8 {
        const home = std.posix.getenv("HOME") orelse return error.NoHomeDir;
        return try std.fmt.allocPrint(allocator, "{s}/.config/softether-zig/config.json", .{home});
    }

    /// Check if default config file exists
    pub fn defaultConfigExists() bool {
        const home = std.posix.getenv("HOME") orelse return false;
        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/.config/softether-zig/config.json", .{home}) catch return false;

        std.fs.cwd().access(path, .{}) catch return false;
        return true;
    }

    /// Merge CLI args with config file (CLI takes priority)
    pub fn mergeWithArgs(self: *const Self, cli_args: *args_mod.CliArgs) void {
        // Server settings
        if (cli_args.server == null) cli_args.server = self.config.server;
        if (cli_args.port == 443 and self.config.port != null) cli_args.port = self.config.port.?;
        if (cli_args.hub == null) cli_args.hub = self.config.hub;

        // Authentication
        if (cli_args.username == null) cli_args.username = self.config.username;
        if (cli_args.password == null) cli_args.password = self.config.password;
        if (cli_args.password_hash == null) cli_args.password_hash = self.config.password_hash;

        // Connection options
        if (self.config.skip_tls_verify) |stv| {
            cli_args.skip_tls_verify = stv;
        }
        if (self.config.use_compress) |comp| {
            if (cli_args.use_compress) cli_args.use_compress = comp;
        }
        if (self.config.udp_accel) |accel| {
            cli_args.udp_accel = accel;
        }
        if (self.config.max_connection) |max| cli_args.max_connection = max;
        if (self.config.mtu) |m| cli_args.mtu = m;

        // Reconnection
        if (self.config.reconnect) |rc| {
            if (rc.enabled) |en| cli_args.reconnect = en;
            if (rc.max_attempts) |ma| cli_args.max_retries = ma;
        }

        // Static IP
        if (self.config.static_ip) |sip| {
            if (sip.ipv4_address) |ip| cli_args.static_ipv4 = ip;
            if (sip.ipv4_netmask) |nm| cli_args.static_ipv4_netmask = nm;
            if (sip.ipv4_gateway) |gw| cli_args.static_ipv4_gateway = gw;
            if (sip.ipv6_address) |ip| cli_args.static_ipv6 = ip;
            if (sip.ipv6_prefix) |pf| cli_args.static_ipv6_prefix = pf;
            if (sip.ipv6_gateway) |gw| cli_args.static_ipv6_gateway = gw;
        }

        // Routing
        if (self.config.routing) |rt| {
            if (rt.default_route) |dr| cli_args.default_route = dr;
            if (rt.accept_pushed_routes) |apr| cli_args.accept_pushed_routes = apr;
            if (rt.enable_custom_routes) |ecr| cli_args.enable_custom_routes = ecr;
            if (rt.ipv4_include) |inc| cli_args.ipv4_include = inc;
            if (rt.ipv4_exclude) |exc| cli_args.ipv4_exclude = exc;
            if (rt.ipv6_include) |inc| cli_args.ipv6_include = inc;
            if (rt.ipv6_exclude) |exc| cli_args.ipv6_exclude = exc;
        }

        // Log level
        if (self.config.log_level) |ll| {
            if (args_mod.LogLevel.fromString(ll)) |l| {
                cli_args.log_level = l;
            }
        }
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
        cfg.max_connection = cli_args.max_connection;
        cfg.mtu = cli_args.mtu;

        cfg.reconnect = .{
            .enabled = cli_args.reconnect,
            .max_attempts = cli_args.max_retries,
        };

        if (cli_args.static_ipv4 != null or cli_args.static_ipv6 != null) {
            cfg.static_ip = .{
                .ipv4_address = cli_args.static_ipv4,
                .ipv4_netmask = cli_args.static_ipv4_netmask,
                .ipv4_gateway = cli_args.static_ipv4_gateway,
                .ipv6_address = cli_args.static_ipv6,
                .ipv6_prefix = cli_args.static_ipv6_prefix,
                .ipv6_gateway = cli_args.static_ipv6_gateway,
            };
        }

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

    // Max connection validation
    if (cfg.max_connection) |mc| {
        if (mc > 32) {
            try errors.append(allocator, .{ .field = "max_connection", .message = "Max connection must be <= 32" });
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
        .server = "cli-server.com", // CLI should take priority
        .port = 443, // Default, should be overridden
    };

    mgr.mergeWithArgs(&cli_args);

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
        .max_connection = 4,
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

test "validateConfig invalid max_connection" {
    const cfg = ConfigFile{
        .max_connection = 100,
    };

    const errors = try validateConfig(&cfg, std.testing.allocator);
    defer std.testing.allocator.free(errors);

    try std.testing.expect(errors.len > 0);
}

test "getDefaultPath" {
    // Only run if HOME is set
    if (std.posix.getenv("HOME")) |_| {
        const path = try ConfigManager.getDefaultPath(std.testing.allocator);
        defer std.testing.allocator.free(path);

        try std.testing.expect(std.mem.endsWith(u8, path, "/config.json"));
    }
}
