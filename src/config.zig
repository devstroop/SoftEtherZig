const std = @import("std");
const errors = @import("errors.zig");

const VpnError = errors.VpnError;

/// Default configuration directory path
pub const DEFAULT_CONFIG_DIR = "~/.config/softether-zig";
pub const DEFAULT_CONFIG_FILE = "config.json";

/// IP version selection
pub const IpVersion = enum {
    auto, // Auto-detect (prefer IPv4, fallback to IPv6)
    ipv4, // Force IPv4 only
    ipv6, // Force IPv6 only
    dual, // Dual-stack (both IPv4 and IPv6)

    /// Parse IpVersion from string
    pub fn fromString(s: []const u8) !IpVersion {
        if (std.mem.eql(u8, s, "auto")) return .auto;
        if (std.mem.eql(u8, s, "ipv4")) return .ipv4;
        if (std.mem.eql(u8, s, "ipv6")) return .ipv6;
        if (std.mem.eql(u8, s, "dual")) return .dual;
        return error.InvalidIpVersion;
    }
};

/// Static IP configuration
pub const StaticIpConfig = struct {
    ipv4_address: ?[]const u8 = null, // e.g., "192.168.1.10"
    ipv4_netmask: ?[]const u8 = null, // e.g., "255.255.255.0"
    ipv4_gateway: ?[]const u8 = null, // e.g., "192.168.1.1"
    ipv6_address: ?[]const u8 = null, // e.g., "2001:db8::1"
    ipv6_prefix_len: ?u8 = null, // e.g., 64
    ipv6_gateway: ?[]const u8 = null, // e.g., "fe80::1"
    dns_servers: ?[]const []const u8 = null, // e.g., ["8.8.8.8", "8.8.4.4"]
};

/// Routing configuration
pub const RoutingConfig = struct {
    /// Send ALL traffic through VPN (set VPN as default gateway)
    default_route: bool = true,
    /// Accept routes pushed by VPN server (DHCP option 121/249)
    accept_pushed_routes: bool = true,
    /// Enable custom route includes/excludes
    enable_custom_routes: bool = false,
    /// IPv4 routes to include (CIDR notation) - only these routes through VPN
    ipv4_include: ?[]const []const u8 = null,
    /// IPv4 routes to exclude (CIDR notation) - these routes NOT through VPN
    ipv4_exclude: ?[]const []const u8 = null,
    /// IPv6 routes to include (CIDR notation)
    ipv6_include: ?[]const []const u8 = null,
    /// IPv6 routes to exclude (CIDR notation)
    ipv6_exclude: ?[]const []const u8 = null,
};

/// Authentication method
pub const AuthMethod = union(enum) {
    anonymous,
    password: struct {
        username: []const u8,
        password: []const u8,
        is_hashed: bool = false, // True if password is pre-hashed (base64-encoded SHA1)
    },
    certificate: struct {
        cert_path: []const u8,
        key_path: []const u8,
    },
    smart_card,
};

/// VPN connection configuration
pub const ConnectionConfig = struct {
    server_name: []const u8,
    server_port: u16,
    hub_name: []const u8,
    account_name: []const u8,
    auth: AuthMethod,
    use_encrypt: bool = true,
    use_compress: bool = true,
    max_connection: u32 = 0, // 0 = follow server policy, 1-32 = force specific count
    half_connection: bool = false,
    additional_connection_interval: u32 = 1,
    ip_version: IpVersion = .auto,
    static_ip: ?StaticIpConfig = null,
    routing: RoutingConfig = .{},

    /// Create a configuration builder
    pub fn builder() ConfigBuilder {
        return ConfigBuilder{};
    }
};

/// Builder pattern for ConnectionConfig
pub const ConfigBuilder = struct {
    server_name: ?[]const u8 = null,
    server_port: u16 = 443,
    hub_name: ?[]const u8 = null,
    account_name: ?[]const u8 = null,
    auth: ?AuthMethod = null,
    use_encrypt: bool = true,
    use_compress: bool = true,
    max_connection: u32 = 0, // 0 = follow server policy, 1-32 = force specific count
    half_connection: bool = false,
    additional_connection_interval: u32 = 1,
    ip_version: IpVersion = .auto,
    static_ip: ?StaticIpConfig = null,
    routing: RoutingConfig = .{}, // Routing configuration

    /// Set VPN server address and port
    pub fn setServer(self: *ConfigBuilder, name: []const u8, port: u16) *ConfigBuilder {
        self.server_name = name;
        self.server_port = port;
        return self;
    }

    /// Set virtual hub name
    pub fn setHub(self: *ConfigBuilder, hub: []const u8) *ConfigBuilder {
        self.hub_name = hub;
        return self;
    }

    /// Set account name
    pub fn setAccount(self: *ConfigBuilder, account: []const u8) *ConfigBuilder {
        self.account_name = account;
        return self;
    }

    /// Set authentication method
    pub fn setAuth(self: *ConfigBuilder, auth: AuthMethod) *ConfigBuilder {
        self.auth = auth;
        return self;
    }

    /// Set encryption flag
    pub fn setEncrypt(self: *ConfigBuilder, encrypt: bool) *ConfigBuilder {
        self.use_encrypt = encrypt;
        return self;
    }

    /// Set compression flag
    pub fn setCompress(self: *ConfigBuilder, compress: bool) *ConfigBuilder {
        self.use_compress = compress;
        return self;
    }

    /// Set maximum number of connections
    pub fn setMaxConnection(self: *ConfigBuilder, max: u32) *ConfigBuilder {
        self.max_connection = max;
        return self;
    }

    /// Set IP version preference
    pub fn setIpVersion(self: *ConfigBuilder, version: IpVersion) *ConfigBuilder {
        self.ip_version = version;
        return self;
    }

    /// Set static IP configuration
    pub fn setStaticIp(self: *ConfigBuilder, static_config: StaticIpConfig) *ConfigBuilder {
        self.static_ip = static_config;
        return self;
    }

    /// Build the final configuration
    pub fn build(self: ConfigBuilder) !ConnectionConfig {
        const server_name = self.server_name orelse return VpnError.MissingParameter;
        const hub_name = self.hub_name orelse return VpnError.MissingParameter;
        const account_name = self.account_name orelse return VpnError.MissingParameter;
        const auth = self.auth orelse return VpnError.MissingParameter;

        return ConnectionConfig{
            .server_name = server_name,
            .server_port = self.server_port,
            .hub_name = hub_name,
            .account_name = account_name,
            .auth = auth,
            .use_encrypt = self.use_encrypt,
            .use_compress = self.use_compress,
            .max_connection = self.max_connection,
            .half_connection = self.half_connection,
            .additional_connection_interval = self.additional_connection_interval,
            .ip_version = self.ip_version,
            .static_ip = self.static_ip,
            .routing = self.routing,
        };
    }
};

test "config builder validation" {
    // Missing server should fail
    var builder1 = ConnectionConfig.builder();
    _ = builder1.setHub("HUB")
        .setAccount("test")
        .setAuth(.anonymous);
    const result1 = builder1.build();
    try std.testing.expectError(VpnError.MissingParameter, result1);

    // Complete config should succeed
    var builder2 = ConnectionConfig.builder();
    _ = builder2.setServer("vpn.example.com", 443)
        .setHub("HUB")
        .setAccount("test")
        .setAuth(.anonymous);
    const result2 = builder2.build();
    try std.testing.expect(result2 != VpnError.MissingParameter);
}

test "config builder chaining" {
    var builder = ConnectionConfig.builder();
    _ = builder
        .setServer("test.vpn.com", 8443)
        .setHub("TEST_HUB")
        .setAccount("user1")
        .setEncrypt(false)
        .setCompress(false);

    try std.testing.expectEqualStrings("test.vpn.com", builder.server_name.?);
    try std.testing.expectEqual(@as(u16, 8443), builder.server_port);
    try std.testing.expectEqual(false, builder.use_encrypt);
}

/// JSON configuration schema
pub const JsonConfig = struct {
    server: ?[]const u8 = null,
    port: ?u16 = null,
    hub: ?[]const u8 = null,
    account: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    password_hash: ?[]const u8 = null,
    use_encrypt: ?bool = null,
    use_compress: ?bool = null,
    max_connection: ?u32 = null,
    ip_version: ?[]const u8 = null,
    static_ipv4: ?[]const u8 = null,
    static_ipv4_netmask: ?[]const u8 = null,
    static_ipv4_gateway: ?[]const u8 = null,
    static_ipv6: ?[]const u8 = null,
    static_ipv6_prefix: ?u8 = null,
    static_ipv6_gateway: ?[]const u8 = null,
    dns_servers: ?[]const []const u8 = null,
    reconnect: ?bool = null,
    max_reconnect_attempts: ?u32 = null,
    min_backoff: ?u32 = null,
    max_backoff: ?u32 = null,
    routing: ?struct {
        default_route: ?bool = null,
        accept_pushed_routes: ?bool = null,
        enable_custom_routes: ?bool = null,
        ipv4_include: ?[]const []const u8 = null,
        ipv4_exclude: ?[]const []const u8 = null,
        ipv6_include: ?[]const []const u8 = null,
        ipv6_exclude: ?[]const []const u8 = null,
    } = null,
};

/// Expand tilde (~) in path to home directory
fn expandPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len > 0 and path[0] == '~') {
        const home = std.posix.getenv("HOME") orelse return error.NoHomeDirectory;
        if (path.len == 1) {
            return try allocator.dupe(u8, home);
        }
        if (path[1] == '/') {
            return try std.fmt.allocPrint(allocator, "{s}{s}", .{ home, path[1..] });
        }
    }
    return try allocator.dupe(u8, path);
}

/// Load configuration from JSON file
/// Caller must call result.deinit() to free memory
pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(JsonConfig) {
    // Expand path (e.g., ~/.config/softether-zig/config.json)
    const expanded_path = try expandPath(allocator, path);
    defer allocator.free(expanded_path);

    // Convert to absolute path if relative
    const absolute_path = if (std.fs.path.isAbsolute(expanded_path))
        try allocator.dupe(u8, expanded_path)
    else blk: {
        const cwd = try std.process.getCwdAlloc(allocator);
        defer allocator.free(cwd);
        break :blk try std.fs.path.join(allocator, &[_][]const u8{ cwd, expanded_path });
    };
    defer allocator.free(absolute_path);

    // Read file contents
    const file = std.fs.openFileAbsolute(absolute_path, .{}) catch |err| {
        switch (err) {
            error.FileNotFound => {
                // Return empty parsed config if file doesn't exist
                var empty_parsed: std.json.Parsed(JsonConfig) = undefined;
                empty_parsed.arena = try allocator.create(std.heap.ArenaAllocator);
                empty_parsed.arena.* = std.heap.ArenaAllocator.init(allocator);
                empty_parsed.value = JsonConfig{};
                return empty_parsed;
            },
            else => return err,
        }
    };
    defer file.close();

    const max_size = 1024 * 1024; // 1MB limit
    const contents = try file.readToEndAlloc(allocator, max_size);
    defer allocator.free(contents);

    // Parse JSON
    const parsed = try std.json.parseFromSlice(JsonConfig, allocator, contents, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    // Note: caller must call parsed.deinit() to free the config

    return parsed; // Return whole Parsed object so caller can deinit()
}

/// Get default config file path
pub fn getDefaultConfigPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = std.posix.getenv("HOME") orelse return error.NoHomeDirectory;
    return try std.fmt.allocPrint(allocator, "{s}/.config/softether-zig/{s}", .{ home, DEFAULT_CONFIG_FILE });
}

/// Helper to pick first non-null value for optional types (CLI > env > file > default)
fn pickOpt(comptime T: type, cli: ?T, env: ?T, file: ?T, default: ?T) ?T {
    return cli orelse env orelse file orelse default;
}

/// Helper to pick first non-null value for non-optional types (CLI > env > file > default)
fn pickVal(comptime T: type, cli: ?T, env: ?T, file: ?T, default: T) T {
    return cli orelse env orelse file orelse default;
}

/// Merge configurations with priority: CLI > env vars > config file
pub fn mergeConfigs(
    allocator: std.mem.Allocator,
    file_config: JsonConfig,
    env_config: JsonConfig,
    cli_config: JsonConfig,
) !ConfigBuilder {
    var builder = ConfigBuilder{};

    // Server configuration
    if (pickOpt([]const u8, cli_config.server, env_config.server, file_config.server, null)) |server| {
        builder.server_name = server;
    }
    builder.server_port = pickVal(u16, cli_config.port, env_config.port, file_config.port, 443);

    if (pickOpt([]const u8, cli_config.hub, env_config.hub, file_config.hub, null)) |hub| {
        builder.hub_name = hub;
    }

    const account = pickOpt([]const u8, cli_config.account, env_config.account, file_config.account, null);
    const username = pickOpt([]const u8, cli_config.username, env_config.username, file_config.username, null);

    if (account) |acc| {
        builder.account_name = acc;
    } else if (username) |user| {
        builder.account_name = user; // Default account name to username
    }

    // Authentication (password_hash takes precedence over password)
    if (username) |user| {
        const password_hash = pickOpt([]const u8, cli_config.password_hash, env_config.password_hash, file_config.password_hash, null);
        const password = pickOpt([]const u8, cli_config.password, env_config.password, file_config.password, null);

        if (password_hash) |hash| {
            builder.auth = .{ .password = .{
                .username = user,
                .password = hash,
                .is_hashed = true,
            } };
        } else if (password) |pass| {
            builder.auth = .{ .password = .{
                .username = user,
                .password = pass,
                .is_hashed = false,
            } };
        }
    }

    // Connection settings
    builder.use_encrypt = pickVal(bool, cli_config.use_encrypt, env_config.use_encrypt, file_config.use_encrypt, true);
    builder.use_compress = pickVal(bool, cli_config.use_compress, env_config.use_compress, file_config.use_compress, true);
    builder.max_connection = pickVal(u32, cli_config.max_connection, env_config.max_connection, file_config.max_connection, 0);

    // IP version
    if (pickOpt([]const u8, cli_config.ip_version, env_config.ip_version, file_config.ip_version, null)) |ip_ver| {
        builder.ip_version = IpVersion.fromString(ip_ver) catch .auto;
    }

    // Static IP configuration
    const has_static_ip = file_config.static_ipv4 != null or file_config.static_ipv6 != null or
        env_config.static_ipv4 != null or env_config.static_ipv6 != null or
        cli_config.static_ipv4 != null or cli_config.static_ipv6 != null;

    if (has_static_ip) {
        var static_config = StaticIpConfig{};

        static_config.ipv4_address = pickOpt([]const u8, cli_config.static_ipv4, env_config.static_ipv4, file_config.static_ipv4, null);
        static_config.ipv4_netmask = pickOpt([]const u8, cli_config.static_ipv4_netmask, env_config.static_ipv4_netmask, file_config.static_ipv4_netmask, null);
        static_config.ipv4_gateway = pickOpt([]const u8, cli_config.static_ipv4_gateway, env_config.static_ipv4_gateway, file_config.static_ipv4_gateway, null);
        static_config.ipv6_address = pickOpt([]const u8, cli_config.static_ipv6, env_config.static_ipv6, file_config.static_ipv6, null);
        static_config.ipv6_prefix_len = pickOpt(u8, cli_config.static_ipv6_prefix, env_config.static_ipv6_prefix, file_config.static_ipv6_prefix, null);
        static_config.ipv6_gateway = pickOpt([]const u8, cli_config.static_ipv6_gateway, env_config.static_ipv6_gateway, file_config.static_ipv6_gateway, null); // DNS servers (merge all sources)
        var dns_list = std.ArrayList([]const u8){};
        defer dns_list.deinit(allocator);

        if (file_config.dns_servers) |dns| {
            try dns_list.appendSlice(allocator, dns);
        }
        if (env_config.dns_servers) |dns| {
            try dns_list.appendSlice(allocator, dns);
        }
        if (cli_config.dns_servers) |dns| {
            try dns_list.appendSlice(allocator, dns);
        }
        if (dns_list.items.len > 0) {
            static_config.dns_servers = try allocator.dupe([]const u8, dns_list.items);
        }

        builder.static_ip = static_config;
    }

    // Routing configuration
    const has_routing = file_config.routing != null or env_config.routing != null or cli_config.routing != null;
    if (has_routing) {
        var routing_config = RoutingConfig{};

        const file_routing = file_config.routing;
        const env_routing = env_config.routing;
        const cli_routing = cli_config.routing;

        routing_config.default_route = pickVal(bool, if (cli_routing) |r| r.default_route else null, if (env_routing) |r| r.default_route else null, if (file_routing) |r| r.default_route else null, true); // Default: send all traffic through VPN

        routing_config.accept_pushed_routes = pickVal(bool, if (cli_routing) |r| r.accept_pushed_routes else null, if (env_routing) |r| r.accept_pushed_routes else null, if (file_routing) |r| r.accept_pushed_routes else null, true);

        routing_config.enable_custom_routes = pickVal(bool, if (cli_routing) |r| r.enable_custom_routes else null, if (env_routing) |r| r.enable_custom_routes else null, if (file_routing) |r| r.enable_custom_routes else null, false);

        routing_config.ipv4_include = pickOpt([]const []const u8, if (cli_routing) |r| r.ipv4_include else null, if (env_routing) |r| r.ipv4_include else null, if (file_routing) |r| r.ipv4_include else null, null);

        routing_config.ipv4_exclude = pickOpt([]const []const u8, if (cli_routing) |r| r.ipv4_exclude else null, if (env_routing) |r| r.ipv4_exclude else null, if (file_routing) |r| r.ipv4_exclude else null, null);

        routing_config.ipv6_include = pickOpt([]const []const u8, if (cli_routing) |r| r.ipv6_include else null, if (env_routing) |r| r.ipv6_include else null, if (file_routing) |r| r.ipv6_include else null, null);

        routing_config.ipv6_exclude = pickOpt([]const []const u8, if (cli_routing) |r| r.ipv6_exclude else null, if (env_routing) |r| r.ipv6_exclude else null, if (file_routing) |r| r.ipv6_exclude else null, null);

        builder.routing = routing_config;
    }

    return builder;
}

test "load from file - nonexistent file" {
    const allocator = std.testing.allocator;
    const config = try loadFromFile(allocator, "/nonexistent/config.json");
    try std.testing.expect(config.server == null);
}

test "expand path with tilde" {
    const allocator = std.testing.allocator;

    // Test tilde expansion
    if (std.posix.getenv("HOME")) |_| {
        const expanded = try expandPath(allocator, "~/test.txt");
        defer allocator.free(expanded);
        try std.testing.expect(!std.mem.startsWith(u8, expanded, "~"));
    }

    // Test non-tilde path
    const normal = try expandPath(allocator, "/tmp/test.txt");
    defer allocator.free(normal);
    try std.testing.expectEqualStrings("/tmp/test.txt", normal);
}
