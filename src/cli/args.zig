//! CLI Argument Parser
//!
//! Phase 8: Pure Zig command-line argument parsing
//! Replaces std.process.args usage with structured parser

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// Argument Types
// ============================================================================

/// Parsed CLI arguments
pub const CliArgs = struct {
    // Help/Version
    help: bool = false,
    version: bool = false,

    // Configuration
    config_file: ?[]const u8 = null,

    // Server settings
    server: ?[]const u8 = null,
    port: u16 = 443,
    hub: ?[]const u8 = null,

    // Authentication
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    password_hash: ?[]const u8 = null,
    account: ?[]const u8 = null,

    // Connection options
    use_encrypt: bool = true,
    use_compress: bool = true,
    max_connection: u8 = 1,

    // Reconnection
    reconnect: bool = true,
    max_retries: u32 = 0,
    min_backoff_sec: u32 = 5,
    max_backoff_sec: u32 = 300,

    // IP configuration
    ip_version: IpVersion = .auto,
    static_ipv4: ?[]const u8 = null,
    static_ipv4_netmask: ?[]const u8 = null,
    static_ipv4_gateway: ?[]const u8 = null,
    static_ipv6: ?[]const u8 = null,
    static_ipv6_prefix: ?u8 = null,
    static_ipv6_gateway: ?[]const u8 = null,
    dns_servers: []const []const u8 = &.{},

    // Runtime options
    daemon: bool = false,
    interactive: bool = false,
    profile: bool = false,
    log_level: LogLevel = .info,

    // Special modes
    gen_hash_user: ?[]const u8 = null,
    gen_hash_pass: ?[]const u8 = null,

    // Allocator for dynamic data
    allocator: ?Allocator = null,

    pub fn deinit(self: *CliArgs) void {
        if (self.allocator) |alloc| {
            if (self.dns_servers.len > 0) {
                alloc.free(self.dns_servers);
            }
        }
    }
};

pub const IpVersion = enum {
    auto,
    ipv4,
    ipv6,
    dual,

    pub fn fromString(s: []const u8) ?IpVersion {
        if (std.mem.eql(u8, s, "auto")) return .auto;
        if (std.mem.eql(u8, s, "ipv4")) return .ipv4;
        if (std.mem.eql(u8, s, "ipv6")) return .ipv6;
        if (std.mem.eql(u8, s, "dual")) return .dual;
        return null;
    }
};

pub const LogLevel = enum {
    silent,
    @"error",
    warn,
    info,
    debug,
    trace,

    pub fn fromString(s: []const u8) ?LogLevel {
        if (std.mem.eql(u8, s, "silent")) return .silent;
        if (std.mem.eql(u8, s, "error")) return .@"error";
        if (std.mem.eql(u8, s, "warn")) return .warn;
        if (std.mem.eql(u8, s, "info")) return .info;
        if (std.mem.eql(u8, s, "debug")) return .debug;
        if (std.mem.eql(u8, s, "trace")) return .trace;
        return null;
    }
};

// ============================================================================
// Parse Errors
// ============================================================================

pub const ParseError = error{
    MissingValue,
    InvalidValue,
    UnknownArgument,
    InvalidPort,
    InvalidNumber,
    ConflictingOptions,
    OutOfMemory,
};

// ============================================================================
// Argument Parser
// ============================================================================

pub const ArgParser = struct {
    allocator: Allocator,
    args: CliArgs,
    dns_list: std.ArrayListUnmanaged([]const u8),
    errors: std.ArrayListUnmanaged([]const u8),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .args = .{ .allocator = allocator },
            .dns_list = .{},
            .errors = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.dns_list.deinit(self.allocator);
        for (self.errors.items) |err| {
            self.allocator.free(err);
        }
        self.errors.deinit(self.allocator);
    }

    /// Parse command line arguments
    pub fn parse(self: *Self, argv: []const []const u8) ParseError!CliArgs {
        var i: usize = 1; // Skip program name

        while (i < argv.len) {
            const arg = argv[i];

            if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
                self.args.help = true;
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
                self.args.version = true;
            } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
                i += 1;
                self.args.config_file = try self.requireValue(argv, i, "--config");
            } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--server")) {
                i += 1;
                self.args.server = try self.requireValue(argv, i, "--server");
            } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--port");
                self.args.port = std.fmt.parseInt(u16, val, 10) catch return ParseError.InvalidPort;
            } else if (std.mem.eql(u8, arg, "-H") or std.mem.eql(u8, arg, "--hub")) {
                i += 1;
                self.args.hub = try self.requireValue(argv, i, "--hub");
            } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
                i += 1;
                self.args.username = try self.requireValue(argv, i, "--user");
            } else if (std.mem.eql(u8, arg, "-P") or std.mem.eql(u8, arg, "--password")) {
                i += 1;
                self.args.password = try self.requireValue(argv, i, "--password");
            } else if (std.mem.eql(u8, arg, "--password-hash")) {
                i += 1;
                self.args.password_hash = try self.requireValue(argv, i, "--password-hash");
            } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--account")) {
                i += 1;
                self.args.account = try self.requireValue(argv, i, "--account");
            } else if (std.mem.eql(u8, arg, "--no-encrypt")) {
                self.args.use_encrypt = false;
            } else if (std.mem.eql(u8, arg, "--no-compress")) {
                self.args.use_compress = false;
            } else if (std.mem.eql(u8, arg, "--reconnect")) {
                self.args.reconnect = true;
            } else if (std.mem.eql(u8, arg, "--no-reconnect")) {
                self.args.reconnect = false;
            } else if (std.mem.eql(u8, arg, "--max-retries")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--max-retries");
                self.args.max_retries = std.fmt.parseInt(u32, val, 10) catch return ParseError.InvalidNumber;
            } else if (std.mem.eql(u8, arg, "--min-backoff")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--min-backoff");
                self.args.min_backoff_sec = std.fmt.parseInt(u32, val, 10) catch return ParseError.InvalidNumber;
            } else if (std.mem.eql(u8, arg, "--max-backoff")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--max-backoff");
                self.args.max_backoff_sec = std.fmt.parseInt(u32, val, 10) catch return ParseError.InvalidNumber;
            } else if (std.mem.eql(u8, arg, "--ip-version")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--ip-version");
                self.args.ip_version = IpVersion.fromString(val) orelse return ParseError.InvalidValue;
            } else if (std.mem.eql(u8, arg, "--static-ipv4")) {
                i += 1;
                self.args.static_ipv4 = try self.requireValue(argv, i, "--static-ipv4");
            } else if (std.mem.eql(u8, arg, "--static-ipv4-netmask")) {
                i += 1;
                self.args.static_ipv4_netmask = try self.requireValue(argv, i, "--static-ipv4-netmask");
            } else if (std.mem.eql(u8, arg, "--static-ipv4-gateway")) {
                i += 1;
                self.args.static_ipv4_gateway = try self.requireValue(argv, i, "--static-ipv4-gateway");
            } else if (std.mem.eql(u8, arg, "--dns-server")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--dns-server");
                try self.dns_list.append(self.allocator, val);
            } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--daemon")) {
                self.args.daemon = true;
            } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interactive")) {
                self.args.interactive = true;
            } else if (std.mem.eql(u8, arg, "--profile")) {
                self.args.profile = true;
            } else if (std.mem.eql(u8, arg, "--log-level")) {
                i += 1;
                const val = try self.requireValue(argv, i, "--log-level");
                self.args.log_level = LogLevel.fromString(val) orelse return ParseError.InvalidValue;
            } else if (std.mem.eql(u8, arg, "--gen-hash")) {
                i += 1;
                self.args.gen_hash_user = try self.requireValue(argv, i, "--gen-hash username");
                i += 1;
                self.args.gen_hash_pass = try self.requireValue(argv, i, "--gen-hash password");
            } else if (arg.len > 0 and arg[0] == '-') {
                return ParseError.UnknownArgument;
            }
            // Ignore positional arguments for now

            i += 1;
        }

        // Convert DNS list to slice
        if (self.dns_list.items.len > 0) {
            self.args.dns_servers = try self.allocator.dupe([]const u8, self.dns_list.items);
        }

        return self.args;
    }

    fn requireValue(self: *Self, argv: []const []const u8, idx: usize, name: []const u8) ParseError![]const u8 {
        _ = self;
        _ = name;
        if (idx >= argv.len) {
            return ParseError.MissingValue;
        }
        return argv[idx];
    }

    /// Load from environment variables
    pub fn loadFromEnv(self: *Self) void {
        if (std.posix.getenv("SOFTETHER_SERVER")) |v| {
            if (self.args.server == null) self.args.server = v;
        }
        if (std.posix.getenv("SOFTETHER_PORT")) |v| {
            if (self.args.port == 443) {
                self.args.port = std.fmt.parseInt(u16, v, 10) catch 443;
            }
        }
        if (std.posix.getenv("SOFTETHER_HUB")) |v| {
            if (self.args.hub == null) self.args.hub = v;
        }
        if (std.posix.getenv("SOFTETHER_USER")) |v| {
            if (self.args.username == null) self.args.username = v;
        }
        if (std.posix.getenv("SOFTETHER_PASSWORD")) |v| {
            if (self.args.password == null) self.args.password = v;
        }
        if (std.posix.getenv("SOFTETHER_PASSWORD_HASH")) |v| {
            if (self.args.password_hash == null) self.args.password_hash = v;
        }
        if (std.posix.getenv("SOFTETHER_CONFIG")) |v| {
            if (self.args.config_file == null) self.args.config_file = v;
        }
    }
};

// ============================================================================
// Validation
// ============================================================================

pub const ValidationResult = struct {
    valid: bool,
    missing_fields: []const []const u8,
    errors: []const []const u8,
};

pub fn validate(args: *const CliArgs, allocator: Allocator) !ValidationResult {
    var missing = std.ArrayListUnmanaged([]const u8){};
    defer missing.deinit(allocator);
    var errs = std.ArrayListUnmanaged([]const u8){};
    defer errs.deinit(allocator);

    // Skip validation for help/version/gen-hash modes
    if (args.help or args.version or args.gen_hash_user != null) {
        return .{
            .valid = true,
            .missing_fields = &.{},
            .errors = &.{},
        };
    }

    // Check required fields
    if (args.server == null) try missing.append(allocator, "server");
    if (args.hub == null) try missing.append(allocator, "hub");
    if (args.username == null) try missing.append(allocator, "username");
    if (args.password == null and args.password_hash == null) {
        try missing.append(allocator, "password or password_hash");
    }

    // Check conflicts
    if (args.password != null and args.password_hash != null) {
        try errs.append(allocator, "Cannot specify both --password and --password-hash");
    }

    if (args.daemon and args.interactive) {
        try errs.append(allocator, "Cannot specify both --daemon and --interactive");
    }

    return .{
        .valid = missing.items.len == 0 and errs.items.len == 0,
        .missing_fields = try allocator.dupe([]const u8, missing.items),
        .errors = try allocator.dupe([]const u8, errs.items),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "ArgParser basic flags" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "-h" };
    const args = try parser.parse(&argv);

    try std.testing.expect(args.help);
    try std.testing.expect(!args.version);
}

test "ArgParser server options" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "-s", "vpn.example.com", "-p", "8443", "-H", "VPN" };
    const args = try parser.parse(&argv);

    try std.testing.expectEqualStrings("vpn.example.com", args.server.?);
    try std.testing.expectEqual(@as(u16, 8443), args.port);
    try std.testing.expectEqualStrings("VPN", args.hub.?);
}

test "ArgParser auth options" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "-u", "testuser", "-P", "testpass" };
    const args = try parser.parse(&argv);

    try std.testing.expectEqualStrings("testuser", args.username.?);
    try std.testing.expectEqualStrings("testpass", args.password.?);
}

test "ArgParser reconnect options" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "--no-reconnect" };
    const args = try parser.parse(&argv);

    try std.testing.expect(!args.reconnect);
}

test "ArgParser ip version" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "--ip-version", "ipv4" };
    const args = try parser.parse(&argv);

    try std.testing.expectEqual(IpVersion.ipv4, args.ip_version);
}

test "ArgParser dns servers" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "--dns-server", "8.8.8.8", "--dns-server", "1.1.1.1" };
    var args = try parser.parse(&argv);
    defer args.deinit();

    try std.testing.expectEqual(@as(usize, 2), args.dns_servers.len);
}

test "ArgParser unknown argument" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "--unknown-option" };
    const result = parser.parse(&argv);

    try std.testing.expectError(ParseError.UnknownArgument, result);
}

test "ArgParser missing value" {
    var parser = ArgParser.init(std.testing.allocator);
    defer parser.deinit();

    const argv = [_][]const u8{ "vpnclient", "-s" };
    const result = parser.parse(&argv);

    try std.testing.expectError(ParseError.MissingValue, result);
}

test "IpVersion fromString" {
    try std.testing.expectEqual(IpVersion.auto, IpVersion.fromString("auto").?);
    try std.testing.expectEqual(IpVersion.ipv4, IpVersion.fromString("ipv4").?);
    try std.testing.expect(IpVersion.fromString("invalid") == null);
}

test "LogLevel fromString" {
    try std.testing.expectEqual(LogLevel.info, LogLevel.fromString("info").?);
    try std.testing.expectEqual(LogLevel.debug, LogLevel.fromString("debug").?);
    try std.testing.expect(LogLevel.fromString("invalid") == null);
}

test "validate missing server" {
    const args = CliArgs{};
    const result = try validate(&args, std.testing.allocator);
    defer std.testing.allocator.free(result.missing_fields);
    defer std.testing.allocator.free(result.errors);

    try std.testing.expect(!result.valid);
    try std.testing.expect(result.missing_fields.len > 0);
}

test "validate help mode skips validation" {
    const args = CliArgs{ .help = true };
    const result = try validate(&args, std.testing.allocator);

    try std.testing.expect(result.valid);
}
