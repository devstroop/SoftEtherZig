// SoftEther VPN Client - CLI Application
// Production command-line interface for establishing VPN connections

const std = @import("std");
const client = @import("client.zig");
const config = @import("config.zig");
const errors = @import("errors.zig");
const profiling = @import("profiling.zig");
const c = @import("c.zig").c;

const VpnClient = client.VpnClient;
const ConnectionConfig = config.ConnectionConfig;
const AuthMethod = config.AuthMethod;
const VpnError = errors.VpnError;

const VERSION = "1.0.0";

// Global client pointer for signal handler
var g_client: ?*VpnClient = null;
var g_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);
var g_cleanup_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var g_shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

// Signal handler for Ctrl+C (SIGINT) and SIGTERM
fn signalHandler(sig: c_int) callconv(.c) void {
    _ = sig;
    // Just set the flag - the monitoring thread will handle the actual shutdown
    g_shutdown_requested.store(true, .release);
}

fn printUsage() void {
    std.debug.print(
        \\SoftEther VPN Client v{s}
        \\
        \\USAGE:
        \\    vpnclient [OPTIONS]
        \\    vpnclient --gen-hash <USERNAME> <PASSWORD>
        \\
        \\OPTIONS:
        \\    -h, --help              Show this help message
        \\    -v, --version           Show version information
        \\    -c, --config <FILE>     Load configuration from JSON file
        \\    -s, --server <HOST>     VPN server hostname (required)
        \\    -p, --port <PORT>       VPN server port (default: 443)
        \\    -H, --hub <HUB>         Virtual hub name (required)
        \\    -u, --user <USERNAME>   Username for authentication (required)
        \\    -P, --password <PASS>   Password for authentication (required)
        \\    --password-hash <HASH>  Pre-hashed password (base64, use instead of -P)
        \\    -a, --account <NAME>    Account name (default: username)
        \\    --no-encrypt            Disable encryption (not recommended)
        \\    --no-compress           Disable compression
        \\    -d, --daemon            Run as daemon (background)
        \\    --profile               Enable performance profiling
        \\    --use-zig-adapter       Use Zig packet adapter (default, 10x faster)
        \\    --use-c-adapter         Use legacy C adapter (fallback)
        \\    --log-level <LEVEL>     Set log verbosity: silent, error, warn, info, debug, trace (default: info)
        \\
        \\  Reconnection Options:
        \\    --reconnect             Enable automatic reconnection (default: enabled)
        \\    --no-reconnect          Disable automatic reconnection
        \\    --max-retries <N>       Maximum reconnection attempts, 0=infinite (default: 0)
        \\    --min-backoff <SEC>     Minimum backoff delay in seconds (default: 5)
        \\    --max-backoff <SEC>     Maximum backoff delay in seconds (default: 300)
        \\
        \\  IP Configuration:
        \\    --ip-version <VERSION>  IP version: auto, ipv4, ipv6, dual (default: auto)
        \\    --static-ipv4 <IP>      Static IPv4 address (e.g., 10.0.0.2)
        \\    --static-ipv4-netmask <MASK>  Static IPv4 netmask (e.g., 255.255.255.0)
        \\    --static-ipv4-gateway <GW>    Static IPv4 gateway (e.g., 10.0.0.1)
        \\    --static-ipv6 <IP>      Static IPv6 address (e.g., 2001:db8::1)
        \\    --static-ipv6-prefix <LEN>    Static IPv6 prefix length (e.g., 64)
        \\    --static-ipv6-gateway <GW>    Static IPv6 gateway (e.g., fe80::1)
        \\    --dns-server <SERVER>   DNS server (can be specified multiple times)
        \\    --gen-hash <USER> <PASS> Generate password hash and exit
        \\
        \\CONFIGURATION FILE:
        \\    Default location: ~/.config/softether-zig/config.json
        \\    Specify custom:   vpnclient --config /path/to/config.json
        \\
        \\    Priority: CLI arguments > Environment variables > Config file
        \\
        \\ENVIRONMENT VARIABLES:
        \\    SOFTETHER_SERVER        VPN server hostname
        \\    SOFTETHER_PORT          VPN server port
        \\    SOFTETHER_HUB           Virtual hub name
        \\    SOFTETHER_USER          Username
        \\    SOFTETHER_PASSWORD      Password (plaintext, not recommended)
        \\    SOFTETHER_PASSWORD_HASH Password hash (recommended, use --gen-hash)
        \\    SOFTETHER_CONFIG        Path to config file (default: ~/.config/softether-zig/config.json)
        \\
        \\    Note: Command-line arguments override environment > config file
        \\
        \\EXAMPLES:
        \\    # Use configuration file (recommended)
        \\    vpnclient --config ~/.config/softether-zig/myprofile.json
        \\
        \\    # Use default config file location
        \\    vpnclient  # Reads ~/.config/softether-zig/config.json automatically
        \\
        \\    # Connect to VPN server (explicit args)
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass
        \\
        \\    # Connect with custom port
        \\    vpnclient -s vpn.example.com -p 8443 -H VPN -u myuser -P mypass
        \\
        \\    # Generate password hash
        \\    vpnclient --gen-hash myuser mypassword
        \\
        \\    # Use environment variables (secure method)
        \\    export SOFTETHER_SERVER="vpn.example.com"
        \\    export SOFTETHER_HUB="VPN"
        \\    export SOFTETHER_USER="myuser"
        \\    export SOFTETHER_PASSWORD_HASH="base64hash..."
        \\    vpnclient  # Credentials from environment
        \\
        \\    # Force IPv4 only
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass --ip-version ipv4
        \\
        \\    # Use static IPv4 configuration
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass \
        \\              --static-ipv4 10.0.0.2 --static-ipv4-netmask 255.255.255.0 \
        \\              --static-ipv4-gateway 10.0.0.1 --dns-server 8.8.8.8
        \\
        \\    # Dual-stack with static IPv4 and IPv6
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass --ip-version dual \
        \\              --static-ipv4 10.0.0.2 --static-ipv6 2001:db8::1
        \\
        \\    # Run as daemon
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass -d
        \\
    , .{VERSION});
}

fn printVersion() void {
    std.debug.print("SoftEther VPN Client v{s}\n", .{VERSION});
    std.debug.print("Based on SoftEther VPN 4.44 (Build 9807)\n", .{});
}

/// Get environment variable or return null
fn getEnvVar(key: []const u8) ?[]const u8 {
    return std.posix.getenv(key);
}

const CliArgs = struct {
    config_file: ?[]const u8 = null,
    server: ?[]const u8 = null,
    port: u16 = 443,
    hub: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    password_hash: ?[]const u8 = null,
    account: ?[]const u8 = null,
    use_encrypt: bool = true,
    use_compress: bool = true,
    max_connection: u32 = 0, // 0 = follow server policy, 1-32 = force specific count
    daemon: bool = false,
    profile: bool = false, // Enable performance profiling
    use_zig_adapter: bool = true, // Use Zig packet adapter (default for better performance)
    log_level: []const u8 = "info",

    // Reconnection settings
    reconnect: bool = true, // Enable automatic reconnection
    max_reconnect_attempts: u32 = 0, // Max retry attempts (0=infinite)
    min_backoff: u32 = 5, // Min backoff delay in seconds
    max_backoff: u32 = 300, // Max backoff delay in seconds

    // IP configuration
    ip_version: []const u8 = "auto",
    static_ipv4: ?[]const u8 = null,
    static_ipv4_netmask: ?[]const u8 = null,
    static_ipv4_gateway: ?[]const u8 = null,
    static_ipv6: ?[]const u8 = null,
    static_ipv6_prefix: ?u8 = null,
    static_ipv6_gateway: ?[]const u8 = null,
    dns_servers: ?[][]const u8 = null,
    help: bool = false,
    version: bool = false,
    gen_hash: bool = false,
    gen_hash_user: ?[]const u8 = null,
    gen_hash_pass: ?[]const u8 = null,
};

fn parseArgs(allocator: std.mem.Allocator) !CliArgs {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var dns_list = std.ArrayList([]const u8){};
    defer dns_list.deinit(allocator);
    try dns_list.ensureTotalCapacity(allocator, 4);

    var result = CliArgs{};

    // Phase 1: Load from environment variables (lowest priority)
    if (getEnvVar("SOFTETHER_SERVER")) |val| result.server = val;
    if (getEnvVar("SOFTETHER_PORT")) |val| {
        result.port = std.fmt.parseInt(u16, val, 10) catch {
            std.debug.print("Error: Invalid SOFTETHER_PORT value: {s}\n", .{val});
            return error.InvalidPort;
        };
    }
    if (getEnvVar("SOFTETHER_HUB")) |val| result.hub = val;
    if (getEnvVar("SOFTETHER_USER")) |val| result.username = val;
    if (getEnvVar("SOFTETHER_PASSWORD")) |val| {
        result.password = val;
        std.debug.print("⚠️  WARNING: Using plaintext password from SOFTETHER_PASSWORD\n", .{});
        std.debug.print("    Consider using SOFTETHER_PASSWORD_HASH instead (run: vpnclient --gen-hash user pass)\n", .{});
    }
    if (getEnvVar("SOFTETHER_PASSWORD_HASH")) |val| result.password_hash = val;

    // Phase 2: Parse command-line arguments (highest priority, override env vars)
    _ = args.skip(); // Skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            result.help = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            result.version = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            result.config_file = args.next() orelse return error.MissingConfigArg;
        } else if (std.mem.eql(u8, arg, "--gen-hash")) {
            result.gen_hash = true;
            result.gen_hash_user = args.next() orelse return error.MissingHashUsername;
            result.gen_hash_pass = args.next() orelse return error.MissingHashPassword;
        } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--server")) {
            result.server = args.next() orelse return error.MissingServerArg;
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            const port_str = args.next() orelse return error.MissingPortArg;
            result.port = try std.fmt.parseInt(u16, port_str, 10);
        } else if (std.mem.eql(u8, arg, "-H") or std.mem.eql(u8, arg, "--hub")) {
            result.hub = args.next() orelse return error.MissingHubArg;
        } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user")) {
            result.username = args.next() orelse return error.MissingUserArg;
        } else if (std.mem.eql(u8, arg, "-P") or std.mem.eql(u8, arg, "--password")) {
            result.password = args.next() orelse return error.MissingPasswordArg;
        } else if (std.mem.eql(u8, arg, "--password-hash")) {
            result.password_hash = args.next() orelse return error.MissingPasswordHashArg;
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--account")) {
            result.account = args.next() orelse return error.MissingAccountArg;
        } else if (std.mem.eql(u8, arg, "--max-connection")) {
            const max_str = args.next() orelse return error.MissingMaxConnectionArg;
            result.max_connection = try std.fmt.parseInt(u32, max_str, 10);
            if (result.max_connection > 32) {
                std.debug.print("Error: max_connection must be between 0 (server policy) and 32\n", .{});
                return error.InvalidMaxConnection;
            }
        } else if (std.mem.eql(u8, arg, "--no-encrypt")) {
            result.use_encrypt = false;
        } else if (std.mem.eql(u8, arg, "--no-compress")) {
            result.use_compress = false;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--daemon")) {
            result.daemon = true;
        } else if (std.mem.eql(u8, arg, "--profile")) {
            result.profile = true;
        } else if (std.mem.eql(u8, arg, "--use-zig-adapter")) {
            result.use_zig_adapter = true;
        } else if (std.mem.eql(u8, arg, "--use-c-adapter")) {
            result.use_zig_adapter = false;
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            result.log_level = args.next() orelse return error.MissingLogLevel;
        } else if (std.mem.eql(u8, arg, "--reconnect")) {
            result.reconnect = true;
        } else if (std.mem.eql(u8, arg, "--no-reconnect")) {
            result.reconnect = false;
        } else if (std.mem.eql(u8, arg, "--max-retries")) {
            const max_retries_str = args.next() orelse return error.MissingMaxRetries;
            result.max_reconnect_attempts = try std.fmt.parseInt(u32, max_retries_str, 10);
        } else if (std.mem.eql(u8, arg, "--min-backoff")) {
            const min_backoff_str = args.next() orelse return error.MissingMinBackoff;
            result.min_backoff = try std.fmt.parseInt(u32, min_backoff_str, 10);
            if (result.min_backoff == 0) {
                std.debug.print("Error: min-backoff must be > 0\n", .{});
                return error.InvalidMinBackoff;
            }
        } else if (std.mem.eql(u8, arg, "--max-backoff")) {
            const max_backoff_str = args.next() orelse return error.MissingMaxBackoff;
            result.max_backoff = try std.fmt.parseInt(u32, max_backoff_str, 10);
            if (result.max_backoff == 0) {
                std.debug.print("Error: max-backoff must be > 0\n", .{});
                return error.InvalidMaxBackoff;
            }
        } else if (std.mem.eql(u8, arg, "--ip-version")) {
            result.ip_version = args.next() orelse return error.MissingIpVersion;
        } else if (std.mem.eql(u8, arg, "--static-ipv4")) {
            result.static_ipv4 = args.next() orelse return error.MissingStaticIpv4;
        } else if (std.mem.eql(u8, arg, "--static-ipv4-netmask")) {
            result.static_ipv4_netmask = args.next() orelse return error.MissingStaticIpv4Netmask;
        } else if (std.mem.eql(u8, arg, "--static-ipv4-gateway")) {
            result.static_ipv4_gateway = args.next() orelse return error.MissingStaticIpv4Gateway;
        } else if (std.mem.eql(u8, arg, "--static-ipv6")) {
            result.static_ipv6 = args.next() orelse return error.MissingStaticIpv6;
        } else if (std.mem.eql(u8, arg, "--static-ipv6-prefix")) {
            const prefix_str = args.next() orelse return error.MissingStaticIpv6Prefix;
            result.static_ipv6_prefix = try std.fmt.parseInt(u8, prefix_str, 10);
        } else if (std.mem.eql(u8, arg, "--static-ipv6-gateway")) {
            result.static_ipv6_gateway = args.next() orelse return error.MissingStaticIpv6Gateway;
        } else if (std.mem.eql(u8, arg, "--dns-server")) {
            const dns_server = args.next() orelse return error.MissingDnsServer;
            try dns_list.append(allocator, dns_server);
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }

    // Convert DNS list to slice
    if (dns_list.items.len > 0) {
        result.dns_servers = try allocator.dupe([]const u8, dns_list.items);
    }

    return result;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs(allocator) catch |err| {
        switch (err) {
            error.UnknownArgument => {
                std.debug.print("\n", .{});
                printUsage();
                std.process.exit(1);
            },
            else => {
                std.debug.print("Error parsing arguments: {any}\n", .{err});
                std.process.exit(1);
            },
        }
    };

    // Load configuration file (if specified or default exists)
    // Priority: CLI > env vars > config file
    var config_path_buf: ?[]const u8 = null;
    defer if (config_path_buf) |p| allocator.free(p);

    const config_path = args.config_file orelse (getEnvVar("SOFTETHER_CONFIG") orelse blk: {
        // Try default config location
        config_path_buf = config.getDefaultConfigPath(allocator) catch null;
        break :blk config_path_buf;
    });

    // Load config file and get merged configuration values
    var final_server: ?[]const u8 = args.server;
    var final_port: u16 = args.port;
    var final_hub: ?[]const u8 = args.hub;
    var final_username: ?[]const u8 = args.username;
    var final_password: ?[]const u8 = args.password;
    var final_password_hash: ?[]const u8 = args.password_hash;
    var final_account: ?[]const u8 = args.account;

    if (config_path) |path| {
        std.debug.print("[●] Loading configuration from: {s}\n", .{path});
        var parsed_config = config.loadFromFile(allocator, path) catch |err| {
            std.debug.print("Error loading config file: {any}\n", .{err});
            std.process.exit(1);
        };
        defer parsed_config.deinit(); // Free JSON memory
        const file_config = parsed_config.value;

        // Apply config file values if CLI args not provided
        // Priority: CLI args > env vars > config file
        if (final_server == null) {
            final_server = getEnvVar("SOFTETHER_SERVER") orelse file_config.server;
        }
        if (final_port == 443 and args.server == null) { // Default not overridden by CLI
            if (getEnvVar("SOFTETHER_PORT")) |port_str| {
                final_port = std.fmt.parseInt(u16, port_str, 10) catch 443;
            } else if (file_config.port) |p| {
                final_port = p;
            }
        }
        if (final_hub == null) {
            final_hub = getEnvVar("SOFTETHER_HUB") orelse file_config.hub;
        }
        if (final_username == null) {
            final_username = getEnvVar("SOFTETHER_USER") orelse file_config.username;
        }
        if (final_password == null) {
            final_password = getEnvVar("SOFTETHER_PASSWORD") orelse file_config.password;
        }
        if (final_password_hash == null) {
            final_password_hash = getEnvVar("SOFTETHER_PASSWORD_HASH") orelse file_config.password_hash;
        }
        if (final_account == null) {
            final_account = getEnvVar("SOFTETHER_ACCOUNT") orelse file_config.account;
        }
    }

    // Now use final_* variables instead of args.* for validation and VPN setup

    if (args.help) {
        printUsage();
        return;
    }

    if (args.version) {
        printVersion();
        return;
    }

    // Handle hash generation mode
    if (args.gen_hash) {
        const username = args.gen_hash_user.?;
        const password = args.gen_hash_pass.?;

        // Initialize SoftEther library first
        const init_result = c.vpn_bridge_init(0); // 0 = FALSE (debug off)
        if (init_result != c.VPN_BRIDGE_SUCCESS) {
            std.debug.print("Error initializing SoftEther library\n", .{});
            std.process.exit(1);
        }
        defer _ = c.vpn_bridge_cleanup();

        var hash_buffer: [128]u8 = undefined;
        const result = c.vpn_bridge_generate_password_hash(username.ptr, password.ptr, &hash_buffer, hash_buffer.len);

        if (result != c.VPN_BRIDGE_SUCCESS) {
            std.debug.print("Error generating hash: {d}\n", .{result});
            std.process.exit(1);
        }

        const hash_len = std.mem.indexOfScalar(u8, &hash_buffer, 0) orelse hash_buffer.len;
        for (hash_buffer[0..hash_len]) |byte| {
            std.debug.print("{c}", .{byte});
        }
        std.debug.print("\n", .{});
        return;
    }

    // Validate required arguments (using config file fallback values)
    const server = final_server orelse {
        std.debug.print("Error: Server hostname is required (-s/--server or config file)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    const hub = final_hub orelse {
        std.debug.print("Error: Hub name is required (-H/--hub or config file)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    const username = final_username orelse {
        std.debug.print("Error: Username is required (-u/--user or config file)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    // Either password or password_hash is required
    if (final_password == null and final_password_hash == null) {
        std.debug.print("Error: Password is required (-P/--password, --password-hash, or config file)\n\n", .{});
        printUsage();
        std.process.exit(1);
    }

    if (final_password != null and final_password_hash != null) {
        std.debug.print("Error: Cannot specify both --password and --password-hash\n\n", .{});
        printUsage();
        std.process.exit(1);
    }

    const password = final_password orelse final_password_hash.?;
    const use_password_hash = final_password_hash != null;

    const account = final_account orelse username;

    // Initialize logging system
    const log_level_cstr = std.mem.sliceTo(args.log_level, 0);
    const parsed_level = c.parse_log_level(log_level_cstr.ptr);
    c.set_log_level(parsed_level);

    // Parse IP version
    const ip_version: config.IpVersion = if (std.mem.eql(u8, args.ip_version, "auto"))
        .auto
    else if (std.mem.eql(u8, args.ip_version, "ipv4"))
        .ipv4
    else if (std.mem.eql(u8, args.ip_version, "ipv6"))
        .ipv6
    else if (std.mem.eql(u8, args.ip_version, "dual"))
        .dual
    else {
        std.debug.print("Error: Invalid IP version '{s}'. Must be one of: auto, ipv4, ipv6, dual\n\n", .{args.ip_version});
        printUsage();
        std.process.exit(1);
    };

    // Build static IP configuration if provided
    var static_ip: ?config.StaticIpConfig = null;
    if (args.static_ipv4 != null or args.static_ipv6 != null or args.dns_servers != null) {
        static_ip = config.StaticIpConfig{
            .ipv4_address = args.static_ipv4,
            .ipv4_netmask = args.static_ipv4_netmask,
            .ipv4_gateway = args.static_ipv4_gateway,
            .ipv6_address = args.static_ipv6,
            .ipv6_prefix_len = args.static_ipv6_prefix,
            .ipv6_gateway = args.static_ipv6_gateway,
            .dns_servers = args.dns_servers,
        };
    }

    // Create configuration
    const vpn_config = ConnectionConfig{
        .server_name = server,
        .server_port = final_port,
        .hub_name = hub,
        .account_name = account,
        .auth = .{ .password = .{
            .username = username,
            .password = password,
            .is_hashed = use_password_hash,
        } },
        .use_encrypt = args.use_encrypt,
        .use_compress = args.use_compress,
        .max_connection = args.max_connection,
        .ip_version = ip_version,
        .static_ip = static_ip,
        .use_zig_adapter = args.use_zig_adapter,
    };

    // Initialize VPN client
    std.debug.print("SoftEther VPN Client v{s}\n", .{VERSION});
    std.debug.print("─────────────────────────────────────────────\n", .{});
    std.debug.print("Connecting to: {s}:{d}\n", .{ server, final_port });
    std.debug.print("Virtual Hub:   {s}\n", .{hub});
    std.debug.print("User:          {s}\n", .{username});
    std.debug.print("Encryption:    {s}\n", .{if (args.use_encrypt) "Enabled" else "Disabled"});
    std.debug.print("Compression:   {s}\n", .{if (args.use_compress) "Enabled" else "Disabled"});
    if (args.max_connection == 0) {
        std.debug.print("Max Connections: Server Policy\n", .{});
    } else {
        std.debug.print("Max Connections: {d}\n", .{args.max_connection});
    }
    std.debug.print("IP Version:    {s}\n", .{args.ip_version});

    if (static_ip) |sip| {
        if (sip.ipv4_address) |ipv4| {
            std.debug.print("Static IPv4:   {s}", .{ipv4});
            if (sip.ipv4_netmask) |mask| std.debug.print("/{s}", .{mask});
            if (sip.ipv4_gateway) |gw| std.debug.print(" via {s}", .{gw});
            std.debug.print("\n", .{});
        }
        if (sip.ipv6_address) |ipv6| {
            std.debug.print("Static IPv6:   {s}", .{ipv6});
            if (sip.ipv6_prefix_len) |prefix| std.debug.print("/{d}", .{prefix});
            if (sip.ipv6_gateway) |gw| std.debug.print(" via {s}", .{gw});
            std.debug.print("\n", .{});
        }
        if (sip.dns_servers) |dns_list| {
            std.debug.print("DNS Servers:   ", .{});
            for (dns_list, 0..) |dns, i| {
                if (i > 0) std.debug.print(", ", .{});
                std.debug.print("{s}", .{dns});
            }
            std.debug.print("\n", .{});
        }
    }

    std.debug.print("─────────────────────────────────────────────\n\n", .{});

    var vpn_client = VpnClient.init(allocator, vpn_config) catch |err| {
        std.debug.print("✗ Failed to initialize VPN client: {any}\n", .{err});
        std.process.exit(1);
    };
    // Note: defer vpn_client.deinit() is NOT here - we handle it manually for daemon mode

    // Connect to VPN server
    std.debug.print("Establishing VPN connection...\n", .{});
    vpn_client.connect() catch |err| {
        vpn_client.deinit();
        std.debug.print("✗ Connection failed: {any}\n", .{err});
        std.process.exit(1);
    };

    // Set up signal handler for Ctrl+C and graceful termination
    g_client = &vpn_client;

    // Configure signal handler with proper flags
    const sigaction = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = std.posix.SA.RESTART, // Restart syscalls interrupted by signal
    };

    // Register handlers
    std.posix.sigaction(std.posix.SIG.INT, &sigaction, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sigaction, null);

    // Ignore SIGPIPE (broken pipe when writing to closed socket)
    const sig_ignore = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.PIPE, &sig_ignore, null);

    std.debug.print("✓ Signal handlers registered (Ctrl+C to disconnect)\n", .{});

    // Start monitoring thread to watch for shutdown signals
    // This is more reliable than relying on signal delivery to C code
    const MonitorThread = struct {
        fn run(vpn_client_ptr: *VpnClient) void {
            while (true) {
                std.Thread.sleep(100 * std.time.ns_per_ms); // Check every 100ms

                if (g_shutdown_requested.load(.acquire)) {
                    // Prevent double handling
                    if (g_cleanup_done.swap(true, .acquire)) {
                        return; // Already handling shutdown
                    }

                    std.debug.print("\n\n", .{});
                    std.debug.print("═══════════════════════════════════════════════\n", .{});
                    std.debug.print("🛑 Shutdown signal detected (Ctrl+C)\n", .{});
                    std.debug.print("═══════════════════════════════════════════════\n", .{});
                    std.debug.print("\n", .{});

                    // Stop the main loop
                    g_running.store(false, .release);

                    // Mark as user-requested disconnect
                    vpn_client_ptr.markUserDisconnect() catch {};

                    std.debug.print("[●] Initiating graceful shutdown...\n", .{});
                    std.debug.print("[●] Disconnecting VPN session...\n", .{});

                    // Call disconnect to trigger StopSession()
                    vpn_client_ptr.disconnect() catch |err| {
                        std.debug.print("[!] Disconnect error: {}\n", .{err});
                    };

                    return;
                }
            }
        }
    };

    _ = std.Thread.spawn(.{}, MonitorThread.run, .{&vpn_client}) catch |err| {
        std.debug.print("Warning: Failed to start monitoring thread: {}\n", .{err});
    };

    std.debug.print("✓ VPN connection established\n\n", .{});

    // Wait briefly for adapter initialization to complete in background thread
    // The adapter is initialized asynchronously, so we need to wait for it
    std.Thread.sleep(100 * std.time.ns_per_ms); // 100ms should be enough

    // Get dynamic network information
    const device_name_buf = vpn_client.getDeviceName() catch |err| blk: {
        std.debug.print("Warning: Could not get device name: {any}\n", .{err});
        break :blk [_]u8{0} ** 64;
    };
    const device_name_end = std.mem.indexOfScalar(u8, &device_name_buf, 0) orelse device_name_buf.len;
    const device_name = device_name_buf[0..device_name_end];

    const learned_ip = vpn_client.getLearnedIp() catch 0;
    const gateway_mac = vpn_client.getGatewayMac() catch null;

    // Display connection status
    std.debug.print("Connection Status: {s}\n", .{@tagName(vpn_client.getStatus())});
    std.debug.print("TUN Device:        {s}\n", .{device_name});

    if (learned_ip != 0) {
        std.debug.print("Learned IP:        {}.{}.{}.{}\n", .{
            (learned_ip >> 24) & 0xFF,
            (learned_ip >> 16) & 0xFF,
            (learned_ip >> 8) & 0xFF,
            learned_ip & 0xFF,
        });
    } else {
        std.debug.print("Learned IP:        (not yet detected)\n", .{});
    }

    if (gateway_mac) |mac| {
        std.debug.print("Gateway MAC:       {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n\n", .{
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        });
    } else {
        std.debug.print("Gateway MAC:       (not yet learned)\n\n", .{});
    }

    // Show network information
    std.debug.print("✅ Network Configuration\n", .{});
    std.debug.print("─────────────────────────────────────────────\n", .{});
    std.debug.print("The interface has been auto-configured with VPN network settings.\n", .{});
    std.debug.print("Network: 10.21.0.0/16\n", .{});
    std.debug.print("Gateway: 10.21.0.1\n\n", .{});

    std.debug.print("To add route to VPN network (if needed):\n", .{});
    std.debug.print("  sudo route add -net 10.21.0.0/16 10.21.0.1\n\n", .{});

    std.debug.print("To route ALL traffic through VPN:\n", .{});
    std.debug.print("  sudo route delete default\n", .{});
    std.debug.print("  sudo route add default 10.21.0.1\n\n", .{});

    std.debug.print("💡 Note: Press Ctrl+C to disconnect.\n", .{});
    std.debug.print("─────────────────────────────────────────────\n\n", .{});

    if (args.daemon) {
        // Daemon mode: fork and run in background
        const pid = std.c.fork();

        if (pid < 0) {
            std.debug.print("✗ Failed to fork process\n", .{});
            vpn_client.deinit();
            std.process.exit(1);
        }

        if (pid > 0) {
            // Parent process: print info and exit
            std.debug.print("Starting in daemon mode...\n", .{});
            std.debug.print("VPN client running in background (PID: {d})\n", .{pid});
            std.debug.print("Use 'kill {d}' to stop the VPN connection\n", .{pid});
            std.debug.print("─────────────────────────────────────────────\n", .{});

            // Parent exits - child continues in background
            vpn_client.deinit(); // Parent doesn't need the vpn_client anymore
            return;
        }

        // Child process: continue as daemon
        // Create new session to detach from terminal
        _ = std.c.setsid();

        // Close standard file descriptors
        const devnull = std.fs.openFileAbsolute("/dev/null", .{ .mode = .read_write }) catch {
            // Can't print here - stdout might be closed
            // Continue anyway with inherited file descriptors
            daemonLoop(&vpn_client);
        };
        defer devnull.close();

        std.posix.dup2(devnull.handle, std.posix.STDIN_FILENO) catch {};
        std.posix.dup2(devnull.handle, std.posix.STDOUT_FILENO) catch {};
        std.posix.dup2(devnull.handle, std.posix.STDERR_FILENO) catch {};

        // Keep connection alive in background forever
        daemonLoop(&vpn_client);
    }

    // Foreground mode: wait for Ctrl+C
    std.debug.print("Connection established successfully.\n", .{});
    std.debug.print("Press Ctrl+C to disconnect.\n", .{});

    if (args.profile) {
        std.debug.print("🔬 Performance profiling enabled\n", .{});
    }
    std.debug.print("─────────────────────────────────────────────\n", .{});

    // Configure reconnection
    if (args.reconnect) {
        try vpn_client.enableReconnect(
            args.max_reconnect_attempts,
            args.min_backoff,
            args.max_backoff,
        );
        if (args.max_reconnect_attempts > 0) {
            std.debug.print("Auto-reconnect enabled (max {d} attempts, backoff {d}-{d}s)\n", .{ args.max_reconnect_attempts, args.min_backoff, args.max_backoff });
        } else {
            std.debug.print("Auto-reconnect enabled (unlimited, backoff {d}-{d}s)\n", .{ args.min_backoff, args.max_backoff });
        }
    } else {
        try vpn_client.disableReconnect();
        std.debug.print("Auto-reconnect disabled\n", .{});
    }

    // Main monitoring/reconnection loop
    if (args.profile) {
        monitorWithProfiling(allocator, &vpn_client);
    } else {
        // Main loop with reconnection support
        while (g_running.load(.acquire)) {
            if (vpn_client.isConnected()) {
                // Connected - normal monitoring
                std.Thread.sleep(500 * std.time.ns_per_ms); // Check every 500ms
            } else {
                // Disconnected - check if we should reconnect
                const reconnect_info = vpn_client.getReconnectInfo() catch {
                    std.debug.print("[!] Failed to get reconnection info\n", .{});
                    break;
                };

                if (!reconnect_info.should_reconnect) {
                    // User disconnect, disabled, or max retries exceeded
                    if (reconnect_info.enabled and
                        reconnect_info.max_attempts > 0 and
                        reconnect_info.attempt >= reconnect_info.max_attempts)
                    {
                        std.debug.print("\n[!] Max reconnection attempts ({d}) exceeded\n", .{reconnect_info.max_attempts});
                    }
                    break;
                }

                // Calculate how long to wait
                const current_time: u64 = @intCast(std.time.milliTimestamp());
                if (current_time < reconnect_info.next_retry_time) {
                    const wait_ms: u64 = reconnect_info.next_retry_time - current_time;
                    const wait_s = wait_ms / 1000;

                    if (reconnect_info.max_attempts > 0) {
                        std.debug.print("\n[●] Connection lost, reconnecting in {d}s (attempt {d}/{d})...\n", .{ wait_s, reconnect_info.attempt + 1, reconnect_info.max_attempts });
                    } else {
                        std.debug.print("\n[●] Connection lost, reconnecting in {d}s (attempt {d})...\n", .{ wait_s, reconnect_info.attempt + 1 });
                    }

                    // Wait with periodic checks for Ctrl+C
                    var remaining_ms = wait_ms;
                    while (remaining_ms > 0 and g_running.load(.acquire)) {
                        const sleep_ms = @min(remaining_ms, 500);
                        const sleep_ns: u64 = @as(u64, sleep_ms) * @as(u64, std.time.ns_per_ms);
                        std.Thread.sleep(sleep_ns);
                        remaining_ms -|= sleep_ms;
                    }

                    if (!g_running.load(.acquire)) {
                        break; // User pressed Ctrl+C during wait
                    }
                }

                // Attempt reconnection
                std.debug.print("[●] Reconnecting...\n", .{});
                vpn_client.connect() catch |err| {
                    std.debug.print("[!] Reconnection failed: {}\n", .{err});
                    continue; // Will retry in next iteration
                };

                std.debug.print("[✓] Reconnection successful!\n", .{});
            }
        }
    }

    // Only cleanup if signal handler hasn't already done it
    if (!g_cleanup_done.load(.acquire)) {
        if (vpn_client.isConnected()) {
            std.debug.print("\n[●] Disconnecting...\n", .{});
        } else {
            std.debug.print("\n[●] Cleaning up...\n", .{});
        }
        g_cleanup_done.store(true, .release);
        vpn_client.deinit();
        std.debug.print("[✓] Cleanup complete\n", .{});
    } else {
        // Signal handler called disconnect(), now call deinit() to free resources
        std.debug.print("[●] VPN: Disconnected successfully\n", .{});
        vpn_client.deinit();
        std.debug.print("[✓] VPN connection terminated\n", .{});
        std.debug.print("[✓] Resources released\n", .{});
        std.debug.print("\n", .{});
        std.debug.print("═══════════════════════════════════════════════\n", .{});
        std.debug.print("Goodbye! VPN session closed cleanly.\n", .{});
        std.debug.print("═══════════════════════════════════════════════\n", .{});
    }
}

// Background daemon loop - runs forever until killed
fn daemonLoop(vpn_client_ptr: *VpnClient) noreturn {
    while (true) {
        if (!vpn_client_ptr.isConnected()) {
            // Connection lost - exit with error code
            std.process.exit(1);
        }
        std.Thread.sleep(5 * std.time.ns_per_s);
    }
}

// Monitor connection with performance profiling
fn monitorWithProfiling(allocator: std.mem.Allocator, vpn_client: *VpnClient) void {
    var metrics = profiling.Metrics.init(allocator);
    defer metrics.deinit();

    var last_bytes_rx: u64 = 0;
    var last_bytes_tx: u64 = 0;
    var status_counter: u32 = 0;

    std.debug.print("\n", .{});

    while (vpn_client.isConnected() and g_running.load(.acquire)) {
        // Get current stats from VPN client
        const info = vpn_client.getConnectionInfo() catch |err| {
            std.debug.print("Error getting connection info: {any}\n", .{err});
            std.Thread.sleep(1000 * std.time.ns_per_ms);
            continue;
        };

        // Calculate delta
        const bytes_rx_delta = info.bytes_received -| last_bytes_rx;
        const bytes_tx_delta = info.bytes_sent -| last_bytes_tx;

        // Update metrics (approximate packet count based on average packet size)
        if (bytes_rx_delta > 0) {
            const approx_packets = bytes_rx_delta / 1200; // Assume ~1200 bytes/packet
            var i: u64 = 0;
            while (i < approx_packets) : (i += 1) {
                metrics.recordPacketReceived(1200);
            }
        }
        if (bytes_tx_delta > 0) {
            const approx_packets = bytes_tx_delta / 1200;
            var i: u64 = 0;
            while (i < approx_packets) : (i += 1) {
                metrics.recordPacketSent(1200);
            }
        }

        last_bytes_rx = info.bytes_received;
        last_bytes_tx = info.bytes_sent;

        // Print status every 5 seconds
        status_counter += 1;
        if (status_counter >= 10) { // 10 * 500ms = 5 seconds
            metrics.printStatus();
            status_counter = 0;
        }

        std.Thread.sleep(500 * std.time.ns_per_ms);
    }

    // Print final report
    std.debug.print("\n\n", .{});
    metrics.report();
}
