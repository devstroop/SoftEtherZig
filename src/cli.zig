// SoftEther VPN Client - CLI Application
// Production command-line interface for establishing VPN connections

const std = @import("std");
const client = @import("client.zig");
const config = @import("config.zig");
const errors = @import("errors.zig");
const c = @import("c.zig").c;

const VpnClient = client.VpnClient;
const ConnectionConfig = config.ConnectionConfig;
const AuthMethod = config.AuthMethod;
const VpnError = errors.VpnError;

const VERSION = "1.0.0";

// Global client pointer for signal handler
var g_client: ?*VpnClient = null;
var g_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true);

// Signal handler for Ctrl+C (SIGINT)
fn signalHandler(sig: c_int) callconv(.c) void {
    _ = sig;
    std.debug.print("\n\n🛑 Interrupt signal received, disconnecting...\n", .{});
    g_running.store(false, .monotonic);
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
        \\    --log-level <LEVEL>     Set log verbosity: silent, error, warn, info, debug, trace (default: info)
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
        \\EXAMPLES:
        \\    # Connect to VPN server
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass
        \\
        \\    # Connect with custom port
        \\    vpnclient -s vpn.example.com -p 8443 -H VPN -u myuser -P mypass
        \\
        \\    # Generate password hash
        \\    vpnclient --gen-hash myuser mypassword
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

const CliArgs = struct {
    server: ?[]const u8 = null,
    port: u16 = 443,
    hub: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    password_hash: ?[]const u8 = null,
    account: ?[]const u8 = null,
    use_encrypt: bool = true,
    use_compress: bool = true,
    daemon: bool = false,
    log_level: []const u8 = "info",
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

    var result = CliArgs{}; // Skip program name
    _ = args.skip();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            result.help = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            result.version = true;
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
        } else if (std.mem.eql(u8, arg, "--no-encrypt")) {
            result.use_encrypt = false;
        } else if (std.mem.eql(u8, arg, "--no-compress")) {
            result.use_compress = false;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--daemon")) {
            result.daemon = true;
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            result.log_level = args.next() orelse return error.MissingLogLevel;
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

    // Validate required arguments
    const server = args.server orelse {
        std.debug.print("Error: Server hostname is required (-s/--server)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    const hub = args.hub orelse {
        std.debug.print("Error: Hub name is required (-H/--hub)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    const username = args.username orelse {
        std.debug.print("Error: Username is required (-u/--user)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    // Either password or password_hash is required
    if (args.password == null and args.password_hash == null) {
        std.debug.print("Error: Password is required (-P/--password or --password-hash)\n\n", .{});
        printUsage();
        std.process.exit(1);
    }

    if (args.password != null and args.password_hash != null) {
        std.debug.print("Error: Cannot specify both --password and --password-hash\n\n", .{});
        printUsage();
        std.process.exit(1);
    }

    const password = args.password orelse args.password_hash.?;
    const use_password_hash = args.password_hash != null;

    const account = args.account orelse username;

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
        .server_port = args.port,
        .hub_name = hub,
        .account_name = account,
        .auth = .{ .password = .{
            .username = username,
            .password = password,
            .is_hashed = use_password_hash,
        } },
        .use_encrypt = args.use_encrypt,
        .use_compress = args.use_compress,
        .ip_version = ip_version,
        .static_ip = static_ip,
    };

    // Initialize VPN client
    std.debug.print("SoftEther VPN Client v{s}\n", .{VERSION});
    std.debug.print("─────────────────────────────────────────────\n", .{});
    std.debug.print("Connecting to: {s}:{d}\n", .{ server, args.port });
    std.debug.print("Virtual Hub:   {s}\n", .{hub});
    std.debug.print("User:          {s}\n", .{username});
    std.debug.print("Encryption:    {s}\n", .{if (args.use_encrypt) "Enabled" else "Disabled"});
    std.debug.print("Compression:   {s}\n", .{if (args.use_compress) "Enabled" else "Disabled"});
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

    // Set up signal handler for Ctrl+C
    g_client = &vpn_client;
    const sigaction = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = 0,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sigaction, null);

    std.debug.print("✓ VPN connection established\n\n", .{});

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
    std.debug.print("─────────────────────────────────────────────\n", .{});

    // Keep connection alive until interrupted
    while (vpn_client.isConnected() and g_running.load(.monotonic)) {
        std.Thread.sleep(500 * std.time.ns_per_ms); // Check more frequently
    }

    std.debug.print("\n🔌 Disconnecting...\n", .{});
    vpn_client.deinit();
    std.debug.print("✅ Disconnected successfully\n", .{});
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
