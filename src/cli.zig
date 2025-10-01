// SoftEther VPN Client - CLI Application
// Production command-line interface for establishing VPN connections

const std = @import("std");
const softether = @import("softether");
const VpnClient = softether.VpnClient;
const ConnectionConfig = softether.ConnectionConfig;
const AuthMethod = softether.AuthMethod;

const VERSION = "1.0.0";

fn printUsage() void {
    std.debug.print(
        \\SoftEther VPN Client v{s}
        \\
        \\USAGE:
        \\    vpnclient [OPTIONS]
        \\
        \\OPTIONS:
        \\    -h, --help              Show this help message
        \\    -v, --version           Show version information
        \\    -s, --server <HOST>     VPN server hostname (required)
        \\    -p, --port <PORT>       VPN server port (default: 443)
        \\    -H, --hub <HUB>         Virtual hub name (required)
        \\    -u, --user <USERNAME>   Username for authentication (required)
        \\    -P, --password <PASS>   Password for authentication (required)
        \\    -a, --account <NAME>    Account name (default: username)
        \\    --no-encrypt            Disable encryption (not recommended)
        \\    --no-compress           Disable compression
        \\    -d, --daemon            Run as daemon (background)
        \\
        \\EXAMPLES:
        \\    # Connect to VPN server
        \\    vpnclient -s vpn.example.com -H VPN -u myuser -P mypass
        \\
        \\    # Connect with custom port
        \\    vpnclient -s vpn.example.com -p 8443 -H VPN -u myuser -P mypass
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
    account: ?[]const u8 = null,
    use_encrypt: bool = true,
    use_compress: bool = true,
    daemon: bool = false,
    help: bool = false,
    version: bool = false,
};

fn parseArgs(allocator: std.mem.Allocator) !CliArgs {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var result = CliArgs{};

    // Skip program name
    _ = args.skip();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            result.help = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            result.version = true;
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
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--account")) {
            result.account = args.next() orelse return error.MissingAccountArg;
        } else if (std.mem.eql(u8, arg, "--no-encrypt")) {
            result.use_encrypt = false;
        } else if (std.mem.eql(u8, arg, "--no-compress")) {
            result.use_compress = false;
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--daemon")) {
            result.daemon = true;
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
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
                std.debug.print("Error parsing arguments: {}\n", .{err});
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

    const password = args.password orelse {
        std.debug.print("Error: Password is required (-P/--password)\n\n", .{});
        printUsage();
        std.process.exit(1);
    };

    const account = args.account orelse username;

    // Create configuration
    const config = ConnectionConfig{
        .server_name = server,
        .server_port = args.port,
        .hub_name = hub,
        .account_name = account,
        .auth = .{ .password = .{
            .username = username,
            .password = password,
        } },
        .use_encrypt = args.use_encrypt,
        .use_compress = args.use_compress,
    };

    // Initialize VPN client
    std.debug.print("SoftEther VPN Client v{s}\n", .{VERSION});
    std.debug.print("─────────────────────────────────────────────\n", .{});
    std.debug.print("Connecting to: {s}:{d}\n", .{ server, args.port });
    std.debug.print("Virtual Hub:   {s}\n", .{hub});
    std.debug.print("User:          {s}\n", .{username});
    std.debug.print("Encryption:    {s}\n", .{if (args.use_encrypt) "Enabled" else "Disabled"});
    std.debug.print("Compression:   {s}\n", .{if (args.use_compress) "Enabled" else "Disabled"});
    std.debug.print("─────────────────────────────────────────────\n\n", .{});

    var client = VpnClient.init(allocator, config) catch |err| {
        std.debug.print("✗ Failed to initialize VPN client: {}\n", .{err});
        std.process.exit(1);
    };
    defer client.deinit();

    // Connect to VPN server
    std.debug.print("Establishing VPN connection...\n", .{});
    client.connect() catch |err| {
        std.debug.print("✗ Connection failed: {}\n", .{err});
        std.process.exit(1);
    };

    std.debug.print("✓ VPN connection established\n\n", .{});

    // Display basic status
    std.debug.print("Connection Status: {s}\n\n", .{@tagName(client.getStatus())});

    if (args.daemon) {
        std.debug.print("Running as daemon. Press Ctrl+C to disconnect.\n", .{});
        std.debug.print("─────────────────────────────────────────────\n", .{});

        // Keep connection alive
        while (client.isConnected()) {
            std.Thread.sleep(5 * std.time.ns_per_s);

            // Try to update stats every 5 seconds
            if (client.getConnectionInfo()) |current_info| {
                std.debug.print("[{d}s] Sent: {d} bytes, Received: {d} bytes, Status: {s}\n", .{
                    current_info.connected_seconds,
                    current_info.bytes_sent,
                    current_info.bytes_received,
                    @tagName(client.getStatus()),
                });
            } else |_| {
                std.debug.print("[Status: {s}] Connection active\n", .{@tagName(client.getStatus())});
            }
        }
        std.debug.print("\nConnection closed.\n", .{});
    } else {
        std.debug.print("Connection established successfully.\n", .{});
        std.debug.print("(This is a test run. Use -d/--daemon for persistent connection)\n", .{});
        std.debug.print("\nWaiting 10 seconds before disconnecting...\n", .{});
        std.Thread.sleep(10 * std.time.ns_per_s);
    }
}
