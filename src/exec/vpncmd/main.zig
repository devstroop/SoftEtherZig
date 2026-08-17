//! SoftEther VPN Command Tool (vpncmd) — Zig Implementation
//!
//! `exec/vpncmd/main.zig` — standalone admin CLI tool. Mirrors C `vpncmd.c`:
//! `InitMayaqua()` → `InitCedar()` → parse args → connect to server via admin
//! RPC → run interactive shell → exit.
//!
//! Unlike vpnserver/vpnclient, vpncmd is a **one-shot tool** — it does NOT
//! run as a daemon, does NOT handle signals, and does NOT load VPN configs.
//!
//! Usage:
//!   vpncmd --server <host> [--port <port>] [--hub <hub>] [--password <pw>]
//!
//! Module layout: this file lives below `src/` so (per the Zig 0.15
//! module-root rule) it reaches the admin client and shared helpers through
//! the named `softether` module (`src/lib.zig`).

const std = @import("std");
const builtin = @import("builtin");

// Named module provided by build.zig (the vpncmd target).
const se = @import("softether");
const cli = se.cli;

const log = std.log.scoped(.vpncmd);

// ============================================================================
// Logging Configuration
// ============================================================================

pub const std_options: std.Options = .{
    .log_level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
    .log_scope_levels = &.{
        .{ .scope = .mayaqua, .level = .info },
        .{ .scope = .cedar_client, .level = .info },
        .{ .scope = .vpncmd, .level = .info },
    },
};

pub const version = se.version;

// ============================================================================
// CLI Arguments
// ============================================================================

pub const CmdArgs = struct {
    server_host: []const u8,
    server_port: u16 = 443,
    hub_name: []const u8 = "DEFAULT",
    password: ?[]const u8 = null,
    allow_self_signed: bool = false,

    pub fn parse(args: []const []const u8) !CmdArgs {
        var result = CmdArgs{
            .server_host = "",
        };

        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const a = args[i];
            if (std.mem.eql(u8, a, "--server") or std.mem.eql(u8, a, "-s")) {
                i += 1;
                if (i >= args.len) return error.MissingServerHost;
                result.server_host = args[i];
            } else if (std.mem.eql(u8, a, "--port") or std.mem.eql(u8, a, "-p")) {
                i += 1;
                if (i >= args.len) return error.MissingPort;
                result.server_port = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidPort;
            } else if (std.mem.eql(u8, a, "--hub") or std.mem.eql(u8, a, "-H")) {
                i += 1;
                if (i >= args.len) return error.MissingHub;
                result.hub_name = args[i];
            } else if (std.mem.eql(u8, a, "--password")) {
                i += 1;
                if (i >= args.len) return error.MissingPassword;
                result.password = args[i];
            } else if (std.mem.eql(u8, a, "--allow-self-signed")) {
                result.allow_self_signed = true;
            } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
                return error.Help;
            } else {
                return error.UnknownOption;
            }
        }

        if (result.server_host.len == 0) return error.MissingServerHost;
        return result;
    }
};

// ============================================================================
// Entry Point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Skip argv[0] (the binary name).
    const cmd_args = CmdArgs.parse(args[1..]) catch |err| {
        switch (err) {
            error.Help => {
                printUsage();
                return;
            },
            else => {
                std.debug.print("Error: {s}\n\n", .{@errorName(err)});
                printUsage();
                std.process.exit(1);
            },
        }
    };

    // Log version.
    log.info("SoftEther VPN Command Tool v{s}", .{version});
    log.info("Connecting to {s}:{d} hub={s}", .{ cmd_args.server_host, cmd_args.server_port, cmd_args.hub_name });

    // Connect to the server via admin RPC.
    var client = se.admin_client.AdminClient.connect(allocator, cmd_args.server_host, cmd_args.server_port, cmd_args.hub_name, cmd_args.allow_self_signed) catch |err| {
        std.debug.print("Connection failed: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    defer client.deinit();

    // Authenticate with the server if a password was provided.
    if (cmd_args.password) |pw| {
        client.authenticate(pw) catch |err| {
            std.debug.print("Authentication failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
    }

    // Run the interactive admin shell.
    const display_ctx = cli.DisplayContext.init();
    var shell = se.admin_shell.Shell.init(allocator, &client, display_ctx);
    shell.run();
}

fn printUsage() void {
    std.debug.print(
        \\SoftEther VPN Command Tool v{s}
        \\
        \\Usage: vpncmd --server <host> [options]
        \\
        \\Options:
        \\  -s, --server <host>          Server hostname or IP (required)
        \\  -p, --port <port>            Server port (default: 443)
        \\  -H, --hub <name>             Virtual Hub name (default: DEFAULT)
        \\      --password <pw>          Admin password
        \\      --allow-self-signed      Allow self-signed server certificates
        \\  -h, --help                   Show this help
        \\
        \\Examples:
        \\  vpncmd --server 192.168.1.1
        \\  vpncmd -s vpn.example.com -H MYHUB --password <password>
        \\
        \\Note: Server certificate verification is enabled by default.
        \\Use --allow-self-signed for self-signed certificates.
        \\
    , .{version});
}
