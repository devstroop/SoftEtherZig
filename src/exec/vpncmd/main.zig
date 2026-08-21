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

    // M19 #253 — local `tools` verbs that do NOT require a server connection.
    // Must be checked before `CmdArgs.parse` which requires `--server`.
    // Parity to `SoftEtherVPN/src/vpncmd/Tools.c:GenerateHashedPassword` /
    // `Mayaqua/Encrypt.c:GenerateNtPasswordHash` (MD4) and
    // `Cedar/Account.c:HashPassword` (SHA-0) — currently SHA-0 path via
    // `src/app/password_hash.zig`. Keep offline so `vpncmd tools
    // generatehashedpassword` works without a running server.
    if (args.len >= 2 and (std.mem.eql(u8, args[1], "tools") or std.mem.eql(u8, args[1], "Tools"))) {
        if (args.len >= 3 and (std.mem.eql(u8, args[2], "generatehashedpassword") or std.mem.eql(u8, args[2], "GenerateHashedPassword"))) {
            var t_user: ?[]const u8 = null;
            var t_pass: ?[]const u8 = null;
            // Positional: `vpncmd tools generatehashedpassword <user> <pass>`
            if (args.len >= 5 and args[3].len > 0 and args[4].len > 0 and args[3][0] != '-' and args[4][0] != '-') {
                t_user = args[3];
                t_pass = args[4];
                if (args.len > 5) {
                    std.debug.print("Warning: ignoring extra arguments after <user> <pass>\n", .{});
                }
            } else {
                var i: usize = 3;
                while (i < args.len) : (i += 1) {
                    const a = args[i];
                    if (std.mem.eql(u8, a, "-u") or std.mem.eql(u8, a, "--user") or std.mem.eql(u8, a, "/u") or std.mem.eql(u8, a, "/USER")) {
                        i += 1;
                        if (i >= args.len) {
                            std.debug.print("Missing value for {s}\n\n", .{a});
                            printToolsUsage();
                            std.process.exit(1);
                        }
                        t_user = args[i];
                    } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--password") or std.mem.eql(u8, a, "/p") or std.mem.eql(u8, a, "/PASSWORD")) {
                        i += 1;
                        if (i >= args.len) {
                            std.debug.print("Missing value for {s}\n\n", .{a});
                            printToolsUsage();
                            std.process.exit(1);
                        }
                        t_pass = args[i];
                    } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "/?")) {
                        printToolsUsage();
                        return;
                    } else {
                        std.debug.print("Unknown tools option: {s}\n\n", .{a});
                        printToolsUsage();
                        std.process.exit(1);
                    }
                }
            }
            if (t_user == null or t_pass == null) {
                std.debug.print("Usage: vpncmd tools generatehashedpassword [-u <user> -p <pass>]\n", .{});
                std.debug.print("   or: vpncmd tools generatehashedpassword <user> <pass>\n\n", .{});
                printToolsUsage();
                std.process.exit(1);
            }
            // Reuse shared SHA-0 generator (identical to `vpnclient passhash`).
            se.password_hash.generate(t_user.?, t_pass.?);
            return;
        } else if (args.len == 2 or (args.len >= 3 and (std.mem.eql(u8, args[2], "--help") or std.mem.eql(u8, args[2], "-h") or std.mem.eql(u8, args[2], "help")))) {
            printToolsUsage();
            return;
        } else {
            std.debug.print("Unknown tools subcommand: {s}\n\n", .{if (args.len >= 3) args[2] else ""});
            printToolsUsage();
            std.process.exit(1);
        }
    }

    // Also support top-level `vpncmd tools --help` without server.
    if (args.len >= 2 and (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "help"))) {
        // Fall through to printUsage via parse error, but show tools hint.
        // Handled below via CmdArgs.parse Help path.
    }

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

fn printToolsUsage() void {
    std.debug.print(
        \\SoftEther VPN Command Tool v{s} — Tools
        \\
        \\Usage: vpncmd tools <command> [options]
        \\
        \\Commands:
        \\  generatehashedpassword     Generate a SoftEther password hash (SHA-0)
        \\                               Alias: GenerateHashedPassword
        \\
        \\Options for generatehashedpassword:
        \\  -u, --user <name>            Username (required)
        \\  -p, --password <pass>        Password (required)
        \\  Positional: <user> <pass>    Alternative to flags
        \\
        \\Examples:
        \\  vpncmd tools generatehashedpassword -u devstroop1 -p devstroop111222
        \\  vpncmd tools generatehashedpassword devstroop1 devstroop111222
        \\  # output: CS9ZXBrvt9GFvoHSvNuUfhP4rmw=  (use with --password-hash)
        \\
        \\Note: This is the same SHA-0(password + UPPERCASE(username)) as
        \\      `vpnclient passhash` (now deprecated) — see src/app/password_hash.zig
        \\      and SoftEtherVPN/src/Cedar/Account.c:HashPassword.
        \\
    , .{version});
}

fn printUsage() void {
    std.debug.print(
        \\SoftEther VPN Command Tool v{s}
        \\
        \\Usage:
        \\  vpncmd tools generatehashedpassword [-u <user> -p <pass>]  (offline)
        \\  vpncmd --server <host> [options]                            (admin RPC)
        \\
        \\Tools (offline, no server required):
        \\  vpncmd tools generatehashedpassword  Generate password hash (SHA-0)
        \\  vpncmd tools --help                   Show tools help
        \\
        \\Server options (admin RPC):
        \\  -s, --server <host>          Server hostname or IP (required for admin)
        \\  -p, --port <port>            Server port (default: 443)
        \\  -H, --hub <name>             Virtual Hub name (default: DEFAULT)
        \\      --password <pw>          Admin password
        \\      --allow-self-signed      Allow self-signed server certificates
        \\  -h, --help                   Show this help
        \\
        \\Examples:
        \\  vpncmd tools generatehashedpassword -u myuser -p mypass
        \\  vpncmd --server 192.168.1.1
        \\  vpncmd -s vpn.example.com -H MYHUB --password <password>
        \\
        \\Note: Server certificate verification is enabled by default.
        \\Use --allow-self-signed for self-signed certificates.
        \\`vpnclient passhash` is deprecated — use `vpncmd tools` instead.
        \\
    , .{version});
}
