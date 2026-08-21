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

    // M21 #262 — local `client` verbs that do NOT require a server connection.
    // vpncmd owns profiles (XDG vpn_client.config Cfg, no external files).
    // Must be checked before CmdArgs.parse which requires --server.
    if (args.len >= 2 and (std.mem.eql(u8, args[1], "client") or std.mem.eql(u8, args[1], "Client"))) {
        handleClientCommand(allocator, args[2..]) catch |err| {
            std.debug.print("client command failed: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        return;
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

fn handleClientCommand(allocator: std.mem.Allocator, cmd_args: []const []const u8) !void {
    const store = se.vpn_client_store;
    if (cmd_args.len == 0 or std.mem.eql(u8, cmd_args[0], "--help") or std.mem.eql(u8, cmd_args[0], "-h") or std.mem.eql(u8, cmd_args[0], "help")) {
        printClientUsage();
        return;
    }
    const verb = cmd_args[0];
    // Normalize verb case-insensitive
    if (std.ascii.eqlIgnoreCase(verb, "AccountCreate")) {
        if (cmd_args.len < 2) {
            std.debug.print("AccountCreate requires <name> [/SERVER:host] [/HUB:hub] [/USERNAME:user] [/PASSWORD:pass]\n", .{});
            printClientUsage();
            return error.MissingAccountName;
        }
        const name = cmd_args[1];
        var server: ?[]const u8 = null;
        var port: u16 = 443;
        var hub: ?[]const u8 = null;
        var username: ?[]const u8 = null;
        var password: ?[]const u8 = null;
        var i: usize = 2;
        while (i < cmd_args.len) : (i += 1) {
            const a = cmd_args[i];
            if (a.len > 1 and a[0] == '/') {
                const slash_arg = a[1..];
                const colon = std.mem.indexOfScalar(u8, slash_arg, ':');
                var key: []const u8 = undefined;
                var val: []const u8 = undefined;
                if (colon) |c| {
                    key = slash_arg[0..c];
                    val = slash_arg[c + 1 ..];
                    // Handle /KEY: value split across two args (if value has spaces)
                    if (val.len == 0 and i + 1 < cmd_args.len and !std.mem.startsWith(u8, cmd_args[i + 1], "/")) {
                        i += 1;
                        val = cmd_args[i];
                    }
                } else {
                    // /KEY value (separated)
                    key = slash_arg;
                    if (i + 1 >= cmd_args.len) {
                        std.debug.print("Missing value for {s}\n", .{a});
                        return error.MissingValue;
                    }
                    i += 1;
                    val = cmd_args[i];
                }
                if (std.ascii.eqlIgnoreCase(key, "SERVER")) {
                    server = val;
                } else if (std.ascii.eqlIgnoreCase(key, "SERVER_PORT") or std.ascii.eqlIgnoreCase(key, "PORT")) {
                    port = std.fmt.parseInt(u16, val, 10) catch return error.InvalidPort;
                } else if (std.ascii.eqlIgnoreCase(key, "HUB")) {
                    hub = val;
                } else if (std.ascii.eqlIgnoreCase(key, "USERNAME") or std.ascii.eqlIgnoreCase(key, "USER")) {
                    username = val;
                } else if (std.ascii.eqlIgnoreCase(key, "PASSWORD")) {
                    password = val;
                } else {
                    std.debug.print("Unknown AccountCreate option: /{s}\n", .{key});
                    return error.UnknownOption;
                }
            } else if (std.mem.startsWith(u8, a, "--")) {
                // also support --server etc for convenience
                if (std.mem.eql(u8, a, "--server")) {
                    i += 1;
                    if (i >= cmd_args.len) return error.MissingValue;
                    server = cmd_args[i];
                } else if (std.mem.eql(u8, a, "--hub")) {
                    i += 1;
                    if (i >= cmd_args.len) return error.MissingValue;
                    hub = cmd_args[i];
                } else if (std.mem.eql(u8, a, "--user")) {
                    i += 1;
                    if (i >= cmd_args.len) return error.MissingValue;
                    username = cmd_args[i];
                } else if (std.mem.eql(u8, a, "--password")) {
                    i += 1;
                    if (i >= cmd_args.len) return error.MissingValue;
                    password = cmd_args[i];
                } else if (std.mem.eql(u8, a, "--port")) {
                    i += 1;
                    if (i >= cmd_args.len) return error.MissingValue;
                    port = std.fmt.parseInt(u16, cmd_args[i], 10) catch return error.InvalidPort;
                } else {
                    std.debug.print("Unknown option: {s}\n", .{a});
                    return error.UnknownOption;
                }
            } else {
                std.debug.print("Unknown argument: {s}\n", .{a});
                return error.UnknownOption;
            }
        }
        if (server == null) {
            std.debug.print("AccountCreate requires /SERVER:<host> (e.g. /SERVER:203.0.113.10)\n", .{});
            return error.MissingServerHost;
        }
        if (hub == null) hub = "VPN";
        if (username == null) {
            std.debug.print("AccountCreate requires /USERNAME:<user>\n", .{});
            return error.MissingUsername;
        }
        // Create account atomically (M21 12-field minimal) — compute hash first so a
        // failure does not leave an incomplete profile (CodeAnt #277)
        var hash_val: ?[]const u8 = null;
        defer if (hash_val) |h| allocator.free(h);
        if (password) |pw| {
            hash_val = try se.password_hash.hashPassword(allocator, username.?, pw);
        }
        try store.createAccount(allocator, .{ .name = name, .server = server.?, .port = port, .hub = hub.?, .username = username.?, .password_hash = hash_val });
        const path = try store.getStorePath(allocator);
        defer allocator.free(path);
        std.debug.print("Account '{s}' created at {s} (/SERVER:{s} /HUB:{s} /USERNAME:{s})\n", .{ name, path, server.?, hub.?, username.? });
        if (password != null) std.debug.print("Password set (hashed)\n", .{});
        return;
    } else if (std.ascii.eqlIgnoreCase(verb, "AccountList") or std.ascii.eqlIgnoreCase(verb, "AccountEnum")) {
        const list = try store.listAccounts(allocator);
        defer {
            for (list) |n| allocator.free(n);
            allocator.free(list);
        }
        if (list.len == 0) {
            std.debug.print("No accounts found. Create one via: vpncmd client AccountCreate <name> /SERVER:<host> /HUB:<hub> /USERNAME:<user>\n", .{});
            const path = try store.getStorePath(allocator);
            defer allocator.free(path);
            std.debug.print("Store: {s}\n", .{path});
        } else {
            std.debug.print("Accounts ({d}):\n", .{list.len});
            for (list) |n| std.debug.print("  - {s}\n", .{n});
            const path = try store.getStorePath(allocator);
            defer allocator.free(path);
            std.debug.print("Store: {s}\n", .{path});
        }
        return;
    } else if (std.ascii.eqlIgnoreCase(verb, "AccountDelete") or std.ascii.eqlIgnoreCase(verb, "AccountRemove")) {
        if (cmd_args.len < 2) {
            std.debug.print("AccountDelete requires <name>\n", .{});
            return error.MissingAccountName;
        }
        const name = cmd_args[1];
        try store.deleteAccount(allocator, name);
        std.debug.print("Account '{s}' deleted\n", .{name});
        return;
    } else if (std.ascii.eqlIgnoreCase(verb, "AccountPasswordSet") or std.ascii.eqlIgnoreCase(verb, "AccountPassword")) {
        if (cmd_args.len < 2) {
            std.debug.print("AccountPasswordSet requires <name> /PASSWORD:<pass> or /PASSWORD_HASH:<hash>\n", .{});
            return error.MissingAccountName;
        }
        const name = cmd_args[1];
        var password: ?[]const u8 = null;
        var hash: ?[]const u8 = null;
        var i: usize = 2;
        while (i < cmd_args.len) : (i += 1) {
            const a = cmd_args[i];
            if (a.len > 1 and a[0] == '/') {
                const slash_arg = a[1..];
                const colon = std.mem.indexOfScalar(u8, slash_arg, ':');
                var key: []const u8 = undefined;
                var val: []const u8 = undefined;
                if (colon) |c| {
                    key = slash_arg[0..c];
                    val = slash_arg[c + 1 ..];
                    if (val.len == 0 and i + 1 < cmd_args.len and !std.mem.startsWith(u8, cmd_args[i + 1], "/")) {
                        i += 1;
                        val = cmd_args[i];
                    }
                } else {
                    key = slash_arg;
                    if (i + 1 >= cmd_args.len) return error.MissingValue;
                    i += 1;
                    val = cmd_args[i];
                }
                if (std.ascii.eqlIgnoreCase(key, "PASSWORD")) {
                    password = val;
                } else if (std.ascii.eqlIgnoreCase(key, "PASSWORD_HASH") or std.ascii.eqlIgnoreCase(key, "HASH")) {
                    hash = val;
                } else {
                    std.debug.print("Unknown option: /{s}\n", .{key});
                    return error.UnknownOption;
                }
            } else {
                std.debug.print("Unknown argument: {s}\n", .{a});
                return error.UnknownOption;
            }
        }
        if (hash) |h| {
            try store.setPasswordHash(allocator, name, h);
            std.debug.print("Account '{s}' password hash set\n", .{name});
        } else if (password) |pw| {
            // Need username to hash correctly (SHA-0(password + UPPERCASE(username)))
            const acc = try store.getAccount(allocator, name);
            if (acc) |a| {
                defer allocator.free(a.name);
                defer allocator.free(a.server);
                defer allocator.free(a.hub);
                defer allocator.free(a.username);
                defer if (a.password_hash) |hh| allocator.free(hh);
                const computed = try se.password_hash.hashPassword(allocator, a.username, pw);
                defer allocator.free(computed);
                try store.setPasswordHash(allocator, name, computed);
                std.debug.print("Account '{s}' password set (hashed)\n", .{name});
            } else return error.AccountNotFound;
        } else {
            std.debug.print("AccountPasswordSet requires /PASSWORD:<pass> or /PASSWORD_HASH:<hash>\n", .{});
            return error.MissingValue;
        }
        return;
    } else if (std.ascii.eqlIgnoreCase(verb, "AccountGet")) {
        if (cmd_args.len < 2) return error.MissingAccountName;
        const name = cmd_args[1];
        const acc = try store.getAccount(allocator, name);
        if (acc) |a| {
            defer allocator.free(a.name);
            defer allocator.free(a.server);
            defer allocator.free(a.hub);
            defer allocator.free(a.username);
            defer if (a.password_hash) |h| allocator.free(h);
            const hash_display = if (a.password_hash != null) "(set, redacted)" else "(none)";
            std.debug.print("Account '{s}':\n  Server: {s}:{d}\n  Hub: {s}\n  Username: {s}\n  PasswordHash: {s}\n", .{ a.name, a.server, a.port, a.hub, a.username, hash_display });
        } else {
            std.debug.print("Account '{s}' not found\n", .{name});
            return error.AccountNotFound;
        }
        return;
    } else {
        std.debug.print("Unknown client subcommand: {s}\n\n", .{verb});
        printClientUsage();
        return error.UnknownOption;
    }
}

fn printClientUsage() void {
    std.debug.print(
        \\SoftEther VPN Command Tool v{s} — Client (M21 #262)
        \\
        \\Usage: vpncmd client <command> [options]
        \\
        \\Commands (offline, no server required, XDG vpn_client.config Cfg):
        \\  AccountCreate <name> /SERVER:<host> [/PORT:<port>] /HUB:<hub> /USERNAME:<user> [/PASSWORD:<pass>]
        \\  AccountList
        \\  AccountDelete <name>
        \\  AccountPasswordSet <name> /PASSWORD:<pass>  (hash via SHA-0)
        \\  AccountPasswordSet <name> /PASSWORD_HASH:<hash>
        \\  AccountGet <name>
        \\
        \\Options use SoftEther slash syntax (/KEY:VALUE) or --key value:
        \\  /SERVER:<host>        Server hostname/IP (required)
        \\  /PORT:<port>          Server port (default 443)
        \\  /HUB:<hub>            Virtual hub (default VPN)
        \\  /USERNAME:<user>      Username
        \\  /PASSWORD:<pass>      Plain password (hashed via SHA-0)
        \\
        \\Store: $XDG_CONFIG_HOME/softether-zig/vpn_client.config
        \\       or $HOME/.config/softether-zig/vpn_client.config (Cfg text, declare tree)
        \\       No JSON import/export — vpncmd manages profile internally (per #262).
        \\
        \\Examples:
        \\  vpncmd client AccountCreate vpn1 /SERVER:203.0.113.10 /HUB:VPN /USERNAME:testuser
        \\  vpncmd client AccountPasswordSet vpn1 /PASSWORD:testpass
        \\  vpncmd client AccountList
        \\  vpncmd client AccountGet vpn1
        \\  vpncmd client AccountDelete vpn1
        \\
        \\Note: `vpnclient connect` without flags will discover this store in M21-3 #263.
        \\
    , .{version});
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
        \\  vpncmd tools generatehashedpassword -u testuser -p testpass
        \\  vpncmd tools generatehashedpassword testuser testpass
        \\  # output: Z8aeAfh8/a88naS5l/Uxf9ig+cM=  (use with --password-hash)
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
