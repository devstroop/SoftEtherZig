//! SoftEther VPN Server — Zig Implementation (issue #83)
//!
//! `exec/vpnserver/main.zig` — the `vpnserver` executable entry. Mirrors C
//! `vpnserver.c`: `InitCedar` → `StInit` → `StStartServer(false)` → daemonize
//! (reuse the `app/daemon.zig` PID-file + run-loop pattern) → signal handling
//! (`SIGTERM`/`SIGINT` → graceful stop).
//!
//! Server lifecycle logic lives in `cedar/server/runtime.zig` (shared with
//! the FFI layer). This file contains only CLI-specific code: argument
//! parsing, PID file management, signal handlers, and the main entry point.

const std = @import("std");
const builtin = @import("builtin");

// Named module provided by build.zig (the vpnserver target).
const softether = @import("softether");
const cli = softether.cli;
const runtime = softether.server.runtime;
const Server = runtime.Server;

const log = std.log.scoped(.app);

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
        .{ .scope = .cedar_server, .level = .info },
        .{ .scope = .app, .level = .info },
    },
};

pub const version = softether.version;

// ============================================================================
// Constants
// ============================================================================

const server_name = "vpnserver";
const pid_filename = "vpnserver.pid";

// ============================================================================
// CLI arguments
// ============================================================================

pub const CliArgs = struct {
    config_path: ?[]const u8 = null,
    daemon: bool = false,
    foreground: bool = false,
    version: bool = false,
    gen_cert: bool = false,
    gen_cert_name: ?[]const u8 = null,
};

pub fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !CliArgs {
    var result = CliArgs{};
    errdefer if (result.config_path) |p| allocator.free(p);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len == 0) continue;
        if (std.mem.eql(u8, a, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            result.config_path = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "--daemon")) {
            result.daemon = true;
        } else if (std.mem.eql(u8, a, "--foreground")) {
            result.foreground = true;
        } else if (std.mem.eql(u8, a, "--version")) {
            result.version = true;
        } else if (std.mem.eql(u8, a, "--gen-cert")) {
            result.gen_cert = true;
            if (i + 1 < args.len and args[i + 1].len > 0 and args[i + 1][0] != '-') {
                i += 1;
                result.gen_cert_name = args[i];
            }
        } else {
            return error.UnknownOption;
        }
    }
    if (result.daemon and result.foreground) return error.ConflictingOptions;
    return result;
}

// ============================================================================
// Signal handling
// ============================================================================

var global_server: ?*Server = null;

pub fn setupSignalHandlers(server: *Server) void {
    if (builtin.os.tag == .windows) return;
    global_server = server;
    const handler = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &handler, null);
    std.posix.sigaction(std.posix.SIG.TERM, &handler, null);
}

fn handleSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_server) |s| s.stop();
}

// ============================================================================
// PID file
// ============================================================================

fn getPidFilePath(buf: *[std.fs.max_path_bytes]u8) ?[]const u8 {
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "XDG_RUNTIME_DIR")) |dir| {
        defer std.heap.page_allocator.free(dir);
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, pid_filename }) catch null;
    } else |_| {}
    return std.fmt.bufPrint(buf, "/tmp/{s}", .{pid_filename}) catch null;
}

fn getCurrentPid() u32 {
    if (builtin.os.tag == .windows) {
        return @intCast(std.os.windows.GetCurrentProcessId());
    }
    return @intCast(std.c.getpid());
}

fn readPidOwner(pid_path: []const u8) ?u32 {
    const file = std.fs.cwd().openFile(pid_path, .{}) catch return null;
    defer file.close();
    var read_buf: [32]u8 = undefined;
    const n = file.readAll(&read_buf) catch return null;
    if (n == 0) return null;
    const content = std.mem.trim(u8, read_buf[0..n], " \n\r\t");
    return std.fmt.parseInt(u32, content, 10) catch null;
}

fn processAlive(pid: u32) bool {
    if (builtin.os.tag == .windows) return true;
    if (std.posix.kill(@as(i32, @intCast(pid)), 0)) {
        return true;
    } else |err| {
        return err == error.PermissionDenied;
    }
}

fn writePidFile() bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf) orelse return false;

    const pid = getCurrentPid();
    var pid_buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{pid}) catch return true;

    var attempt: u2 = 0;
    while (attempt < 2) : (attempt += 1) {
        if (std.fs.cwd().createFile(pid_path, .{ .exclusive = true })) |file| {
            file.writeAll(pid_str) catch {};
            file.close();
            log.info("PID file: {s} (PID {d})", .{ pid_path, pid });
            return true;
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                if (readPidOwner(pid_path)) |old_pid| {
                    if (processAlive(old_pid)) {
                        log.err("another instance is running (PID {d})", .{old_pid});
                        return false;
                    }
                }
                std.fs.cwd().deleteFile(pid_path) catch {};
            },
            else => {
                log.warn("could not write PID file: {s}", .{@errorName(err)});
                return true;
            },
        }
    }
    log.warn("could not claim PID file after retry", .{});
    return false;
}

fn removePidFile() void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf) orelse return;
    if (readPidOwner(pid_path) != getCurrentPid()) return;
    std.fs.cwd().deleteFile(pid_path) catch {};
}

// ============================================================================
// Server run loop
// ============================================================================

fn run(server: *Server) !void {
    try server.build();
    try server.start();

    if (server.listeners.items.len == 0) {
        log.err("no listeners could be started", .{});
        return error.NoListenersStarted;
    }
    if (!server.waitForListening(5_000)) {
        log.err("no listener reached listening state", .{});
        return error.NoListenersStarted;
    }

    log.info("{s} {s} ready — hub {s}, account {s}", .{
        server_name,
        version,
        server.config.hub_name,
        server.config.admin_user,
    });

    while (server.isRunning()) {
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    server.stopListeners();
    log.info("{s} stopped", .{server_name});
}

// ============================================================================
// Entry point
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var display = cli.DisplayContext.init();

    const args = std.process.argsAlloc(allocator) catch |err| {
        log.err("failed to get arguments: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer std.process.argsFree(allocator, args);

    // M20 #258 — service verbs for vpnserver (parity with vpnclient, default --system)
    if (args.len >= 2 and args[1].len > 0 and args[1][0] != '-') {
        const verb = args[1];
        if (std.mem.eql(u8, verb, "install") or std.mem.eql(u8, verb, "uninstall") or
            std.mem.eql(u8, verb, "start") or std.mem.eql(u8, verb, "stop") or
            std.mem.eql(u8, verb, "restart") or std.mem.eql(u8, verb, "status") or
            std.mem.eql(u8, verb, "enable") or std.mem.eql(u8, verb, "disable"))
        {
            var scope: softether.daemon.ServiceScope = .system; // default --system for vpnserver
            var i: usize = 2;
            while (i < args.len) : (i += 1) {
                const a = args[i];
                if (std.mem.eql(u8, a, "--system")) {
                    scope = .system;
                } else if (std.mem.eql(u8, a, "--user")) {
                    scope = .user;
                } else if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) {
                    std.debug.print("Usage: vpnserver {s} [--system|--user]\n", .{verb});
                    std.process.exit(0);
                } else {
                    std.debug.print("Unknown option for {s}: {s}\n", .{ verb, a });
                    std.process.exit(1);
                }
            }
            const d = softether.daemon;
            if (std.mem.eql(u8, verb, "install")) {
                d.installServerService(allocator, &display, scope) catch |err| {
                    std.debug.print("install failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, verb, "uninstall")) {
                d.uninstallServerService(allocator, &display, scope) catch |err| {
                    std.debug.print("uninstall failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, verb, "start")) {
                d.startServerService(allocator, &display, scope) catch |err| {
                    std.debug.print("start failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, verb, "stop")) {
                d.stopServerService(allocator, &display, scope) catch |err| {
                    std.debug.print("stop failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, verb, "restart")) {
                // restart = stop + start (reuse daemon helpers via stop/start)
                d.stopServerService(allocator, &display, scope) catch {};
                std.Thread.sleep(500 * std.time.ns_per_ms);
                d.startServerService(allocator, &display, scope) catch |err| {
                    std.debug.print("restart failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, verb, "status")) {
                d.statusServerService(allocator, &display, scope) catch |err| {
                    std.debug.print("status failed: {s}\n", .{@errorName(err)});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, verb, "enable") or std.mem.eql(u8, verb, "disable")) {
                std.debug.print("{s}: use install/uninstall for enable/disable (systemd enable is part of install)\n", .{verb});
                std.process.exit(0);
            }
            std.process.exit(0);
        } else if (std.mem.eql(u8, verb, "help") or std.mem.eql(u8, verb, "version")) {
            // fall through to normal handling (parseArgs will handle --version, but help verb shown here)
            if (std.mem.eql(u8, verb, "help")) {
                std.debug.print("Usage: vpnserver [--config <path>] [--daemon|--foreground] [--version] [--gen-cert] | install|uninstall|start|stop|restart|status [--system|--user]\n", .{});
                std.process.exit(0);
            }
        }
    }

    const cli_args = parseArgs(allocator, args) catch |err| {
        log.err("argument error: {s}", .{@errorName(err)});
        cli.display.failure(&display, "usage: {s} [--config <path>] [--daemon | --foreground] [--version] [--gen-cert] | install|uninstall|start|stop|restart|status [--system|--user] | help", .{server_name});
        std.process.exit(1);
    };

    if (cli_args.version) {
        std.debug.print("{s} {s}\n", .{ server_name, version });
        std.process.exit(0);
    }

    if (cli_args.gen_cert) {
        softether.server_cert.generateServerCertFiles(allocator, &display, cli_args.gen_cert_name) catch {
            std.process.exit(1);
        };
        std.process.exit(0);
    }

    if (cli_args.config_path) |path| {
        log.warn("--config {s}: config persistence not implemented yet; using defaults", .{path});
    }

    var server = Server.init(allocator, .{
        .persist_cert = true,
    });
    setupSignalHandlers(&server);
    defer global_server = null;

    var daemon_pid = false;
    if (cli_args.daemon) {
        if (!writePidFile()) {
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const pid_path = getPidFilePath(&path_buf) orelse pid_filename;
            cli.display.failure(&display, "could not start: {s} already running (see {s})", .{ server_name, pid_path });
            std.process.exit(1);
        }
        daemon_pid = true;
    }
    defer if (daemon_pid) removePidFile();

    // Free CLI args that the server config may have borrowed.
    defer if (cli_args.config_path) |p| allocator.free(p);

    run(&server) catch |err| {
        log.err("{s} failed: {s}", .{ server_name, @errorName(err) });
        std.process.exit(1);
    };
    // Note: server.deinit() is not called on the run path — session threads
    // may still borrow hubs. The OS reclaims on exit.
}

// ============================================================================
// Tests
// ============================================================================

test "server.exe parse --version" {
    const args = [_][]const u8{ server_name, "--version" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.version);
    try std.testing.expect(!cli_args.daemon);
    try std.testing.expect(!cli_args.gen_cert);
}

test "server.exe parse --config" {
    const args = [_][]const u8{ server_name, "--config", "/etc/vpn_server.config" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    defer if (cli_args.config_path) |p| std.testing.allocator.free(p);
    try std.testing.expectEqualStrings("/etc/vpn_server.config", cli_args.config_path.?);
}

test "server.exe parse --daemon --foreground conflict" {
    const args = [_][]const u8{ server_name, "--daemon", "--foreground" };
    try std.testing.expectError(error.ConflictingOptions, parseArgs(std.testing.allocator, &args));
}

test "server.exe parse rejects unknown option" {
    const args = [_][]const u8{ server_name, "--bogus" };
    try std.testing.expectError(error.UnknownOption, parseArgs(std.testing.allocator, &args));
}

test "server.exe parse --gen-cert" {
    const args = [_][]const u8{ server_name, "--gen-cert" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.gen_cert);
}

test "server.exe parse --gen-cert empty common name" {
    const args = [_][]const u8{ server_name, "--gen-cert", "" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.gen_cert);
    try std.testing.expect(cli_args.gen_cert_name == null);
}

test "server.exe parse --gen-cert common name" {
    const args = [_][]const u8{ server_name, "--gen-cert", "myhost" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.gen_cert);
    try std.testing.expectEqualStrings("myhost", cli_args.gen_cert_name.?);
}

test "server.exe bootstrap creates DEFAULT hub with Administrator" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, .{ .persist_cert = false });
    defer server.deinit();

    try server.build();

    try std.testing.expectEqualStrings("DEFAULT", server.config.hub_name);
    try std.testing.expect(server.auth_hub != null);
    try std.testing.expect(server.switch_hub != null);
    try std.testing.expect(server.server_ctx != null);
    try std.testing.expect(server.cert_pem != null);
    try std.testing.expect(server.key_pem != null);
}
