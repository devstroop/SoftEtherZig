//! SoftEther VPN Server — Zig Implementation (issue #83)
//!
//! `exec/vpnserver/main.zig` — the `vpnserver` executable entry. Mirrors C
//! `vpnserver.c`: `InitCedar` → `StInit` → `StStartServer(false)` → daemonize
//! (reuse the `app/daemon.zig` PID-file + run-loop pattern) → signal handling
//! (`SIGTERM`/`SIGINT` → graceful stop).
//!
//! Phase 0: no config persistence (`vpn_server.config`) yet. The server boots
//! from in-memory defaults — hub `DEFAULT`, account `Administrator` (dev
//! password, logged at startup), a first-run self-signed certificate, and the
//! four default listener ports (443/992/1194/5555). On `SIGTERM`/`SIGINT` it
//! stops accepting new connections and exits 0. Config autosave lands with the
//! config subsystem.
//!
//! Module layout: this file lives below `src/` so (per the Zig 0.15
//! module-root rule) it reaches the server core and shared helpers through the
//! named `softether` module (`src/lib.zig`, which re-exports `server.*`,
//! `server_tls`, `server_cert`) instead of escaping relative imports.

const std = @import("std");
const builtin = @import("builtin");

// Named module provided by build.zig (the vpnserver target).
const softether = @import("softether");
const cli = softether.cli;

const log = std.log.scoped(.app);

// ============================================================================
// Logging Configuration
// ============================================================================

/// Scope naming follows the module hierarchy. The server core logs under
/// `.cedar_server`; this executable and app-layer lifecycle under `.app`.
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

/// Version info (from build.zig.zon via lib).
pub const version = softether.version;

// ============================================================================
// Constants
// ============================================================================

const server_name = "vpnserver";
/// Virtual Hub name created on first boot (C `SERVER_DEFAULT_HUB` = "DEFAULT").
const default_hub_name = "DEFAULT";
/// First-run account (C `ADMINISTRATOR_USERNAME`).
const default_admin_user = "administrator";
/// Phase-0 dev password for the first-run account. C generates a random one
/// and prints it; with no config subsystem yet, use a well-known default so
/// the M1 acceptance gate can log in. Printed at startup, not secret.
const default_admin_password = "softether";
const cert_filename = softether.server_cert.cert_filename;
const key_filename = softether.server_cert.key_filename;
const pid_filename = "vpnserver.pid";

// ============================================================================
// CLI arguments
// ============================================================================

pub const CliArgs = struct {
    /// `--config <path>`: parsed but unused in Phase 0 (config subsystem
    /// later). Owned (allocator.dupe).
    config_path: ?[]const u8 = null,
    /// `--daemon`: write a PID file and run detached-style (no fork yet).
    daemon: bool = false,
    /// `--foreground`: explicit foreground run (default). Mutually exclusive
    /// with `--daemon`.
    foreground: bool = false,
    /// `--version`: print version and exit.
    version: bool = false,
    /// `--gen-cert`: write a first-run self-signed cert/key pair and exit.
    gen_cert: bool = false,
    /// Optional common name for `--gen-cert` (argv-owned, not allocated).
    gen_cert_name: ?[]const u8 = null,
};

pub fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !CliArgs {
    var result = CliArgs{};
    errdefer if (result.config_path) |p| allocator.free(p);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
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
            if (i + 1 < args.len and args[i + 1][0] != '-') {
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
// Server state
// ============================================================================

/// Owns everything the running server needs. Mirrors the client `AppState`
/// contract that `app/signals.zig` and `app/daemon.zig` rely on: a `running`
/// flag flipped by the signal handler plus a run-until-stopped loop.
pub const ServerState = struct {
    allocator: std.mem.Allocator,
    cli_args: CliArgs,
    running: bool = true,
    /// Persist a first-run generated cert (off in unit tests).
    persist_cert: bool = true,
    cert_pem: ?[]u8 = null,
    key_pem: ?[]u8 = null,
    auth_hub: ?softether.server.auth.Hub = null,
    switch_hub: ?*softether.server.hub.Hub = null,
    server_ctx: ?*softether.server.accept.ServerContext = null,
    listeners: std.ArrayListUnmanaged(*softether.server.listener.Listener) = .{},

    pub fn init(allocator: std.mem.Allocator, cli_args: CliArgs) ServerState {
        return .{ .allocator = allocator, .cli_args = cli_args };
    }

    pub fn isRunning(self: *const ServerState) bool {
        return self.running;
    }

    /// Flip the stop flag (async-signal-safe; called from the signal handler).
    pub fn stop(self: *ServerState) void {
        self.running = false;
    }

    /// Full teardown. Stops listeners first so no new connection threads
    /// spawn, then frees the hubs, context and cert buffers.
    pub fn deinit(self: *ServerState) void {
        for (self.listeners.items) |listener| listener.stop();
        self.listeners.deinit(self.allocator);

        if (self.server_ctx) |ctx| self.allocator.destroy(ctx);
        self.server_ctx = null;

        if (self.switch_hub) |hub| hub.deinit(); // Hub.deinit frees itself
        self.switch_hub = null;

        if (self.auth_hub) |*hub| hub.deinit();
        self.auth_hub = null;

        if (self.cert_pem) |p| self.allocator.free(p);
        self.cert_pem = null;
        if (self.key_pem) |p| self.allocator.free(p);
        self.key_pem = null;

        if (self.cli_args.config_path) |p| self.allocator.free(p);
        self.cli_args.config_path = null;
    }
};

// ============================================================================
// Signal handling — mirrors app/signals.zig
// ============================================================================

/// Global state pointer for signal handling (set before setupSignalHandlers).
var global_state: ?*ServerState = null;

pub fn setGlobalState(s: *ServerState) void {
    global_state = s;
}

pub fn clearGlobalState() void {
    global_state = null;
}

/// Register SIGINT/SIGTERM handlers (same shape as `app/signals.zig`).
pub fn setupSignalHandlers() void {
    if (builtin.os.tag == .windows) return;
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
    // Async-signal-safe: only flip the stop flag. Listener/session teardown
    // happens on the main thread after the run loop observes it.
    if (global_state) |s| s.stop();
}

// ============================================================================
// PID file (S-038) — mirrors app/daemon.zig
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

/// Write `vpnserver.pid` (XDG_RUNTIME_DIR or /tmp), refusing if another live
/// instance already owns it. Mirrors `app/daemon.zig` `writePidFile` (S-038).
fn writePidFile() bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf) orelse return false;

    if (std.fs.cwd().openFile(pid_path, .{})) |file| {
        defer file.close();
        var read_buf: [32]u8 = undefined;
        const n = file.readAll(&read_buf) catch 0;
        if (n > 0) {
            const content = std.mem.trim(u8, read_buf[0..n], " \n\r\t");
            if (std.fmt.parseInt(u32, content, 10)) |old_pid| {
                if (builtin.os.tag != .windows) {
                    if (std.posix.kill(@as(i32, @intCast(old_pid)), 0)) {
                        log.err("another instance is running (PID {d})", .{old_pid});
                        return false;
                    } else |_| {}
                }
            } else |_| {}
        }
    } else |_| {}

    const pid = getCurrentPid();
    const file = std.fs.cwd().createFile(pid_path, .{}) catch |err| {
        log.warn("could not write PID file: {s}", .{@errorName(err)});
        return true; // Non-fatal
    };
    defer file.close();

    var pid_buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{pid}) catch return true;
    file.writeAll(pid_str) catch {};
    log.info("PID file: {s} (PID {d})", .{ pid_path, pid });
    return true;
}

fn removePidFile() void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf) orelse return;
    std.fs.cwd().deleteFile(pid_path) catch {};
}

// ============================================================================
// Server bootstrap — mirrors StInit → StStartServer
// ============================================================================

fn persistPem(path: []const u8, data: []const u8, mode: u32) void {
    const file = std.fs.cwd().createFile(path, .{ .truncate = true, .mode = mode }) catch |err| {
        log.warn("could not write {s}: {s}", .{ path, @errorName(err) });
        return;
    };
    defer file.close();
    if (builtin.os.tag != .windows) std.posix.fchmod(file.handle, mode) catch {};
    file.writeAll(data) catch {};
}

/// Load an existing cert/key pair, or auto-generate one on first run (C
/// first-run behavior: `SiLoadConfiguration` → `SiGenerateDefaultCertEx`) and
/// persist it so restarts keep the same identity.
fn ensureCertificate(state: *ServerState) !void {
    const cert = std.fs.cwd().readFileAlloc(state.allocator, cert_filename, 1 << 20) catch null;
    const key = std.fs.cwd().readFileAlloc(state.allocator, key_filename, 1 << 20) catch null;
    if (cert != null and key != null) {
        state.cert_pem = cert;
        state.key_pem = key;
        log.info("loaded {s} and {s}", .{ cert_filename, key_filename });
        return;
    }
    if (cert) |c| state.allocator.free(c);
    if (key) |k| state.allocator.free(k);

    const generated = try softether.server_tls.generateSelfSignedCert(state.allocator, null);
    state.cert_pem = generated.cert_pem;
    state.key_pem = generated.key_pem;
    if (state.persist_cert) {
        persistPem(cert_filename, state.cert_pem.?, 0o644);
        persistPem(key_filename, state.key_pem.?, 0o600);
    }
    log.info("generated first-run {s} + {s}", .{ cert_filename, key_filename });
}

/// Create the in-memory server identity: cert, SAM hub with the first-run
/// account, L2 switch hub, and the accept `ServerContext`. No sockets.
fn buildServer(state: *ServerState) !void {
    try ensureCertificate(state);

    state.auth_hub = try softether.server.auth.Hub.init(state.allocator, default_hub_name);
    state.auth_hub.?.setAdminPassword(default_admin_password);
    _ = try state.auth_hub.?.addUser(default_admin_user, .password, default_admin_password);

    state.switch_hub = try softether.server.hub.Hub.init(state.allocator, default_hub_name);

    const ctx = try state.allocator.create(softether.server.accept.ServerContext);
    ctx.* = .{
        .allocator = state.allocator,
        .cert_pem = state.cert_pem.?,
        .key_pem = state.key_pem.?,
        .auth_hub = &state.auth_hub.?,
        .switch_hub = state.switch_hub.?,
    };
    state.server_ctx = ctx;
}

/// Start a listener on each default port. A port that fails to bind (e.g. 443
/// without privileges) is skipped — the C server retries in the listener loop;
/// the ports that bind are enough to serve.
fn startListeners(state: *ServerState) !void {
    const ctx = state.server_ctx.?;
    for (softether.server.listener.default_ports) |port| {
        const listener = softether.server.listener.Listener.start(
            state.allocator,
            port,
            .{},
            softether.server.accept.acceptConnection,
            ctx,
        ) catch |err| {
            log.warn("failed to start listener on port {d}: {s}", .{ port, @errorName(err) });
            continue;
        };
        state.listeners.append(state.allocator, listener) catch {
            listener.stop();
            continue;
        };
    }
}

/// Graceful stop: halt the accept threads so no new connections are admitted.
/// Active session threads are detached in Phase 0 (no session registry yet);
/// the process exits right after, so the OS reclaims them and the hubs/certs.
fn stopListeners(state: *ServerState) void {
    for (state.listeners.items) |listener| listener.stop();
    state.listeners.clearRetainingCapacity();
}

/// Boot the server and run until a signal flips `running` (mirrors
/// `app/daemon.zig`'s run-until-stopped loop).
pub fn run(state: *ServerState) !void {
    try buildServer(state);
    try startListeners(state);

    if (state.listeners.items.len == 0) {
        log.err("no listeners could be started", .{});
        return error.NoListenersStarted;
    }

    log.info("{s} {s} ready — hub {s}, account {s} (password: {s})", .{
        server_name,
        version,
        default_hub_name,
        default_admin_user,
        default_admin_password,
    });

    while (state.isRunning()) {
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    stopListeners(state);
    log.info("{s} stopped", .{server_name});
}

// ============================================================================
// Entry point
// ============================================================================

pub fn main() !void {
    // Phase 0: no GPA deinit on the run path. Graceful shutdown returns from
    // run() with detached session threads that may still borrow hubs, so the
    // process lets the OS reclaim. Deinit paths are covered by tests
    // (testing.allocator). `std.process.exit` paths below skip defers anyway.
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var display = cli.DisplayContext.init();

    const args = std.process.argsAlloc(allocator) catch |err| {
        log.err("failed to get arguments: {s}", .{@errorName(err)});
        std.process.exit(1);
    };
    defer std.process.argsFree(allocator, args);

    const cli_args = parseArgs(allocator, args) catch |err| {
        log.err("argument error: {s}", .{@errorName(err)});
        cli.display.failure(&display, "usage: {s} [--config <path>] [--daemon | --foreground] [--version] [--gen-cert]", .{server_name});
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

    // Phase 0: `--config` is parsed but config persistence (`vpn_server.config`)
    // arrives with the config subsystem. Warn and run with in-memory defaults.
    if (cli_args.config_path) |path| {
        log.warn("--config {s}: config persistence not implemented yet (Phase 0); using defaults", .{path});
    }

    var daemon_pid = false;
    if (cli_args.daemon) {
        if (!writePidFile()) {
            cli.display.failure(&display, "could not start: {s} already running (see /tmp/{s})", .{ server_name, pid_filename });
            std.process.exit(1);
        }
        daemon_pid = true;
    }
    // Function-scope defer: a defer nested in the `if` block would run the
    // moment the block exits, deleting the PID file right after writing it.
    defer if (daemon_pid) removePidFile();

    var state = ServerState.init(allocator, cli_args);
    setGlobalState(&state);
    defer clearGlobalState();
    setupSignalHandlers();

    run(&state) catch |err| {
        log.err("{s} failed: {s}", .{ server_name, @errorName(err) });
        std.process.exit(1);
    };
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

test "server.exe bootstrap creates DEFAULT hub with Administrator" {
    const allocator = std.testing.allocator;
    var state = ServerState.init(allocator, CliArgs{});
    state.persist_cert = false;
    defer state.deinit();

    try buildServer(&state);

    try std.testing.expectEqualStrings(default_hub_name, state.auth_hub.?.name);
    try std.testing.expect(state.auth_hub.?.getUser(default_admin_user) != null);
    try std.testing.expect(state.switch_hub != null);
    try std.testing.expect(state.server_ctx != null);
    try std.testing.expect(state.cert_pem != null);
    try std.testing.expect(state.key_pem != null);
}

test "server.exe setGlobalState and clearGlobalState" {
    var state = ServerState.init(std.testing.allocator, CliArgs{});
    defer state.deinit();

    try std.testing.expect(global_state == null);
    setGlobalState(&state);
    try std.testing.expect(global_state != null);
    clearGlobalState();
    try std.testing.expect(global_state == null);
}
