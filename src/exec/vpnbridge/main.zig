//! SoftEther VPN Bridge — Zig Implementation (issue #156)
//!
//! `exec/vpnbridge/main.zig` — the `vpnbridge` executable entry. Mirrors C
//! `vpnbridge.c`: `InitCedar` → `StInit` → `StStartServer(true)` → daemonize
//! → signal handling. Bridge mode restricts hub creation and positions the
//! server as a LocalBridge endpoint.
//!
//! This is a thin wrapper around the same server core used by `vpnserver`.
//! The only behavioral difference is `bridge_mode = true` on the
//! `ServerContext`, which the accept layer and admin dispatch can check to
//! gate bridge-specific behavior.

const std = @import("std");
const builtin = @import("builtin");

const softether = @import("softether");
const cli = softether.cli;

const log = std.log.scoped(.app);

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

const server_name = "vpnbridge";
const default_hub_name = "DEFAULT";
const default_admin_user = "administrator";
const default_admin_password = "softether";
const cert_filename = softether.server_cert.cert_filename;
const key_filename = softether.server_cert.key_filename;
const pid_filename = "vpnbridge.pid";

// ============================================================================
// CLI arguments — identical to vpnserver
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
// Server state
// ============================================================================

pub const ServerState = struct {
    allocator: std.mem.Allocator,
    cli_args: CliArgs,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    persist_cert: bool = true,
    cert_pem: ?[]u8 = null,
    key_pem: ?[]u8 = null,
    auth_hub: ?softether.server.auth.Hub = null,
    switch_hub: ?*softether.server.hub.Hub = null,
    server_ctx: ?*softether.server.accept.ServerContext = null,
    session_registry: ?*softether.server.session_registry.SessionRegistry = null,
    admin_server: ?*softether.server.admin_dispatch.Server = null,
    listeners: std.ArrayListUnmanaged(*softether.server.listener.Listener) = .{},

    pub fn init(allocator: std.mem.Allocator, cli_args: CliArgs) ServerState {
        return .{ .allocator = allocator, .cli_args = cli_args };
    }

    pub fn isRunning(self: *const ServerState) bool {
        return self.running.load(.acquire);
    }

    pub fn stop(self: *ServerState) void {
        self.running.store(false, .release);
    }

    pub fn deinit(self: *ServerState) void {
        for (self.listeners.items) |listener| listener.stop();
        self.listeners.deinit(self.allocator);

        if (self.session_registry) |registry| {
            registry.deinit();
            self.allocator.destroy(registry);
        }
        self.session_registry = null;

        if (self.server_ctx) |ctx| self.allocator.destroy(ctx);
        self.server_ctx = null;

        if (self.admin_server) |server| {
            server.deinit();
            self.allocator.destroy(server);
        }
        self.admin_server = null;

        if (self.switch_hub) |hub| hub.deinit();
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
// Signal handling
// ============================================================================

var global_state: ?*ServerState = null;

pub fn setGlobalState(s: *ServerState) void {
    global_state = s;
}

pub fn clearGlobalState() void {
    global_state = null;
}

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
    if (global_state) |s| s.stop();
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
// Server bootstrap
// ============================================================================

fn persistPem(path: []const u8, data: []const u8, mode: std.fs.File.Mode) void {
    const file = std.fs.cwd().createFile(path, .{ .truncate = true, .mode = mode }) catch |err| {
        log.warn("could not write {s}: {s}", .{ path, @errorName(err) });
        return;
    };
    defer file.close();
    if (builtin.os.tag != .windows) std.posix.fchmod(file.handle, mode) catch {};
    file.writeAll(data) catch {};
}

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

fn buildServer(state: *ServerState) !void {
    try ensureCertificate(state);

    state.auth_hub = try softether.server.auth.Hub.init(state.allocator, default_hub_name);
    state.auth_hub.?.setAdminPassword(default_admin_password);
    _ = try state.auth_hub.?.addUser(default_admin_user, .password, default_admin_password);

    state.switch_hub = try softether.server.hub.Hub.init(state.allocator, default_hub_name);

    const registry = try state.allocator.create(softether.server.session_registry.SessionRegistry);
    registry.* = softether.server.session_registry.SessionRegistry.init(state.allocator);
    state.session_registry = registry;

    const admin = try state.allocator.create(softether.server.admin_dispatch.Server);
    admin.* = try softether.server.admin_dispatch.Server.init(state.allocator);
    state.admin_server = admin;

    const ctx = try state.allocator.create(softether.server.accept.ServerContext);
    ctx.* = .{
        .allocator = state.allocator,
        .cert_pem = state.cert_pem.?,
        .key_pem = state.key_pem.?,
        .auth_hub = &state.auth_hub.?,
        .switch_hub = state.switch_hub.?,
        .session_registry = registry,
        .admin_server = admin,
        .bridge_mode = true,
    };
    state.server_ctx = ctx;
}

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

fn stopListeners(state: *ServerState) void {
    for (state.listeners.items) |listener| listener.stop();
    state.listeners.clearRetainingCapacity();
}

fn waitForListening(state: *ServerState, timeout_ms: i64) bool {
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (std.time.milliTimestamp() < deadline) {
        for (state.listeners.items) |listener| {
            if (listener.getStatus() == .listening) return true;
        }
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }
    return false;
}

pub fn run(state: *ServerState) !void {
    try buildServer(state);
    try startListeners(state);

    if (state.listeners.items.len == 0) {
        log.err("no listeners could be started", .{});
        return error.NoListenersStarted;
    }
    if (!waitForListening(state, 5_000)) {
        log.err("no listener reached listening state", .{});
        return error.NoListenersStarted;
    }

    log.info("{s} {s} ready (bridge mode) — hub {s}, account {s} (password: {s})", .{
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

    if (cli_args.config_path) |path| {
        log.warn("--config {s}: config persistence not implemented yet; using defaults", .{path});
    }

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

test "bridge.exe parse --version" {
    const args = [_][]const u8{ server_name, "--version" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.version);
    try std.testing.expect(!cli_args.daemon);
    try std.testing.expect(!cli_args.gen_cert);
}

test "bridge.exe parse --config" {
    const args = [_][]const u8{ server_name, "--config", "/etc/vpn_bridge.config" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    defer if (cli_args.config_path) |p| std.testing.allocator.free(p);
    try std.testing.expectEqualStrings("/etc/vpn_bridge.config", cli_args.config_path.?);
}

test "bridge.exe parse --daemon --foreground conflict" {
    const args = [_][]const u8{ server_name, "--daemon", "--foreground" };
    try std.testing.expectError(error.ConflictingOptions, parseArgs(std.testing.allocator, &args));
}

test "bridge.exe parse rejects unknown option" {
    const args = [_][]const u8{ server_name, "--bogus" };
    try std.testing.expectError(error.UnknownOption, parseArgs(std.testing.allocator, &args));
}

test "bridge.exe parse --gen-cert" {
    const args = [_][]const u8{ server_name, "--gen-cert" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.gen_cert);
}

test "bridge.exe parse --gen-cert common name" {
    const args = [_][]const u8{ server_name, "--gen-cert", "mybridge" };
    const cli_args = try parseArgs(std.testing.allocator, &args);
    try std.testing.expect(cli_args.gen_cert);
    try std.testing.expectEqualStrings("mybridge", cli_args.gen_cert_name.?);
}

test "bridge.exe bootstrap creates DEFAULT hub with bridge_mode" {
    const allocator = std.testing.allocator;
    var state = ServerState.init(allocator, CliArgs{});
    state.persist_cert = false;
    defer state.deinit();

    try buildServer(&state);

    try std.testing.expectEqualStrings(default_hub_name, state.auth_hub.?.name);
    try std.testing.expect(state.auth_hub.?.getUser(default_admin_user) != null);
    try std.testing.expect(state.switch_hub != null);
    try std.testing.expect(state.server_ctx != null);
    try std.testing.expect(state.server_ctx.?.bridge_mode);
    try std.testing.expect(state.cert_pem != null);
    try std.testing.expect(state.key_pem != null);
}
