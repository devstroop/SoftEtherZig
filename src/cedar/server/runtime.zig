//! Server runtime — shared between the `vpnserver` executable and the FFI
//! layer. Encapsulates the server lifecycle: create → build → start →
//! (running) → stop → destroy.
//!
//! Extracted from `exec/vpnserver/main.zig` (M15, issue #197) so the FFI
//! layer can import it without pulling in the CLI-specific `std_options`,
//! PID file, or signal handler code.

const std = @import("std");
const Allocator = std.mem.Allocator;

const lib = @import("../../lib.zig");
const log = std.log.scoped(.cedar_server);

// ============================================================================
// Server configuration — replaces CliArgs for the FFI path
// ============================================================================

/// Server runtime configuration. Callers create this before calling
/// `Server.init()` — all fields have sane defaults.
pub const Config = struct {
    /// Hub name (default: "DEFAULT").
    hub_name: []const u8 = "DEFAULT",
    /// Admin username (default: "administrator").
    admin_user: []const u8 = "administrator",
    /// Admin password (default: "softether" — dev only, logged at startup).
    admin_password: []const u8 = "softether",
    /// Auto-generate + persist a self-signed cert on first run (default: true).
    persist_cert: bool = true,
};

// ============================================================================
// Server runtime
// ============================================================================

/// Owns everything the running server needs. Mirrors the C server's
/// `SERVER` struct: cert, hubs, admin dispatch, farm, syslog, listeners.
pub const Server = struct {
    allocator: Allocator,
    config: Config,
    /// Atomic stop flag — race-free between caller thread and signal handler.
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    persist_cert: bool = true,
    cert_pem: ?[]u8 = null,
    key_pem: ?[]u8 = null,
    auth_hub: ?lib.server.auth.Hub = null,
    switch_hub: ?*lib.server.hub.Hub = null,
    server_ctx: ?*lib.server.accept.ServerContext = null,
    session_registry: ?*lib.server.session_registry.SessionRegistry = null,
    admin_server: ?*lib.server.admin_dispatch.Server = null,
    farm_state: ?*lib.server.farm.FarmState = null,
    farm_server: ?*lib.server.farm_rpc.FarmServer = null,
    syslog_client: ?*lib.server.logging.SyslogClient = null,
    listeners: std.ArrayListUnmanaged(*lib.server.listener.Listener) = .{},

    /// Create a new server with the given configuration. Does not start
    /// listeners — call `build()` then `start()` for that.
    pub fn init(allocator: Allocator, config: Config) Server {
        return .{
            .allocator = allocator,
            .config = config,
            .persist_cert = config.persist_cert,
        };
    }

    pub fn isRunning(self: *const Server) bool {
        return self.running.load(.acquire);
    }

    /// Flip the stop flag (async-signal-safe).
    pub fn stop(self: *Server) void {
        self.running.store(false, .release);
    }

    /// Full teardown. Stops listeners first so no new connection threads
    /// spawn, then frees the hubs, context, and cert buffers.
    pub fn deinit(self: *Server) void {
        for (self.listeners.items) |listener| listener.stop();
        self.listeners.deinit(self.allocator);

        if (self.session_registry) |registry| {
            registry.deinit();
            self.allocator.destroy(registry);
        }
        self.session_registry = null;

        if (self.admin_server) |server| {
            server.server_ctx = null;
            server.bridge_ops.ctx = null;
            server.syslog_ops.ctx = null;
        }

        if (self.syslog_client) |sc| {
            sc.deinit();
            self.allocator.destroy(sc);
        }
        self.syslog_client = null;

        if (self.farm_server) |fs| {
            fs.deinit();
            self.allocator.destroy(fs);
        }
        self.farm_server = null;

        if (self.server_ctx) |ctx| {
            ctx.farm_server = null;
            ctx.deinit();
            self.allocator.destroy(ctx);
        }
        self.server_ctx = null;

        if (self.admin_server) |server| {
            server.deinit();
            self.allocator.destroy(server);
        }
        self.admin_server = null;

        if (self.farm_state) |fs| {
            fs.deinit();
            self.allocator.destroy(fs);
        }
        self.farm_state = null;

        if (self.switch_hub) |hub| hub.deinit();
        self.switch_hub = null;

        if (self.auth_hub) |*hub| hub.deinit();
        self.auth_hub = null;

        if (self.cert_pem) |p| self.allocator.free(p);
        self.cert_pem = null;
        if (self.key_pem) |p| self.allocator.free(p);
        self.key_pem = null;
    }

    /// Create the in-memory server identity: cert, SAM hub with first-run
    /// account, L2 switch hub, and the accept `ServerContext`. No sockets.
    pub fn build(self: *Server) !void {
        try self.ensureCertificate();

        self.auth_hub = try lib.server.auth.Hub.init(self.allocator, self.config.hub_name);
        self.auth_hub.?.setAdminPassword(self.config.admin_password);
        _ = try self.auth_hub.?.addUser(self.config.admin_user, .password, self.config.admin_password);

        self.switch_hub = try lib.server.hub.Hub.init(self.allocator, self.config.hub_name);

        const registry = try self.allocator.create(lib.server.session_registry.SessionRegistry);
        registry.* = lib.server.session_registry.SessionRegistry.init(self.allocator);
        self.session_registry = registry;

        const admin = try self.allocator.create(lib.server.admin_dispatch.Server);
        admin.* = try lib.server.admin_dispatch.Server.init(self.allocator);
        self.admin_server = admin;

        const farm_state = try self.allocator.create(lib.server.farm.FarmState);
        farm_state.* = lib.server.farm.FarmState.init(self.allocator);
        self.farm_state = farm_state;

        const farm_server = try self.allocator.create(lib.server.farm_rpc.FarmServer);
        farm_server.* = lib.server.farm_rpc.FarmServer.init(self.allocator, farm_state);
        self.farm_server = farm_server;

        const ctx = try self.allocator.create(lib.server.accept.ServerContext);
        ctx.* = .{
            .allocator = self.allocator,
            .cert_pem = self.cert_pem.?,
            .key_pem = self.key_pem.?,
            .auth_hub = &self.auth_hub.?,
            .switch_hub = self.switch_hub.?,
            .session_registry = registry,
            .admin_server = admin,
            .farm_server = farm_server,
        };
        self.server_ctx = ctx;

        const syslog_client = try self.allocator.create(lib.server.logging.SyslogClient);
        syslog_client.* = lib.server.logging.SyslogClient.init(self.allocator);
        ctx.syslog_client = syslog_client;
        self.syslog_client = syslog_client;

        admin.bridge_ops = .{
            .ctx = @ptrCast(ctx),
            .create = &lib.server.accept.bridgeCreate,
            .destroy = &lib.server.accept.bridgeDestroy,
        };

        admin.syslog_ops = .{
            .ctx = @ptrCast(syslog_client),
            .configure = &lib.server.logging.syslogConfigure,
        };

        self.switch_hub.?.syslog_client = syslog_client;
    }

    /// Start a listener on each default port. Ports that fail to bind
    /// (e.g. 443 without privileges) are skipped.
    pub fn start(self: *Server) !void {
        const ctx = self.server_ctx orelse return error.ServerNotBuilt;
        for (lib.server.listener.default_ports) |port| {
            const listener = lib.server.listener.Listener.start(
                self.allocator,
                port,
                .{},
                lib.server.accept.acceptConnection,
                ctx,
            ) catch |err| {
                log.warn("failed to start listener on port {d}: {s}", .{ port, @errorName(err) });
                continue;
            };
            self.listeners.append(self.allocator, listener) catch {
                listener.stop();
                continue;
            };
        }
    }

    /// Stop all listeners.
    pub fn stopListeners(self: *Server) void {
        for (self.listeners.items) |listener| listener.stop();
        self.listeners.clearRetainingCapacity();
    }

    /// Wait up to `timeout_ms` for at least one listener to reach `.listening`.
    pub fn waitForListening(self: *Server, timeout_ms: i64) bool {
        const deadline = std.time.milliTimestamp() + timeout_ms;
        while (std.time.milliTimestamp() < deadline) {
            for (self.listeners.items) |listener| {
                if (listener.getStatus() == .listening) return true;
            }
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
        return false;
    }

    // ---- Internal ----------------------------------------------------------

    fn ensureCertificate(self: *Server) !void {
        const cert_filename = lib.server_cert.cert_filename;
        const key_filename = lib.server_cert.key_filename;

        const cert = std.fs.cwd().readFileAlloc(self.allocator, cert_filename, 1 << 20) catch null;
        const key = std.fs.cwd().readFileAlloc(self.allocator, key_filename, 1 << 20) catch null;
        if (cert != null and key != null) {
            self.cert_pem = cert;
            self.key_pem = key;
            log.info("loaded {s} and {s}", .{ cert_filename, key_filename });
            return;
        }
        if (cert) |c| self.allocator.free(c);
        if (key) |k| self.allocator.free(k);

        const generated = try lib.server_tls.generateSelfSignedCert(self.allocator, null);
        self.cert_pem = generated.cert_pem;
        self.key_pem = generated.key_pem;
        if (self.persist_cert) {
            persistPem(cert_filename, self.cert_pem.?, 0o644);
            persistPem(key_filename, self.key_pem.?, 0o600);
        }
        log.info("generated first-run {s} + {s}", .{ cert_filename, key_filename });
    }
};

// ============================================================================
// Helpers
// ============================================================================

fn persistPem(path: []const u8, data: []const u8, mode: std.fs.File.Mode) void {
    const file = std.fs.cwd().createFile(path, .{ .truncate = true, .mode = mode }) catch |err| {
        log.warn("could not write {s}: {s}", .{ path, @errorName(err) });
        return;
    };
    defer file.close();
    if (@import("builtin").os.tag != .windows) std.posix.fchmod(file.handle, mode) catch {};
    file.writeAll(data) catch {};
}

// ============================================================================
// Tests
// ============================================================================

test "Server init defaults" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, .{});
    defer server.deinit();

    try std.testing.expect(server.isRunning());
    try std.testing.expectEqualStrings("DEFAULT", server.config.hub_name);
    try std.testing.expectEqualStrings("administrator", server.config.admin_user);
}

test "Server build and teardown" {
    const allocator = std.testing.allocator;
    var server = Server.init(allocator, .{ .persist_cert = false });
    defer server.deinit();

    try server.build();

    try std.testing.expect(server.auth_hub != null);
    try std.testing.expect(server.switch_hub != null);
    try std.testing.expect(server.server_ctx != null);
    try std.testing.expect(server.admin_server != null);
    try std.testing.expect(server.syslog_client != null);
    try std.testing.expect(server.cert_pem != null);
    try std.testing.expect(server.key_pem != null);
}

test "Server stop flag" {
    var server = Server.init(std.testing.allocator, .{});
    defer server.deinit();

    try std.testing.expect(server.isRunning());
    server.stop();
    try std.testing.expect(!server.isRunning());
}
