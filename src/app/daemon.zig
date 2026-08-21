//! Daemon Mode
//!
//! Runs the VPN client in daemon (non-interactive) mode.
//! Supports PID file management and connection progress display.

const std = @import("std");
const log = std.log.scoped(.app);
const builtin = @import("builtin");

const cli = @import("../cli/mod.zig");
const client = @import("../cedar/client/mod.zig");
const state_mod = @import("state.zig");
const config_mod = @import("config.zig");
const events_mod = @import("events.zig");

const AppState = state_mod.AppState;

// ============================================================================
// PID File Management (S-038)
// ============================================================================

const pid_filename = "softether.pid";

fn getPidFilePath(buf: *[std.fs.max_path_bytes]u8, filename: []const u8) ?[]const u8 {
    // Try XDG_RUNTIME_DIR first (e.g. /run/user/1000/)
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "XDG_RUNTIME_DIR") catch null) |dir| {
        defer std.heap.page_allocator.free(dir);
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, filename }) catch null;
    } else {}

    // Fall back to /tmp
    return std.fmt.bufPrint(buf, "/tmp/{s}", .{filename}) catch null;
}

fn getCurrentPid() u32 {
    if (builtin.os.tag == .windows) {
        return @intCast(std.os.windows.GetCurrentProcessId());
    } else {
        return @intCast(std.c.getpid());
    }
}

pub fn writePidFile(display_ctx: *cli.display.DisplayContext, filename: []const u8) bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf, filename) orelse return false;

    // Check for stale PID file
    if (std.fs.cwd().openFile(pid_path, .{})) |file| {
        defer file.close();
        var read_buf: [32]u8 = undefined;
        const n = file.readAll(&read_buf) catch 0;
        if (n > 0) {
            const content = std.mem.trim(u8, read_buf[0..n], " \n\r\t");
            if (std.fmt.parseInt(u32, content, 10)) |old_pid| {
                // Check if process still exists (signal 0 = check only)
                if (builtin.os.tag != .windows) {
                    if (std.posix.kill(@as(i32, @intCast(old_pid)), 0)) {
                        cli.display.failure(display_ctx, "Another instance is running (PID {d})", .{old_pid});
                        return false;
                    } else |_| {}
                }
            } else |_| {}
        }
    } else |_| {}

    // Write current PID
    const pid = getCurrentPid();
    const file = std.fs.cwd().createFile(pid_path, .{}) catch |err| {
        cli.display.warning(display_ctx, "Could not write PID file: {s}", .{@errorName(err)});
        return true; // Non-fatal
    };
    defer file.close();

    var pid_buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}\n", .{pid}) catch return true;
    file.writeAll(pid_str) catch {};

    cli.display.debug(display_ctx, "PID file: {s} (PID {d})", .{ pid_path, pid });
    return true;
}

pub fn removePidFile(filename: []const u8) void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_path = getPidFilePath(&path_buf, filename) orelse return;
    std.fs.cwd().deleteFile(pid_path) catch {};
}

// ============================================================================
// Service Management (M20 #256) — install/uninstall for systemd/launchd/SCM
// ============================================================================

pub const ServiceScope = enum { user, system };

fn isRoot() bool {
    if (builtin.os.tag == .windows) return true; // SCM requires admin, but check via isAdmin later
    return std.c.getuid() == 0;
}

fn getExePath(allocator: std.mem.Allocator) ![]const u8 {
    // Try selfExePath, fallback to argv[0] via /proc/self/exe readlink is handled by Zig
    return try std.fs.selfExePathAlloc(allocator);
}

fn ensureDir(path: []const u8) !void {
    std.fs.cwd().makePath(path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn getHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (std.process.getEnvVarOwned(allocator, "HOME") catch null) |h| return h;
    return error.MissingHome;
}

// Systemd unit path for given scope
fn systemdUnitPath(allocator: std.mem.Allocator, scope: ServiceScope) ![]const u8 {
    if (scope == .system) {
        return try allocator.dupe(u8, "/etc/systemd/system/softether-vpnclient.service");
    } else {
        // --user: $XDG_CONFIG_HOME/systemd/user or $HOME/.config/systemd/user
        if (std.process.getEnvVarOwned(allocator, "XDG_CONFIG_HOME") catch null) |xdg| {
            defer allocator.free(xdg);
            return try std.fmt.allocPrint(allocator, "{s}/systemd/user/softether-vpnclient.service", .{xdg});
        } else {
            const home = try getHomeDir(allocator);
            defer allocator.free(home);
            return try std.fmt.allocPrint(allocator, "{s}/.config/systemd/user/softether-vpnclient.service", .{home});
        }
    }
}

fn launchdPlistPath(allocator: std.mem.Allocator, scope: ServiceScope) ![]const u8 {
    if (scope == .system) {
        // System LaunchDaemon requires root and is loaded at boot
        return try allocator.dupe(u8, "/Library/LaunchDaemons/com.devstroop.vpnclient.plist");
    } else {
        const home = try getHomeDir(allocator);
        defer allocator.free(home);
        return try std.fmt.allocPrint(allocator, "{s}/Library/LaunchAgents/com.devstroop.vpnclient.plist", .{home});
    }
}

pub fn installService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    const exe_path = try getExePath(allocator);
    defer allocator.free(exe_path);

    if (builtin.os.tag == .linux) {
        // Linux — systemd
        const unit_path = try systemdUnitPath(allocator, scope);
        defer allocator.free(unit_path);

        if (scope == .system and !isRoot()) {
            cli.display.failure(display, "install --system requires sudo (writes to /etc/systemd/system)", .{});
            return error.PermissionDenied;
        }

        // Ensure parent dir exists (for --user)
        if (scope == .user) {
            if (std.fs.path.dirname(unit_path)) |dir| {
                try ensureDir(dir);
            }
        }

        const wanted_by = if (scope == .system) "multi-user.target" else "default.target";
        const unit_content = if (scope == .system) try std.fmt.allocPrint(allocator,
            \\[Unit]
            \\Description=SoftEther VPN Client
            \\After=network.target
            \\Wants=network.target
            \\
            \\[Service]
            \\Type=simple
            \\ExecStart={s} connect
            \\Restart=on-failure
            \\RestartSec=5
            \\AmbientCapabilities=CAP_NET_ADMIN
            \\CapabilityBoundingSet=CAP_NET_ADMIN
            \\
            \\[Install]
            \\WantedBy={s}
            \\
        , .{ exe_path, wanted_by }) else try std.fmt.allocPrint(allocator,
            \\[Unit]
            \\Description=SoftEther VPN Client (user)
            \\After=network.target
            \\Wants=network.target
            \\
            \\[Service]
            \\Type=simple
            \\ExecStart={s} connect
            \\Restart=on-failure
            \\RestartSec=5
            \\
            \\[Install]
            \\WantedBy={s}
            \\
        , .{ exe_path, wanted_by });
        defer allocator.free(unit_content);

        // Write unit file (need root for /etc, so use createFile which will fail if not root — already checked)
        const dir = std.fs.path.dirname(unit_path) orelse ".";
        _ = dir; // already ensured for user
        var file = try std.fs.createFileAbsolute(unit_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(unit_content);

        cli.display.success(display, "Created {s}", .{unit_path});

        // daemon-reload + enable
        if (scope == .system) {
            runCommand(allocator, &.{ "systemctl", "daemon-reload" }) catch |err| {
                cli.display.warning(display, "systemctl daemon-reload failed: {s} (run manually)", .{@errorName(err)});
            };
            runCommand(allocator, &.{ "systemctl", "enable", "softether-vpnclient.service" }) catch |err| {
                cli.display.warning(display, "systemctl enable failed: {s} (run manually: sudo systemctl enable softether-vpnclient)", .{@errorName(err)});
            };
            cli.display.info(display, "Enabled systemd service (system). Use: sudo systemctl start softether-vpnclient", .{});
        } else {
            runCommand(allocator, &.{ "systemctl", "--user", "daemon-reload" }) catch |err| {
                cli.display.warning(display, "systemctl --user daemon-reload failed: {s}", .{@errorName(err)});
            };
            runCommand(allocator, &.{ "systemctl", "--user", "enable", "softether-vpnclient.service" }) catch |err| {
                cli.display.warning(display, "systemctl --user enable failed: {s} (run: systemctl --user enable softether-vpnclient)", .{@errorName(err)});
            };
            cli.display.info(display, "Enabled systemd service (user). Use: systemctl --user start softether-vpnclient", .{});
        }

        // Verify is-enabled
        if (scope == .system) {
            runCommand(allocator, &.{ "systemctl", "is-enabled", "softether-vpnclient.service" }) catch {};
        } else {
            runCommand(allocator, &.{ "systemctl", "--user", "is-enabled", "softether-vpnclient.service" }) catch {};
        }
    } else if (builtin.os.tag == .macos) {
        if (scope == .system and !isRoot()) {
            cli.display.failure(display, "install --system on macOS requires sudo (writes to /Library/LaunchDaemons)", .{});
            return error.PermissionDenied;
        }
        const plist_path = try launchdPlistPath(allocator, scope);
        defer allocator.free(plist_path);

        if (std.fs.path.dirname(plist_path)) |dir| {
            try ensureDir(dir);
        }

        const plist_content = try std.fmt.allocPrint(allocator,
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            \\<plist version="1.0">
            \\<dict>
            \\    <key>Label</key>
            \\    <string>com.devstroop.vpnclient</string>
            \\    <key>ProgramArguments</key>
            \\    <array>
            \\        <string>{s}</string>
            \\        <string>connect</string>
            \\    </array>
            \\    <key>RunAtLoad</key>
            \\    <true/>
            \\    <key>KeepAlive</key>
            \\    <true/>
            \\    <key>StandardOutPath</key>
            \\    <string>/tmp/softether-vpnclient.log</string>
            \\    <key>StandardErrorPath</key>
            \\    <string>/tmp/softether-vpnclient.log</string>
            \\</dict>
            \\</plist>
            \\
        , .{exe_path});
        defer allocator.free(plist_content);

        var file = try std.fs.createFileAbsolute(plist_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(plist_content);

        cli.display.success(display, "Created {s}", .{plist_path});
        if (scope == .system) {
            cli.display.info(display, "launchd system plist installed. Use: sudo launchctl bootstrap system {s}", .{plist_path});
            runCommand(allocator, &.{ "launchctl", "print", "system/com.devstroop.vpnclient" }) catch {};
        } else {
            cli.display.info(display, "launchd plist installed. Use: launchctl load {s}", .{plist_path});
            runCommand(allocator, &.{ "launchctl", "print", "gui/501/com.devstroop.vpnclient" }) catch {};
        }
    } else if (builtin.os.tag == .windows) {
        // Windows — SCM (Mayaqua/WinService.c pattern)
        // Use `sc create` as simplest parity; requires admin.
        const bin_path = try std.fmt.allocPrint(allocator, "\"{s}\" connect", .{exe_path});
        defer allocator.free(bin_path);
        cli.display.info(display, "Creating Windows service SoftEtherVPNClient...", .{});
        runCommand(allocator, &.{ "sc", "create", "SoftEtherVPNClient", "binPath=", bin_path, "start=", "auto", "DisplayName=", "SoftEther VPN Client" }) catch |err| {
            cli.display.failure(display, "sc create failed: {s} (run as Administrator)", .{@errorName(err)});
            return err;
        };
        cli.display.success(display, "Created Windows service SoftEtherVPNClient (SERVICE_AUTO_START)", .{});
        cli.display.info(display, "Use: sc start SoftEtherVPNClient", .{});
    } else {
        cli.display.failure(display, "Service install not supported on {s}", .{@tagName(builtin.os.tag)});
        return error.UnsupportedPlatform;
    }
}

pub fn uninstallService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const unit_path = try systemdUnitPath(allocator, scope);
        defer allocator.free(unit_path);

        if (scope == .system and !isRoot()) {
            cli.display.failure(display, "uninstall --system requires sudo", .{});
            return error.PermissionDenied;
        }

        // disable, delete, then reload (avoid stale)
        if (scope == .system) {
            runCommand(allocator, &.{ "systemctl", "disable", "softether-vpnclient.service" }) catch {};
            std.fs.deleteFileAbsolute(unit_path) catch |err| {
                if (err != error.FileNotFound) cli.display.warning(display, "Could not remove {s}: {s}", .{ unit_path, @errorName(err) });
            };
            runCommand(allocator, &.{ "systemctl", "daemon-reload" }) catch {};
        } else {
            runCommand(allocator, &.{ "systemctl", "--user", "disable", "softether-vpnclient.service" }) catch {};
            std.fs.deleteFileAbsolute(unit_path) catch |err| {
                if (err != error.FileNotFound) cli.display.warning(display, "Could not remove {s}: {s}", .{ unit_path, @errorName(err) });
            };
            runCommand(allocator, &.{ "systemctl", "--user", "daemon-reload" }) catch {};
        }
        cli.display.success(display, "Removed {s}", .{unit_path});
    } else if (builtin.os.tag == .macos) {
        if (scope == .system and !isRoot()) {
            cli.display.failure(display, "uninstall --system on macOS requires sudo", .{});
            return error.PermissionDenied;
        }
        const plist_path = try launchdPlistPath(allocator, scope);
        defer allocator.free(plist_path);
        // unload first (use bootout for system, unload for user)
        if (scope == .system) {
            runCommand(allocator, &.{ "launchctl", "bootout", "system/com.devstroop.vpnclient" }) catch {};
        } else {
            runCommand(allocator, &.{ "launchctl", "unload", plist_path }) catch {};
        }
        std.fs.deleteFileAbsolute(plist_path) catch |err| {
            if (err != error.FileNotFound) cli.display.warning(display, "Could not remove {s}: {s}", .{ plist_path, @errorName(err) });
        };
        cli.display.success(display, "Removed {s}", .{plist_path});
    } else if (builtin.os.tag == .windows) {
        runCommand(allocator, &.{ "sc", "stop", "SoftEtherVPNClient" }) catch {};
        runCommand(allocator, &.{ "sc", "delete", "SoftEtherVPNClient" }) catch |err| {
            cli.display.failure(display, "sc delete failed: {s}", .{@errorName(err)});
            return err;
        };
        cli.display.success(display, "Removed Windows service SoftEtherVPNClient", .{});
    } else {
        cli.display.failure(display, "Service uninstall not supported on {s}", .{@tagName(builtin.os.tag)});
        return error.UnsupportedPlatform;
    }
}

fn runSystemctl(allocator: std.mem.Allocator, args: []const []const u8, display: *cli.display.DisplayContext) !void {
    var child = std.process.Child.init(args, allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) {
            cli.display.warning(display, "systemctl {s} exited with {d}", .{ args[1], code });
            return error.CommandFailed;
        },
        else => return error.CommandFailed,
    }
}

fn launchdDomainTarget(allocator: std.mem.Allocator, scope: ServiceScope) ![]const u8 {
    if (scope == .system) {
        return try allocator.dupe(u8, "system/com.devstroop.vpnclient");
    } else {
        const uid = std.c.getuid();
        return try std.fmt.allocPrint(allocator, "gui/{d}/com.devstroop.vpnclient", .{uid});
    }
}

pub fn startService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const args = if (scope == .user)
            &[_][]const u8{ "systemctl", "--user", "start", "softether-vpnclient.service" }
        else
            &[_][]const u8{ "systemctl", "start", "softether-vpnclient.service" };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Started softether-vpnclient", .{});
    } else if (builtin.os.tag == .macos) {
        const target = try launchdDomainTarget(allocator, scope);
        defer allocator.free(target);
        // Try kickstart first; if not bootstrapped, bootstrap then kickstart
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "kickstart", "-k", target }, allocator);
        var term = try child.spawnAndWait();
        if (term == .Exited and term.Exited == 0) {
            cli.display.success(display, "Started softether-vpnclient", .{});
            return;
        }
        // Not bootstrapped — bootstrap the plist then kickstart
        const plist_path = try launchdPlistPath(allocator, scope);
        defer allocator.free(plist_path);
        const domain = if (scope == .system) "system" else blk: {
            const uid = std.c.getuid();
            break :blk try std.fmt.allocPrint(allocator, "gui/{d}", .{uid});
        };
        defer if (scope != .system) allocator.free(domain);
        var boot = std.process.Child.init(&[_][]const u8{ "launchctl", "bootstrap", domain, plist_path }, allocator);
        _ = try boot.spawnAndWait();
        var child2 = std.process.Child.init(&[_][]const u8{ "launchctl", "kickstart", "-k", target }, allocator);
        term = try child2.spawnAndWait();
        switch (term) {
            .Exited => |code| if (code != 0) return error.StartFailed,
            else => return error.StartFailed,
        }
        cli.display.success(display, "Started softether-vpnclient", .{});
    } else {
        return error.UnsupportedPlatform;
    }
}

pub fn stopService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const args = if (scope == .user)
            &[_][]const u8{ "systemctl", "--user", "stop", "softether-vpnclient.service" }
        else
            &[_][]const u8{ "systemctl", "stop", "softether-vpnclient.service" };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Stopped softether-vpnclient", .{});
    } else if (builtin.os.tag == .macos) {
        const target = try launchdDomainTarget(allocator, scope);
        defer allocator.free(target);
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "bootout", target }, allocator);
        const term = try child.spawnAndWait();
        switch (term) {
            .Exited => |code| if (code != 0) return error.StopFailed,
            else => return error.StopFailed,
        }
        cli.display.success(display, "Stopped softether-vpnclient", .{});
    } else {
        return error.UnsupportedPlatform;
    }
}

pub fn restartService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const args = if (scope == .user)
            &[_][]const u8{ "systemctl", "--user", "restart", "softether-vpnclient.service" }
        else
            &[_][]const u8{ "systemctl", "restart", "softether-vpnclient.service" };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Restarted softether-vpnclient", .{});
    } else if (builtin.os.tag == .macos) {
        try stopService(allocator, display, scope);
        try startService(allocator, display, scope);
    } else {
        return error.UnsupportedPlatform;
    }
}

pub fn statusService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const args = if (scope == .user)
            &[_][]const u8{ "systemctl", "--user", "is-active", "softether-vpnclient.service" }
        else
            &[_][]const u8{ "systemctl", "is-active", "softether-vpnclient.service" };
        var child = std.process.Child.init(args, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        try child.spawn();
        var out_buf: [256]u8 = undefined;
        var err_buf: [256]u8 = undefined;
        const n_out = child.stdout.?.read(&out_buf) catch 0;
        const n_err = child.stderr.?.read(&err_buf) catch 0;
        const term = try child.wait();
        const out_str = std.mem.trim(u8, out_buf[0..n_out], " \n\r\t");
        const err_str = std.mem.trim(u8, err_buf[0..n_err], " \n\r\t");
        switch (term) {
            .Exited => |code| {
                if (code == 0) {
                    cli.display.success(display, "softether-vpnclient is active ({s})", .{out_str});
                } else {
                    cli.display.info(display, "softether-vpnclient is inactive ({s}) {s}", .{ out_str, err_str });
                }
            },
            else => return error.StatusFailed,
        }
        const journal_args = if (scope == .user)
            &[_][]const u8{ "journalctl", "--user", "-u", "softether-vpnclient.service", "-n", "5", "--no-pager" }
        else
            &[_][]const u8{ "journalctl", "-u", "softether-vpnclient.service", "-n", "5", "--no-pager" };
        var j_child = std.process.Child.init(journal_args, allocator);
        j_child.stdout_behavior = .Inherit;
        j_child.stderr_behavior = .Inherit;
        _ = j_child.spawnAndWait() catch {};
    } else if (builtin.os.tag == .macos) {
        const target = try launchdDomainTarget(allocator, scope);
        defer allocator.free(target);
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "print", target }, allocator);
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        const term = try child.spawnAndWait();
        switch (term) {
            .Exited => |code| if (code != 0) return error.StatusFailed,
            else => return error.StatusFailed,
        }
    } else {
        return error.UnsupportedPlatform;
    }
}

pub fn enableService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const args = if (scope == .user)
            &[_][]const u8{ "systemctl", "--user", "enable", "softether-vpnclient.service" }
        else
            &[_][]const u8{ "systemctl", "enable", "softether-vpnclient.service" };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Enabled softether-vpnclient autostart", .{});
    } else if (builtin.os.tag == .macos) {
        cli.display.info(display, "launchd KeepAlive already enabled via plist", .{});
    } else {
        return error.UnsupportedPlatform;
    }
}

pub fn disableService(allocator: std.mem.Allocator, display: *cli.display.DisplayContext, scope: ServiceScope) !void {
    if (builtin.os.tag == .linux) {
        const args = if (scope == .user)
            &[_][]const u8{ "systemctl", "--user", "disable", "softether-vpnclient.service" }
        else
            &[_][]const u8{ "systemctl", "disable", "softether-vpnclient.service" };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Disabled softether-vpnclient autostart", .{});
    } else if (builtin.os.tag == .macos) {
        const target = try launchdDomainTarget(allocator, scope);
        defer allocator.free(target);
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "bootout", target }, allocator);
        const term = try child.spawnAndWait();
        switch (term) {
            .Exited => |code| if (code != 0) return error.DisableFailed,
            else => return error.DisableFailed,
        }
        cli.display.success(display, "Disabled softether-vpnclient", .{});
    } else {
        return error.UnsupportedPlatform;
    }
}

// ============================================================================
// Connection Progress Display (S-040)
// ============================================================================

const ConnectPhase = struct {
    name: []const u8,
    number: u8,
    total: u8,
};

fn stateToPhase(state: client.ClientState) ?ConnectPhase {
    return switch (state) {
        .connecting_tcp => .{ .name = "Connecting", .number = 1, .total = 6 },
        .ssl_handshake => .{ .name = "TLS Handshake", .number = 2, .total = 6 },
        .authenticating => .{ .name = "Authenticating", .number = 3, .total = 6 },
        .establishing_session => .{ .name = "Establishing Session", .number = 4, .total = 6 },
        .configuring_adapter => .{ .name = "Configuring Network", .number = 5, .total = 6 },
        .connected => .{ .name = "Connected", .number = 6, .total = 6 },
        else => null,
    };
}

fn showConnectProgress(display_ctx: *cli.display.DisplayContext, vpn: *client.VpnClient) void {
    var spinner = cli.display.Spinner.init("Connecting...");
    var last_state: client.ClientState = .disconnected;
    var msg_buf: [128]u8 = undefined;

    // Poll state changes during connect
    while (vpn.isConnecting()) {
        const current_state = vpn.getState();
        if (current_state != last_state) {
            if (stateToPhase(current_state)) |phase| {
                const msg = std.fmt.bufPrint(&msg_buf, "{s} ({d}/{d})", .{
                    phase.name,
                    phase.number,
                    phase.total,
                }) catch phase.name;

                spinner.message = msg;
            }
            last_state = current_state;
        }
        spinner.render(display_ctx);
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Show final result
    if (vpn.isConnected()) {
        spinner.finish(display_ctx, true);
        cli.display.success(display_ctx, "Connected successfully!", .{});

        // Show connection info
        const ip = vpn.getAssignedIp();
        const gw = vpn.getGatewayIp();
        if (ip != 0) {
            var ip_buf: [16]u8 = undefined;
            cli.display.info(display_ctx, "  VPN IP:   {s}", .{cli.display.formatIpv4(ip, &ip_buf)});
        }
        if (gw != 0) {
            var gw_buf: [16]u8 = undefined;
            cli.display.info(display_ctx, "  Gateway:  {s}", .{cli.display.formatIpv4(gw, &gw_buf)});
        }
    } else {
        spinner.finish(display_ctx, false);
    }
}

// ============================================================================
// Daemon Entry Point
// ============================================================================

/// Run the VPN client in daemon mode
pub fn run(state: *AppState) !void {
    cli.display.info(&state.display, "Running in daemon mode...", .{});

    // Write PID file (S-038)
    if (!writePidFile(&state.display, pid_filename)) {
        state.setExitCode(1);
        return;
    }
    defer removePidFile(pid_filename);

    // Create VPN client
    const config = config_mod.buildClientConfig(&state.cli_args) catch |err| {
        cli.display.failure(&state.display, "Invalid configuration: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

    const vpn = try state.allocator.create(client.VpnClient);
    vpn.* = client.VpnClient.init(state.allocator, config);
    state.setVpnClient(vpn);

    // Set event callback
    vpn.setEventCallback(events_mod.handleVpnEvent, state);

    // Connect with progress display (S-040)
    cli.display.info(&state.display, "Connecting to {s}:{d}...", .{ config.server_hostname orelse config.server_address, config.server_port });

    // Spawn connect in a thread so we can show progress
    const connect_thread = std.Thread.spawn(.{}, struct {
        fn doConnect(v: *client.VpnClient) void {
            v.connect() catch {};
        }
    }.doConnect, .{vpn}) catch |err| {
        cli.display.failure(&state.display, "Failed to start connect thread: {s}", .{@errorName(err)});
        state.setExitCode(1);
        return;
    };

    // Show animated progress while connecting
    showConnectProgress(&state.display, vpn);
    connect_thread.join();

    if (!vpn.isConnected()) {
        cli.display.failure(&state.display, "Connection failed", .{});
        state.setExitCode(1);
        return;
    }

    // NOTE: do NOT spawn a data loop here. connect() already runs the data loop
    // on its own thread (VpnClient.connect → runDataLoopThread). Spawning a
    // second runDataLoop ran TWO loops on the SAME TLS sockets → concurrent
    // SSL_write → "bad write retry" → BrokenPipe → the session died in seconds.
    // disconnect() (in cleanup below) joins the connect-spawned loop thread.

    // Main loop - wait for signals
    while (state.isRunning()) {
        if (vpn.isConnected()) {
            // Update stats periodically
            const stats = vpn.getStats();
            if (stats.connected_duration_ms > 0 and stats.connected_duration_ms % 60000 < 1000) {
                var sent_buf: [32]u8 = undefined;
                var recv_buf: [32]u8 = undefined;
                cli.display.debug(&state.display, "Traffic: ↑{s} ↓{s}", .{
                    cli.display.formatBytes(stats.bytes_sent, &sent_buf),
                    cli.display.formatBytes(stats.bytes_received, &recv_buf),
                });
            }
        } else if (!vpn.isConnecting()) {
            // Disconnected unexpectedly
            if (config.reconnect.enabled and state.isRunning()) {
                cli.display.warning(&state.display, "Connection lost, reconnecting...", .{});
                vpn.reconnect() catch {
                    std.Thread.sleep(1 * std.time.ns_per_s);
                };
            } else {
                state.stop();
            }
        }

        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Cleanup
    cli.display.info(&state.display, "Shutting down...", .{});

    // Signal stop first (doesn't free resources yet)
    vpn.requestStop();

    // disconnect() joins the connect-spawned data loop thread and frees resources.
    vpn.disconnect() catch {};
}

test "service install/uninstall user creates and removes unit" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const tmp_path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);

    const old_xdg = std.posix.getenv("XDG_CONFIG_HOME");
    try std.posix.setenv("XDG_CONFIG_HOME", tmp_path);
    defer {
        if (old_xdg) |v| std.posix.setenv("XDG_CONFIG_HOME", v) catch {} else std.posix.unsetenv("XDG_CONFIG_HOME") catch {};
    }

    var ctx = cli.display.DisplayContext.initNull();
    const alloc = std.testing.allocator;

    try installService(alloc, &ctx, .user);
    const unit_path = try std.fmt.allocPrint(alloc, "{s}/systemd/user/softether-vpnclient.service", .{tmp_path});
    defer alloc.free(unit_path);
    _ = std.fs.cwd().openFile(unit_path, .{}) catch |err| {
        std.debug.print("unit not found at {s}: {}\n", .{ unit_path, err });
        return err;
    };

    try statusService(alloc, &ctx, .user);

    try uninstallService(alloc, &ctx, .user);
    if (std.fs.cwd().openFile(unit_path, .{})) |f| {
        f.close();
        return error.FileStillExists;
    } else {}
}

test "service install requires sudo for --system without root" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (std.c.getuid() == 0) return error.SkipZigTest;
    var ctx = cli.display.DisplayContext.initNull();
    const err = installService(std.testing.allocator, &ctx, .system) catch |e| e;
    try std.testing.expectEqual(error.PermissionDenied, err);
}
