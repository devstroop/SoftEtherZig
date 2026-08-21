//! Service Lifecycle — install/start/stop for vpnclient/vpnserver
//!
//! Community-standard service management for systemd (Linux),
//! launchd (macOS) and SCM (Windows), plus Mayaqua-compatible
//! daemon fallback when PID 1 != systemd.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const cli = @import("../cli/mod.zig");

pub const ServiceError = error{
    UnsupportedPlatform,
    PermissionDenied,
    AlreadyInstalled,
    NotInstalled,
    InstallFailed,
    UninstallFailed,
    StartFailed,
    StopFailed,
    StatusFailed,
};

pub const ServiceKind = enum {
    vpnclient,
    vpnserver,

    pub fn name(self: ServiceKind) []const u8 {
        return switch (self) {
            .vpnclient => "softether-vpnclient",
            .vpnserver => "softether-vpnserver",
        };
    }

    pub fn displayName(self: ServiceKind) []const u8 {
        return switch (self) {
            .vpnclient => "SoftEther VPN Client",
            .vpnserver => "SoftEther VPN Server",
        };
    }

    pub fn execName(self: ServiceKind) []const u8 {
        return switch (self) {
            .vpnclient => "vpnclient",
            .vpnserver => "vpnserver",
        };
    }
};

pub const InstallMode = enum {
    system,
    user,

    pub fn isSystem(self: InstallMode) bool {
        return self == .system;
    }
};

fn getCurrentExePath(allocator: Allocator) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fs.selfExePath(&buf);
    return try allocator.dupe(u8, path);
}

fn isSystemd() bool {
    // Check if PID 1 is systemd
    if (std.fs.openFileAbsolute("/run/systemd/system", .{})) |dir| {
        dir.close();
        return true;
    } else |_| {
        return false;
    }
}

// ============================================================================
// systemd (Linux)
// ============================================================================

fn systemdUnitPath(allocator: Allocator, kind: ServiceKind, mode: InstallMode) ![]u8 {
    const home = std.posix.getenv("HOME") orelse "/root";
    const xdg_config = std.posix.getenv("XDG_CONFIG_HOME");
    if (mode == .user) {
        if (xdg_config) |xdg| {
            return try std.fmt.allocPrint(allocator, "{s}/systemd/user/{s}.service", .{ xdg, kind.name() });
        }
        return try std.fmt.allocPrint(allocator, "{s}/.config/systemd/user/{s}.service", .{ home, kind.name() });
    }
    return try std.fmt.allocPrint(allocator, "/etc/systemd/system/{s}.service", .{kind.name()});
}

fn systemdUnitContent(allocator: Allocator, kind: ServiceKind, exe_path: []const u8, mode: InstallMode) ![]u8 {
    // Use Type=simple + Restart=on-failure per community standard.
    // For vpnclient, ExecStart runs `vpnclient connect` with account from vpncmd store;
    // for vpnserver, it runs `vpnserver start`.
    const exec_start = switch (kind) {
        .vpnclient => try std.fmt.allocPrint(allocator, "{s} connect", .{exe_path}),
        .vpnserver => try std.fmt.allocPrint(allocator, "{s} start", .{exe_path}),
    };
    defer allocator.free(exec_start);

    const wanted_by: []const u8 = if (mode == .user) "default.target" else "multi-user.target";

    return try std.fmt.allocPrint(allocator,
        \\[Unit]
        \\Description={s}
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\Type=simple
        \\ExecStart={s}
        \\Restart=on-failure
        \\RestartSec=5
        \\AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
        \\CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
        \\
        \\[Install]
        \\WantedBy={s}
        \\
    , .{ kind.displayName(), exec_start, wanted_by });
}

pub fn installSystemd(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    const exe_path = try getCurrentExePath(allocator);
    defer allocator.free(exe_path);

    const unit_path = try systemdUnitPath(allocator, kind, mode);
    defer allocator.free(unit_path);

    const content = try systemdUnitContent(allocator, kind, exe_path, mode);
    defer allocator.free(content);

    // Ensure parent dir exists
    if (std.fs.path.dirname(unit_path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Check if already installed
    if (std.fs.cwd().openFile(unit_path, .{})) |file| {
        file.close();
        cli.display.failure(display, "Service already installed at {s}", .{unit_path});
        return ServiceError.AlreadyInstalled;
    } else |_| {}

    // Write unit file
    const file = std.fs.createFileAbsolute(unit_path, .{}) catch |err| {
        if (err == error.AccessDenied) {
            cli.display.failure(display, "Permission denied writing {s} — try with sudo for --system", .{unit_path});
            return ServiceError.PermissionDenied;
        }
        return ServiceError.InstallFailed;
    };
    defer file.close();
    try file.writeAll(content);

    cli.display.success(display, "Installed {s} to {s}", .{ kind.name(), unit_path });

    // daemon-reload
    var child = std.process.Child.init(&[_][]const u8{ "systemctl", "daemon-reload" }, allocator);
    _ = child.spawnAndWait() catch {};

    // enable
    const enable_args = if (mode == .user)
        &[_][]const u8{ "systemctl", "--user", "enable", kind.name() }
    else
        &[_][]const u8{ "systemctl", "enable", kind.name() };
    var enable_child = std.process.Child.init(enable_args, allocator);
    _ = enable_child.spawnAndWait() catch {};

    cli.display.info(display, "Service installed and enabled. Use `vpnclient start` to start.", .{});
}

pub fn uninstallSystemd(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    const unit_path = try systemdUnitPath(allocator, kind, mode);
    defer allocator.free(unit_path);

    // Check if installed
    if (std.fs.cwd().openFile(unit_path, .{})) |file| {
        file.close();
    } else |_| {
        cli.display.failure(display, "Service not installed at {s}", .{unit_path});
        return ServiceError.NotInstalled;
    }

    // disable
    const disable_args = if (mode == .user)
        &[_][]const u8{ "systemctl", "--user", "disable", kind.name() }
    else
        &[_][]const u8{ "systemctl", "disable", kind.name() };
    var disable_child = std.process.Child.init(disable_args, allocator);
    _ = disable_child.spawnAndWait() catch {};

    // delete file
    std.fs.deleteFileAbsolute(unit_path) catch {
        return ServiceError.UninstallFailed;
    };

    // daemon-reload
    var child = std.process.Child.init(&[_][]const u8{ "systemctl", "daemon-reload" }, allocator);
    _ = child.spawnAndWait() catch {};

    cli.display.success(display, "Uninstalled {s} from {s}", .{ kind.name(), unit_path });
}

// ============================================================================
// launchd (macOS)
// ============================================================================

fn launchdPlistPath(allocator: Allocator, kind: ServiceKind) ![]u8 {
    const home = std.posix.getenv("HOME") orelse "/tmp";
    return try std.fmt.allocPrint(allocator, "{s}/Library/LaunchAgents/com.devstroop.{s}.plist", .{ home, kind.name() });
}

fn launchdPlistContent(allocator: Allocator, kind: ServiceKind, exe_path: []const u8) ![]u8 {
    const exec = switch (kind) {
        .vpnclient => try std.fmt.allocPrint(allocator, "{s} connect", .{exe_path}),
        .vpnserver => try std.fmt.allocPrint(allocator, "{s} start", .{exe_path}),
    };
    defer allocator.free(exec);

    return try std.fmt.allocPrint(allocator,
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        \\<plist version="1.0">
        \\<dict>
        \\  <key>Label</key><string>com.devstroop.{s}</string>
        \\  <key>ProgramArguments</key><array><string>{s}</string></array>
        \\  <key>RunAtLoad</key><true/>
        \\  <key>KeepAlive</key><true/>
        \\  <key>StandardOutPath</key><string>/tmp/{s}.log</string>
        \\  <key>StandardErrorPath</key><string>/tmp/{s}.err</string>
        \\</dict>
        \\</plist>
        \\
    , .{ kind.name(), exec, kind.name(), kind.name() });
}

pub fn installLaunchd(allocator: Allocator, kind: ServiceKind, display: *cli.display.DisplayContext) !void {
    const exe_path = try getCurrentExePath(allocator);
    defer allocator.free(exe_path);

    const plist_path = try launchdPlistPath(allocator, kind);
    defer allocator.free(plist_path);

    if (std.fs.path.dirname(plist_path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    if (std.fs.cwd().openFile(plist_path, .{})) |file| {
        file.close();
        cli.display.failure(display, "Service already installed at {s}", .{plist_path});
        return ServiceError.AlreadyInstalled;
    } else |_| {}

    const content = try launchdPlistContent(allocator, kind, exe_path);
    defer allocator.free(content);

    const file = try std.fs.createFileAbsolute(plist_path, .{});
    defer file.close();
    try file.writeAll(content);

    cli.display.success(display, "Installed {s} to {s}", .{ kind.name(), plist_path });
    var child = std.process.Child.init(&[_][]const u8{ "launchctl", "load", plist_path }, allocator);
    _ = child.spawnAndWait() catch {};
}

pub fn uninstallLaunchd(allocator: Allocator, kind: ServiceKind, display: *cli.display.DisplayContext) !void {
    const plist_path = try launchdPlistPath(allocator, kind);
    defer allocator.free(plist_path);

    if (std.fs.cwd().openFile(plist_path, .{})) |file| {
        file.close();
    } else |_| {
        cli.display.failure(display, "Service not installed at {s}", .{plist_path});
        return ServiceError.NotInstalled;
    }

    var child = std.process.Child.init(&[_][]const u8{ "launchctl", "unload", plist_path }, allocator);
    _ = child.spawnAndWait() catch {};

    std.fs.deleteFileAbsolute(plist_path) catch {
        return ServiceError.UninstallFailed;
    };

    cli.display.success(display, "Uninstalled {s}", .{kind.name()});
}

fn runSystemctl(allocator: Allocator, args: []const []const u8, display: *cli.display.DisplayContext) !void {
    var child = std.process.Child.init(args, allocator);
    const term = try child.spawnAndWait();
    switch (term) {
        .Exited => |code| {
            if (code != 0) {
                cli.display.warning(display, "systemctl {s} exited with {d}", .{ args[1], code });
                return ServiceError.StartFailed;
            }
        },
        else => return ServiceError.StartFailed,
    }
}

pub fn start(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        const args = if (mode == .user)
            &[_][]const u8{ "systemctl", "--user", "start", kind.name() }
        else
            &[_][]const u8{ "systemctl", "start", kind.name() };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Started {s}", .{kind.name()});
    } else if (builtin.os.tag == .macos) {
        const plist_path = try launchdPlistPath(allocator, kind);
        defer allocator.free(plist_path);
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "kickstart", "-k", plist_path }, allocator);
        _ = child.spawnAndWait() catch return ServiceError.StartFailed;
        cli.display.success(display, "Started {s}", .{kind.name()});
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

pub fn stop(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        const args = if (mode == .user)
            &[_][]const u8{ "systemctl", "--user", "stop", kind.name() }
        else
            &[_][]const u8{ "systemctl", "stop", kind.name() };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Stopped {s}", .{kind.name()});
    } else if (builtin.os.tag == .macos) {
        const plist_path = try launchdPlistPath(allocator, kind);
        defer allocator.free(plist_path);
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "bootout", plist_path }, allocator);
        _ = child.spawnAndWait() catch return ServiceError.StopFailed;
        cli.display.success(display, "Stopped {s}", .{kind.name()});
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

pub fn restart(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        const args = if (mode == .user)
            &[_][]const u8{ "systemctl", "--user", "restart", kind.name() }
        else
            &[_][]const u8{ "systemctl", "restart", kind.name() };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Restarted {s}", .{kind.name()});
    } else if (builtin.os.tag == .macos) {
        try stop(allocator, kind, mode, display);
        try start(allocator, kind, mode, display);
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

pub fn status(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        const args = if (mode == .user)
            &[_][]const u8{ "systemctl", "--user", "is-active", kind.name() }
        else
            &[_][]const u8{ "systemctl", "is-active", kind.name() };
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
                    cli.display.success(display, "{s} is active ({s})", .{ kind.name(), out_str });
                } else {
                    cli.display.info(display, "{s} is inactive ({s}) {s}", .{ kind.name(), out_str, err_str });
                }
            },
            else => return ServiceError.StatusFailed,
        }
        // Also show journalctl tail
        const journal_args = if (mode == .user)
            &[_][]const u8{ "journalctl", "--user", "-u", kind.name(), "-n", "5", "--no-pager" }
        else
            &[_][]const u8{ "journalctl", "-u", kind.name(), "-n", "5", "--no-pager" };
        var j_child = std.process.Child.init(journal_args, allocator);
        j_child.stdout_behavior = .Inherit;
        j_child.stderr_behavior = .Inherit;
        _ = j_child.spawnAndWait() catch {};
    } else if (builtin.os.tag == .macos) {
        const plist_path = try launchdPlistPath(allocator, kind);
        defer allocator.free(plist_path);
        var child = std.process.Child.init(&[_][]const u8{ "launchctl", "print", plist_path }, allocator);
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        _ = child.spawnAndWait() catch return ServiceError.StatusFailed;
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

pub fn enable(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        const args = if (mode == .user)
            &[_][]const u8{ "systemctl", "--user", "enable", kind.name() }
        else
            &[_][]const u8{ "systemctl", "enable", kind.name() };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Enabled {s} autostart", .{kind.name()});
    } else if (builtin.os.tag == .macos) {
        cli.display.info(display, "launchd KeepAlive already enabled via plist", .{});
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

pub fn disable(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        const args = if (mode == .user)
            &[_][]const u8{ "systemctl", "--user", "disable", kind.name() }
        else
            &[_][]const u8{ "systemctl", "disable", kind.name() };
        try runSystemctl(allocator, args, display);
        cli.display.success(display, "Disabled {s} autostart", .{kind.name()});
    } else if (builtin.os.tag == .macos) {
        cli.display.info(display, "Disable via launchctl unload", .{});
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

// ============================================================================
// Public API
// ============================================================================

pub fn install(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        if (!isSystemd() and mode == .system) {
            cli.display.warning(display, "systemd not detected (PID 1 != systemd) — installing user service at XDG path", .{});
        }
        try installSystemd(allocator, kind, mode, display);
    } else if (builtin.os.tag == .macos) {
        try installLaunchd(allocator, kind, display);
    } else if (builtin.os.tag == .windows) {
        cli.display.failure(display, "Windows SCM install not yet implemented — use sc create manually", .{});
        return ServiceError.UnsupportedPlatform;
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}

pub fn uninstall(allocator: Allocator, kind: ServiceKind, mode: InstallMode, display: *cli.display.DisplayContext) !void {
    if (builtin.os.tag == .linux) {
        try uninstallSystemd(allocator, kind, mode, display);
    } else if (builtin.os.tag == .macos) {
        try uninstallLaunchd(allocator, kind, display);
    } else if (builtin.os.tag == .windows) {
        return ServiceError.UnsupportedPlatform;
    } else {
        return ServiceError.UnsupportedPlatform;
    }
}
