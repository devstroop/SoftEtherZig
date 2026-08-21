//! vpn_client.config store — vpncmd owns profiles, no external JSON (M21 #262)
//!
//! XDG `vpn_client.config` Cfg binary (text format via `src/cedar/server/config/cfg.zig`
//! declare tree, Cfg.c parity, not hand-edited JSON). No import/export.
//! `vpncmd client AccountCreate` creates `vpn_client.config` and `vpnclient
//! connect` without flags can discover it (M21-3 #263).
//!
//! Structure (text Cfg):
//!   declare ClientConfig
//!   {
//!     declare Accounts
//!     {
//!       declare vpn1
//!       {
//!         string Server 203.0.113.10
//!         uint Port 443
//!         string Hub VPN
//!         string Username testuser
//!         string PasswordHash <base64 SHA-0>  // optional, via AccountPasswordSet
//!       }
//!     }
//!   }

const std = @import("std");
const cfg_mod = @import("../cedar/server/config/cfg.zig");

const Cfg = cfg_mod.Cfg;
const Folder = cfg_mod.Folder;

const store_filename = "vpn_client.config";
const store_subdir = "softether-zig";

/// Resolve XDG store path: $XDG_CONFIG_HOME/softether-zig/vpn_client.config
/// or $HOME/.config/softether-zig/vpn_client.config
pub fn getStorePath(allocator: std.mem.Allocator) ![]const u8 {
    if (std.process.getEnvVarOwned(allocator, "XDG_CONFIG_HOME") catch null) |xdg| {
        defer allocator.free(xdg);
        return try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ xdg, store_subdir, store_filename });
    } else {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch return error.MissingHome;
        defer allocator.free(home);
        return try std.fmt.allocPrint(allocator, "{s}/.config/{s}/{s}", .{ home, store_subdir, store_filename });
    }
}

pub fn getStoreDir(allocator: std.mem.Allocator) ![]const u8 {
    const path = try getStorePath(allocator);
    defer allocator.free(path);
    const dir = std.fs.path.dirname(path) orelse return error.InvalidPath;
    return try allocator.dupe(u8, dir);
}

fn ensureStoreDir(allocator: std.mem.Allocator) !void {
    const dir_path = try getStoreDir(allocator);
    defer allocator.free(dir_path);
    std.fs.cwd().makePath(dir_path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
}

/// Account fields for M21 12-field matrix (minimal)
pub const Account = struct {
    name: []const u8,
    server: []const u8,
    port: u16 = 443,
    hub: []const u8,
    username: []const u8,
    password_hash: ?[]const u8 = null,
};

fn getAccountsFolder(cfg: *Cfg) !*Folder {
    const root = cfg.root;
    const client_cfg = try root.addFolder("ClientConfig");
    const accounts = try client_cfg.addFolder("Accounts");
    return accounts;
}

fn lockStoreFile(file: std.fs.File) !void {
    // Use flock for interprocess serialization (best-effort, ignore if not supported)
    std.posix.flock(file.handle, std.posix.LOCK.EX) catch {};
}

fn unlockStoreFile(file: std.fs.File) void {
    std.posix.flock(file.handle, std.posix.LOCK.UN) catch {};
}

pub fn loadCfg(allocator: std.mem.Allocator) !*Cfg {
    const store_path = try getStorePath(allocator);
    defer allocator.free(store_path);
    const dir = std.fs.path.dirname(store_path) orelse return error.InvalidPath;
    const file = std.fs.path.basename(store_path);

    // Try to load existing; if not found, create new
    var dir_handle = std.fs.cwd().openDir(dir, .{}) catch |err| {
        if (err == error.FileNotFound) {
            try ensureStoreDir(allocator);
            return try Cfg.init(allocator);
        }
        return err;
    };
    defer dir_handle.close();

    const cfg = Cfg.loadFromFile(allocator, dir_handle, file) catch |err| {
        if (err == error.FileNotFound) {
            return try Cfg.init(allocator);
        }
        return err;
    };
    return cfg;
}

pub fn saveCfg(allocator: std.mem.Allocator, cfg: *Cfg) !void {
    const store_path = try getStorePath(allocator);
    defer allocator.free(store_path);
    const dir = std.fs.path.dirname(store_path) orelse return error.InvalidPath;
    const file = std.fs.path.basename(store_path);
    try ensureStoreDir(allocator);
    var dir_handle = try std.fs.cwd().openDir(dir, .{});
    defer dir_handle.close();
    // Serialize mutations with interprocess lock (M21 #262 race)
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{file});
    defer allocator.free(lock_path);
    const lock_file = dir_handle.createFile(lock_path, .{ .truncate = false }) catch dir_handle.openFile(lock_path, .{}) catch null;
    if (lock_file) |lf| {
        defer lf.close();
        try lockStoreFile(lf);
        defer unlockStoreFile(lf);
        try cfg.saveToFile(dir_handle, file);
    } else {
        try cfg.saveToFile(dir_handle, file);
    }
}

fn withStoreLock(allocator: std.mem.Allocator, comptime doFn: fn (*Cfg) anyerror!void) !void {
    const store_path = try getStorePath(allocator);
    defer allocator.free(store_path);
    const dir = std.fs.path.dirname(store_path) orelse return error.InvalidPath;
    const file = std.fs.path.basename(store_path);
    try ensureStoreDir(allocator);
    var dir_handle = try std.fs.cwd().openDir(dir, .{});
    defer dir_handle.close();
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{file});
    defer allocator.free(lock_path);
    const lock_file = try dir_handle.createFile(lock_path, .{ .truncate = false });
    defer lock_file.close();
    try lockStoreFile(lock_file);
    defer unlockStoreFile(lock_file);
    const cfg = try loadCfg(allocator);
    defer cfg.deinit();
    try doFn(cfg);
    // Re-open dir_handle for save (already locked)
    var save_dir = try std.fs.cwd().openDir(dir, .{});
    defer save_dir.close();
    try cfg.saveToFile(save_dir, file);
}

/// Create or update an account (atomic, locked, single transaction)
pub fn createAccount(allocator: std.mem.Allocator, acc: Account) !void {
    const store_path = try getStorePath(allocator);
    defer allocator.free(store_path);
    const dir = std.fs.path.dirname(store_path) orelse return error.InvalidPath;
    const file = std.fs.path.basename(store_path);
    try ensureStoreDir(allocator);
    var dir_handle = try std.fs.cwd().openDir(dir, .{});
    defer dir_handle.close();
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{file});
    defer allocator.free(lock_path);
    const lock_file = try dir_handle.createFile(lock_path, .{ .truncate = false });
    defer lock_file.close();
    try lockStoreFile(lock_file);
    defer unlockStoreFile(lock_file);
    const cfg = try loadCfg(allocator);
    defer cfg.deinit();
    const accounts = try getAccountsFolder(cfg);
    const folder = try accounts.addFolder(acc.name);
    try folder.setStr("Server", acc.server);
    try folder.setUint("Port", acc.port);
    try folder.setStr("Hub", acc.hub);
    try folder.setStr("Username", acc.username);
    if (acc.password_hash) |h| try folder.setStr("PasswordHash", h);
    var save_dir = try std.fs.cwd().openDir(dir, .{});
    defer save_dir.close();
    try cfg.saveToFile(save_dir, file);
}

pub fn deleteAccount(allocator: std.mem.Allocator, name: []const u8) !void {
    const store_path = try getStorePath(allocator);
    defer allocator.free(store_path);
    const dir = std.fs.path.dirname(store_path) orelse return error.InvalidPath;
    const file = std.fs.path.basename(store_path);
    try ensureStoreDir(allocator);
    var dir_handle = try std.fs.cwd().openDir(dir, .{});
    defer dir_handle.close();
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{file});
    defer allocator.free(lock_path);
    const lock_file = try dir_handle.createFile(lock_path, .{ .truncate = false });
    defer lock_file.close();
    try lockStoreFile(lock_file);
    defer unlockStoreFile(lock_file);
    const cfg = try loadCfg(allocator);
    defer cfg.deinit();
    const accounts = try getAccountsFolder(cfg);
    var idx: ?usize = null;
    for (accounts.folders.items, 0..) |f, i| {
        if (std.mem.eql(u8, f.name, name)) {
            idx = i;
            break;
        }
    }
    if (idx) |i| {
        const folder = accounts.folders.orderedRemove(i);
        folder.deinit();
        var save_dir = try std.fs.cwd().openDir(dir, .{});
        defer save_dir.close();
        try cfg.saveToFile(save_dir, file);
    } else return error.AccountNotFound;
}

pub fn setPasswordHash(allocator: std.mem.Allocator, name: []const u8, hash: []const u8) !void {
    const store_path = try getStorePath(allocator);
    defer allocator.free(store_path);
    const dir = std.fs.path.dirname(store_path) orelse return error.InvalidPath;
    const file = std.fs.path.basename(store_path);
    try ensureStoreDir(allocator);
    var dir_handle = try std.fs.cwd().openDir(dir, .{});
    defer dir_handle.close();
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{file});
    defer allocator.free(lock_path);
    const lock_file = try dir_handle.createFile(lock_path, .{ .truncate = false });
    defer lock_file.close();
    try lockStoreFile(lock_file);
    defer unlockStoreFile(lock_file);
    const cfg = try loadCfg(allocator);
    defer cfg.deinit();
    const accounts = try getAccountsFolder(cfg);
    const folder = accounts.getFolder(name) orelse return error.AccountNotFound;
    try folder.setStr("PasswordHash", hash);
    var save_dir = try std.fs.cwd().openDir(dir, .{});
    defer save_dir.close();
    try cfg.saveToFile(save_dir, file);
}

pub fn listAccounts(allocator: std.mem.Allocator) ![][]const u8 {
    const cfg = try loadCfg(allocator);
    defer cfg.deinit();
    const accounts = try getAccountsFolder(cfg);
    var list = std.ArrayListUnmanaged([]const u8){};
    for (accounts.folders.items) |f| {
        try list.append(allocator, try allocator.dupe(u8, f.name));
    }
    return try list.toOwnedSlice(allocator);
}

pub fn getAccount(allocator: std.mem.Allocator, name: []const u8) !?Account {
    const cfg = try loadCfg(allocator);
    defer cfg.deinit();
    const accounts = try getAccountsFolder(cfg);
    const folder = accounts.getFolder(name) orelse return null;
    const server = folder.getStr("Server", "");
    if (server.len == 0) return null;
    return Account{
        .name = try allocator.dupe(u8, name),
        .server = try allocator.dupe(u8, folder.getStr("Server", "")),
        .port = @intCast(folder.getUint("Port", 443)),
        .hub = try allocator.dupe(u8, folder.getStr("Hub", "")),
        .username = try allocator.dupe(u8, folder.getStr("Username", "")),
        .password_hash = if (folder.getItem("PasswordHash")) |it| switch (it.value) {
            .string => |s| try allocator.dupe(u8, s),
            else => null,
        } else null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "vpn_client_store create/list/delete" {
    // Use tmp XDG
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);
    const old = std.posix.getenv("XDG_CONFIG_HOME");
    try std.posix.setenv("XDG_CONFIG_HOME", tmp_path);
    defer {
        if (old) |v| std.posix.setenv("XDG_CONFIG_HOME", v) catch {} else std.posix.unsetenv("XDG_CONFIG_HOME") catch {};
    }
    const alloc = std.testing.allocator;
    try createAccount(alloc, .{ .name = "vpn1", .server = "203.0.113.10", .port = 443, .hub = "VPN", .username = "testuser" });
    const list = try listAccounts(alloc);
    defer {
        for (list) |n| alloc.free(n);
        alloc.free(list);
    }
    try std.testing.expectEqual(@as(usize, 1), list.len);
    try std.testing.expectEqualStrings("vpn1", list[0]);
    const acc = try getAccount(alloc, "vpn1");
    try std.testing.expect(acc != null);
    if (acc) |a| {
        defer alloc.free(a.name);
        defer alloc.free(a.server);
        defer alloc.free(a.hub);
        defer alloc.free(a.username);
        defer if (a.password_hash) |h| alloc.free(h);
        try std.testing.expectEqualStrings("203.0.113.10", a.server);
    }
    try setPasswordHash(alloc, "vpn1", "Z8aeAfh8/a88naS5l/Uxf9ig+cM=");
    const acc2 = try getAccount(alloc, "vpn1");
    try std.testing.expect(acc2 != null);
    if (acc2) |a| {
        defer alloc.free(a.name);
        defer alloc.free(a.server);
        defer alloc.free(a.hub);
        defer alloc.free(a.username);
        defer if (a.password_hash) |h| alloc.free(h);
        try std.testing.expectEqualStrings("Z8aeAfh8/a88naS5l/Uxf9ig+cM=", a.password_hash.?);
    }
    try deleteAccount(alloc, "vpn1");
    const list2 = try listAccounts(alloc);
    defer {
        for (list2) |n| alloc.free(n);
        alloc.free(list2);
    }
    try std.testing.expectEqual(@as(usize, 0), list2.len);
}
