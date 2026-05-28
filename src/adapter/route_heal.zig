// SoftEther VPN Client - Route Healing
// Auto-repairs stale routes pointing through vanished utun interfaces.
//
// #9: On EADDRNOTAVAIL during TCP connect, deletes the stale host route and retries.
// #10: On startup, scans the routing table for routes via dead utunN and removes them.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Result of a stale-route scan
pub const StaleRoute = struct {
    destination: [64]u8,
    destination_len: usize,
    gateway: [64]u8,
    gateway_len: usize,
    interface: [32]u8,
    interface_len: usize,
};

/// Maximum number of utun interfaces to check
const MAX_UTUN: u8 = 16;

/// Check if a utun interface number exists (e.g. utun3).
/// Returns true if the interface is live.
fn utunExists(allocator: std.mem.Allocator, utun_num: u8) bool {
    var cmd_buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "ifconfig utun{d} 2>/dev/null", .{utun_num}) catch return false;

    var child = std.process.Child.init(
        &[_][]const u8{ "/bin/sh", "-c", cmd },
        allocator,
    );
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

/// Build a bitmask of which utun interfaces currently exist.
/// Bit i set = utun{i} exists.
fn liveUtunMask(allocator: std.mem.Allocator) [MAX_UTUN]bool {
    var mask: [MAX_UTUN]bool = [_]bool{false} ** MAX_UTUN;
    var i: u8 = 0;
    while (i < MAX_UTUN) : (i += 1) {
        mask[i] = utunExists(allocator, i);
    }
    return mask;
}

/// #10: Startup self-check — remove all routes pointing through vanished utunN.
/// Returns the number of stale routes removed.
pub fn purgeStaleRoutes(allocator: std.mem.Allocator) u32 {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return 0;

    const live = liveUtunMask(allocator);
    var removed: u32 = 0;

    // Get routing table
    const route_output = runCommandCapture(allocator, switch (builtin.os.tag) {
        .macos => "netstat -rn 2>/dev/null",
        .linux => "ip route show 2>/dev/null",
        else => return 0,
    }) orelse return 0;
    defer allocator.free(route_output);

    // Parse each line looking for routes via utunN
    var lines = std.mem.splitScalar(u8, route_output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        // Skip header lines
        if (std.mem.startsWith(u8, line, "Internet") or
            std.mem.startsWith(u8, line, "Kernel") or
            std.mem.startsWith(u8, line, "Destination") or
            std.mem.startsWith(u8, line, "default"))
        {
            continue;
        }

        // Find "utun" in the line
        const utun_pos = std.mem.indexOf(u8, line, "utun") orelse continue;
        if (utun_pos + 5 > line.len) continue;

        // Extract utun number
        const num_start = utun_pos + 4;
        var num_end = num_start;
        while (num_end < line.len and line[num_end] >= '0' and line[num_end] <= '9') {
            num_end += 1;
        }
        if (num_end == num_start) continue;

        const utun_num = std.fmt.parseInt(u8, line[num_start..num_end], 10) catch continue;
        if (utun_num >= MAX_UTUN) continue;

        // Check if this utun is alive
        if (live[utun_num]) continue;

        // Stale route found — extract destination and gateway for logging
        std.log.warn("[ROUTE-HEAL] Purging stale route: {s} (utun{d} is gone)", .{ line, utun_num });
        removed += 1;

        // Delete the route
        deleteRouteByLine(allocator, line);
    }

    if (removed > 0) {
        std.log.info("[ROUTE-HEAL] Purged {} stale route(s)", .{removed});
    }
    return removed;
}

/// #9: Auto-repair stale host route for a specific destination.
/// Called when TCP connect fails with EADDRNOTAVAIL.
/// Returns true if a stale route was found and deleted (caller should retry connect).
pub fn repairStaleHostRoute(allocator: std.mem.Allocator, hostname: []const u8, port: u16) bool {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return false;

    // First resolve the hostname to get the IP we're trying to reach
    const target_ip = resolveToIp(allocator, hostname) orelse return false;
    defer allocator.free(target_ip);

    const live = liveUtunMask(allocator);

    // Get routing table
    const route_output = runCommandCapture(allocator, switch (builtin.os.tag) {
        .macos => "netstat -rn 2>/dev/null",
        .linux => "ip route show 2>/dev/null",
        else => return false,
    }) orelse return false;
    defer allocator.free(route_output);

    // Find routes through dead utun interfaces that could match our target
    var lines = std.mem.splitScalar(u8, route_output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const utun_pos = std.mem.indexOf(u8, line, "utun") orelse continue;
        if (utun_pos + 5 > line.len) continue;

        const num_start = utun_pos + 4;
        var num_end = num_start;
        while (num_end < line.len and line[num_end] >= '0' and line[num_end] <= '9') {
            num_end += 1;
        }
        if (num_end == num_start) continue;

        const utun_num = std.fmt.parseInt(u8, line[num_start..num_end], 10) catch continue;
        if (utun_num >= MAX_UTUN) continue;

        // Only fix routes through dead utun
        if (live[utun_num]) continue;

        std.log.warn(
            "[ROUTE-HEAL] Found stale route via utun{d} — deleting for {s}:{d}",
            .{ utun_num, hostname, port },
        );
        deleteRouteByLine(allocator, line);
        return true;
    }

    return false;
}

/// Resolve hostname to a printable IP string for matching against routes.
fn resolveToIp(allocator: std.mem.Allocator, hostname: []const u8) ?[]u8 {
    // If it's already an IP, return it
    if (std.mem.indexOf(u8, hostname, ".") != null and
        std.mem.indexOf(u8, hostname, ":") == null)
    {
        return allocator.dupe(u8, hostname) catch return null;
    }

    // DNS lookup — just grab first result
    const addrs = std.net.getAddressList(allocator, hostname, 0) catch return null;
    defer addrs.deinit();

    if (addrs.addrs.len == 0) return null;

    const addr = addrs.addrs[0];
    if (addr.any.family == posix.AF.INET) {
        const a = addr.in.sa.addr;
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            @as(u8, @truncate(a >> 24)),
            @as(u8, @truncate(a >> 16)),
            @as(u8, @truncate(a >> 8)),
            @as(u8, @truncate(a)),
        }) catch return null;
    }
    return null;
}

/// Delete a route by parsing a routing table line.
/// Best-effort: logs and ignores failures.
fn deleteRouteByLine(allocator: std.mem.Allocator, line: []const u8) void {
    if (builtin.os.tag == .macos) {
        // netstat -rn format: "destination  gateway  flags  ...
        // We need "route delete <dest>"
        var parts = std.mem.splitScalar(u8, line, ' ');
        const dest = parts.next() orelse return;
        if (dest.len == 0 or std.mem.eql(u8, dest, "default")) return;

        var cmd_buf: [128]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "route delete -net {s} 2>/dev/null", .{dest}) catch return;
        _ = runCommand(allocator, cmd);
    } else if (builtin.os.tag == .linux) {
        // ip route format: "dest/proto via gw dev iface ..."
        // "ip route del <full line>"
        var cmd_buf: [512]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "ip route del {s} 2>/dev/null", .{line}) catch return;
        _ = runCommand(allocator, cmd);
    }
}

/// Run a command, return true if exit code 0.
fn runCommand(allocator: std.mem.Allocator, cmd: []const u8) bool {
    if (builtin.os.tag == .macos) {
        const escalate = @import("utun_escalate.zig");
        if (escalate.runPrivilegedCommand(cmd)) return true;
    }

    var child = std.process.Child.init(
        &[_][]const u8{ "/bin/sh", "-c", cmd },
        allocator,
    );
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

/// Run a command and capture stdout.
fn runCommandCapture(allocator: std.mem.Allocator, cmd: []const u8) ?[]u8 {
    var child = std.process.Child.init(
        &[_][]const u8{ "/bin/sh", "-c", cmd },
        allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return null;

    const stdout = child.stdout.?;

    // Read into a fixed buffer, then dupe if needed
    var buf: [8192]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = stdout.read(buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }
    _ = child.wait() catch {};

    if (total == 0) return null;
    return allocator.dupe(u8, buf[0..total]) catch null;
}

// ============================================================================
// Tests
// ============================================================================

test "StaleRoute struct layout" {
    const sr = StaleRoute{
        .destination = [_]u8{0} ** 64,
        .destination_len = 0,
        .gateway = [_]u8{0} ** 64,
        .gateway_len = 0,
        .interface = [_]u8{0} ** 32,
        .interface_len = 0,
    };
    try std.testing.expectEqual(@as(usize, 0), sr.destination_len);
}
