// SoftEther VPN Client - Route Healing
// Auto-repairs stale routes pointing through vanished utun interfaces.
//
// #9: On EADDRNOTAVAIL during TCP connect, deletes the stale host route and retries.
// #10: On startup, scans the routing table for routes via dead utunN and removes them.

const std = @import("std");
const builtin = @import("builtin");

const c = struct {
    extern "c" fn fork() std.c.pid_t;
    extern "c" fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;
    extern "c" fn waitpid(pid: std.c.pid_t, status: ?*c_int, options: c_int) std.c.pid_t;
    extern "c" fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern "c" fn pclose(stream: *anyopaque) c_int;
    extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, stream: *anyopaque) usize;
};

fn _WIFEXITED(status: c_int) bool {
    return (status & 0x7f) == 0;
}
fn _WEXITSTATUS(status: c_int) i32 {
    return @intCast((status >> 8) & 0xff);
}

fn spawnShAndWait(cmd: [:0]const u8) i32 {
    const pid = c.fork();
    if (pid == 0) {
        const argv: [4:null]?[*:0]const u8 = .{ "/bin/sh", "-c", cmd.ptr, null };
        _ = c.execve("/bin/sh", &argv, @ptrCast(@alignCast(&std.c.environ)));
        _ = std.c._exit(1);
    } else if (pid > 0) {
        var status: c_int = 0;
        _ = c.waitpid(pid, &status, 0);
        if (_WIFEXITED(status)) return _WEXITSTATUS(status);
        return -1;
    }
    return -1;
}

/// Result of a stale-route scan
pub const StaleRoute = struct {
    destination: [64]u8,
    destination_len: usize,
    gateway: [64]u8,
    gateway_len: usize,
    interface: [32]u8,
    interface_len: usize,
};

/// Maximum number of utun interfaces to check.
/// macOS can assign utun numbers into the 40s after many VPN sessions.
const MAX_UTUN: u8 = 64;

/// Check if a utun interface number exists (e.g. utun3).
/// Returns true if the interface is live.
fn utunExists(allocator: std.mem.Allocator, utun_num: u8) bool {
    var cmd_buf: [64]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "ifconfig utun{d} 2>/dev/null", .{utun_num}) catch return false;
    const cmd_z = allocator.dupeZ(u8, cmd) catch return false;
    defer allocator.free(cmd_z);
    return spawnShAndWait(cmd_z) == 0;
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

/// Aggressive cleanup: for every dead utunN (one that exists in the routing
/// table but no longer has a corresponding kernel interface — left over from
/// a SIGKILL'd or crashed VPN run), remove every route through it AND
/// restore a default route via the physical interface if one is missing.
/// Returns the number of routes removed.
pub fn purgeStaleUtunState(allocator: std.mem.Allocator) u32 {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return 0;

    const live = liveUtunMask(allocator);
    var removed: u32 = 0;

    // 1. Remove ALL routes through dead utun interfaces
    const route_output = runCommandCapture(allocator, switch (builtin.os.tag) {
        .macos => "netstat -rn 2>/dev/null",
        .linux => "ip route show 2>/dev/null",
        else => return 0,
    }) orelse return 0;
    defer allocator.free(route_output);

    var lines = std.mem.splitScalar(u8, route_output, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "Internet") or
            std.mem.startsWith(u8, line, "Kernel") or
            std.mem.startsWith(u8, line, "Destination"))
        {
            continue;
        }

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
        if (live[utun_num]) continue;

        // Dead utun — drop this route
        std.log.warn("[ROUTE-HEAL] Purging route through dead utun{d}: {s}", .{ utun_num, line });
        deleteRouteByLine(allocator, line);
        removed += 1;
    }

    // 2. If the default route was pointing to a dead utun and got removed in
    // step 1, restore a default via the physical interface. Without this, the
    // host has no internet and the only way to recover is replug.
    const default_output = runCommandCapture(allocator, switch (builtin.os.tag) {
        .macos => "netstat -rn 2>/dev/null | grep '^default' | grep -v utun | head -1",
        .linux => "ip route show default 2>/dev/null | grep -v utun | head -1",
        else => "",
    });
    if (default_output) |out| {
        defer allocator.free(out);
        // If there's already a non-utun default, we're fine
        if (out.len > 0) {
            return removed;
        }
    }

    // No non-utun default route — try to restore one via the physical NIC
    if (builtin.os.tag == .macos) {
        // Get the default interface
        if (runCommandCapture(allocator, "route get 8.8.8.8 2>/dev/null | awk '/interface:/{print $2}' | head -1")) |iface_out| {
            defer allocator.free(iface_out);
            var iface_buf: [64]u8 = undefined;
            const len = @min(iface_out.len, iface_buf.len);
            @memcpy(iface_buf[0..len], iface_out[0..len]);
            // Strip trailing whitespace
            var trimmed_len: usize = 0;
            while (trimmed_len < len and iface_buf[trimmed_len] != ' ' and iface_buf[trimmed_len] != '\n' and iface_buf[trimmed_len] != '\r' and iface_buf[trimmed_len] != '\t') : (trimmed_len += 1) {}
            const iface = iface_buf[0..trimmed_len];
            if (iface.len > 0 and !std.mem.eql(u8, iface, "utun")) {
                // Get the gateway for this interface
                if (runCommandCapture(allocator, "route get 8.8.8.8 2>/dev/null | awk '/gateway:/{print $2}' | head -1")) |gw_out| {
                    defer allocator.free(gw_out);
                    var gw_buf: [64]u8 = undefined;
                    const gw_len = @min(gw_out.len, gw_buf.len);
                    @memcpy(gw_buf[0..gw_len], gw_out[0..gw_len]);
                    var gw_trimmed: usize = 0;
                    while (gw_trimmed < gw_len and gw_buf[gw_trimmed] != ' ' and gw_buf[gw_trimmed] != '\n' and gw_buf[gw_trimmed] != '\r' and gw_buf[gw_trimmed] != '\t') : (gw_trimmed += 1) {}
                    const gw = gw_buf[0..gw_trimmed];
                    if (gw.len > 0) {
                        var cmd_buf: [256]u8 = undefined;
                        const cmd = std.fmt.bufPrint(&cmd_buf, "route add default {s} 2>/dev/null", .{gw}) catch return removed;
                        if (runCommand(allocator, cmd)) {
                            std.log.info("[ROUTE-HEAL] Restored default route via {s} gateway {s}", .{ iface, gw });
                        }
                    }
                }
            }
        }
    }

    return removed;
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

    // IPv6 scan — separate pass because output format and delete syntax differ
    if (builtin.os.tag == .macos or builtin.os.tag == .linux) {
        const v6_cmd = if (builtin.os.tag == .macos) "netstat -rn -f inet6 2>/dev/null" else "ip -6 route show 2>/dev/null";
        if (runCommandCapture(allocator, v6_cmd)) |v6_output| {
            defer allocator.free(v6_output);
            var v6_lines = std.mem.splitScalar(u8, v6_output, '\n');
            while (v6_lines.next()) |line| {
                if (line.len == 0) continue;
                if (std.mem.startsWith(u8, line, "Internet") or
                    std.mem.startsWith(u8, line, "Kernel") or
                    std.mem.startsWith(u8, line, "Destination") or
                    std.mem.startsWith(u8, line, "default"))
                {
                    continue;
                }

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
                if (live[utun_num]) continue;

                std.log.warn("[ROUTE-HEAL] Purging stale IPv6 route: {s} (utun{d} is gone)", .{ line, utun_num });
                removed += 1;

                // Delete using IPv6-aware syntax
                if (builtin.os.tag == .macos) {
                    var parts = std.mem.splitScalar(u8, line, ' ');
                    const dest = parts.next() orelse continue;
                    if (dest.len == 0 or std.mem.eql(u8, dest, "default")) continue;
                    var cmd_buf: [128]u8 = undefined;
                    const cmd = std.fmt.bufPrint(&cmd_buf, "route -A inet6 delete {s} 2>/dev/null", .{dest}) catch continue;
                    _ = runCommand(allocator, cmd);
                } else if (builtin.os.tag == .linux) {
                    var cmd_buf: [512]u8 = undefined;
                    const cmd = std.fmt.bufPrint(&cmd_buf, "ip -6 route del {s} 2>/dev/null", .{line}) catch continue;
                    _ = runCommand(allocator, cmd);
                }
            }
        }
    }

    if (removed > 0) {
        std.log.info("[ROUTE-HEAL] Purged {} stale route(s) (including IPv6)", .{removed});
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

    // Fallback: direct host-route deletion for the target IP.
    // The utun-based netstat -rn scan above misses routes where the Netif
    // column displays "link#N" (the kernel interface index) instead of the
    // BSD name "utunN".  We already know the target IP is unreachable, so
    // just try deleting it directly — the kernel returns success if a
    // matching host route existed, or a harmless error if not.
    if (builtin.os.tag == .macos) {
        var del_cmd_buf: [128]u8 = undefined;
        const del_cmd = std.fmt.bufPrint(
            &del_cmd_buf,
            "route delete -host {s} 2>/dev/null",
            .{target_ip},
        ) catch return false;
        if (runCommand(allocator, del_cmd)) {
            std.log.warn(
                "[ROUTE-HEAL] Directly deleted stale host route to {s} (utun-based scan missed it)",
                .{target_ip},
            );
            return true;
        }
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

    // DNS lookup — use host command via popen
    const cmd = std.fmt.allocPrint(allocator, "host {s} 2>/dev/null | grep 'has address' | head -1 | awk '{{print $4}}'", .{hostname}) catch return null;
    defer allocator.free(cmd);
    const line = runCommandCapture(allocator, cmd) orelse return null;
    defer allocator.free(line);
    if (line.len == 0) return null;
    // Validate it's an IPv4 address
    if (std.mem.indexOf(u8, line, ".") == null) return null;
    return std.fmt.allocPrint(allocator, "{s}", .{line}) catch return null;
}

/// Clean up a stale /32 host route to a known VPN server IP.
///
/// Unlike purgeStaleRoutes (which only finds routes through dead utun
/// interfaces), this targets the host bypass route — which goes through the
/// *physical* gateway (en0/en1). When a VPN session crashes or is SIGKILL'd,
/// the utun interface disappears but the host route to the VPN server IP
/// remains, and purgeStaleRoutes cannot see it because the route's interface
/// column shows the physical NIC, not utun.
///
/// Called at connect time after DNS resolution so we have the resolved IP.
pub fn cleanupStaleHostRoute(allocator: std.mem.Allocator, target_ip: []const u8) void {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return;
    if (target_ip.len == 0) return;

    var cmd_buf: [128]u8 = undefined;
    const cmd = if (builtin.os.tag == .macos)
        std.fmt.bufPrint(&cmd_buf, "route delete -host {s} 2>/dev/null", .{target_ip}) catch return
    else
        std.fmt.bufPrint(&cmd_buf, "ip route del {s}/32 2>/dev/null", .{target_ip}) catch return;

    if (runCommand(allocator, cmd)) {
        std.log.info("[ROUTE-HEAL] Cleaned up stale host route to {s} from previous session", .{target_ip});
    }
}

/// Delete a route by parsing a routing table line.
/// Best-effort: logs and ignores failures.
fn deleteRouteByLine(allocator: std.mem.Allocator, line: []const u8) void {
    const is_v6 = std.mem.indexOf(u8, line, ":") != null and
        (std.mem.indexOf(u8, line, ".") == null or
            std.mem.startsWith(u8, line, "default") == false);

    if (builtin.os.tag == .macos) {
        var parts = std.mem.splitScalar(u8, line, ' ');
        const dest = parts.next() orelse return;
        if (dest.len == 0 or std.mem.eql(u8, dest, "default")) return;

        var cmd_buf: [128]u8 = undefined;
        const cmd = if (is_v6)
            std.fmt.bufPrint(&cmd_buf, "route -A inet6 delete {s} 2>/dev/null", .{dest}) catch return
        else if (std.mem.indexOfScalar(u8, dest, '/') == null)
            std.fmt.bufPrint(&cmd_buf, "route delete -host {s} 2>/dev/null", .{dest}) catch return
        else
            std.fmt.bufPrint(&cmd_buf, "route delete -net {s} 2>/dev/null", .{dest}) catch return;
        _ = runCommand(allocator, cmd);
    } else if (builtin.os.tag == .linux) {
        var cmd_buf: [512]u8 = undefined;
        const cmd = if (is_v6)
            std.fmt.bufPrint(&cmd_buf, "ip -6 route del {s} 2>/dev/null", .{line}) catch return
        else
            std.fmt.bufPrint(&cmd_buf, "ip route del {s} 2>/dev/null", .{line}) catch return;
        _ = runCommand(allocator, cmd);
    }
}

/// Run a command, return true if exit code 0.
fn runCommand(allocator: std.mem.Allocator, cmd: []const u8) bool {
    if (builtin.os.tag == .macos) {
        const escalate = @import("utun_escalate.zig");
        if (escalate.runPrivilegedCommand(cmd)) return true;
    }

    const cmd_z = allocator.dupeZ(u8, cmd) catch return false;
    defer allocator.free(cmd_z);
    return spawnShAndWait(cmd_z) == 0;
}

/// Run a command and capture stdout.
fn runCommandCapture(allocator: std.mem.Allocator, cmd: []const u8) ?[]u8 {
    const cmd_z = allocator.dupeZ(u8, cmd) catch return null;
    defer allocator.free(cmd_z);
    const mode_z: [:0]const u8 = "r";
    const stream = c.popen(cmd_z.ptr, mode_z.ptr) orelse return null;
    defer _ = c.pclose(stream);

    var buf: [8192]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = c.fread(buf[total..].ptr, 1, buf.len - total, stream);
        if (n == 0) break;
        total += n;
    }
    if (total == 0) return null;

    // Trim trailing whitespace/newlines
    while (total > 0 and (buf[total - 1] == '\n' or buf[total - 1] == '\r' or buf[total - 1] == ' ')) total -= 1;
    if (total == 0) return null;
    return allocator.dupe(u8, buf[0..total]) catch return null;
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
