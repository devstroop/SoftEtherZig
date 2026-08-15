// SoftEther VPN - macOS Privilege Escalation for utun
//
// When direct utun creation fails with EPERM (common on macOS),
// launches a small helper binary with admin privileges via osascript.
// The helper creates the utun device and passes the fd back via
// Unix domain socket + SCM_RIGHTS.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const SCM_RIGHTS: c_int = 0x01;
const SOL_SOCKET: c_int = 0xFFFF;

const Cmsghdr = extern struct {
    cmsg_len: u32,
    cmsg_level: c_int,
    cmsg_type: c_int,
};

pub const EscalationError = error{
    SocketCreateFailed,
    BindFailed,
    ListenFailed,
    HelperLaunchFailed,
    HelperFailed,
    AcceptFailed,
    RecvFailed,
    NoFdReceived,
    HelperNotFound,
    PathTooLong,
};

pub const EscalatedUtun = struct {
    fd: posix.fd_t,
    device_name: [64]u8,
    device_name_len: usize,
};

/// Module-level fd for the persistent privileged command channel.
/// Set after successful escalation; used by runPrivilegedCommand().
pub var privileged_cmd_fd: posix.fd_t = -1;

/// Stable system-wide install path for the privileged helper.
/// Once installed setuid-root here, subsequent connects spawn the
/// helper directly with no password prompt. The bundled helper inside the
/// .app is copied here on first run (one-time prompt only).
const INSTALLED_HELPER_PATH: [:0]const u8 = "/usr/local/libexec/softether-utun-helper";

/// Returns true if INSTALLED_HELPER_PATH exists, is owned by root, and has
/// the setuid bit set — meaning we can exec it directly with no osascript.
///
/// SEA-50 cycle-9 fix: previous version compared mtime(bundled) > mtime(installed)
/// to detect upgrades, but every Flutter rebuild gives the bundled helper a
/// fresh mtime, so the check ALWAYS triggered reinstall → sudo prompt every
/// connect. Now we compare file SIZE instead. If the bundled helper changes
/// size (real upgrade), reinstall. Otherwise trust the installed copy. This
/// is conservative: an update with the same byte count won't be detected,
/// but in practice helper updates change the binary size enough to trigger.
fn installedHelperReady(bundled_helper: ?[]const u8) bool {
    var st: std.c.Stat = undefined;
    if (std.c.stat(INSTALLED_HELPER_PATH.ptr, &st) != 0) return false;
    // Must be owned by root (uid 0) and have setuid bit (S_ISUID = 0o4000).
    if (st.uid != 0) return false;
    if ((st.mode & 0o4000) == 0) return false;
    // Compare by size to detect real upgrades without false positives from
    // mtime churn during dev rebuilds.
    if (bundled_helper) |bp| {
        var bst: std.c.Stat = undefined;
        var path_buf: [1024]u8 = undefined;
        if (bp.len >= path_buf.len) return true;
        @memcpy(path_buf[0..bp.len], bp);
        path_buf[bp.len] = 0;
        if (std.c.stat(@ptrCast(&path_buf), &bst) == 0) {
            if (bst.size != st.size) return false;
        }
    }
    return true;
}

/// Attempt to create a utun device via privilege escalation.
///
/// Fast-path: if the setuid helper is already installed at
/// /usr/local/libexec/softether-utun-helper (from a previous connect), we
/// spawn it directly — no osascript, no password prompt, ~instant.
/// Otherwise we run a single-shot install script via osascript that copies
/// the bundled helper into place setuid-root and execs it. After that, all
/// future connects take the fast path.
pub fn escalatedUtunOpen(allocator: std.mem.Allocator) EscalationError!EscalatedUtun {
    if (builtin.os.tag != .macos) return EscalationError.HelperNotFound;

    // Find the bundled helper binary (next to the dylib or in the app bundle).
    // Used both as the source for one-time install and as a runtime fallback.
    var helper_path_buf: [1024]u8 = undefined;
    const bundled_helper = findHelperPath(&helper_path_buf);

    const installed_ready = installedHelperReady(bundled_helper);
    if (!installed_ready and bundled_helper == null) {
        std.log.err("utun_escalate: helper binary not found", .{});
        return EscalationError.HelperNotFound;
    }
    // Path we'll actually exec. Prefer the installed setuid copy.
    const helper_path: []const u8 = if (installed_ready) INSTALLED_HELPER_PATH[0..] else bundled_helper.?;

    // Create a temporary Unix domain socket
    var sock_path_buf: [108]u8 = undefined;
    var rand_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);

    const sock_path = std.fmt.bufPrint(&sock_path_buf, "/tmp/se-utun-{x}{x}{x}{x}{x}{x}{x}{x}.sock", .{
        rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
        rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7],
    }) catch return EscalationError.PathTooLong;

    // Create and bind the listening socket
    const listen_fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch {
        return EscalationError.SocketCreateFailed;
    };
    // errdefer ensures listen_fd is closed on ANY error return.
    // Using errdefer instead of defer: if bind/listen below fails, this
    // closes the socket before we return. Without this, a failed bind
    // would leak listen_fd (defer only runs on normal exit).
    errdefer posix.close(listen_fd);

    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..sock_path.len], sock_path);

    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) catch {
        return EscalationError.BindFailed;
    };

    // Clean up socket file on exit (listen_fd stays open for accept)
    defer {
        _ = std.c.unlink(@ptrCast(&addr.path));
    }

    posix.listen(listen_fd, 1) catch {
        return EscalationError.ListenFailed;
    };

    // Build the command we'll run.
    //
    // Fast path (installed_ready=true): the helper at INSTALLED_HELPER_PATH
    // is already setuid root, so we exec it directly with NO password prompt.
    //
    // Slow path (first run / app updated): wrap the helper invocation in a
    // single-shot install script and run it via osascript with admin
    // privileges. The install script is idempotent and atomic; afterward the
    // setuid binary at INSTALLED_HELPER_PATH lives forever and all future
    // connects take the fast path.
    var cmd_buf: [4096]u8 = undefined;
    const cmd = if (installed_ready) blk: {
        std.log.info("utun_escalate: using installed setuid helper at {s} (no prompt)", .{helper_path});
        break :blk std.fmt.bufPrint(&cmd_buf, "{s} {s}", .{ helper_path, sock_path }) catch return EscalationError.PathTooLong;
    } else blk: {
        std.log.info("utun_escalate: installing privileged helper to {s} (one-time admin prompt)", .{INSTALLED_HELPER_PATH});
        // mkdir → cp → chown root:wheel → chmod 4755 → exec
        // All quoted carefully because osascript wraps the whole thing in
        // double quotes when handed to /bin/sh.
        break :blk std.fmt.bufPrint(
            &cmd_buf,
            "osascript -e 'do shell script \"mkdir -p /usr/local/libexec && cp -f \\\"{s}\\\" \\\"{s}\\\" && chown root:wheel \\\"{s}\\\" && chmod 4755 \\\"{s}\\\" && exec \\\"{s}\\\" \\\"{s}\\\"\" with administrator privileges' 2>&1",
            .{ bundled_helper.?, INSTALLED_HELPER_PATH, INSTALLED_HELPER_PATH, INSTALLED_HELPER_PATH, INSTALLED_HELPER_PATH, sock_path },
        ) catch return EscalationError.PathTooLong;
    };

    // Launch helper (fast path: direct setuid exec; slow path: osascript admin dialog)
    var child = std.process.Child.init(
        &[_][]const u8{ "sh", "-c", cmd },
        allocator,
    );
    child.spawn() catch {
        return EscalationError.HelperLaunchFailed;
    };

    // Accept connection from the helper. Fast path is near-instant (~50ms);
    // slow path needs up to 60s for user to type the admin password.
    const accept_timeout_ms: i32 = if (installed_ready) 5_000 else 60_000;
    var poll_fds = [1]std.posix.pollfd{
        .{ .fd = listen_fd, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const poll_result = std.posix.poll(&poll_fds, accept_timeout_ms) catch {
        _ = child.wait() catch {};
        return EscalationError.AcceptFailed;
    };

    if (poll_result == 0) {
        std.log.err("utun_escalate: timeout waiting for helper (user cancelled?)", .{});
        _ = child.wait() catch {};
        return EscalationError.HelperFailed;
    }

    const client_fd = posix.accept(listen_fd, null, null, 0) catch {
        _ = child.wait() catch {};
        return EscalationError.AcceptFailed;
    };
    // NOTE: Do NOT close client_fd here — it becomes the persistent privileged command channel.

    // Receive the utun fd via SCM_RIGHTS
    const CMSG_SPACE = @sizeOf(Cmsghdr) + @sizeOf(c_int);
    var cmsg_buf: [CMSG_SPACE + 16]u8 align(@alignOf(Cmsghdr)) = [_]u8{0} ** (CMSG_SPACE + 16);
    var device_name: [64]u8 = [_]u8{0} ** 64;

    var iov = [1]posix.iovec{
        .{
            .base = &device_name,
            .len = 64,
        },
    };

    var msg = std.c.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = @intCast(cmsg_buf.len),
        .flags = 0,
    };

    const received = std.c.recvmsg(client_fd, &msg, 0);
    if (received < 0) {
        posix.close(client_fd);
        _ = child.wait() catch {};
        return EscalationError.RecvFailed;
    }

    // Do NOT wait for helper — it stays alive as our privileged command server.

    // Extract fd from control message
    const cmsg: *const Cmsghdr = @ptrCast(@alignCast(&cmsg_buf));
    if (cmsg.cmsg_level != SOL_SOCKET or cmsg.cmsg_type != SCM_RIGHTS) {
        // NOTE: client_fd is NOT closed here — the Unix domain socket to the
        // helper stays open as our privileged command channel. The helper
        // owns it; we don't need it after receiving the utun fd.
        return EscalationError.NoFdReceived;
    }

    const received_fd: *const c_int = @ptrCast(@alignCast(&cmsg_buf[@sizeOf(Cmsghdr)]));
    if (received_fd.* < 0) {
        return EscalationError.NoFdReceived;
    }

    var name_len: usize = 0;
    while (name_len < 64 and device_name[name_len] != 0) : (name_len += 1) {}

    std.log.info("utun_escalate: received {s} (fd={d}) from helper", .{ device_name[0..name_len], received_fd.* });

    // Store the socket as our persistent privileged command channel
    privileged_cmd_fd = client_fd;
    std.log.info("utun_escalate: privileged command channel established (fd={d})", .{client_fd});

    return EscalatedUtun{
        .fd = received_fd.*,
        .device_name = device_name,
        .device_name_len = name_len,
    };
}

/// Send a shell command to the privileged helper for execution as root.
/// Returns true if the command succeeded (exit code 0).
/// Uses poll() with a 5-second timeout to avoid blocking indefinitely
/// while the VpnClient mutex is held during disconnect.
pub fn runPrivilegedCommand(cmd: []const u8) bool {
    if (privileged_cmd_fd < 0) return false;
    if (cmd.len == 0 or cmd.len > 2048) return false;

    // Send length prefix (2 bytes, little-endian)
    const len: u16 = @intCast(cmd.len);
    const len_bytes = [2]u8{ @intCast(len & 0xFF), @intCast((len >> 8) & 0xFF) };
    _ = posix.write(privileged_cmd_fd, &len_bytes) catch {
        std.log.err("utun_escalate: privileged channel write failed (length)", .{});
        privileged_cmd_fd = -1;
        return false;
    };

    // Send command bytes
    _ = posix.write(privileged_cmd_fd, cmd) catch {
        std.log.err("utun_escalate: privileged channel write failed (command)", .{});
        privileged_cmd_fd = -1;
        return false;
    };

    // Wait up to 5 seconds for the helper response. Route commands
    // (add/delete) should complete in <100ms; a 5s timeout is generous
    // while preventing indefinite mutex hold during disconnect.
    var poll_fds = [1]std.posix.pollfd{
        .{ .fd = privileged_cmd_fd, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const poll_ret = std.posix.poll(&poll_fds, 5000) catch {
        std.log.err("utun_escalate: poll failed on privileged channel", .{});
        privileged_cmd_fd = -1;
        return false;
    };
    if (poll_ret == 0) {
        std.log.err("utun_escalate: privileged command timed out after 5s", .{});
        privileged_cmd_fd = -1;
        return false;
    }

    // Read 1-byte response (exit code)
    var resp: [1]u8 = undefined;
    const n = posix.read(privileged_cmd_fd, &resp) catch {
        std.log.err("utun_escalate: privileged channel read failed", .{});
        privileged_cmd_fd = -1;
        return false;
    };
    if (n == 0) {
        std.log.err("utun_escalate: privileged channel closed by helper", .{});
        privileged_cmd_fd = -1;
        return false;
    }

    if (resp[0] != 0) {
        std.log.warn("utun_escalate: privileged command returned exit code {d}", .{resp[0]});
    }
    return resp[0] == 0;
}

/// Ensure a privileged command channel exists without opening a utun device.
/// Called after a direct utun open so that routing commands (route add/delete)
/// can still be executed as root via the setuid helper.
/// No-op if the channel is already established.
/// If the installed helper is stale (size mismatch vs bundled), reinstalls it
/// via a one-time osascript admin prompt before connecting.
pub fn ensurePrivilegedChannel(allocator: std.mem.Allocator) void {
    if (privileged_cmd_fd >= 0) return;
    // Already root — no helper needed; direct /bin/sh fallback works.
    if (std.c.getuid() == 0) return;

    var helper_path_buf: [1024]u8 = undefined;
    const bundled_helper = findHelperPath(&helper_path_buf);

    if (!installedHelperReady(bundled_helper)) {
        if (bundled_helper == null) {
            std.log.warn("utun_escalate: helper binary not found; route commands cannot run as root", .{});
            return;
        }
        // Installed helper is missing or stale — reinstall setuid-root via osascript.
        std.log.info("utun_escalate: installing/updating privileged helper (one-time admin prompt)", .{});
        var reinstall_buf: [4096]u8 = undefined;
        const reinstall_cmd = std.fmt.bufPrint(
            &reinstall_buf,
            "osascript -e 'do shell script \"mkdir -p /usr/local/libexec && cp -f \\\"{s}\\\" \\\"{s}\\\" && chown root:wheel \\\"{s}\\\" && chmod 4755 \\\"{s}\\\"\" with administrator privileges' 2>&1",
            .{ bundled_helper.?, INSTALLED_HELPER_PATH, INSTALLED_HELPER_PATH, INSTALLED_HELPER_PATH },
        ) catch return;
        var install_child = std.process.Child.init(&[_][]const u8{ "sh", "-c", reinstall_cmd }, allocator);
        const term = install_child.spawnAndWait() catch return;
        switch (term) {
            .Exited => |code| if (code != 0) {
                std.log.err("utun_escalate: helper install failed (exit {d})", .{code});
                return;
            },
            else => return,
        }
        std.log.info("utun_escalate: helper installed to {s}", .{INSTALLED_HELPER_PATH});
    }

    // Create a temporary Unix socket for the helper to connect back on.
    var sock_path_buf: [108]u8 = undefined;
    var rand_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&rand_bytes);
    const sock_path = std.fmt.bufPrint(&sock_path_buf, "/tmp/se-cmd-{x}{x}{x}{x}{x}{x}{x}{x}.sock", .{
        rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
        rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7],
    }) catch return;

    const listen_fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch return;

    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    if (sock_path.len >= addr.path.len) {
        posix.close(listen_fd);
        return;
    }
    @memcpy(addr.path[0..sock_path.len], sock_path);

    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) catch {
        posix.close(listen_fd);
        return;
    };
    defer _ = std.c.unlink(@ptrCast(&addr.path));

    posix.listen(listen_fd, 1) catch {
        posix.close(listen_fd);
        return;
    };

    // Launch the setuid helper in cmd-only mode (no utun, no password prompt).
    var cmd_buf: [1200]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "{s} {s} --cmd-only", .{ INSTALLED_HELPER_PATH, sock_path }) catch {
        posix.close(listen_fd);
        return;
    };

    var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
    child.spawn() catch {
        posix.close(listen_fd);
        return;
    };

    // Wait for helper to connect (5 s — setuid exec is near-instant).
    var poll_fds = [1]std.posix.pollfd{
        .{ .fd = listen_fd, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const poll_result = std.posix.poll(&poll_fds, 5_000) catch {
        _ = child.wait() catch {};
        posix.close(listen_fd);
        return;
    };
    if (poll_result == 0) {
        std.log.err("utun_escalate: timeout waiting for cmd-only helper", .{});
        _ = child.wait() catch {};
        posix.close(listen_fd);
        return;
    }

    const client_fd = posix.accept(listen_fd, null, null, 0) catch {
        _ = child.wait() catch {};
        posix.close(listen_fd);
        return;
    };
    posix.close(listen_fd);

    // Read the 1-byte ready signal from the helper.
    var ready: [1]u8 = undefined;
    const n = posix.read(client_fd, &ready) catch {
        posix.close(client_fd);
        return;
    };
    if (n == 0 or ready[0] != 0x00) {
        posix.close(client_fd);
        return;
    }

    privileged_cmd_fd = client_fd;
    std.log.info("utun_escalate: privileged command channel established via cmd-only helper (fd={d})", .{client_fd});
}

/// Close the privileged command channel and signal the helper to exit.
pub fn closePrivilegedChannel() void {
    if (privileged_cmd_fd >= 0) {
        // Send EXIT signal (length = 0)
        const exit_signal = [2]u8{ 0, 0 };
        _ = posix.write(privileged_cmd_fd, &exit_signal) catch {};
        posix.close(privileged_cmd_fd);
        privileged_cmd_fd = -1;
        std.log.info("utun_escalate: privileged command channel closed", .{});
    }
}

/// Search for the helper binary in likely locations.
fn findHelperPath(buf: []u8) ?[]const u8 {
    // Try to find it relative to the current executable (app bundle)
    if (std.fs.selfExeDirPath(buf[0 .. buf.len - 64])) |exe_dir| {
        const helper_name = "/softether-utun-helper";
        if (exe_dir.len + helper_name.len < buf.len) {
            @memcpy(buf[exe_dir.len .. exe_dir.len + helper_name.len], helper_name);
            const full_len = exe_dir.len + helper_name.len;
            buf[full_len] = 0;
            if (std.fs.cwd().access(buf[0..full_len], .{})) |_| {
                return buf[0..full_len];
            } else |_| {}
        }
    } else |_| {}

    // Fallback: well-known paths
    const search_paths = [_][]const u8{
        "/usr/local/bin/softether-utun-helper",
        "/opt/homebrew/bin/softether-utun-helper",
    };

    for (search_paths) |path| {
        if (std.fs.cwd().access(path, .{})) |_| {
            const len = @min(path.len, buf.len - 1);
            @memcpy(buf[0..len], path[0..len]);
            buf[len] = 0;
            return buf[0..len];
        } else |_| {
            continue;
        }
    }

    // Try to find it relative to the current executable
    if (std.fs.selfExeDirPath(buf[0 .. buf.len - 64])) |exe_dir| {
        const helper_name = "/softether-utun-helper";
        if (exe_dir.len + helper_name.len < buf.len) {
            @memcpy(buf[exe_dir.len .. exe_dir.len + helper_name.len], helper_name);
            const full_len = exe_dir.len + helper_name.len;
            buf[full_len] = 0;
            if (std.fs.cwd().access(buf[0..full_len], .{})) |_| {
                return buf[0..full_len];
            } else |_| {}
        }
    } else |_| {}

    return null;
}
