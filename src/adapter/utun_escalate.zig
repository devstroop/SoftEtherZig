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

/// Attempt to create a utun device via privilege escalation.
/// Shows the macOS admin password dialog, then creates the utun as root.
pub fn escalatedUtunOpen(allocator: std.mem.Allocator) EscalationError!EscalatedUtun {
    if (builtin.os.tag != .macos) return EscalationError.HelperNotFound;

    // Find the helper binary (next to the dylib or in the app bundle)
    var helper_path_buf: [1024]u8 = undefined;
    const helper_path = findHelperPath(&helper_path_buf) orelse {
        std.log.err("utun_escalate: helper binary not found", .{});
        return EscalationError.HelperNotFound;
    };

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
    defer posix.close(listen_fd);

    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    @memcpy(addr.path[0..sock_path.len], sock_path);

    posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) catch {
        return EscalationError.BindFailed;
    };

    // Clean up socket file on exit
    defer {
        _ = std.c.unlink(@ptrCast(&addr.path));
    }

    posix.listen(listen_fd, 1) catch {
        return EscalationError.ListenFailed;
    };

    // Build osascript command to launch helper with admin privileges
    var cmd_buf: [2048]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "osascript -e 'do shell script \"{s} {s}\" with administrator privileges' 2>&1", .{ helper_path, sock_path }) catch return EscalationError.PathTooLong;

    // Launch helper via osascript (shows admin dialog)
    std.log.info("utun_escalate: requesting admin privileges for utun creation...", .{});
    var child = std.process.Child.init(
        &[_][]const u8{ "sh", "-c", cmd },
        allocator,
    );
    child.spawn() catch {
        return EscalationError.HelperLaunchFailed;
    };

    // Accept connection from the helper (with timeout via poll)
    var poll_fds = [1]std.posix.pollfd{
        .{ .fd = listen_fd, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const poll_result = std.posix.poll(&poll_fds, 60000) catch { // 60s timeout for user to enter password
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
