// SoftEther VPN - macOS utun Privilege Helper
//
// Small binary that runs as root (via osascript privilege escalation).
// Creates a utun device, configures it with a temporary IP, and sends
// the fd back to the parent process via Unix domain socket + SCM_RIGHTS.
//
// Usage: softether-utun-helper <unix-socket-path>

const std = @import("std");

// Zig 0.16 removed posix.socket/close/write/connect/bind/listen/accept/fcntl.
// Use raw C functions directly. posix.read still exists.
const c = struct {
    extern "c" fn socket(domain: c_int, type_: c_int, protocol: c_int) c_int;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn write(fd: c_int, buf: [*]const u8, nbyte: usize) isize;
    extern "c" fn connect(sockfd: c_int, sock_addr: *const std.c.sockaddr, addrlen: std.c.socklen_t) c_int;
    extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;
    extern "c" fn fork() std.c.pid_t;
    extern "c" fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;
    extern "c" fn waitpid(pid: std.c.pid_t, status: ?*c_int, options: c_int) std.c.pid_t;
};
const posix = std.posix;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const SOCK_DGRAM: c_int = 2;

const sockaddr_un = extern struct {
    sun_len: u8 = 0,
    sun_family: std.c.sa_family_t = 0,
    sun_path: [104]u8 = [_]u8{0} ** 104,
};

/// Spawn a shell command via fork+exec and wait.
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

fn _WIFEXITED(status: c_int) bool {
    return (status & 0x7f) == 0;
}
fn _WEXITSTATUS(status: c_int) i32 {
    return @intCast((status >> 8) & 0xff);
}

// macOS utun constants
const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: u8 = 2;
const UTUN_OPT_IFNAME: u32 = 2;
const CTLIOCGINFO: u32 = 0xC0644E03;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";
const SCM_RIGHTS: c_int = 0x01;
const SOL_SOCKET: c_int = 0xFFFF;

const CtlInfo = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

const SockaddrCtl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

// msghdr / cmsghdr for SCM_RIGHTS
const Cmsghdr = extern struct {
    cmsg_len: u32,
    cmsg_level: c_int,
    cmsg_type: c_int,
};

pub fn main(init: std.process.Init.Minimal) !void {
    // SEA-50 fast-path fix: when invoked as a setuid-root binary directly
    // (no osascript wrapper), our real UID is the invoking user even though
    // EUID is 0. Spawning child processes (/sbin/ifconfig) inherits the
    // RUID, which causes "ifconfig: up: permission denied". Promote RUID
    // to 0 so children inherit full root privileges.
    //
    // When invoked via osascript-with-admin (slow path / first install),
    // both UIDs are already 0, so this is a no-op.
    _ = std.c.setuid(0);

    // Collect args using Zig 0.16 API
    const gpa = std.heap.page_allocator;
    var arg_list = std.ArrayList([:0]const u8).empty;
    defer arg_list.deinit(gpa);
    var args_iter = std.process.Args.Iterator.init(init.args);
    while (args_iter.next()) |arg| {
        arg_list.append(gpa, arg) catch {
            std.debug.print("ERROR: failed to collect args\n", .{});
            std.process.exit(1);
        };
    }

    if (arg_list.items.len < 2) {
        std.debug.print("Usage: softether-utun-helper <unix-socket-path> [--cmd-only]\n", .{});
        std.process.exit(1);
    }

    const socket_path = arg_list.items[1];

    // --cmd-only: skip utun creation, only establish the privileged command channel.
    // Used when the app opened utun directly but still needs root for route commands.
    const cmd_only = arg_list.items.len >= 3 and std.mem.eql(u8, arg_list.items[2], "--cmd-only");
    if (cmd_only) {
        const sock_fd = c.socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            std.debug.print("ERROR: socket(AF_UNIX) failed\n", .{});
            std.process.exit(10);
        }
        defer _ = c.close(sock_fd);

        var addr: sockaddr_un = .{ .sun_family = @intCast(AF_UNIX), .sun_path = undefined };
        @memset(&addr.sun_path, 0);
        if (socket_path.len >= addr.sun_path.len) std.process.exit(11);
        @memcpy(addr.sun_path[0..socket_path.len], socket_path);

        if (c.connect(sock_fd, @ptrCast(&addr), @sizeOf(sockaddr_un)) < 0) {
            std.debug.print("ERROR: connect to parent socket failed\n", .{});
            std.process.exit(12);
        }

        // Send 1-byte ready signal
        const ready = [_]u8{0x00};
        if (c.write(sock_fd, &ready, 1) < 0) std.process.exit(13);

        std.debug.print("OK: cmd-only mode, entering privileged command loop\n", .{});
        runCommandLoop(sock_fd);
        return;
    }

    // Step 1: Create utun device
    const temp_fd = c.socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (temp_fd < 0) {
        std.debug.print("ERROR: socket(AF_SYSTEM) failed\n", .{});
        std.process.exit(2);
    }
    defer _ = c.close(temp_fd);

    var info = CtlInfo{ .ctl_id = 0, .ctl_name = [_]u8{0} ** 96 };
    @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

    const ioctl_result = std.c.ioctl(temp_fd, @bitCast(CTLIOCGINFO), @intFromPtr(&info));
    if (ioctl_result < 0) {
        std.debug.print("ERROR: ioctl(CTLIOCGINFO) failed\n", .{});
        std.process.exit(3);
    }

    var utun_fd: c_int = -1;
    var found = false;

    for (0..64) |unit_number| {
        utun_fd = c.socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (utun_fd < 0) continue;

        var addr = SockaddrCtl{
            .sc_len = @sizeOf(SockaddrCtl),
            .sc_family = AF_SYSTEM,
            .ss_sysaddr = AF_SYS_CONTROL,
            .sc_id = info.ctl_id,
            .sc_unit = @intCast(unit_number + 1),
            .sc_reserved = [_]u32{0} ** 5,
        };

        const connect_result = std.c.connect(utun_fd, @ptrCast(&addr), @sizeOf(SockaddrCtl));
        if (connect_result < 0) {
            _ = c.close(utun_fd);
            continue;
        }
        found = true;
        break;
    }

    if (!found) {
        std.debug.print("ERROR: Could not connect to any utun device (tried 64)\n", .{});
        std.process.exit(4);
    }

    // Get device name
    var device_name: [64]u8 = [_]u8{0} ** 64;
    var optlen: u32 = 64;
    const gso_result = std.c.getsockopt(utun_fd, SYSPROTO_CONTROL, @intCast(UTUN_OPT_IFNAME), &device_name, &optlen);
    if (gso_result < 0) {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: getsockopt(UTUN_OPT_IFNAME) failed\n", .{});
        std.process.exit(5);
    }

    var name_len: usize = 0;
    while (name_len < 64 and device_name[name_len] != 0) : (name_len += 1) {}

    // Set non-blocking
    const O_NONBLOCK: c_int = 0x0004;
    const flags = c.fcntl(utun_fd, F_GETFL, @as(c_int, 0));
    if (flags < 0) {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: fcntl(GETFL) failed\n", .{});
        std.process.exit(6);
    }
    if (c.fcntl(utun_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: fcntl(SETFL) failed\n", .{});
        std.process.exit(6);
    }

    const dev_name_slice = device_name[0..name_len];

    // Step 2: Configure with temporary IP via ifconfig
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "/sbin/ifconfig {s} 169.254.1.1 169.254.0.1 netmask 255.255.0.0 up", .{dev_name_slice}) catch {
        _ = c.close(utun_fd);
        std.process.exit(7);
    };

    const ifconfig_z = gpa.dupeZ(u8, cmd) catch {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: ifconfig failed to spawn\n", .{});
        std.process.exit(8);
    };
    defer gpa.free(ifconfig_z);
    const ifconfig_ret = spawnShAndWait(ifconfig_z);
    if (ifconfig_ret != 0) {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: ifconfig exited with {d}\n", .{ifconfig_ret});
        std.process.exit(9);
    }

    // Step 3: Connect to the parent's Unix domain socket and send the fd
    const sock_fd = c.socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: socket(AF_UNIX) failed\n", .{});
        std.process.exit(10);
    }
    defer _ = c.close(sock_fd);

    var addr: sockaddr_un = .{ .sun_family = @intCast(AF_UNIX), .sun_path = undefined };
    @memset(&addr.sun_path, 0);
    if (socket_path.len >= addr.sun_path.len) {
        std.debug.print("ERROR: socket path too long\n", .{});
        std.process.exit(11);
    }
    @memcpy(addr.sun_path[0..socket_path.len], socket_path);

    if (c.connect(sock_fd, @ptrCast(&addr), @sizeOf(sockaddr_un)) < 0) {
        _ = c.close(utun_fd);
        std.debug.print("ERROR: connect to parent socket failed\n", .{});
        std.process.exit(12);
    }

    // Send utun_fd via SCM_RIGHTS + device name as data
    // Build the control message with the fd
    const CMSG_SPACE = @sizeOf(Cmsghdr) + @sizeOf(c_int);
    var cmsg_buf: [CMSG_SPACE + 16]u8 align(@alignOf(Cmsghdr)) = [_]u8{0} ** (CMSG_SPACE + 16);
    const cmsg: *Cmsghdr = @ptrCast(&cmsg_buf);
    cmsg.cmsg_len = @intCast(@sizeOf(Cmsghdr) + @sizeOf(c_int));
    cmsg.cmsg_level = SOL_SOCKET;
    cmsg.cmsg_type = SCM_RIGHTS;

    // Write the fd value after the cmsghdr
    const fd_ptr: *c_int = @ptrCast(@alignCast(&cmsg_buf[@sizeOf(Cmsghdr)]));
    fd_ptr.* = utun_fd;

    // Data payload: device name
    var iov = [1]std.posix.iovec_const{
        .{
            .base = &device_name,
            .len = 64,
        },
    };

    const msg = std.c.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = @intCast(CMSG_SPACE),
        .flags = 0,
    };

    const sent = std.c.sendmsg(sock_fd, &msg, 0);
    if (sent < 0) {
        std.debug.print("ERROR: sendmsg failed ({d})\n", .{sent});
        std.process.exit(13);
    }

    std.debug.print("OK: Created {s} (fd={d}), sent to parent\n", .{ dev_name_slice, utun_fd });

    // Step 4: Enter privileged command loop.
    std.debug.print("OK: Entering privileged command loop\n", .{});
    runCommandLoop(sock_fd);
    std.debug.print("OK: Command loop ended, helper exiting\n", .{});
}

/// Privileged command loop.
/// Protocol: [u16 LE length][command bytes] -> [u8 exit_code]. Length 0 = EXIT.
fn runCommandLoop(sock_fd: c_int) void {
    const gpa = std.heap.page_allocator;
    while (true) {
        var len_buf: [2]u8 = undefined;
        if (!readExact(sock_fd, &len_buf)) break;

        const cmd_len: u16 = @as(u16, len_buf[0]) | (@as(u16, len_buf[1]) << 8);
        if (cmd_len == 0) break;
        if (cmd_len > 2048) break;

        var cmd_data: [2048]u8 = undefined;
        if (!readExact(sock_fd, cmd_data[0..cmd_len])) break;

        const cmd_str = cmd_data[0..cmd_len];
        std.debug.print("CMD: {s}\n", .{cmd_str});

        const cmd_z = gpa.dupeZ(u8, cmd_str) catch {
            if (c.write(sock_fd, &[_]u8{1}, 1) < 0) break;
            continue;
        };
        defer gpa.free(cmd_z);

        const exit_code = spawnShAndWait(cmd_z);
        const resp: u8 = @intCast(@min(@max(exit_code, 0), 255));
        if (c.write(sock_fd, &[_]u8{resp}, 1) < 0) break;
    }
}

/// Read exactly buf.len bytes from fd. Returns false on EOF or error.
fn readExact(fd: c_int, buf: []u8) bool {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch return false;
        if (n == 0) return false;
        total += n;
    }
    return true;
}
