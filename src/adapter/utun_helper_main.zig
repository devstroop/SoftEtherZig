// SoftEther VPN - macOS utun Privilege Helper
//
// Small binary that runs as root (via osascript privilege escalation).
// Creates a utun device, configures it with a temporary IP, and sends
// the fd back to the parent process via Unix domain socket + SCM_RIGHTS.
//
// Usage: softether-utun-helper <unix-socket-path> [--cmd-only]
//        softether-utun-helper <unix-socket-path> --bpf-open <ifname>

const std = @import("std");
const posix = std.posix;

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

// /dev/bpfN ioctls (macOS <net/bpf.h>); request codes exceed i32::MAX, so
// they are stored as bitcast c_int for std.c.ioctl.
const BIOCSBLEN: c_int = @bitCast(@as(u32, 0xc0044262)); // set buffer length
const BIOCSETIF: c_int = @bitCast(@as(u32, 0x8024426c)); // set interface
const BIOCPROMISC: c_int = @bitCast(@as(u32, 0x80044269)); // force promiscuous
const BIOCIMMEDIATE: c_int = @bitCast(@as(u32, 0x80044270)); // return immediately on packet
const BIOCNONBLOCK: c_int = @bitCast(@as(u32, 0x8004426e)); // non-blocking mode
const IFNAMSIZ: usize = 16;

const BpfIfreq = extern struct {
    ifr_name: [IFNAMSIZ]u8,
    ifru_pad: [24]u8,
};

/// `--bpf-open` allowlist (H-7): only /dev/bpf0..9 may be opened. The
/// interface name is validated to a conservative charset — no separators,
/// no shell metacharacters — and is used ONLY as a BIOCSETIF argument, never
/// interpolated into a shell command. This mode performs no shell execution.
const MAX_BPF_UNIT: usize = 9;

fn validIfname(name: []const u8) bool {
    if (name.len == 0 or name.len >= IFNAMSIZ) return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '_' or c == ':' or c == '-' or c == '.';
        if (!ok) return false;
    }
    return true;
}

// msghdr / cmsghdr for SCM_RIGHTS
const Cmsghdr = extern struct {
    cmsg_len: u32,
    cmsg_level: c_int,
    cmsg_type: c_int,
};

pub fn main() !void {
    // SEA-50 fast-path fix: when invoked as a setuid-root binary directly
    // (no osascript wrapper), our real UID is the invoking user even though
    // EUID is 0. Spawning child processes (/sbin/ifconfig) inherits the
    // RUID, which causes "ifconfig: up: permission denied". Promote RUID
    // to 0 so children inherit full root privileges.
    //
    // When invoked via osascript-with-admin (slow path / first install),
    // both UIDs are already 0, so this is a no-op.
    _ = std.c.setuid(0);

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    defer std.process.argsFree(std.heap.page_allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: softether-utun-helper <unix-socket-path> [--cmd-only]\n", .{});
        std.process.exit(1);
    }

    const socket_path = args[1];

    // --cmd-only: skip utun creation, only establish the privileged command channel.
    // Used when the app opened utun directly but still needs root for route commands.
    const cmd_only = args.len >= 3 and std.mem.eql(u8, args[2], "--cmd-only");
    if (cmd_only) {
        const sock_fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch {
            std.debug.print("ERROR: socket(AF_UNIX) failed\n", .{});
            std.process.exit(10);
        };
        defer posix.close(sock_fd);

        var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
        @memset(&addr.path, 0);
        if (socket_path.len >= addr.path.len) std.process.exit(11);
        @memcpy(addr.path[0..socket_path.len], socket_path);

        posix.connect(sock_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) catch {
            std.debug.print("ERROR: connect to parent socket failed\n", .{});
            std.process.exit(12);
        };

        // Send 1-byte ready signal so parent knows the channel is up
        const ready = [_]u8{0x00};
        _ = posix.write(sock_fd, &ready) catch std.process.exit(13);

        std.debug.print("OK: cmd-only mode, entering privileged command loop\n", .{});
        runCommandLoop(sock_fd);
        return;
    }

    // --bpf-open <ifname>: open an allowlisted /dev/bpfN, attach it to the
    // interface, enable promiscuous + immediate + non-blocking, and hand the
    // fd back to the parent via SCM_RIGHTS. NO shell execution in this mode
    // (H-7): the ifname is charset-validated and only ever used as a
    // BIOCSETIF argument; the device path is built from a digit, never the
    // raw string.
    const bpf_open = args.len >= 4 and std.mem.eql(u8, args[2], "--bpf-open");
    if (bpf_open) {
        const ifname = args[3];
        if (!validIfname(ifname)) {
            std.debug.print("ERROR: invalid interface name\n", .{});
            std.process.exit(20);
        }

        // Open the first free /dev/bpfN (root, so permission is fine).
        var bpf_fd: posix.fd_t = -1;
        for (0..MAX_BPF_UNIT + 1) |unit| {
            var dev_buf: [16]u8 = undefined;
            const dev_path = std.fmt.bufPrintZ(&dev_buf, "/dev/bpf{d}", .{unit}) catch continue;
            bpf_fd = posix.openZ(dev_path, .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0) catch continue;
            break;
        }
        if (bpf_fd < 0) {
            std.debug.print("ERROR: no free /dev/bpfN device\n", .{});
            std.process.exit(21);
        }
        errdefer posix.close(bpf_fd);

        // Configure capture: buffer size before attach, then attach + flags.
        var buf_len: c_uint = 65536;
        if (std.c.ioctl(bpf_fd, BIOCSBLEN, @intFromPtr(&buf_len)) < 0) {
            std.debug.print("ERROR: ioctl(BIOCSBLEN) failed\n", .{});
            std.process.exit(22);
        }
        var req = BpfIfreq{ .ifr_name = [_]u8{0} ** IFNAMSIZ, .ifru_pad = [_]u8{0} ** 24 };
        if (ifname.len >= req.ifr_name.len) std.process.exit(23);
        @memcpy(req.ifr_name[0..ifname.len], ifname);
        if (std.c.ioctl(bpf_fd, BIOCSETIF, @intFromPtr(&req)) < 0) {
            std.debug.print("ERROR: ioctl(BIOCSETIF) failed\n", .{});
            std.process.exit(24);
        }
        if (std.c.ioctl(bpf_fd, BIOCPROMISC, @as(c_uint, 0)) < 0) {
            std.debug.print("ERROR: ioctl(BIOCPROMISC) failed\n", .{});
            std.process.exit(25);
        }
        const on: c_uint = 1;
        if (std.c.ioctl(bpf_fd, BIOCIMMEDIATE, @intFromPtr(&on)) < 0) {
            std.debug.print("ERROR: ioctl(BIOCIMMEDIATE) failed\n", .{});
            std.process.exit(26);
        }
        if (std.c.ioctl(bpf_fd, BIOCNONBLOCK, @intFromPtr(&on)) < 0) {
            std.debug.print("ERROR: ioctl(BIOCNONBLOCK) failed\n", .{});
            std.process.exit(27);
        }
        const flags = posix.fcntl(bpf_fd, posix.F.GETFL, 0) catch 0;
        _ = posix.fcntl(bpf_fd, posix.F.SETFL, flags | 0x0004) catch {};

        // Connect to the parent socket and hand the fd over (SCM_RIGHTS).
        const sock_fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch {
            std.debug.print("ERROR: socket(AF_UNIX) failed\n", .{});
            std.process.exit(28);
        };
        defer posix.close(sock_fd);

        var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
        @memset(&addr.path, 0);
        if (socket_path.len >= addr.path.len) {
            std.debug.print("ERROR: socket path too long\n", .{});
            std.process.exit(29);
        }
        @memcpy(addr.path[0..socket_path.len], socket_path);

        posix.connect(sock_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) catch {
            std.debug.print("ERROR: connect to parent socket failed\n", .{});
            std.process.exit(30);
        };

        const CMSG_SPACE = @sizeOf(Cmsghdr) + @sizeOf(c_int);
        var cmsg_buf: [CMSG_SPACE + 16]u8 align(@alignOf(Cmsghdr)) = [_]u8{0} ** (CMSG_SPACE + 16);
        const cmsg: *Cmsghdr = @ptrCast(&cmsg_buf);
        cmsg.cmsg_len = @intCast(@sizeOf(Cmsghdr) + @sizeOf(c_int));
        cmsg.cmsg_level = SOL_SOCKET;
        cmsg.cmsg_type = SCM_RIGHTS;
        const fd_ptr: *c_int = @ptrCast(@alignCast(&cmsg_buf[@sizeOf(Cmsghdr)]));
        fd_ptr.* = bpf_fd;

        var iov = [1]std.posix.iovec_const{
            .{ .base = @constCast(ifname.ptr), .len = ifname.len },
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
        if (std.c.sendmsg(sock_fd, &msg, 0) < 0) {
            std.debug.print("ERROR: sendmsg failed\n", .{});
            std.process.exit(31);
        }

        std.debug.print("OK: bpf-open mode, sent /dev/bpfN (fd={d}) for {s}\n", .{ bpf_fd, ifname });
        return; // bpf fd lives in the parent; helper exits.
    }

    // Step 1: Create utun device
    const temp_fd = posix.socket(AF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL) catch {
        std.debug.print("ERROR: socket(AF_SYSTEM) failed\n", .{});
        std.process.exit(2);
    };
    defer posix.close(temp_fd);

    var info = CtlInfo{ .ctl_id = 0, .ctl_name = [_]u8{0} ** 96 };
    @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

    const ioctl_result = std.c.ioctl(temp_fd, @bitCast(CTLIOCGINFO), @intFromPtr(&info));
    if (ioctl_result < 0) {
        std.debug.print("ERROR: ioctl(CTLIOCGINFO) failed\n", .{});
        std.process.exit(3);
    }

    var utun_fd: posix.fd_t = undefined;
    var found = false;

    for (0..64) |unit_number| {
        utun_fd = posix.socket(AF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL) catch continue;

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
            posix.close(utun_fd);
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
        posix.close(utun_fd);
        std.debug.print("ERROR: getsockopt(UTUN_OPT_IFNAME) failed\n", .{});
        std.process.exit(5);
    }

    var name_len: usize = 0;
    while (name_len < 64 and device_name[name_len] != 0) : (name_len += 1) {}

    // Set non-blocking
    const O_NONBLOCK: usize = 0x0004;
    const flags = posix.fcntl(utun_fd, posix.F.GETFL, 0) catch {
        posix.close(utun_fd);
        std.debug.print("ERROR: fcntl(GETFL) failed\n", .{});
        std.process.exit(6);
    };
    _ = posix.fcntl(utun_fd, posix.F.SETFL, flags | O_NONBLOCK) catch {
        posix.close(utun_fd);
        std.debug.print("ERROR: fcntl(SETFL) failed\n", .{});
        std.process.exit(6);
    };

    const dev_name_slice = device_name[0..name_len];

    // Step 2: Configure with temporary IP via ifconfig (must use full path, running as root)
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "/sbin/ifconfig {s} 169.254.1.1 169.254.0.1 netmask 255.255.0.0 up", .{dev_name_slice}) catch {
        posix.close(utun_fd);
        std.process.exit(7);
    };

    var child = std.process.Child.init(
        &[_][]const u8{ "/bin/sh", "-c", cmd },
        std.heap.page_allocator,
    );
    const term = child.spawnAndWait() catch {
        posix.close(utun_fd);
        std.debug.print("ERROR: ifconfig failed to spawn\n", .{});
        std.process.exit(8);
    };

    if (term.Exited != 0) {
        posix.close(utun_fd);
        std.debug.print("ERROR: ifconfig exited with {d}\n", .{term.Exited});
        std.process.exit(9);
    }

    // Step 3: Connect to the parent's Unix domain socket and send the fd
    const sock_fd = posix.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0) catch {
        posix.close(utun_fd);
        std.debug.print("ERROR: socket(AF_UNIX) failed\n", .{});
        std.process.exit(10);
    };
    defer posix.close(sock_fd);

    // Build sockaddr_un
    var addr: posix.sockaddr.un = .{ .family = posix.AF.UNIX, .path = undefined };
    @memset(&addr.path, 0);
    if (socket_path.len >= addr.path.len) {
        std.debug.print("ERROR: socket path too long\n", .{});
        std.process.exit(11);
    }
    @memcpy(addr.path[0..socket_path.len], socket_path);

    posix.connect(sock_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un)) catch {
        posix.close(utun_fd);
        std.debug.print("ERROR: connect to parent socket failed\n", .{});
        std.process.exit(12);
    };

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
fn runCommandLoop(sock_fd: posix.fd_t) void {
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

        var proc = std.process.Child.init(
            &[_][]const u8{ "/bin/sh", "-c", cmd_str },
            std.heap.page_allocator,
        );
        proc.stderr_behavior = .Ignore;
        proc.stdout_behavior = .Ignore;
        const proc_term = proc.spawnAndWait() catch {
            const err_resp = [_]u8{1};
            _ = posix.write(sock_fd, &err_resp) catch break;
            continue;
        };

        const exit_code: u8 = if (proc_term.Exited <= 255) @intCast(proc_term.Exited) else 1;
        _ = posix.write(sock_fd, &[_]u8{exit_code}) catch break;
    }
}

/// Read exactly buf.len bytes from fd. Returns false on EOF or error.
fn readExact(fd: posix.fd_t, buf: []u8) bool {
    var total: usize = 0;
    while (total < buf.len) {
        const n = posix.read(fd, buf[total..]) catch return false;
        if (n == 0) return false;
        total += n;
    }
    return true;
}
