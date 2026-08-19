//! LocalBridge — connects a virtual hub to a physical NIC.
//!
//! Mirrors C `Bridge.c` + `BridgeUnix.c`: opens an L2 port (AF_PACKET on
//! Linux, BPF on macOS, Npcap on Windows) on a named interface and runs
//! the bridge pump (loop.zig) in a dedicated thread.  Frames flow:
//!
//!   NIC  →  L2 port  →  BridgeEngine (learn/resolve)  →  session sink
//!   session sink  →  BridgeEngine  →  L2 port  →  NIC
//!
//! The caller owns the `LocalBridge` instance; `start()` spawns the thread
//! and `stop()` joins it.  Lifecycle is: `init → start → stop → deinit`.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

const port_mod = @import("../adapter/port.zig");
const NetPort = port_mod.NetPort;

const loop_mod = @import("loop.zig");
const BridgeLoop = loop_mod.BridgeLoop;
const BridgeStats = loop_mod.BridgeStats;
const SessionSink = loop_mod.SessionSink;

const af_packet = @import("../adapter/af_packet.zig");
const AfPacketPort = af_packet.AfPacketPort;

/// One LocalBridge instance: a named NIC bridged to a session sink.
pub const LocalBridge = struct {
    allocator: Allocator,
    /// Interface name (e.g. "eth0", "en0").
    device_name: []const u8,
    /// Hub this bridge is attached to.
    hub_name: []const u8,
    /// The AF_PACKET port backing this bridge (null until start()).
    af_port: ?AfPacketPort = null,
    /// The bridge pump (null until start()).
    bridge_loop: ?BridgeLoop = null,
    /// Pump thread handle (null when not running).
    thread: ?Thread = null,
    /// Signal the pump thread to stop.
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Whether the pump is currently running.
    active: bool = false,
    /// Tap mode flag (currently unused, reserved for future TAP support).
    tap_mode: bool = false,

    pub const InitError = error{
        NotLinux,
        InterfaceNotFound,
        OpenFailed,
        NoCapability,
    };

    pub const StartError = error{
        OutOfMemory,
        AlreadyStarted,
        PortNotOpen,
        BridgeInitFailed,
    };

    /// Create a LocalBridge.  Does not open the port or start the thread.
    pub fn init(allocator: Allocator, device_name: []const u8, hub_name: []const u8) LocalBridge {
        return .{
            .allocator = allocator,
            .device_name = device_name,
            .hub_name = hub_name,
        };
    }

    pub fn deinit(self: *LocalBridge) void {
        self.stop();
        if (self.bridge_loop) |*bl| bl.deinit();
        self.bridge_loop = null;
        if (self.af_port) |*port| port.close();
        self.af_port = null;
    }

    /// Open the AF_PACKET port on the named interface.
    pub fn openPort(self: *LocalBridge) InitError!void {
        if (builtin.os.tag != .linux) return error.NotLinux;
        var port = AfPacketPort{};
        port.ifname = self.device_name;
        port.open() catch |err| {
            std.log.err("LocalBridge: open {s} failed: {s}", .{ self.device_name, @errorName(err) });
            return switch (err) {
                af_packet.AfPacketError.NotLinux => error.NotLinux,
                af_packet.AfPacketError.InterfaceNotFound => error.InterfaceNotFound,
                af_packet.AfPacketError.NoCapability => error.NoCapability,
                else => error.OpenFailed,
            };
        };
        self.af_port = port;
        std.log.info("LocalBridge: opened {s} (ifindex={d})", .{ self.device_name, port.ifindex });
    }

    /// Start the bridge pump thread.  `sink` is the session-side callback.
    pub fn start(self: *LocalBridge, sink: SessionSink) StartError!void {
        if (self.active) return error.AlreadyStarted;
        if (self.af_port == null) return error.PortNotOpen;

        var ports_slice = try self.allocator.alloc(NetPort, 1);
        errdefer self.allocator.free(ports_slice);
        ports_slice[0] = af_packet.afPacketPort(&self.af_port.?, self.device_name);

        var bl = BridgeLoop.init(self.allocator, ports_slice, sink, 4096, 300) catch return error.BridgeInitFailed;
        errdefer bl.deinit();
        self.allocator.free(ports_slice);

        self.bridge_loop = bl;
        self.stop_flag.store(false, .seq_cst);
        self.active = true;

        self.thread = Thread.spawn(.{}, pumpThread, .{self}) catch {
            self.active = false;
            self.bridge_loop.?.deinit();
            self.bridge_loop = null;
            return error.BridgeInitFailed;
        };
        std.log.info("LocalBridge: {s} → hub {s} started", .{ self.device_name, self.hub_name });
    }

    /// Signal the pump thread to stop and join it.
    pub fn stop(self: *LocalBridge) void {
        if (!self.active) return;
        self.stop_flag.store(true, .seq_cst);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.active = false;
        std.log.info("LocalBridge: {s} stopped", .{self.device_name});
    }

    /// Snapshot of this bridge's stats (delegates to the pump).
    pub fn getStats(self: *const LocalBridge) BridgeStats {
        if (self.bridge_loop) |bl| return bl.getStats();
        return .{};
    }

    /// Pump thread entry point: polls L2 ports + session, dispatches frames.
    fn pumpThread(self: *LocalBridge) void {
        const bl = &self.bridge_loop.?;
        const port_fd = self.af_port.?.fd;
        var buf: [loop_mod.SESSION_FRAME_BUDGET]u8 = undefined;

        while (!self.stop_flag.load(.seq_cst)) {
            // Poll the L2 port for incoming frames
            var pfd = [_]std.posix.pollfd{.{
                // pollfd.fd is a SOCKET pointer on Windows, not an int.
                .fd = if (comptime builtin.os.tag == .windows) @ptrCast(port_fd) else port_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const n = std.posix.poll(&pfd, 100) catch break;
            if (n == 0) continue;

            if (pfd[0].revents & std.posix.POLL.IN != 0) {
                if (self.af_port.?.read(&buf)) |maybe_len| {
                    if (maybe_len) |len| {
                        if (len >= 14) {
                            bl.dispatchPortFrame(0, buf[0..len]);
                        }
                    }
                } else |_| break;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "LocalBridge init/deinit" {
    const bridge = LocalBridge.init(std.testing.allocator, "eth0", "SECURE");
    try std.testing.expectEqualStrings("eth0", bridge.device_name);
    try std.testing.expectEqualStrings("SECURE", bridge.hub_name);
    try std.testing.expect(!bridge.active);
    try std.testing.expect(bridge.af_port == null);
    try std.testing.expect(bridge.bridge_loop == null);
}

test "LocalBridge stop is idempotent" {
    var bridge = LocalBridge.init(std.testing.allocator, "lo", "TEST");
    bridge.stop();
    bridge.stop();
    try std.testing.expect(!bridge.active);
}
