const std = @import("std");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const net = std.net;
const log = std.log.scoped(.farm);
const Sha1 = @import("../../mayaqua/encrypt/hash.zig").Sha1;

// ── Constants ────────────────────────────────────────────────────────

/// C `SERVER_TYPE_STANDALONE` (Server.h:397).
pub const server_type_standalone: u32 = 0;
/// C `SERVER_TYPE_FARM_CONTROLLER` (Server.h:398).
pub const server_type_farm_controller: u32 = 1;
/// C `SERVER_TYPE_FARM_MEMBER` (Server.h:399).
pub const server_type_farm_member: u32 = 2;

/// C `CEDAR_CLIENT` (Cedar.h:1050).
pub const cedar_client: u32 = 0;
/// C `CEDAR_STANDALONE_SERVER` (Cedar.h:1051).
pub const cedar_standalone_server: u32 = 1;
/// C `CEDAR_FARM_CONTROLLER` (Cedar.h:1052).
pub const cedar_farm_controller: u32 = 2;
/// C `CEDAR_FARM_MEMBER` (Cedar.h:1053).
pub const cedar_farm_member: u32 = 3;

/// C `HUB_TYPE_STANDALONE` (Cedar.h:411).
pub const hub_type_standalone: u32 = 0;
/// C `HUB_TYPE_FARM_STATIC` (Cedar.h:412).
pub const hub_type_farm_static: u32 = 1;
/// C `HUB_TYPE_FARM_DYNAMIC` (Cedar.h:413).
pub const hub_type_farm_dynamic: u32 = 2;

/// C `FARM_BASE_POINT` (Cedar.h:1054) — reference value for cluster score.
pub const farm_base_point: u32 = 100000;
/// C `FARM_DEFAULT_WEIGHT` (Cedar.h:1055).
pub const farm_default_weight: u32 = 100;

/// C `SERVER_FARM_CONTROL_INTERVAL` (Server.h:283) — 10 seconds.
pub const farm_control_interval_ms: u64 = 10_000;
/// C `SERVER_CONTROL_TCP_TIMEOUT` (Server.h:284) — 60 seconds.
pub const farm_control_tcp_timeout_ms: u64 = 60_000;
/// C `RETRY_CONNECT_TO_CONTROLLER_INTERVAL` (Server.h:285) — 1 second.
pub const retry_connect_interval_ms: u64 = 1_000;

/// C `MAX_PUBLIC_PORT_NUM` (Server.h:287).
pub const max_public_port_num: usize = 128;
/// C `MAX_HOST_NAME_LEN` (Cedar.h:59).
pub const max_host_name_len: usize = 255;

/// C `CEDAR_SERVER_FARM_STR` (GlobalConst.h) — farm RPC product string.
pub const cedar_server_farm_str: []const u8 = "SoftEther VPN Server (Cluster RPC Mode)";

const sha1_size = Sha1.digest_length;

// ── Farm Hub List ────────────────────────────────────────────────────

/// C `HUB_LIST` (Server.h:154) — virtual HUB hosted by a farm member.
pub const FarmHub = struct {
    /// The farm member hosting this HUB.
    member: ?*FarmMember = null,
    dynamic_hub: bool = false,
    name: [max_host_name_len + 1:0]u8 = .{0} ** (max_host_name_len + 1),
    num_sessions: u32 = 0,
    num_sessions_client: u32 = 0,
    num_sessions_bridge: u32 = 0,
    num_mac_tables: u32 = 0,
    num_ip_tables: u32 = 0,

    pub fn setName(self: *FarmHub, n: []const u8) void {
        const len = @min(n.len, max_host_name_len);
        @memcpy(self.name[0..len], n[0..len]);
        self.name[len] = 0;
    }
};

// ── Farm Member ──────────────────────────────────────────────────────

/// C `FARM_MEMBER` (Server.h:178) — one node in the cluster.
///
/// A farm member entry lives on the controller's `FarmMemberList`. When
/// `me` is true, this is the controller's own self-referencing entry.
pub const FarmMember = struct {
    allocator: Allocator,

    /// True for the controller's own self-entry (C `FARM_MEMBER.Me`).
    me: bool = false,
    /// IP address (host byte order).
    ip: u32 = 0,
    /// Public port numbers.
    ports: []u32 = &.{},
    /// Hostname (network-visible).
    hostname: [max_host_name_len + 1:0]u8 = .{0} ** (max_host_name_len + 1),
    /// Server certificate (DER-encoded).
    server_cert: ?[]u8 = null,
    /// List of HUBs hosted by this member.
    hub_list: std.ArrayListUnmanaged(FarmHub) = .{},
    /// Task queue for RPC dispatch (protected by `queue_lock`).
    task_queue: std.ArrayListUnmanaged(*FarmTask) = .{},
    /// Lock protecting `task_queue` between the service loop (consumer)
    /// and `postTask` callers (producer).
    queue_lock: std.Thread.Mutex = .{},
    /// Load balancing score (higher = less loaded).
    point: u32 = 0,
    /// Performance weight (C `FARM_MEMBER.Weight`).
    weight: u32 = farm_default_weight,
    /// Connected time (epoch ms).
    connected_time: u64 = 0,
    /// Current session count.
    num_sessions: u32 = 0,
    /// Maximum sessions.
    max_sessions: u32 = 0,
    /// TCP connection count.
    num_tcp_connections: u32 = 0,
    /// Assigned client licenses.
    assigned_client_license: u32 = 0,
    /// Assigned bridge licenses.
    assigned_bridge_license: u32 = 0,
    /// Halting flag.
    halting: bool = false,

    pub fn init(allocator: Allocator) FarmMember {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FarmMember) void {
        for (self.hub_list.items) |*hub| {
            _ = hub;
        }
        self.hub_list.deinit(self.allocator);
        for (self.task_queue.items) |task| {
            task.deinit();
            self.allocator.destroy(task);
        }
        self.task_queue.deinit(self.allocator);
        if (self.server_cert) |cert| self.allocator.free(cert);
        if (self.ports.len > 0) self.allocator.free(self.ports);
    }

    pub fn setHostname(self: *FarmMember, h: []const u8) void {
        const len = @min(h.len, max_host_name_len);
        @memcpy(self.hostname[0..len], h[0..len]);
        self.hostname[len] = 0;
    }
};

// ── Farm Task ────────────────────────────────────────────────────────

/// C `FARM_TASK` (Server.h:167) — single RPC request/response pair queued
/// from a controller to a member (or vice versa).
pub const FarmTask = struct {
    complete: bool = false,
    task_name: [260:0]u8 = .{0} ** 260,
    host_name: [260:0]u8 = .{0} ** 260,
    request: ?@import("../../cedar/protocol/pack.zig").Pack = null,
    response: ?@import("../../cedar/protocol/pack.zig").Pack = null,

    pub fn deinit(self: *FarmTask) void {
        if (self.request) |*r| r.deinit();
        if (self.response) |*r| r.deinit();
    }
};

// ── Farm Controller (member-side) ────────────────────────────────────

/// C `FARM_CONTROLLER` (Server.h:205) — member-side state for the
/// connection from a FARM_MEMBER to the FARM_CONTROLLER.
pub const FarmController = struct {
    allocator: Allocator,

    /// True if currently connected to the controller.
    online: bool = false,
    /// Last error code.
    last_error: u32 = 0,
    /// Start time (epoch ms).
    started_time: u64 = 0,
    /// Current connection start time.
    current_connected_time: u64 = 0,
    /// First-ever connection time.
    first_connected_time: u64 = 0,
    /// Successful connection count.
    num_connected: u32 = 0,
    /// Total connection attempts.
    num_try: u32 = 0,
    /// Failure count.
    num_failed: u32 = 0,
    /// Currently connected flag.
    is_connected: bool = false,
    /// Halt flag — set to true to stop the control thread.
    halting: bool = false,

    pub fn init(allocator: Allocator) FarmController {
        return .{
            .allocator = allocator,
            .started_time = nowMs(),
        };
    }

    pub fn deinit(self: *FarmController) void {
        _ = self;
    }
};

// ── Farm State ───────────────────────────────────────────────────────

/// Farm-related server state. Stored as an optional field on the
/// `dispatch.Server` and managed by `vpnserver/main.zig` during lifecycle
/// transitions.
///
/// Mirrors C `SERVER` farm fields (Server.h:251) that are relevant to
/// the Zig server implementation.
pub const FarmState = struct {
    allocator: Allocator,

    /// Current active server type (`SERVER_TYPE_*`).
    server_type: u32 = server_type_standalone,
    /// Pending server type (set by `setServerType`, takes effect on reboot).
    updated_server_type: u32 = server_type_standalone,

    /// Controller-only mode (C `SERVER.ControllerOnly`).
    /// When true the farm controller does not host local HUBs.
    controller_only: bool = false,

    /// Performance weight for load balancing.
    weight: u32 = farm_default_weight,

    // ── Farm member fields (when server_type == FARM_MEMBER) ──
    /// Controller hostname.
    controller_name: [max_host_name_len + 1:0]u8 = .{0} ** (max_host_name_len + 1),
    /// Controller port.
    controller_port: u32 = 0,
    /// Shared password for farm member authentication (SHA-1 hash).
    member_password: [sha1_size]u8 = .{0} ** sha1_size,
    /// Public IP of this member (host byte order).
    public_ip: u32 = 0,
    /// Number of public ports.
    num_public_port: u32 = 0,
    /// Public port numbers.
    public_ports: [max_public_port_num]u32 = .{0} ** max_public_port_num,

    // ── Farm controller fields (when server_type == FARM_CONTROLLER) ──
    /// List of all connected farm members (C `SERVER.FarmMemberList`).
    members: std.ArrayListUnmanaged(FarmMember) = .{},
    /// Self-referencing entry on the controller (C `SERVER.Me`).
    me: ?*FarmMember = null,

    /// Whether the farm controller has been initialized.
    farm_controller_inited: bool = false,

    // ── Cluster-wide totals (maintained by farm control thread) ──
    /// Total sessions across all farm members.
    current_total_num_sessions_on_farm: u32 = 0,
    /// Total client licenses assigned cluster-wide.
    current_assigned_client_license: u32 = 0,
    /// Total bridge licenses assigned cluster-wide.
    current_assigned_bridge_license: u32 = 0,

    pub fn init(allocator: Allocator) FarmState {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *FarmState) void {
        for (self.members.items) |*m| {
            m.deinit();
        }
        self.members.deinit(self.allocator);
        if (self.me) |me| {
            me.deinit();
            self.allocator.destroy(me);
        }
    }

    // ── Queries ─────────────────────────────────────────────────────

    pub fn isStandalone(self: *const FarmState) bool {
        return self.server_type == server_type_standalone;
    }

    pub fn isFarmController(self: *const FarmState) bool {
        return self.server_type == server_type_farm_controller;
    }

    pub fn isFarmMember(self: *const FarmState) bool {
        return self.server_type == server_type_farm_member;
    }

    pub fn cedarType(self: *const FarmState) u32 {
        return switch (self.server_type) {
            server_type_standalone => cedar_standalone_server,
            server_type_farm_controller => cedar_farm_controller,
            server_type_farm_member => cedar_farm_member,
            else => cedar_client,
        };
    }

    pub fn memberCount(self: *const FarmState) usize {
        return self.members.items.len;
    }

    // ── State transitions ───────────────────────────────────────────

    /// C `SiSetServerType` (Server.c:6832) — store pending server type
    /// and cluster parameters. Does NOT reboot; call `prepareReboot`
    /// afterwards to trigger a full restart.
    pub fn setServerType(
        self: *FarmState,
        new_type: u32,
        ip: u32,
        num_port: u32,
        ports: []const u32,
        controller_name: []const u8,
        controller_port: u32,
        password: []const u8,
        weight: u32,
        controller_only: bool,
    ) void {
        // Validate member parameters.
        if (new_type == server_type_farm_member) {
            if (num_port == 0 or ports.len == 0 or
                controller_name.len == 0 or
                controller_port == 0 or
                password.len == 0 or
                num_port > max_public_port_num)
            {
                log.warn("SiSetServerType: invalid farm member parameters", .{});
                return;
            }
        }

        const w = if (weight == 0) farm_default_weight else weight;

        self.updated_server_type = new_type;
        self.weight = w;

        if (new_type == server_type_farm_member) {
            // Store controller connection info.
            const len = @min(controller_name.len, max_host_name_len);
            @memcpy(self.controller_name[0..len], controller_name[0..len]);
            self.controller_name[len] = 0;
            self.controller_port = controller_port;

            // Hash the password: SHA-1 of the plaintext password.
            if (password.len > 0) {
                var h = Sha1.init(.{});
                h.update(password);
                h.final(&self.member_password);
            }

            self.public_ip = ip;
            self.num_public_port = @min(num_port, max_public_port_num);
            for (0..self.num_public_port) |i| {
                if (i < ports.len)
                    self.public_ports[i] = ports[i];
            }
        }

        if (new_type == server_type_farm_controller) {
            self.controller_only = controller_only;
        }
    }

    /// Initialize as a farm controller — create self-entry and member list.
    /// C `SiNewServerEx` lines 11073-11093.
    pub fn initAsController(self: *FarmState, hostname: []const u8) !void {
        self.members = std.ArrayListUnmanaged(FarmMember){};
        self.me = try self.allocator.create(FarmMember);
        self.me.?.* = FarmMember.init(self.allocator);
        self.me.?.me = true;
        self.me.?.weight = self.weight;
        self.me.?.setHostname(hostname);
        self.farm_controller_inited = true;
        log.info("Farm controller initialized (self-entry: {s})", .{hostname});
    }

    /// Initialize as a farm member — create the FarmController struct.
    /// C `SiNewServerEx` line 11068.
    pub fn initAsMember(self: *FarmState) FarmController {
        log.info("Farm member initialized (controller: {s}:{d})", .{
            std.mem.sliceTo(&self.controller_name, 0),
            self.controller_port,
        });
        return FarmController.init(self.allocator);
    }

    // ── Load balancing ──────────────────────────────────────────────

    /// C `SiCalcPoint` (Server.c:6795) — calculate cluster load score.
    ///
    /// Formula: `(max_sessions - min(num * 100.0 / weight, max_sessions)) * FARM_BASE_POINT / max_sessions`
    ///
    /// Higher score = less loaded = preferred for new connections.
    /// A score of `farm_base_point` means completely idle.
    pub fn calcPoint(self: *const FarmState, num_sessions: u32) u32 {
        const max_sessions: u32 = 1000; // default if not reported
        const w = if (self.weight == 0) farm_default_weight else self.weight;

        if (max_sessions == 0) return 0;

        const effective: f64 = @floatFromInt(num_sessions * 100 / w);
        const cap: f64 = @floatFromInt(max_sessions);
        const used = @min(effective, cap);
        const available = cap - used;

        return @intFromFloat(available * @as(f64, @floatFromInt(farm_base_point)) / cap);
    }

    // ── Farm member selection ───────────────────────────────────────

    /// Find the next farm member with the best (highest) score.
    /// C `SiGetNextFarmMember` (Server.c:8158) — simplified version
    /// that returns the least-loaded member.
    pub fn getNextFarmMember(self: *FarmState) ?*FarmMember {
        if (self.members.items.len == 0) return null;

        var best_idx: ?usize = null;
        var best_point: u32 = 0;

        for (self.members.items, 0..) |*m, i| {
            if (m.halting) continue;
            if (m.point > best_point) {
                best_point = m.point;
                best_idx = i;
            }
        }

        if (best_idx) |idx| return &self.members.items[idx];
        return null;
    }

    /// Find the farm member that hosts a specific HUB.
    /// C `SiGetHubHostingMember` (Server.c:8214) — simplified.
    pub fn getHubHostingMember(self: *FarmState, hub_name: []const u8) ?*FarmMember {
        for (self.members.items) |*m| {
            if (m.halting) continue;
            for (m.hub_list.items) |hub| {
                if (mem.eql(u8, hub.name[0..mem.indexOfScalar(u8, &hub.name, 0) orelse hub.name.len], hub_name)) {
                    return m;
                }
            }
        }
        return null;
    }
};

// ── Helpers ──────────────────────────────────────────────────────────

fn nowMs() u64 {
    return @intCast(@as(i64, @intCast(std.time.timestamp())) * 1000);
}

// ── Tests ────────────────────────────────────────────────────────────

test "server type constants" {
    try std.testing.expectEqual(@as(u32, 0), server_type_standalone);
    try std.testing.expectEqual(@as(u32, 1), server_type_farm_controller);
    try std.testing.expectEqual(@as(u32, 2), server_type_farm_member);
}

test "cedar type mapping" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    state.server_type = server_type_standalone;
    try std.testing.expectEqual(cedar_standalone_server, state.cedarType());

    state.server_type = server_type_farm_controller;
    try std.testing.expectEqual(cedar_farm_controller, state.cedarType());

    state.server_type = server_type_farm_member;
    try std.testing.expectEqual(cedar_farm_member, state.cedarType());
}

test "FarmState queries" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    state.server_type = server_type_standalone;
    try std.testing.expect(state.isStandalone());
    try std.testing.expect(!state.isFarmController());
    try std.testing.expect(!state.isFarmMember());

    state.server_type = server_type_farm_controller;
    try std.testing.expect(!state.isStandalone());
    try std.testing.expect(state.isFarmController());

    state.server_type = server_type_farm_member;
    try std.testing.expect(state.isFarmMember());
}

test "setServerType validates member params" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    // Missing required member fields → no change.
    state.setServerType(
        server_type_farm_member,
        0, // ip
        0, // num_port
        &.{}, // ports
        "", // controller_name
        0, // controller_port
        "", // password
        100, // weight
        false, // controller_only
    );
    try std.testing.expectEqual(server_type_standalone, state.updated_server_type);

    // Valid member fields → update.
    state.setServerType(
        server_type_farm_member,
        0x0A00_0001, // ip: 10.0.0.1
        1, // num_port
        &.{443}, // ports
        "controller.example.com", // controller_name
        995, // controller_port
        "secret123", // password
        200, // weight
        false, // controller_only
    );
    try std.testing.expectEqual(server_type_farm_member, state.updated_server_type);
    try std.testing.expectEqual(@as(u32, 200), state.weight);
    try std.testing.expectEqual(@as(u32, 0x0A00_0001), state.public_ip);
    try std.testing.expectEqual(@as(u32, 995), state.controller_port);
    try std.testing.expect(!std.mem.eql(u8, &state.member_password, &([_]u8{0} ** sha1_size)));

    // controller_only set for controller type.
    state.setServerType(
        server_type_farm_controller,
        0, 0, &.{}, "", 0, "", 100, true,
    );
    try std.testing.expectEqual(server_type_farm_controller, state.updated_server_type);
    try std.testing.expect(state.controller_only);
}

test "calcPoint load balancing" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    state.weight = 100;
    // Zero sessions → fully available → point = farm_base_point (100000).
    const p0 = state.calcPoint(0);
    try std.testing.expectEqual(farm_base_point, p0);

    // 50 sessions with weight=100 → some used → point < base.
    const p50 = state.calcPoint(50);
    try std.testing.expect(p50 < farm_base_point);
    try std.testing.expect(p50 > 0);

    // 100 sessions with weight=100 → fully loaded → point = 0.
    const p100 = state.calcPoint(100);
    try std.testing.expectEqual(@as(u32, 0), p100);
}

test "FarmMember basic lifecycle" {
    var m = FarmMember.init(std.testing.allocator);
    m.setHostname("node1.example.com");
    try std.testing.expectEqualStrings("node1.example.com", std.mem.sliceTo(&m.hostname, 0));
    m.deinit();
}

test "initAsController creates self-entry" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    state.weight = 150;
    try state.initAsController("ctrl1.example.com");

    try std.testing.expect(state.farm_controller_inited);
    try std.testing.expect(state.me != null);
    try std.testing.expect(state.me.?.me);
    try std.testing.expectEqual(@as(u32, 150), state.me.?.weight);
    try std.testing.expectEqualStrings("ctrl1.example.com", std.mem.sliceTo(&state.me.?.hostname, 0));
}

test "getNextFarmMember returns highest score" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    var m1 = FarmMember.init(std.testing.allocator);
    m1.point = 50000;
    var m2 = FarmMember.init(std.testing.allocator);
    m2.point = 80000;
    var m3 = FarmMember.init(std.testing.allocator);
    m3.point = 30000;
    m3.halting = true;

    try state.members.append(state.allocator, m1);
    try state.members.append(state.allocator, m2);
    try state.members.append(state.allocator, m3);

    const best = state.getNextFarmMember();
    try std.testing.expect(best != null);
    try std.testing.expectEqual(@as(u32, 80000), best.?.point);
}

test "getNextFarmMember skips halting members" {
    var state = FarmState.init(std.testing.allocator);
    defer state.deinit();

    var m1 = FarmMember.init(std.testing.allocator);
    m1.halting = true;
    m1.point = 99999;
    try state.members.append(state.allocator, m1);

    try std.testing.expect(state.getNextFarmMember() == null);
}

test "hub type constants" {
    try std.testing.expectEqual(@as(u32, 0), hub_type_standalone);
    try std.testing.expectEqual(@as(u32, 1), hub_type_farm_static);
    try std.testing.expectEqual(@as(u32, 2), hub_type_farm_dynamic);
}

test "FarmHub.setName" {
    var hub: FarmHub = .{};
    hub.setName("TEST_HUB");
    try std.testing.expectEqualStrings("TEST_HUB", std.mem.sliceTo(&hub.name, 0));
}
