//! Spanning Tree Protocol (IEEE 802.1D) for the L2 bridge.
//!
//! Prevents broadcast storms in multi-switch topologies by electing a
//! root bridge and blocking redundant paths. Implements the core STP
//! state machine: root election, BPDU processing, port state transitions
//! (Blocking → Listening → Learning → Forwarding), and topology change
//! notification.
//!
//! Design:
//! - `StpBridge` owns per-port state and the bridge-level root election.
//! - The bridge pump calls `processBpdu` on received BPDUs and `tick`
//!   once per second to drive timers (hello, max-age, forward-delay).
//! - `isForwarding(port)` gates user-frame forwarding in `writePort`.
//!
//! Reference: IEEE 802.1D-2004 §17 (STP), §9.2.9 (BPDU format).

const std = @import("std");
const fdb_mod = @import("fdb.zig");
const MacAddress = fdb_mod.MacAddress;

// ============================================================================
// Constants
// ============================================================================

/// STP ethertype (network byte order).
pub const STP_ETHERTYPE: u16 = 0x0000;
/// Actually, STP BPDUs are sent to the bridge group address with LLC.
/// For simplicity, we use a custom ethertype to identify STP frames.
/// In production, STP uses 0x0000 + LLC; here we use 0x0027 as a sentinel.
pub const BPDU_ETHERTYPE: u16 = 0x0027;

/// BPDU protocol version (802.1D).
pub const BPDU_VERSION: u8 = 0;
/// Configuration BPDU type.
pub const BPDU_TYPE_CONFIG: u8 = 0x00;
/// Topology Change Notification BPDU type.
pub const BPDU_TYPE_TCN: u8 = 0x80;
/// Topology Change Acknowledgment BPDU type.
pub const BPDU_TYPE_TCA: u8 = 0x80;

/// Default hello time in seconds.
pub const DEFAULT_HELLO_S: u32 = 2;
/// Default max age in seconds.
pub const DEFAULT_MAX_AGE_S: u32 = 20;
/// Default forward delay in seconds.
pub const DEFAULT_FORWARD_DELAY_S: u32 = 15;
/// Default bridge priority (0–65535, lower wins).
pub const DEFAULT_BRIDGE_PRIORITY: u16 = 32768;
/// Default port priority (0–255).
pub const DEFAULT_PORT_PRIORITY: u8 = 128;
/// Default path cost for a 100 Mbps link.
pub const DEFAULT_PATH_COST: u32 = 19;

/// Maximum number of STP ports.
pub const MAX_PORTS: usize = 256;

/// Invalid port index sentinel.
pub const PORT_NONE: u16 = 0xFFFF;

// ============================================================================
// Types
// ============================================================================

/// 8-byte Bridge ID: 2-byte priority + 6-byte MAC.
pub const BridgeId = extern struct {
    priority: u16,
    mac: MacAddress,

    pub fn order(self: *const BridgeId) u64 {
        // Composite for comparison: priority in high 16 bits, MAC in low 48.
        return (@as(u64, self.priority) << 48) |
            (@as(u64, self.mac[0]) << 40) |
            (@as(u64, self.mac[1]) << 32) |
            (@as(u64, self.mac[2]) << 24) |
            (@as(u64, self.mac[3]) << 16) |
            (@as(u64, self.mac[4]) << 8) |
            @as(u64, self.mac[5]);
    }

    pub fn lessThan(self: *const BridgeId, other: *const BridgeId) bool {
        return self.order() < other.order();
    }
};

/// 2-byte Port ID: 1-byte priority + 1-byte port number.
pub const PortId = extern struct {
    priority: u8,
    port_num: u8,

    pub fn order(self: *const PortId) u16 {
        return (@as(u16, self.priority) << 8) | @as(u16, self.port_num);
    }

    pub fn lessThan(self: *const PortId, other: *const PortId) bool {
        return self.order() < other.order();
    }
};

/// STP port states (IEEE 802.1D §17.5).
pub const PortState = enum(u8) {
    /// Port is down — no BPDU processing, no forwarding.
    disabled = 0,
    /// Port is up but blocks data frames. BPDUs are received and processed.
    blocking = 1,
    /// Transitional state: BPDUs processed, no data forwarding, FDB not learned.
    listening = 2,
    /// Transitional state: same as listening but FDB learning enabled.
    learning = 3,
    /// Fully operational: BPDUs processed, data forwarded, FDB learned.
    forwarding = 4,
};

/// STP port roles (IEEE 802.1D §17.6).
pub const PortRole = enum(u8) {
    /// Port is disabled or not yet assigned a role.
    disabled = 0,
    /// Port is on the best path toward the root bridge.
    root = 1,
    /// Port is on the best path away from the root bridge.
    designated = 2,
    /// Port provides an alternate path to the root (blocked).
    alternate = 3,
};

/// Configuration BPDU (IEEE 802.1D §9.2.9).
pub const ConfigBpdu = struct {
    /// Root bridge ID.
    root_id: BridgeId,
    /// Root path cost.
    root_path_cost: u32,
    /// Sender bridge ID.
    sender_id: BridgeId,
    /// Sender port ID.
    sender_port_id: PortId,
    /// Message age in 256ths of a second.
    message_age: u16,
    /// Maximum age in 256ths of a second.
    max_age: u16,
    /// Hello time in 256ths of a second.
    hello_time: u16,
    /// Forward delay in 256ths of a second.
    forward_delay: u16,
};

/// Topology Change Notification BPDU (IEEE 802.1D §9.2.9).
pub const TcnBpdu = struct {};

/// STP port-level state.
pub const StpPort = struct {
    /// Port ID (priority + number).
    port_id: PortId,
    /// Current port state.
    state: PortState = .disabled,
    /// Current port role.
    role: PortRole = .disabled,
    /// Path cost toward the root bridge.
    path_cost: u32 = DEFAULT_PATH_COST,
    /// Designated bridge ID for this segment.
    designated_id: BridgeId = .{ .priority = 0xFFFF, .mac = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
    /// Designated port ID for this segment.
    designated_port_id: PortId = .{ .priority = 0xFF, .port_num = 0xFF },
    /// Root bridge ID as last received from this port.
    last_root_id: BridgeId = .{ .priority = 0xFFFF, .mac = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
    /// Root path cost as last received from this port.
    last_root_path_cost: u32 = 0,
    /// Sender bridge ID as last received from this port.
    last_sender_id: BridgeId = .{ .priority = 0xFFFF, .mac = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
    /// Sender port ID as last received from this port.
    last_sender_port_id: PortId = .{ .priority = 0xFF, .port_num = 0xFF },
    /// Time since last BPDU was received (seconds).
    info_age_s: u32 = 0,
    /// Forward delay timer (seconds).
    forward_delay_timer_s: u32 = 0,
    /// Whether we have received a BPDU on this port.
    bpdu_received: bool = false,
    /// Whether this port is edge (connected to end hosts, no BPDUs expected).
    is_edge: bool = false,
};

/// The STP bridge instance. Owns bridge-level state and per-port STP state.
pub const StpBridge = struct {
    /// Bridge ID (priority + MAC).
    bridge_id: BridgeId,
    /// Current root bridge ID (initially self).
    root_id: BridgeId,
    /// Root path cost (0 if self is root).
    root_path_cost: u32 = 0,
    /// Port that leads to the root bridge.
    root_port: u16 = PORT_NONE,
    /// Whether this bridge is currently the root.
    is_root: bool = true,
    /// Per-port STP state. Length must match `port_count`.
    ports: []StpPort,
    /// Number of ports.
    port_count: u16,
    /// Hello time in seconds.
    hello_s: u32 = DEFAULT_HELLO_S,
    /// Max age in seconds.
    max_age_s: u32 = DEFAULT_MAX_AGE_S,
    /// Forward delay in seconds.
    forward_delay_s: u32 = DEFAULT_FORWARD_DELAY_S,
    /// Hello timer — counts down to next BPDU send.
    hello_timer_s: u32 = DEFAULT_HELLO_S,
    /// Topology change detected flag.
    topology_change: bool = false,
    /// Topology change timer (35 seconds = 20s max-age + 15s forward delay).
    topology_change_timer_s: u32 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, port_count: u16, bridge_mac: MacAddress, priority: u16) !StpBridge {
        if (port_count == 0 or port_count > MAX_PORTS) return error.InvalidPortCount;
        const ports = try allocator.alloc(StpPort, port_count);
        errdefer allocator.free(ports);

        const bridge_id = BridgeId{ .priority = priority, .mac = bridge_mac };
        for (ports, 0..) |*p, i| {
            p.* = .{
                .port_id = .{ .priority = DEFAULT_PORT_PRIORITY, .port_num = @intCast(i + 1) },
                .state = .disabled,
                .role = .disabled,
                .path_cost = DEFAULT_PATH_COST,
                .designated_id = bridge_id,
                .designated_port_id = .{ .priority = 0xFF, .port_num = @intCast(i + 1) },
                .last_root_id = bridge_id,
                .last_root_path_cost = 0,
                .last_sender_id = bridge_id,
                .last_sender_port_id = .{ .priority = 0xFF, .port_num = @intCast(i + 1) },
                .info_age_s = 0,
                .forward_delay_timer_s = 0,
                .bpdu_received = false,
                .is_edge = false,
            };
        }

        return .{
            .bridge_id = bridge_id,
            .root_id = bridge_id,
            .ports = ports,
            .port_count = port_count,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *StpBridge) void {
        self.allocator.free(self.ports);
        self.* = undefined;
    }

    /// Enable STP on a specific port.
    pub fn enablePort(self: *StpBridge, port: u16) void {
        if (port >= self.port_count) return;
        self.ports[port].state = .blocking;
        self.ports[port].role = .designated;
    }

    /// Disable STP on a specific port.
    pub fn disablePort(self: *StpBridge, port: u16) void {
        if (port >= self.port_count) return;
        self.ports[port].state = .disabled;
        self.ports[port].role = .disabled;
    }

    /// Mark a port as an edge port (connected to end hosts).
    pub fn setEdgePort(self: *StpBridge, port: u16, is_edge: bool) void {
        if (port >= self.port_count) return;
        const was_edge = self.ports[port].is_edge;
        self.ports[port].is_edge = is_edge;
        if (is_edge and self.ports[port].state != .disabled) {
            self.ports[port].state = .forwarding;
            self.ports[port].role = .designated;
        } else if (!is_edge and was_edge) {
            // Un-setting edge: restore to blocking so STP reconverges.
            self.ports[port].state = .blocking;
            self.ports[port].role = .designated;
            self.recompute();
        }
    }

    /// Check if a port is in forwarding state (data frames may be sent).
    pub fn isForwarding(self: *const StpBridge, port: u16) bool {
        if (port >= self.port_count) return false;
        return self.ports[port].state == .forwarding;
    }

    /// Check if a port should learn MAC addresses.
    pub fn isLearning(self: *const StpBridge, port: u16) bool {
        if (port >= self.port_count) return false;
        return self.ports[port].state == .learning or self.ports[port].state == .forwarding;
    }

    /// Process a received Configuration BPDU on a port.
    /// Returns the action the bridge should take (send BPDU, change state, etc.).
    pub fn processConfigBpdu(self: *StpBridge, port: u16, bpdu: ConfigBpdu) BpduAction {
        // Session port (port_count) is a virtual port — process BPDU without
        // per-port state (it only affects root election).
        const is_session_port = port >= self.port_count;
        if (!is_session_port) {
            const p = &self.ports[port];
            p.bpdu_received = true;
            p.info_age_s = 0;
            p.last_root_id = bpdu.root_id;
            p.last_root_path_cost = bpdu.root_path_cost;
            p.last_sender_id = bpdu.sender_id;
            p.last_sender_port_id = bpdu.sender_port_id;
        }

        // Ignore BPDUs from a superior (higher bridge ID) root.
        // STP §17.2.1: Use superior information only if it's better.
        const current_root_is_self = self.is_root;
        const new_root_better = bpdu.root_id.lessThan(&self.root_id);
        const same_root = !bpdu.root_id.lessThan(&self.root_id) and !self.root_id.lessThan(&bpdu.root_id);

        // Path cost from this port to us.
        const link_cost: u32 = if (is_session_port) DEFAULT_PATH_COST else self.ports[port].path_cost;

        var action = BpduAction{ .none = {} };

        if (new_root_better) {
            // We have a new root — update root info.
            self.root_id = bpdu.root_id;
            self.root_path_cost = bpdu.root_path_cost + link_cost;
            self.root_port = port;
            self.is_root = false;
            action = .recompute;

            if (current_root_is_self) {
                action = .recompute;
            }
        } else if (same_root) {
            // Same root — check if this path is better than current.
            const new_cost = bpdu.root_path_cost + link_cost;
            if (new_cost < self.root_path_cost) {
                self.root_path_cost = new_cost;
                self.root_port = port;
                action = .recompute;
            } else if (new_cost == self.root_path_cost) {
                // Equal cost — use sender port ID as tiebreaker.
                if (bpdu.sender_port_id.lessThan(&self.ports[self.root_port].port_id)) {
                    self.root_port = port;
                    action = .recompute;
                }
            } else {
                // This BPDU is inferior — send ours if we're designated.
                if (!is_session_port and self.ports[port].role == .designated) {
                    action = .send_bpdu;
                }
            }
        } else {
            // Received root ID is worse than our root — inferior BPDU.
            if (!is_session_port and self.ports[port].role == .designated) {
                action = .send_bpdu;
            }
        }

        return action;
    }

    /// Process a received TCN BPDU on a port.
    pub fn processTcnBpdu(self: *StpBridge, port: u16) void {
        if (port > self.port_count) return; // session port (port_count) is valid
        self.topology_change = true;
        self.topology_change_timer_s = DEFAULT_MAX_AGE_S + DEFAULT_FORWARD_DELAY_S;
    }

    /// Process a received TCA (Topology Change Acknowledgment) BPDU.
    pub fn processTcaBpdu(_: *StpBridge, _: u16) void {
        // ACK received — topology change notification propagated.
        // No-op for now; the topology change flag is already set by TCN processing.
    }

    /// Timer tick — called once per second. Drives hello timer, info age,
    /// forward delay timer, and topology change timer.
    pub fn tick(self: *StpBridge) TickAction {
        var action = TickAction{};

        // Hello timer: send periodic BPDUs from designated ports (root and non-root).
        if (self.hello_timer_s > 0) {
            self.hello_timer_s -= 1;
        }
        if (self.hello_timer_s == 0) {
            self.hello_timer_s = self.hello_s;
            action.send_hello = true;
        }

        // Per-port info age: increment and age out stale BPDUs.
        var any_bpdu_received = false;
        for (self.ports) |*p| {
            if (p.state == .disabled) continue;
            if (p.bpdu_received and p.info_age_s < self.max_age_s) {
                p.info_age_s += 1;
            }
            if (p.info_age_s >= self.max_age_s and p.bpdu_received) {
                // BPDU aged out — recompute roles.
                p.bpdu_received = false;
                action.recompute = true;
            }
            if (p.bpdu_received) any_bpdu_received = true;

            // Forward delay timer: transition between states.
            if (p.state == .listening or p.state == .learning) {
                p.forward_delay_timer_s += 1;
                if (p.forward_delay_timer_s >= self.forward_delay_s) {
                    p.forward_delay_timer_s = 0;
                    if (p.state == .listening) {
                        p.state = .learning;
                    } else {
                        p.state = .forwarding;
                    }
                    action.recompute = true;
                }
            }
        }

        // If no port has received a BPDU and we are not root, re-elect self.
        if (!any_bpdu_received and !self.is_root) {
            self.is_root = true;
            self.root_id = self.bridge_id;
            self.root_path_cost = 0;
            self.root_port = PORT_NONE;
            action.recompute = true;
        }

        // Topology change timer.
        if (self.topology_change_timer_s > 0) {
            self.topology_change_timer_s -= 1;
            if (self.topology_change_timer_s == 0) {
                self.topology_change = false;
            }
        }

        return action;
    }

    /// Recompute port roles and states after a topology change.
    /// Must be called after processConfigBpdu returns .recompute or
    /// after aging out a BPDU.
    pub fn recompute(self: *StpBridge) void {
        // If we are the root, all enabled ports are designated (forwarding
        // if not explicitly blocked).
        if (self.is_root) {
            self.root_port = PORT_NONE;
            self.root_path_cost = 0;
            for (self.ports) |*p| {
                if (p.state == .disabled) continue;
                if (p.is_edge) {
                    p.role = .designated;
                    p.state = .forwarding;
                    continue;
                }
                if (p.role != .designated) {
                    p.role = .designated;
                    // Transition to listening before forwarding.
                    if (p.state == .blocking) {
                        p.state = .listening;
                        p.forward_delay_timer_s = 0;
                    }
                }
            }
            return;
        }

        // Non-root: assign roles based on best path info per port.
        for (self.ports, 0..) |*p, i| {
            if (p.state == .disabled) continue;
            if (p.is_edge) {
                p.role = .designated;
                p.state = .forwarding;
                continue;
            }

            if (@as(u16, @intCast(i)) == self.root_port) {
                // Root port: best path to root.
                p.role = .root;
                if (p.state == .blocking) {
                    p.state = .listening;
                    p.forward_delay_timer_s = 0;
                }
            } else if (p.bpdu_received) {
                // Has BPDU info — compare to determine role.
                const our_root_cost = self.root_path_cost;
                const their_root_cost = p.last_root_path_cost;
                const same_root = self.root_id.order() == p.last_root_id.order();

                if (same_root and their_root_cost + p.path_cost <= our_root_cost) {
                    // This port's path to root is equal or better — designated or equal-cost.
                    if (their_root_cost + p.path_cost < our_root_cost) {
                        p.role = .designated;
                        if (p.state == .blocking) {
                            p.state = .listening;
                            p.forward_delay_timer_s = 0;
                        }
                    } else {
                        // Equal cost — compare port IDs as tiebreaker.
                        // If our port ID is lower, we are designated; else alternate.
                        const their_port_order = p.last_sender_port_id.order();
                        const our_port_order = p.port_id.order();
                        if (our_port_order < their_port_order) {
                            p.role = .designated;
                            if (p.state == .blocking) {
                                p.state = .listening;
                                p.forward_delay_timer_s = 0;
                            }
                        } else {
                            p.role = .alternate;
                            if (p.state != .blocking and p.state != .disabled) {
                                p.state = .blocking;
                            }
                        }
                    }
                } else {
                    // Inferior BPDU — the remote bridge has a better root path.
                    // We are NOT designated for this segment; block the port.
                    p.role = .alternate;
                    if (p.state != .blocking and p.state != .disabled) {
                        p.state = .blocking;
                    }
                }
            } else {
                // No BPDU received — if we're not root, default to designated
                // but keep in listening until we hear from someone.
                p.role = .designated;
                if (p.state == .blocking) {
                    p.state = .listening;
                    p.forward_delay_timer_s = 0;
                }
            }
        }
    }

    /// Build a Configuration BPDU for a specific port.
    pub fn buildConfigBpdu(self: *const StpBridge, port: u16) ConfigBpdu {
        return .{
            .root_id = self.root_id,
            .root_path_cost = self.root_path_cost,
            .sender_id = self.bridge_id,
            .sender_port_id = if (port < self.port_count) self.ports[port].port_id else .{
                .priority = 0xFF,
                .port_num = 0xFF,
            },
            .message_age = 0,
            .max_age = @intCast(self.max_age_s << 8), // seconds → 256ths
            .hello_time = @intCast(self.hello_s << 8),
            .forward_delay = @intCast(self.forward_delay_s << 8),
        };
    }

    /// Build a TCN BPDU.
    pub fn buildTcnBpdu(_: *const StpBridge) TcnBpdu {
        return .{};
    }
};

/// Action returned by `processConfigBpdu`.
pub const BpduAction = union(enum) {
    none: void,
    recompute: void,
    send_bpdu: void,
};

/// Action returned by `tick`.
pub const TickAction = struct {
    send_hello: bool = false,
    recompute: bool = false,
};

// ============================================================================
// BPDU wire encoding/decoding
// ============================================================================

/// Encode a ConfigBpdu into an IEEE 802.1D BPDU frame.
/// Frame layout: [DST 6][SRC 6][Length 2][LLC 3][BPDU 35].
/// Total frame length: 52 bytes (padded to 60 on the wire by the port layer).
/// `src_mac` is the bridge's MAC address for the sender field.
pub fn encodeConfigBpdu(bpdu: ConfigBpdu, src_mac: MacAddress, out: []u8) !usize {
    if (out.len < 52) return error.BufferTooSmall;

    // DST: STP multicast address 01:80:C2:00:00:00
    out[0] = 0x01;
    out[1] = 0x80;
    out[2] = 0xC2;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x00;

    // SRC: bridge MAC.
    @memcpy(out[6..12], &src_mac);

    // 802.3 Length field: LLC(3) + BPDU(35) = 38 bytes.
    std.mem.writeInt(u16, out[12..14], 38, .big);

    // LLC header: DSAP=0x42, SSAP=0x42, Control=0x03
    out[14] = 0x42;
    out[15] = 0x42;
    out[16] = 0x03;

    // BPDU protocol identifier (0x0000).
    std.mem.writeInt(u16, out[17..19], 0x0000, .big);
    // BPDU version (0x00).
    out[19] = BPDU_VERSION;
    // BPDU type (0x00 = Configuration).
    out[20] = BPDU_TYPE_CONFIG;
    // BPDU flags (0x00 — no topology change proposal).
    out[21] = 0x00;

    // Root bridge ID (8 bytes: priority 2 + MAC 6).
    std.mem.writeInt(u16, out[22..24], bpdu.root_id.priority, .big);
    @memcpy(out[24..30], &bpdu.root_id.mac);

    // Root path cost (4 bytes).
    std.mem.writeInt(u32, out[30..34], bpdu.root_path_cost, .big);

    // Sender bridge ID (8 bytes).
    std.mem.writeInt(u16, out[34..36], bpdu.sender_id.priority, .big);
    @memcpy(out[36..42], &bpdu.sender_id.mac);

    // Sender port ID (2 bytes).
    std.mem.writeInt(u16, out[42..44], bpdu.sender_port_id.order(), .big);

    // Message age (2 bytes, in 256ths of a second).
    std.mem.writeInt(u16, out[44..46], bpdu.message_age, .big);

    // Max age (2 bytes).
    std.mem.writeInt(u16, out[46..48], bpdu.max_age, .big);

    // Hello time (2 bytes).
    std.mem.writeInt(u16, out[48..50], bpdu.hello_time, .big);

    // Forward delay (2 bytes).
    std.mem.writeInt(u16, out[50..52], bpdu.forward_delay, .big);

    return 52;
}

/// Decode a Configuration BPDU from a frame. Returns null if the frame is
/// not a valid Configuration BPDU.
pub fn decodeConfigBpdu(frame: []const u8) ?ConfigBpdu {
    if (frame.len < 52) return null;
    // Check for LLC header: DSAP=0x42, SSAP=0x42.
    if (frame[14] != 0x42 or frame[15] != 0x42) return null;
    // Check BPDU protocol ID.
    if (std.mem.readInt(u16, frame[17..19], .big) != 0x0000) return null;
    // Check BPDU version.
    if (frame[19] != BPDU_VERSION) return null;
    // Check BPDU type.
    if (frame[20] != BPDU_TYPE_CONFIG) return null;

    var bpdu: ConfigBpdu = undefined;
    // Flags at offset 21 — ignored for now.
    bpdu.root_id.priority = std.mem.readInt(u16, frame[22..24], .big);
    @memcpy(&bpdu.root_id.mac, frame[24..30]);
    bpdu.root_path_cost = std.mem.readInt(u32, frame[30..34], .big);
    bpdu.sender_id.priority = std.mem.readInt(u16, frame[34..36], .big);
    @memcpy(&bpdu.sender_id.mac, frame[36..42]);
    bpdu.sender_port_id = .{
        .priority = @truncate(std.mem.readInt(u16, frame[42..44], .big) >> 8),
        .port_num = @truncate(std.mem.readInt(u16, frame[42..44], .big)),
    };
    bpdu.message_age = std.mem.readInt(u16, frame[44..46], .big);
    bpdu.max_age = std.mem.readInt(u16, frame[46..48], .big);
    bpdu.hello_time = std.mem.readInt(u16, frame[48..50], .big);
    bpdu.forward_delay = std.mem.readInt(u16, frame[50..52], .big);

    return bpdu;
}

/// Check if a frame is a TCN BPDU.
pub fn isTcnBpdu(frame: []const u8) bool {
    if (frame.len < 21) return false;
    if (frame[14] != 0x42 or frame[15] != 0x42) return false;
    if (std.mem.readInt(u16, frame[17..19], .big) != 0x0000) return false;
    if (frame[19] != BPDU_VERSION) return false;
    return frame[20] == BPDU_TYPE_TCN;
}

/// Check if a frame is a TCA BPDU.
pub fn isTcaBpdu(frame: []const u8) bool {
    if (frame.len < 21) return false;
    if (frame[14] != 0x42 or frame[15] != 0x42) return false;
    if (std.mem.readInt(u16, frame[17..19], .big) != 0x0000) return false;
    if (frame[19] != BPDU_VERSION) return false;
    return frame[20] == BPDU_TYPE_TCA;
}

/// Check if a frame is a BPDU (Configuration, TCN, or TCA).
pub fn isBpdu(frame: []const u8) bool {
    if (frame.len < 21) return false;
    if (frame[14] != 0x42 or frame[15] != 0x42) return false;
    if (std.mem.readInt(u16, frame[17..19], .big) != 0x0000) return false;
    if (frame[19] != BPDU_VERSION) return false;
    const bpdu_type = frame[20];
    return bpdu_type == BPDU_TYPE_CONFIG or bpdu_type == BPDU_TYPE_TCN or bpdu_type == BPDU_TYPE_TCA;
}

// ============================================================================
// Tests
// ============================================================================

fn makeMac(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) MacAddress {
    return .{ a, b, c, d, e, f };
}

test "BridgeId comparison" {
    const id1 = BridgeId{ .priority = 32768, .mac = makeMac(0, 0, 0, 0, 0, 1) };
    const id2 = BridgeId{ .priority = 32768, .mac = makeMac(0, 0, 0, 0, 0, 2) };
    const id3 = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 2) };

    try std.testing.expect(id1.lessThan(&id2));
    try std.testing.expect(!id2.lessThan(&id1));
    try std.testing.expect(id3.lessThan(&id1)); // lower priority wins
}

test "PortId comparison" {
    const pid1 = PortId{ .priority = 128, .port_num = 1 };
    const pid2 = PortId{ .priority = 128, .port_num = 2 };
    const pid3 = PortId{ .priority = 64, .port_num = 2 };

    try std.testing.expect(pid1.lessThan(&pid2));
    try std.testing.expect(pid3.lessThan(&pid1)); // lower priority wins
}

test "STP bridge init and basic state" {
    var bridge = try StpBridge.init(std.testing.allocator, 4, makeMac(0, 0, 0, 0, 0, 1), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();

    try std.testing.expect(bridge.is_root);
    try std.testing.expectEqual(@as(u16, PORT_NONE), bridge.root_port);
    try std.testing.expectEqual(@as(u32, 0), bridge.root_path_cost);

    // All ports start as disabled.
    for (bridge.ports) |p| {
        try std.testing.expectEqual(PortState.disabled, p.state);
        try std.testing.expectEqual(PortRole.disabled, p.role);
    }

    // Enable ports.
    bridge.enablePort(0);
    bridge.enablePort(1);
    try std.testing.expectEqual(PortState.blocking, bridge.ports[0].state);
    try std.testing.expectEqual(PortRole.designated, bridge.ports[0].role);
}

test "STP root election: lower bridge ID wins" {
    var bridge = try StpBridge.init(std.testing.allocator, 2, makeMac(0, 0, 0, 0, 0, 2), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);
    bridge.enablePort(1);

    // Receive a BPDU from a bridge with lower priority (better).
    const remote_bpdu = ConfigBpdu{
        .root_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .root_path_cost = 0,
        .sender_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .sender_port_id = PortId{ .priority = 128, .port_num = 1 },
        .message_age = 0,
        .max_age = DEFAULT_MAX_AGE_S << 8,
        .hello_time = DEFAULT_HELLO_S << 8,
        .forward_delay = DEFAULT_FORWARD_DELAY_S << 8,
    };

    const action = bridge.processConfigBpdu(0, remote_bpdu);
    try std.testing.expectEqual(BpduAction.recompute, action);
    try std.testing.expect(!bridge.is_root);
    try std.testing.expectEqual(@as(u16, 0), bridge.root_port);
    try std.testing.expectEqual(@as(u32, DEFAULT_PATH_COST), bridge.root_path_cost);
}

test "STP root election: same root, higher cost path ignored" {
    var bridge = try StpBridge.init(std.testing.allocator, 2, makeMac(0, 0, 0, 0, 0, 2), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);
    bridge.enablePort(1);

    // First, accept a BPDU from root bridge on port 0.
    const good_bpdu = ConfigBpdu{
        .root_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .root_path_cost = 0,
        .sender_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .sender_port_id = PortId{ .priority = 128, .port_num = 1 },
        .message_age = 0,
        .max_age = DEFAULT_MAX_AGE_S << 8,
        .hello_time = DEFAULT_HELLO_S << 8,
        .forward_delay = DEFAULT_FORWARD_DELAY_S << 8,
    };
    _ = bridge.processConfigBpdu(0, good_bpdu);

    // Now receive a BPDU with same root but higher cost on port 1.
    const worse_bpdu = ConfigBpdu{
        .root_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .root_path_cost = 100, // higher cost
        .sender_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .sender_port_id = PortId{ .priority = 128, .port_num = 1 },
        .message_age = 0,
        .max_age = DEFAULT_MAX_AGE_S << 8,
        .hello_time = DEFAULT_HELLO_S << 8,
        .forward_delay = DEFAULT_FORWARD_DELAY_S << 8,
    };
    const action = bridge.processConfigBpdu(1, worse_bpdu);
    // Should not recompute — the worse path doesn't change our root port.
    try std.testing.expect(action == .none or action == .send_bpdu);
    try std.testing.expectEqual(@as(u16, 0), bridge.root_port); // still port 0
}

test "STP BPDU encode/decode round-trip" {
    const bpdu = ConfigBpdu{
        .root_id = BridgeId{ .priority = 32768, .mac = makeMac(0, 1, 2, 3, 4, 5) },
        .root_path_cost = 100,
        .sender_id = BridgeId{ .priority = 16384, .mac = makeMac(6, 7, 8, 9, 10, 11) },
        .sender_port_id = PortId{ .priority = 128, .port_num = 3 },
        .message_age = 256,
        .max_age = 5120,
        .hello_time = 512,
        .forward_delay = 3840,
    };

    var buf: [64]u8 = undefined;
    const src_mac = makeMac(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    const len = try encodeConfigBpdu(bpdu, src_mac, &buf);
    try std.testing.expectEqual(@as(usize, 52), len);

    const decoded = decodeConfigBpdu(&buf);
    try std.testing.expect(decoded != null);
    try std.testing.expectEqual(bpdu.root_id.order(), decoded.?.root_id.order());
    try std.testing.expectEqual(bpdu.root_path_cost, decoded.?.root_path_cost);
    try std.testing.expectEqual(bpdu.sender_id.order(), decoded.?.sender_id.order());
    try std.testing.expectEqual(bpdu.sender_port_id.order(), decoded.?.sender_port_id.order());
    try std.testing.expectEqual(bpdu.message_age, decoded.?.message_age);
    try std.testing.expectEqual(bpdu.max_age, decoded.?.max_age);
    try std.testing.expectEqual(bpdu.hello_time, decoded.?.hello_time);
    try std.testing.expectEqual(bpdu.forward_delay, decoded.?.forward_delay);

    // Verify source MAC was encoded correctly.
    try std.testing.expectEqualSlices(u8, &src_mac, buf[6..12]);
}

test "STP isBpdu detection" {
    const bpdu = ConfigBpdu{
        .root_id = BridgeId{ .priority = 32768, .mac = makeMac(0, 1, 2, 3, 4, 5) },
        .root_path_cost = 0,
        .sender_id = BridgeId{ .priority = 32768, .mac = makeMac(0, 1, 2, 3, 4, 5) },
        .sender_port_id = PortId{ .priority = 128, .port_num = 1 },
        .message_age = 0,
        .max_age = 5120,
        .hello_time = 512,
        .forward_delay = 3840,
    };

    var buf: [64]u8 = undefined;
    const src_mac_for_test = makeMac(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    _ = try encodeConfigBpdu(bpdu, src_mac_for_test, &buf);
    try std.testing.expect(isBpdu(&buf));

    // Non-BPDU frame (ARP).
    var arp: [42]u8 = undefined;
    @memset(&arp, 0);
    arp[12] = 0x08;
    arp[13] = 0x06;
    try std.testing.expect(!isBpdu(&arp));
}

test "STP tick sends hello when root" {
    var bridge = try StpBridge.init(std.testing.allocator, 2, makeMac(0, 0, 0, 0, 0, 1), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);
    bridge.enablePort(1);

    // Tick until hello timer expires.
    var action: TickAction = .{};
    for (0..DEFAULT_HELLO_S) |_| {
        action = bridge.tick();
    }
    try std.testing.expect(action.send_hello);
    try std.testing.expectEqual(DEFAULT_HELLO_S, bridge.hello_timer_s);
}

test "STP edge port goes straight to forwarding" {
    var bridge = try StpBridge.init(std.testing.allocator, 2, makeMac(0, 0, 0, 0, 0, 1), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);
    bridge.setEdgePort(0, true);

    // Edge port should be forwarding immediately.
    try std.testing.expectEqual(PortState.forwarding, bridge.ports[0].state);
    try std.testing.expectEqual(PortRole.designated, bridge.ports[0].role);
}

test "STP recompute: non-root assigns root port and blocks alternates" {
    var bridge = try StpBridge.init(std.testing.allocator, 3, makeMac(0, 0, 0, 0, 0, 2), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);
    bridge.enablePort(1);
    bridge.enablePort(2);

    // Accept BPDU on port 0 from a better root.
    const bpdu0 = ConfigBpdu{
        .root_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .root_path_cost = 0,
        .sender_id = BridgeId{ .priority = 16384, .mac = makeMac(0, 0, 0, 0, 0, 1) },
        .sender_port_id = PortId{ .priority = 128, .port_num = 1 },
        .message_age = 0,
        .max_age = DEFAULT_MAX_AGE_S << 8,
        .hello_time = DEFAULT_HELLO_S << 8,
        .forward_delay = DEFAULT_FORWARD_DELAY_S << 8,
    };
    _ = bridge.processConfigBpdu(0, bpdu0);
    bridge.recompute();

    // Port 0 should be root port.
    try std.testing.expectEqual(PortRole.root, bridge.ports[0].role);
    try std.testing.expectEqual(PortState.listening, bridge.ports[0].state);

    // Port 1 and 2 should be designated (no BPDU received).
    try std.testing.expectEqual(PortRole.designated, bridge.ports[1].role);
    try std.testing.expectEqual(PortRole.designated, bridge.ports[2].role);
}

test "STP forward delay: listening → learning → forwarding" {
    var bridge = try StpBridge.init(std.testing.allocator, 1, makeMac(0, 0, 0, 0, 0, 1), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);
    try std.testing.expectEqual(PortState.blocking, bridge.ports[0].state);

    // Transition to listening.
    bridge.ports[0].state = .listening;
    bridge.ports[0].forward_delay_timer_s = 0;

    // Tick for forward_delay seconds.
    for (0..DEFAULT_FORWARD_DELAY_S) |_| {
        _ = bridge.tick();
    }
    try std.testing.expectEqual(PortState.learning, bridge.ports[0].state);

    // Tick for another forward_delay seconds.
    for (0..DEFAULT_FORWARD_DELAY_S) |_| {
        _ = bridge.tick();
    }
    try std.testing.expectEqual(PortState.forwarding, bridge.ports[0].state);
}

test "STP TCN BPDU sets topology change flag" {
    var bridge = try StpBridge.init(std.testing.allocator, 2, makeMac(0, 0, 0, 0, 0, 1), DEFAULT_BRIDGE_PRIORITY);
    defer bridge.deinit();
    bridge.enablePort(0);

    try std.testing.expect(!bridge.topology_change);
    bridge.processTcnBpdu(0);
    try std.testing.expect(bridge.topology_change);
    try std.testing.expect(bridge.topology_change_timer_s > 0);
}
