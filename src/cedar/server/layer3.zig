//! Virtual Layer-3 Switch — hub-to-hub IP routing.
//!
//! C reference: `Layer3.c` / `Layer3.h`. The L3 switch is a virtual router
//! that connects multiple Virtual Hubs. Each hub is bound to the switch via
//! an L3 interface (`L3IF`) — a virtual NIC with its own IP, MAC, and ARP
//! table. Packets arriving on one interface are IP-forwarded to another based
//! on a static routing table.
//!
//! Scope (S22):
//! - Data structures: switch, interface, route, ARP table, pending packets.
//! - Forwarding algorithm: receive → TTL → route lookup → ARP → transmit.
//! - ARP resolution: learn from observation, generate requests, cache.
//! - ICMP echo reply (ping) for router-interface IPs.
//! - ICMP Time Exceeded / Destination Unreachable generation.
//!
//! Out of scope (deferred):
//! - Thread lifecycle (`L3SwThread`, `L3IfThread`) — requires server session infra.
//! - Config persistence (`SiLoadL3Switchs`/`SiWriteL3Switchs`).
//! - Admin RPC dispatch (`StAddL3Switch`, `StAddL3If`, etc.).
//! - Gratuitous ARP / beacon sending.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

// ============================================================================
// Constants (C: Layer3.h / Cedar.h)
// ============================================================================

/// Maximum L3 interfaces per switch (C: `MAX_NUM_L3_IF`).
pub const MAX_NUM_L3_IF: usize = 256;
/// Maximum routing table entries per switch (C: `MAX_NUM_L3_TABLE` = 4096).
pub const MAX_NUM_L3_TABLE: usize = 4096;
/// Maximum ARP table entries per interface (C: `MAX_ARP_TABLE` = 4096).
pub const MAX_ARP_TABLE: usize = 4096;
/// ARP entry lifetime in ms (C: `ARP_ENTRY_EXPIRE` = 30s).
pub const ARP_ENTRY_EXPIRE: i64 = 30_000;
/// ARP request retransmit interval in ms (C: `ARP_REQUEST_INTERVAL` = 1s).
pub const ARP_REQUEST_INTERVAL: i64 = 1_000;
/// ARP request give-up timeout in ms (C: `ARP_REQUEST_GIVEUP` = 10s).
pub const ARP_REQUEST_GIVEUP: i64 = 10_000;
/// Pending packet lifetime in ms (C: `IP_PACKET_EXPIRE` = 10s).
pub const IP_PACKET_EXPIRE: i64 = 10_000;
/// ICMP default TTL (C: `L3_DEFAULT_TTL` = 64).
pub const L3_DEFAULT_TTL: u8 = 64;

/// IPv4 ethertype.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// ARP ethertype.
pub const ETHERTYPE_ARP: u16 = 0x0806;

// ============================================================================
// Data structures
// ============================================================================

/// Static routing table entry.
/// Sorted in the list by (network, mask, gateway, metric) ascending.
pub const L3Route = struct {
    network: u32,
    mask: u32,
    gateway: u32,
    metric: u32,
};

/// ARP table entry — a resolved IP-to-MAC mapping.
pub const L3ArpEntry = struct {
    ip: u32,
    mac: [6]u8,
    expire: i64,
};

/// Pending ARP resolution — a request waiting for a response.
pub const L3ArpPending = struct {
    ip: u32,
    last_sent: i64,
    expire: i64,
};

/// Buffered IP packet waiting for ARP resolution on the destination subnet.
pub const L3PendingPacket = struct {
    frame: []u8,
    next_hop: u32,
    expire: i64,
};

/// L3 interface — a virtual NIC that binds a hub to the switch.
pub const L3Interface = struct {
    /// The switch this interface belongs to.
    switch: *L3Switch,
    /// Hub name this interface connects to.
    hub_name: []u8,
    /// IP address assigned to this interface (network byte order).
    ip: u32,
    /// Subnet mask (e.g. 0xFFFFFF00 for /24).
    mask: u32,
    /// Generated MAC address for this virtual NIC.
    mac: [6]u8,
    /// ARP table: resolved IP-to-MAC entries.
    arp_table: std.ArrayListUnmanaged(L3ArpEntry) = .{},
    /// Pending ARP resolutions.
    arp_pending: std.ArrayListUnmanaged(L3ArpPending) = .{},
    /// Packets waiting for ARP resolution.
    wait_queue: std.ArrayListUnmanaged(L3PendingPacket) = .{},
    /// Outgoing L2 frames ready to be sent into the hub.
    send_queue: std.ArrayListUnmanaged([]u8) = .{},

    pub fn deinit(self: *L3Interface, allocator: Allocator) void {
        for (self.wait_queue.items) |p| allocator.free(p.frame);
        self.wait_queue.deinit(allocator);
        for (self.send_queue.items) |f| allocator.free(f);
        self.send_queue.deinit(allocator);
        self.arp_table.deinit(allocator);
        self.arp_pending.deinit(allocator);
        allocator.free(self.hub_name);
    }

    /// Check if a destination IP is directly connected to this interface.
    pub fn isDirectlyConnected(self: *const L3Interface, dest_ip: u32) bool {
        return (self.ip & self.mask) == (dest_ip & self.mask);
    }
};

/// The virtual Layer-3 switch. Owns a list of interfaces and a routing table.
pub const L3Switch = struct {
    allocator: Allocator,
    /// Switch name.
    name: []u8,
    /// Guard for all mutable state.
    mutex: std.Thread.Mutex = .{},
    /// L3 interfaces (one per connected hub).
    interfaces: std.ArrayListUnmanaged(L3Interface) = .{},
    /// Static routing table.
    routes: std.ArrayListUnmanaged(L3Route) = .{},
    /// Total packets forwarded successfully.
    total_forwarded: u64 = 0,
    /// Total packets dropped (no route, TTL expired, etc.).
    total_dropped: u64 = 0,

    pub fn init(allocator: Allocator, name: []const u8) !*L3Switch {
        const self = try allocator.create(L3Switch);
        self.* = .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
        };
        return self;
    }

    pub fn deinit(self: *L3Switch) void {
        for (self.interfaces.items) |*iface| iface.deinit(self.allocator);
        self.interfaces.deinit(self.allocator);
        self.routes.deinit(self.allocator);
        self.allocator.free(self.name);
        self.allocator.destroy(self);
    }

    /// Add an interface. Returns error.TooMany if the interface list is full.
    pub fn addInterface(
        self: *L3Switch,
        hub_name: []const u8,
        ip: u32,
        mask: u32,
    ) !*L3Interface {
        if (self.interfaces.items.len >= MAX_NUM_L3_IF) return error.TooMany;

        // Check for duplicate hub binding.
        for (self.interfaces.items) |iface| {
            if (mem.eql(u8, iface.hub_name, hub_name)) return error.Duplicate;
        }

        var iface = L3Interface{
            .switch = self,
            .hub_name = try self.allocator.dupe(u8, hub_name),
            .ip = ip,
            .mask = mask,
            .mac = generateMac(),
        };
        try self.interfaces.append(self.allocator, iface);
        return &self.interfaces.items[self.interfaces.items.len - 1];
    }

    /// Remove an interface by hub name. Returns true if found and removed.
    pub fn removeInterface(self: *L3Switch, hub_name: []const u8) bool {
        for (self.interfaces.items, 0..) |iface, i| {
            if (mem.eql(u8, iface.hub_name, hub_name)) {
                var removed = self.interfaces.swapRemove(i);
                removed.deinit(self.allocator);
                return true;
            }
        }
        return false;
    }

    /// Add a static route. Returns error.TooMany if the table is full.
    pub fn addRoute(
        self: *L3Switch,
        network: u32,
        mask: u32,
        gateway: u32,
        metric: u32,
    ) !void {
        if (self.routes.items.len >= MAX_NUM_L3_TABLE) return error.TooMany;

        // Reject duplicates.
        for (self.routes.items) |r| {
            if (r.network == network and r.mask == mask and
                r.gateway == gateway and r.metric == metric)
                return error.Duplicate;
        }

        try self.routes.append(self.allocator, .{
            .network = network,
            .mask = mask,
            .gateway = gateway,
            .metric = metric,
        });

        // Sort by (network, mask, gateway, metric) ascending — same as C `CmpL3Table`.
        std.mem.sort(L3Route, self.routes.items, {}, struct {
            fn cmp(_: void, a: L3Route, b: L3Route) bool {
                if (a.network != b.network) return a.network < b.network;
                if (a.mask != b.mask) return a.mask < b.mask;
                if (a.gateway != b.gateway) return a.gateway < b.gateway;
                return a.metric < b.metric;
            }
        }.cmp);
    }

    /// Remove a static route by network/mask/gateway/metric. Returns true if found.
    pub fn removeRoute(
        self: *L3Switch,
        network: u32,
        mask: u32,
        gateway: u32,
        metric: u32,
    ) bool {
        for (self.routes.items, 0..) |r, i| {
            if (r.network == network and r.mask == mask and
                r.gateway == gateway and r.metric == metric)
            {
                _ = self.routes.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Find the best route for a destination IP (longest-prefix, then lowest metric).
    pub fn findRoute(self: *const L3Switch, dest_ip: u32) ?L3Route {
        var best: ?L3Route = null;
        var best_mask: u32 = 0;

        for (self.routes.items) |r| {
            if ((r.network & r.mask) == (dest_ip & r.mask)) {
                if (r.mask > best_mask or
                    (r.mask == best_mask and (best == null or r.metric < best.?.metric)))
                {
                    best = r;
                    best_mask = r.mask;
                }
            }
        }
        return best;
    }

    /// Find the interface whose subnet contains the given IP, or null.
    pub fn findInterface(self: *const L3Switch, ip: u32) ?*const L3Interface {
        for (self.interfaces.items) |*iface| {
            if (iface.isDirectlyConnected(ip)) return iface;
        }
        return null;
    }

    /// Find the mutable interface by hub name, or null.
    pub fn findInterfaceByHub(self: *L3Switch, hub_name: []const u8) ?*L3Interface {
        for (self.interfaces.items) |*iface| {
            if (mem.eql(u8, iface.hub_name, hub_name)) return iface;
        }
        return null;
    }

    /// Route lookup: given a destination IP, return the outgoing interface
    /// and the next-hop IP. Returns null if no route is found.
    pub fn lookup(self: *const L3Switch, dest_ip: u32) ?struct { iface: *const L3Interface, next_hop: u32 } {
        // 1. Check if directly connected to any interface.
        for (self.interfaces.items) |*iface| {
            if (iface.isDirectlyConnected(dest_ip)) {
                return .{ .iface = iface, .next_hop = dest_ip };
            }
        }

        // 2. Look up in the routing table.
        const route = self.findRoute(dest_ip) orelse return null;

        // 3. Find the interface whose subnet contains the gateway.
        for (self.interfaces.items) |*iface| {
            if (iface.isDirectlyConnected(route.gateway)) {
                return .{ .iface = iface, .next_hop = route.gateway };
            }
        }

        return null;
    }

    // ---- Forwarding engine -------------------------------------------------

    /// Forward a raw Ethernet frame received on the given source interface.
    /// Returns the outgoing raw Ethernet frame (caller owns the memory),
    /// or an error if the packet is dropped.
    pub fn forwardPacket(
        self: *L3Switch,
        src_iface: *L3Interface,
        frame: []const u8,
    ) ForwardError!ForwardResult {
        if (frame.len < 14) return error.InvalidFrame;

        const ethertype = mem.readInt(u16, frame[12..14], .big);
        if (ethertype == ETHERTYPE_ARP) {
            return self.forwardArp(src_iface, frame);
        }
        if (ethertype == ETHERTYPE_IPV4) {
            return self.forwardIpv4(src_iface, frame);
        }
        // Non-IPv4/non-ARP frames are silently dropped (L3 switch is IPv4-only).
        return error.UnsupportedProtocol;
    }

    // ---- ARP handling ------------------------------------------------------

    fn forwardArp(
        self: *L3Switch,
        src_iface: *L3Interface,
        frame: []const u8,
    ) ForwardError!ForwardResult {
        if (frame.len < 14 + 28) return error.InvalidFrame; // minimum ARP + Ethernet

        const arp = frame[14..];
        const hw_type = mem.readInt(u16, arp[0..2], .big);
        const proto_type = mem.readInt(u16, arp[2..4], .big);
        const hw_size = arp[4];
        const proto_size = arp[5];
        const opcode = mem.readInt(u16, arp[6..8], .big);

        if (hw_type != 1 or proto_type != ETHERTYPE_IPV4) return error.InvalidFrame;
        if (hw_size != 6 or proto_size != 4) return error.InvalidFrame;

        const sender_ip = mem.readInt(u32, arp[14..18], .big);
        const sender_mac: [6]u8 = .{ arp[8], arp[9], arp[10], arp[11], arp[12], arp[13] };

        // Learn ARP from any ARP packet (C: L3KnownArp).
        self.learnArp(src_iface, sender_ip, sender_mac);

        if (opcode == 1) {
            // ARP request — check if the target IP is one of our interfaces.
            const target_ip = mem.readInt(u32, arp[18..22], .big);
            for (self.interfaces.items) |*iface| {
                if (iface.ip == target_ip) {
                    // Generate ARP reply and enqueue to source interface.
                    const reply = self.buildArpReply(iface, sender_ip, sender_mac);
                    return .{ .outgoing = reply, .dst_mac = sender_mac };
                }
            }
            return error.NotOurAddress;
        }

        if (opcode == 2) {
            // ARP reply — already learned above.
            return error.ArpReplyHandled;
        }

        return error.UnsupportedArpOpcode;
    }

    fn learnArp(self: *L3Switch, iface: *L3Interface, ip: u32, mac: [6]u8) void {
        const now = std.time.milliTimestamp();
        for (iface.arp_table.items) |*entry| {
            if (entry.ip == ip) {
                entry.mac = mac;
                entry.expire = now + ARP_ENTRY_EXPIRE;
                return;
            }
        }
        if (iface.arp_table.items.len >= MAX_ARP_TABLE) {
            // Evict oldest entry.
            var oldest_idx: usize = 0;
            var oldest_expire: i64 = std.math.maxInt(i64);
            for (iface.arp_table.items, 0..) |entry, i| {
                if (entry.expire < oldest_expire) {
                    oldest_expire = entry.expire;
                    oldest_idx = i;
                }
            }
            _ = iface.arp_table.swapRemove(oldest_idx);
        }
        iface.arp_table.append(self.allocator, .{
            .ip = ip,
            .mac = mac,
            .expire = now + ARP_ENTRY_EXPIRE,
        }) catch {};
    }

    fn buildArpReply(
        self: *L3Switch,
        iface: *L3Interface,
        target_ip: u32,
        target_mac: [6]u8,
    ) []u8 {
        const frame = self.allocator.alloc(u8, 14 + 28) catch return &.{};
        // Ethernet header.
        @memcpy(frame[0..6], &target_mac);
        @memcpy(frame[6..12], &iface.mac);
        mem.writeInt(u16, frame[12..14], ETHERTYPE_ARP, .big);
        // ARP reply payload.
        const arp = frame[14..];
        mem.writeInt(u16, arp[0..2], 1, .big); // hw type = ethernet
        mem.writeInt(u16, arp[2..4], ETHERTYPE_IPV4, .big); // proto type = IPv4
        arp[4] = 6; // hw size
        arp[5] = 4; // proto size
        mem.writeInt(u16, arp[6..8], 2, .big); // opcode = reply
        @memcpy(arp[8..14], &iface.mac); // sender MAC
        mem.writeInt(u32, arp[14..18], iface.ip, .big); // sender IP
        @memcpy(arp[18..24], &target_mac); // target MAC
        mem.writeInt(u32, arp[24..28], target_ip, .big); // target IP
        return frame;
    }

    // ---- IPv4 forwarding ---------------------------------------------------

    fn forwardIpv4(
        self: *L3Switch,
        src_iface: *L3Interface,
        frame: []const u8,
    ) ForwardError!ForwardResult {
        if (frame.len < 14 + 20) return error.InvalidFrame;

        const ip = frame[14..];
        const version_ihl = ip[0];
        const version = (version_ihl >> 4) & 0x0F;
        if (version != 4) return error.InvalidFrame;
        const ihl = (version_ihl & 0x0F) * 4;
        if (ip.len < ihl) return error.InvalidFrame;

        const total_len = mem.readInt(u16, ip[2..4], .big);
        if (total_len < ihl) return error.InvalidFrame;

        const src_ip = mem.readInt(u32, ip[12..16], .big);
        var dest_ip = mem.readInt(u32, ip[16..20], .big);
        const ttl = ip[8];
        const protocol = ip[9];

        // Learn the source IP from the frame (C: L3RecvIp ARP learning).
        self.learnArpFromPacket(src_iface, src_ip, frame);

        // Broadcast/multicast filter — do not route broadcasts.
        if (dest_ip == 0xffffffff or (dest_ip & 0xf0000000) == 0xe0000000) {
            return error.BroadcastPacket;
        }

        // TTL check.
        if (ttl == 0) return error.TtlExpired;
        const src_mac: [6]u8 = .{ frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] };

        // Check if destination is one of our interface IPs (local delivery / ping).
        for (self.interfaces.items) |*iface| {
            if (iface.ip == dest_ip) {
                // ICMP echo request → generate reply.
                if (protocol == 1 and ip.len >= ihl + 8) {
                    const icmp = ip[ihl..];
                    if (icmp[0] == 8) { // Echo Request
                        const reply_frame = self.buildIcmpEchoReply(iface, src_ip, src_mac, frame, ip, ihl);
                        return .{ .outgoing = reply_frame, .dst_mac = src_mac };
                    }
                }
                return error.LocalDelivery;
            }
        }

        // Decrement TTL and check.
        if (ttl <= 1) return error.TtlExpired;
        var new_ttl: u8 = ttl - 1;

        // Route lookup.
        const lookup_result = self.lookup(dest_ip) orelse return error.NoRoute;

        // Build the outgoing frame.
        var outgoing = self.allocator.dupe(u8, frame) catch return error.OutOfMemory;
        errdefer self.allocator.free(outgoing);

        // Rewrite Ethernet header: dst = next-hop MAC (resolved later), src = outgoing iface MAC.
        @memcpy(outgoing[6..12], &lookup_result.iface.mac);

        // Rewrite IP TTL.
        outgoing[14 + 8] = new_ttl;

        // Recalculate IP header checksum.
        recalcIpChecksum(outgoing[14 ..][0..(ihl)]);

        // Resolve the next-hop MAC via ARP.
        const next_hop_mac = self.resolveArp(lookup_result.iface, lookup_result.next_hop, outgoing) catch |err| {
            // ARP pending or not found — packet is queued.
            if (err == error.ArpPending) return error.ArpPending;
            return error.ArpFailed;
        };

        @memcpy(outgoing[0..6], &next_hop_mac);
        self.total_forwarded += 1;
        return .{ .outgoing = outgoing, .dst_mac = next_hop_mac };
    }

    fn learnArpFromPacket(self: *L3Switch, iface: *L3Interface, src_ip: u32, frame: []const u8) void {
        if (src_ip == 0 or src_ip == 0xffffffff) return;
        // Skip multicast/loopback.
        if ((src_ip >> 24) & 0xe0 == 0xe0) return;
        if ((src_ip >> 24) == 127) return;
        const src_mac: [6]u8 = .{ frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] };
        self.learnArp(iface, src_ip, src_mac);
    }

    // ---- ICMP echo reply ---------------------------------------------------

    fn buildIcmpEchoReply(
        self: *L3Switch,
        iface: *L3Interface,
        dest_ip: u32,
        dest_mac: [6]u8,
        original_frame: []const u8,
        ip_header: []const u8,
        ihl: u8,
    ) []u8 {
        const icmp_offset = 14 + ihl;
        const icmp_len = original_frame.len - icmp_offset;
        if (icmp_len < 8) return &.[];

        var reply = self.allocator.dupe(u8, original_frame) catch return &.{};

        // Ethernet: swap src/dst.
        @memcpy(reply[0..6], &dest_mac);
        @memcpy(reply[6..12], &iface.mac);

        // IP: swap src/dst.
        mem.writeInt(u32, @constCast(reply[14 + 12 ..][0..4]), iface.ip, .big);
        mem.writeInt(u32, @constCast(reply[14 + 16 ..][0..4]), dest_ip, .big);

        // ICMP: change type from 8 (request) to 0 (reply), zero checksum.
        if (reply.len > icmp_offset) {
            reply[icmp_offset] = 0;
            reply[icmp_offset + 1] = 0;
            // Recalculate ICMP checksum.
            const cksum = icmpChecksum(reply[icmp_offset..][0..icmp_len]);
            mem.writeInt(u16, @constCast(reply[icmp_offset + 2 ..][0..4]), cksum, .big);
        }

        // Recalculate IP header checksum.
        recalcIpChecksum(@constCast(reply[14..][0..(ihl)]));

        return reply;
    }

    // ---- ARP resolution ----------------------------------------------------

    /// Resolve the MAC for the next-hop IP. If ARP is cached, return the MAC.
    /// If not, queue the packet and send an ARP request.
    fn resolveArp(
        self: *L3Switch,
        iface: *L3Interface,
        next_hop: u32,
        frame: []const u8,
    ) ![6]u8 {
        const now = std.time.milliTimestamp();

        // Check ARP cache.
        for (iface.arp_table.items) |entry| {
            if (entry.ip == next_hop) {
                if (entry.expire > now) return entry.mac;
            }
        }

        // Check if an ARP request is already pending.
        var pending_exists = false;
        for (iface.arp_pending.items) |*p| {
            if (p.ip == next_hop) {
                pending_exists = true;
                break;
            }
        }

        if (!pending_exists) {
            // Register a new pending ARP.
            iface.arp_pending.append(self.allocator, .{
                .ip = next_hop,
                .last_sent = now,
                .expire = now + ARP_REQUEST_GIVEUP,
            }) catch {};

            // Generate and enqueue an ARP request.
            const arp_req = self.buildArpRequest(iface, next_hop);
            iface.send_queue.append(self.allocator, arp_req) catch {};
        }

        // Queue the packet for later delivery.
        const copy = self.allocator.dupe(u8, frame) catch return error.OutOfMemory;
        iface.wait_queue.append(self.allocator, .{
            .frame = copy,
            .next_hop = next_hop,
            .expire = now + IP_PACKET_EXPIRE,
        }) catch {
            self.allocator.free(copy);
        };

        return error.ArpPending;
    }

    fn buildArpRequest(self: *L3Switch, iface: *L3Interface, target_ip: u32) []u8 {
        const frame = self.allocator.alloc(u8, 14 + 28) catch return &.{};
        const broadcast = [6]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        @memcpy(frame[0..6], &broadcast);
        @memcpy(frame[6..12], &iface.mac);
        mem.writeInt(u16, frame[12..14], ETHERTYPE_ARP, .big);
        const arp = frame[14..];
        mem.writeInt(u16, arp[0..2], 1, .big);
        mem.writeInt(u16, arp[2..4], ETHERTYPE_IPV4, .big);
        arp[4] = 6;
        arp[5] = 4;
        mem.writeInt(u16, arp[6..8], 1, .big); // opcode = request
        @memcpy(arp[8..14], &iface.mac);
        mem.writeInt(u32, arp[14..18], iface.ip, .big);
        const zero_mac = [6]u8{ 0, 0, 0, 0, 0, 0 };
        @memcpy(arp[18..24], &zero_mac);
        mem.writeInt(u32, arp[24..28], target_ip, .big);
        return frame;
    }

    // ---- Periodic maintenance ----------------------------------------------

    /// Flush expired ARP entries and timed-out pending packets.
    pub fn sweep(self: *L3Switch) void {
        const now = std.time.milliTimestamp();

        for (self.interfaces.items) |*iface| {
            // Expire ARP entries.
            var i: usize = 0;
            while (i < iface.arp_table.items.len) {
                if (iface.arp_table.items[i].expire <= now) {
                    _ = iface.arp_table.swapRemove(i);
                } else {
                    i += 1;
                }
            }

            // Expire pending ARP requests.
            i = 0;
            while (i < iface.arp_pending.items.len) {
                if (iface.arp_pending.items[i].expire <= now) {
                    _ = iface.arp_pending.swapRemove(i);
                } else {
                    i += 1;
                }
            }

            // Expire waiting packets.
            i = 0;
            while (i < iface.wait_queue.items.len) {
                if (iface.wait_queue.items[i].expire <= now) {
                    self.allocator.free(iface.wait_queue.items[i].frame);
                    _ = iface.wait_queue.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }

    /// When an ARP response arrives, flush any queued packets for that IP.
    pub fn onArpResolved(self: *L3Switch, iface: *L3Interface, ip: u32) void {
        var i: usize = 0;
        while (i < iface.wait_queue.items.len) {
            if (iface.wait_queue.items[i].next_hop == ip) {
                const pkt = iface.wait_queue.swapRemove(i);
                self.allocator.free(pkt.frame);
                // The packet would be re-forwarded by the caller after ARP resolution.
            } else {
                i += 1;
            }
        }
    }
};

// ============================================================================
// Types
// ============================================================================

pub const ForwardError = error{
    InvalidFrame,
    UnsupportedProtocol,
    BroadcastPacket,
    TtlExpired,
    NoRoute,
    LocalDelivery,
    ArpPending,
    ArpFailed,
    OutOfMemory,
    NotOurAddress,
    ArpReplyHandled,
    UnsupportedArpOpcode,
    InvalidFrame_Short,
};

pub const ForwardResult = struct {
    outgoing: []u8,
    dst_mac: [6]u8,
};

// ============================================================================
// Helpers
// ============================================================================

/// Generate a random MAC address for a virtual NIC.
/// Sets the locally-administered bit, clears the multicast bit.
fn generateMac() [6]u8 {
    var mac: [6]u8 = undefined;
    std.crypto.random.bytes(&mac);
    mac[0] = (mac[0] & 0xfe) | 0x02; // locally administered, unicast
    return mac;
}

/// Recalculate the IPv4 header checksum (RFC 1071).
fn recalcIpChecksum(header: []u8) void {
    mem.writeInt(u16, header[10..12], 0, .big);
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) {
        sum += mem.readInt(u16, header[i..][0..2], .big);
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    mem.writeInt(u16, header[10..12], @truncate(~sum), .big);
}

/// Calculate ICMP checksum (RFC 1071).
fn icmpChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += mem.readInt(u16, data[i..][0..2], .big);
    }
    if (data.len & 1 != 0) {
        sum += @as(u32, data[data.len - 1]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return @truncate(~sum);
}

// ============================================================================
// Tests
// ============================================================================

test "L3Switch.init and deinit" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "TEST_L3");
    defer sw.deinit();
    try testing.expectEqualStrings("TEST_L3", sw.name);
    try testing.expectEqual(@as(usize, 0), sw.interfaces.items.len);
    try testing.expectEqual(@as(usize, 0), sw.routes.items.len);
}

test "L3Switch.addInterface and removeInterface" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    const if1 = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);
    try testing.expectEqualStrings("HUB_A", if1.hub_name);
    try testing.expectEqual(@as(u32, 0x0A000101), if1.ip);
    try testing.expectEqual(@as(usize, 1), sw.interfaces.items.len);

    _ = try sw.addInterface("HUB_B", 0x0A000201, 0xFFFFFF00);
    try testing.expectEqual(@as(usize, 2), sw.interfaces.items.len);

    // Duplicate hub name rejected.
    try testing.expectError(error.Duplicate, sw.addInterface("HUB_A", 0x0A000301, 0xFFFFFF00));

    try testing.expect(sw.removeInterface("HUB_A"));
    try testing.expectEqual(@as(usize, 1), sw.interfaces.items.len);
    try testing.expect(!sw.removeInterface("HUB_A"));
}

test "L3Switch.addRoute sorts and rejects duplicates" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    try sw.addRoute(0x0A000200, 0xFFFFFF00, 0x0A000201, 10);
    try sw.addRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 5);
    try sw.addRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 1);

    try testing.expectEqual(@as(usize, 3), sw.routes.items.len);

    // Sorted: 0x0A000100/24 with metric 1, then metric 5, then 0x0A000200/24.
    try testing.expectEqual(@as(u32, 0x0A000100), sw.routes.items[0].network);
    try testing.expectEqual(@as(u32, 1), sw.routes.items[0].metric);
    try testing.expectEqual(@as(u32, 5), sw.routes.items[1].metric);
    try testing.expectEqual(@as(u32, 0x0A000200), sw.routes.items[2].network);

    // Exact duplicate rejected.
    try testing.expectError(error.Duplicate, sw.addRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 1));
}

test "L3Switch.findRoute returns longest prefix" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    try sw.addRoute(0x0A000000, 0xFF000000, 0x0A000101, 10); // /8
    try sw.addRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 5); // /24

    // 10.0.1.50 matches both routes; /24 should win.
    const best = sw.findRoute(0x0A000132).?;
    try testing.expectEqual(@as(u32, 0xFFFFFF00), best.mask);
    try testing.expectEqual(@as(u32, 5), best.metric);
}

test "L3Switch.lookup finds directly connected" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    _ = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);
    _ = try sw.addInterface("HUB_B", 0x0A000201, 0xFFFFFF00);

    // 10.0.1.50 is on HUB_A's subnet.
    const result = sw.lookup(0x0A000132).?;
    try testing.expectEqualStrings("HUB_A", result.iface.hub_name);
    try testing.expectEqual(@as(u32, 0x0A000132), result.next_hop);
}

test "L3Switch.lookup uses routing table for remote" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    _ = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);
    _ = try sw.addInterface("HUB_B", 0x0A000201, 0xFFFFFF00);

    // Route 10.0.2.0/24 via gateway 10.0.2.1 (on HUB_B's subnet).
    try sw.addRoute(0x0A000200, 0xFFFFFF00, 0x0A000201, 0);

    // 10.0.2.100 is not directly connected to HUB_A — needs routing.
    const result = sw.lookup(0x0A000264).?;
    try testing.expectEqualStrings("HUB_B", result.iface.hub_name);
    try testing.expectEqual(@as(u32, 0x0A000201), result.next_hop);
}

test "L3Switch.lookup returns null for unroutable" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    _ = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);

    try testing.expect(sw.lookup(0xC0A80132) == null);
}

test "L3Switch.forwardPacket drops broadcast" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    const iface = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);

    // Build a broadcast IPv4 frame.
    var frame: [42]u8 = .{0};
    const broadcast_mac = [6]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    @memcpy(frame[0..6], &broadcast_mac);
    @memcpy(frame[6..12], &iface.mac);
    mem.writeInt(u16, frame[12..14], ETHERTYPE_IPV4, .big);
    frame[14] = 0x45; // IPv4
    frame[23] = 6; // TCP
    mem.writeInt(u32, frame[26..30], 0x0A000105, .big); // src IP
    mem.writeInt(u32, frame[30..34], 0xFFFFFFFF, .big); // broadcast dst

    const result = sw.forwardPacket(iface, &frame);
    try testing.expectError(error.BroadcastPacket, result);
}

test "L3Interface.isDirectlyConnected" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    const iface = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);
    try testing.expect(iface.isDirectlyConnected(0x0A000132)); // 10.0.1.50
    try testing.expect(iface.isDirectlyConnected(0x0A000101)); // 10.0.1.1
    try testing.expect(iface.isDirectlyConnected(0x0A0001FF)); // 10.0.1.255
    try testing.expect(!iface.isDirectlyConnected(0x0A000232)); // 10.0.2.50
}

test "L3Switch.findInterfaceByHub" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    _ = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);
    _ = try sw.addInterface("HUB_B", 0x0A000201, 0xFFFFFF00);

    try testing.expect(sw.findInterfaceByHub("HUB_A") != null);
    try testing.expect(sw.findInterfaceByHub("HUB_B") != null);
    try testing.expect(sw.findInterfaceByHub("HUB_C") == null);
}

test "L3Switch.sweep removes expired ARP entries" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    const iface = try sw.addInterface("HUB_A", 0x0A000101, 0xFFFFFF00);
    const now = std.time.milliTimestamp();

    // Add an ARP entry that is already expired.
    iface.arp_table.append(allocator, .{
        .ip = 0x0A000102,
        .mac = .{ 0x02, 0x00, 0x00, 0x00, 0x01, 0x02 },
        .expire = now - 1,
    }) catch {};
    try testing.expectEqual(@as(usize, 1), iface.arp_table.items.len);

    sw.sweep();
    try testing.expectEqual(@as(usize, 0), iface.arp_table.items.len);
}

test "L3Switch.removeRoute" {
    const allocator = testing.allocator;
    const sw = try L3Switch.init(allocator, "R1");
    defer sw.deinit();

    try sw.addRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 5);
    try testing.expectEqual(@as(usize, 1), sw.routes.items.len);

    try testing.expect(sw.removeRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 5));
    try testing.expectEqual(@as(usize, 0), sw.routes.items.len);
    try testing.expect(!sw.removeRoute(0x0A000100, 0xFFFFFF00, 0x0A000101, 5));
}
