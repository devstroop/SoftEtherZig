//! SoftEther VPN Packet Processor
//!
//! Handles packet processing pipeline including:
//! - Ethernet frame handling
//! - IP packet routing
//! - Protocol-specific processing
//! - Packet queuing and buffering

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// ============================================================================
// Ethernet Frame Types
// ============================================================================

/// Ethernet frame types (EtherType values)
pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    unknown = 0x0000,

    pub fn fromBytes(bytes: [2]u8) EtherType {
        const value = (@as(u16, bytes[0]) << 8) | bytes[1];
        return switch (value) {
            0x0800 => .ipv4,
            0x0806 => .arp,
            0x86DD => .ipv6,
            0x8100 => .vlan,
            else => .unknown,
        };
    }

    pub fn toBytes(self: EtherType) [2]u8 {
        const value = @intFromEnum(self);
        return .{ @truncate(value >> 8), @truncate(value) };
    }
};

/// IP protocol numbers
pub const IpProtocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    unknown = 0,

    pub fn fromByte(byte: u8) IpProtocol {
        return switch (byte) {
            1 => .icmp,
            6 => .tcp,
            17 => .udp,
            58 => .icmpv6,
            else => .unknown,
        };
    }
};

// ============================================================================
// Packet Headers
// ============================================================================

/// Ethernet header (14 bytes)
pub const EthernetHeader = struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ether_type: EtherType,

    pub const SIZE = 14;

    pub fn parse(data: []const u8) ?EthernetHeader {
        if (data.len < SIZE) return null;

        return .{
            .dst_mac = data[0..6].*,
            .src_mac = data[6..12].*,
            .ether_type = EtherType.fromBytes(data[12..14].*),
        };
    }

    pub fn serialize(self: *const EthernetHeader, buffer: []u8) !usize {
        if (buffer.len < SIZE) return error.BufferTooSmall;

        @memcpy(buffer[0..6], &self.dst_mac);
        @memcpy(buffer[6..12], &self.src_mac);
        const et = self.ether_type.toBytes();
        buffer[12] = et[0];
        buffer[13] = et[1];

        return SIZE;
    }

    pub fn isBroadcast(self: *const EthernetHeader) bool {
        return mem.eql(u8, &self.dst_mac, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
    }

    pub fn isMulticast(self: *const EthernetHeader) bool {
        return (self.dst_mac[0] & 0x01) != 0;
    }
};

/// IPv4 header (20+ bytes)
pub const Ipv4Header = struct {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: IpProtocol,
    checksum: u16,
    src_ip: u32,
    dst_ip: u32,

    pub const MIN_SIZE = 20;

    pub fn parse(data: []const u8) ?Ipv4Header {
        if (data.len < MIN_SIZE) return null;

        const version = data[0] >> 4;
        if (version != 4) return null;

        return .{
            .version_ihl = data[0],
            .dscp_ecn = data[1],
            .total_length = (@as(u16, data[2]) << 8) | data[3],
            .identification = (@as(u16, data[4]) << 8) | data[5],
            .flags_fragment = (@as(u16, data[6]) << 8) | data[7],
            .ttl = data[8],
            .protocol = IpProtocol.fromByte(data[9]),
            .checksum = (@as(u16, data[10]) << 8) | data[11],
            .src_ip = (@as(u32, data[12]) << 24) | (@as(u32, data[13]) << 16) |
                (@as(u32, data[14]) << 8) | data[15],
            .dst_ip = (@as(u32, data[16]) << 24) | (@as(u32, data[17]) << 16) |
                (@as(u32, data[18]) << 8) | data[19],
        };
    }

    pub fn getHeaderLength(self: *const Ipv4Header) u8 {
        return (self.version_ihl & 0x0F) * 4;
    }

    pub fn getPayloadOffset(self: *const Ipv4Header) u8 {
        return self.getHeaderLength();
    }
};

/// IPv6 header (40 bytes)
pub const Ipv6Header = struct {
    version_tc_fl: u32,
    payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    src_ip: [16]u8,
    dst_ip: [16]u8,

    pub const SIZE = 40;

    pub fn parse(data: []const u8) ?Ipv6Header {
        if (data.len < SIZE) return null;

        const version = data[0] >> 4;
        if (version != 6) return null;

        return .{
            .version_tc_fl = (@as(u32, data[0]) << 24) | (@as(u32, data[1]) << 16) |
                (@as(u32, data[2]) << 8) | data[3],
            .payload_length = (@as(u16, data[4]) << 8) | data[5],
            .next_header = data[6],
            .hop_limit = data[7],
            .src_ip = data[8..24].*,
            .dst_ip = data[24..40].*,
        };
    }
};

/// ARP header (28 bytes for IPv4)
pub const ArpHeader = struct {
    hardware_type: u16,
    protocol_type: u16,
    hardware_len: u8,
    protocol_len: u8,
    operation: ArpOperation,
    sender_mac: [6]u8,
    sender_ip: u32,
    target_mac: [6]u8,
    target_ip: u32,

    pub const SIZE = 28;

    pub const ArpOperation = enum(u16) {
        request = 1,
        reply = 2,
        unknown = 0,

        pub fn fromU16(value: u16) ArpOperation {
            return switch (value) {
                1 => .request,
                2 => .reply,
                else => .unknown,
            };
        }
    };

    pub fn parse(data: []const u8) ?ArpHeader {
        if (data.len < SIZE) return null;

        return .{
            .hardware_type = (@as(u16, data[0]) << 8) | data[1],
            .protocol_type = (@as(u16, data[2]) << 8) | data[3],
            .hardware_len = data[4],
            .protocol_len = data[5],
            .operation = ArpOperation.fromU16((@as(u16, data[6]) << 8) | data[7]),
            .sender_mac = data[8..14].*,
            .sender_ip = (@as(u32, data[14]) << 24) | (@as(u32, data[15]) << 16) |
                (@as(u32, data[16]) << 8) | data[17],
            .target_mac = data[18..24].*,
            .target_ip = (@as(u32, data[24]) << 24) | (@as(u32, data[25]) << 16) |
                (@as(u32, data[26]) << 8) | data[27],
        };
    }
};

// ============================================================================
// Packet Classification
// ============================================================================

/// Packet classification result
pub const PacketClass = enum {
    // Layer 2
    arp_request,
    arp_reply,
    ethernet_broadcast,
    ethernet_multicast,
    ethernet_unicast,

    // Layer 3
    ipv4_unicast,
    ipv4_broadcast,
    ipv4_multicast,
    ipv6_unicast,
    ipv6_multicast,

    // Layer 4
    tcp,
    udp,
    icmp,
    icmpv6,

    // Control
    dhcp,
    dns,

    // Unknown
    unknown,
};

/// Packet information
pub const PacketInfo = struct {
    class: PacketClass,
    ether_type: EtherType,
    ip_protocol: ?IpProtocol,
    src_mac: ?[6]u8,
    dst_mac: ?[6]u8,
    src_ip: ?u32,
    dst_ip: ?u32,
    src_port: ?u16,
    dst_port: ?u16,
    payload_offset: usize,
    payload_length: usize,

    pub fn init() PacketInfo {
        return .{
            .class = .unknown,
            .ether_type = .unknown,
            .ip_protocol = null,
            .src_mac = null,
            .dst_mac = null,
            .src_ip = null,
            .dst_ip = null,
            .src_port = null,
            .dst_port = null,
            .payload_offset = 0,
            .payload_length = 0,
        };
    }
};

/// Classify a packet
pub fn classifyPacket(data: []const u8) PacketInfo {
    var info = PacketInfo.init();

    // Parse Ethernet header
    const eth = EthernetHeader.parse(data) orelse return info;
    info.src_mac = eth.src_mac;
    info.dst_mac = eth.dst_mac;
    info.ether_type = eth.ether_type;
    info.payload_offset = EthernetHeader.SIZE;

    // Classify based on destination MAC
    if (eth.isBroadcast()) {
        info.class = .ethernet_broadcast;
    } else if (eth.isMulticast()) {
        info.class = .ethernet_multicast;
    } else {
        info.class = .ethernet_unicast;
    }

    // Parse based on EtherType
    switch (eth.ether_type) {
        .arp => {
            const arp_data = data[EthernetHeader.SIZE..];
            if (ArpHeader.parse(arp_data)) |arp| {
                info.src_ip = arp.sender_ip;
                info.dst_ip = arp.target_ip;
                info.class = switch (arp.operation) {
                    .request => .arp_request,
                    .reply => .arp_reply,
                    else => .unknown,
                };
            }
        },
        .ipv4 => {
            const ip_data = data[EthernetHeader.SIZE..];
            if (Ipv4Header.parse(ip_data)) |ipv4| {
                info.src_ip = ipv4.src_ip;
                info.dst_ip = ipv4.dst_ip;
                info.ip_protocol = ipv4.protocol;
                info.payload_offset = EthernetHeader.SIZE + ipv4.getHeaderLength();
                info.payload_length = ipv4.total_length - ipv4.getHeaderLength();

                // Classify IP packet
                if (ipv4.dst_ip == 0xFFFFFFFF) {
                    info.class = .ipv4_broadcast;
                } else if ((ipv4.dst_ip & 0xF0000000) == 0xE0000000) {
                    info.class = .ipv4_multicast;
                } else {
                    info.class = .ipv4_unicast;
                }

                // Check for DHCP (UDP port 67/68)
                if (ipv4.protocol == .udp and ip_data.len >= ipv4.getHeaderLength() + 8) {
                    const udp_data = ip_data[ipv4.getHeaderLength()..];
                    const src_port = (@as(u16, udp_data[0]) << 8) | udp_data[1];
                    const dst_port = (@as(u16, udp_data[2]) << 8) | udp_data[3];
                    info.src_port = src_port;
                    info.dst_port = dst_port;

                    if ((src_port == 67 or src_port == 68) and (dst_port == 67 or dst_port == 68)) {
                        info.class = .dhcp;
                    } else if (dst_port == 53 or src_port == 53) {
                        info.class = .dns;
                    } else {
                        info.class = .udp;
                    }
                } else if (ipv4.protocol == .tcp) {
                    info.class = .tcp;
                    if (ip_data.len >= ipv4.getHeaderLength() + 4) {
                        const tcp_data = ip_data[ipv4.getHeaderLength()..];
                        info.src_port = (@as(u16, tcp_data[0]) << 8) | tcp_data[1];
                        info.dst_port = (@as(u16, tcp_data[2]) << 8) | tcp_data[3];
                    }
                } else if (ipv4.protocol == .icmp) {
                    info.class = .icmp;
                }
            }
        },
        .ipv6 => {
            const ip_data = data[EthernetHeader.SIZE..];
            if (Ipv6Header.parse(ip_data)) |ipv6| {
                info.payload_offset = EthernetHeader.SIZE + Ipv6Header.SIZE;
                info.payload_length = ipv6.payload_length;

                // Check multicast (ff00::/8)
                if (ipv6.dst_ip[0] == 0xFF) {
                    info.class = .ipv6_multicast;
                } else {
                    info.class = .ipv6_unicast;
                }

                if (ipv6.next_header == 58) {
                    info.class = .icmpv6;
                }
            }
        },
        else => {},
    }

    return info;
}

// ============================================================================
// Packet Queue
// ============================================================================

/// Maximum packets in queue
pub const MAX_QUEUE_SIZE = 256;

/// Packet with metadata
pub const QueuedPacket = struct {
    data: []u8,
    info: PacketInfo,
    timestamp: i64,
    priority: u8,
};

/// Thread-safe packet queue
pub const PacketQueue = struct {
    allocator: Allocator,
    packets: std.ArrayListUnmanaged(QueuedPacket),
    mutex: std.Thread.Mutex,
    total_bytes: u64,
    dropped_count: u64,

    pub fn init(allocator: Allocator) PacketQueue {
        return .{
            .allocator = allocator,
            .packets = .{},
            .mutex = .{},
            .total_bytes = 0,
            .dropped_count = 0,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.packets.items) |pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.deinit(self.allocator);
    }

    /// Enqueue a packet
    pub fn enqueue(self: *PacketQueue, data: []const u8, priority: u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.packets.items.len >= MAX_QUEUE_SIZE) {
            self.dropped_count += 1;
            return error.QueueFull;
        }

        const copy = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(copy);

        try self.packets.append(self.allocator, .{
            .data = copy,
            .info = classifyPacket(copy),
            .timestamp = std.time.milliTimestamp(),
            .priority = priority,
        });

        self.total_bytes += data.len;
    }

    /// Dequeue a packet
    pub fn dequeue(self: *PacketQueue) ?QueuedPacket {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.packets.items.len == 0) return null;

        return self.packets.orderedRemove(0);
    }

    /// Get queue length
    pub fn len(self: *PacketQueue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.packets.items.len;
    }

    /// Check if empty
    pub fn isEmpty(self: *PacketQueue) bool {
        return self.len() == 0;
    }

    /// Clear all packets
    pub fn clear(self: *PacketQueue) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.packets.items) |pkt| {
            self.allocator.free(pkt.data);
        }
        self.packets.clearRetainingCapacity();
    }
};

// ============================================================================
// Packet Processor
// ============================================================================

/// Packet processing actions
pub const PacketAction = enum {
    forward, // Forward to tunnel/adapter
    drop, // Drop the packet
    respond, // Generate a response
    queue, // Queue for later processing
    modify, // Modify and forward
};

/// Packet processor for VPN client
pub const PacketProcessor = struct {
    allocator: Allocator,
    local_mac: [6]u8,
    local_ip: u32,
    gateway_mac: ?[6]u8,
    gateway_ip: u32,

    // Queues
    send_queue: PacketQueue,
    recv_queue: PacketQueue,

    // Stats
    packets_processed: u64,
    packets_dropped: u64,
    packets_modified: u64,

    pub fn init(allocator: Allocator) PacketProcessor {
        return .{
            .allocator = allocator,
            .local_mac = [_]u8{0} ** 6,
            .local_ip = 0,
            .gateway_mac = null,
            .gateway_ip = 0,
            .send_queue = PacketQueue.init(allocator),
            .recv_queue = PacketQueue.init(allocator),
            .packets_processed = 0,
            .packets_dropped = 0,
            .packets_modified = 0,
        };
    }

    pub fn deinit(self: *PacketProcessor) void {
        self.send_queue.deinit();
        self.recv_queue.deinit();
    }

    /// Configure local network settings
    pub fn configure(self: *PacketProcessor, mac: [6]u8, ip: u32, gateway_ip: u32) void {
        self.local_mac = mac;
        self.local_ip = ip;
        self.gateway_ip = gateway_ip;
    }

    /// Set gateway MAC (learned from ARP)
    pub fn setGatewayMac(self: *PacketProcessor, mac: [6]u8) void {
        self.gateway_mac = mac;
    }

    /// Process outgoing packet (to VPN tunnel)
    pub fn processOutgoing(self: *PacketProcessor, data: []const u8) PacketAction {
        const info = classifyPacket(data);
        self.packets_processed += 1;

        // Always forward most packets
        return switch (info.class) {
            .arp_request, .arp_reply => .forward,
            .dhcp => .forward,
            .ipv4_unicast, .ipv4_broadcast, .ipv4_multicast => .forward,
            .ipv6_unicast, .ipv6_multicast => .forward,
            .ethernet_broadcast => .forward,
            else => .forward,
        };
    }

    /// Process incoming packet (from VPN tunnel)
    pub fn processIncoming(self: *PacketProcessor, data: []const u8) PacketAction {
        const info = classifyPacket(data);
        self.packets_processed += 1;

        // Check if packet is for us
        if (info.dst_mac) |dst| {
            // Accept if for our MAC, broadcast, or multicast
            if (!mem.eql(u8, &dst, &self.local_mac) and
                !mem.eql(u8, &dst, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }) and
                (dst[0] & 0x01) == 0)
            {
                self.packets_dropped += 1;
                return .drop;
            }
        }

        // Handle ARP
        if (info.class == .arp_request) {
            if (info.dst_ip) |target| {
                if (target == self.local_ip) {
                    return .respond; // Need to send ARP reply
                }
            }
        }

        // Handle ARP reply - learn gateway MAC
        if (info.class == .arp_reply) {
            if (info.src_ip) |sender| {
                if (sender == self.gateway_ip) {
                    if (info.src_mac) |mac| {
                        self.gateway_mac = mac;
                    }
                }
            }
        }

        return .forward;
    }

    /// Queue packet for sending
    pub fn queueSend(self: *PacketProcessor, data: []const u8) !void {
        try self.send_queue.enqueue(data, 0);
    }

    /// Queue received packet
    pub fn queueRecv(self: *PacketProcessor, data: []const u8) !void {
        try self.recv_queue.enqueue(data, 0);
    }

    /// Get next packet to send
    pub fn getNextSend(self: *PacketProcessor) ?QueuedPacket {
        return self.send_queue.dequeue();
    }

    /// Get next received packet
    pub fn getNextRecv(self: *PacketProcessor) ?QueuedPacket {
        return self.recv_queue.dequeue();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "EtherType conversion" {
    try std.testing.expectEqual(EtherType.ipv4, EtherType.fromBytes(.{ 0x08, 0x00 }));
    try std.testing.expectEqual(EtherType.arp, EtherType.fromBytes(.{ 0x08, 0x06 }));
    try std.testing.expectEqual(EtherType.ipv6, EtherType.fromBytes(.{ 0x86, 0xDD }));

    const bytes = EtherType.ipv4.toBytes();
    try std.testing.expectEqual(@as(u8, 0x08), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x00), bytes[1]);
}

test "IpProtocol conversion" {
    try std.testing.expectEqual(IpProtocol.tcp, IpProtocol.fromByte(6));
    try std.testing.expectEqual(IpProtocol.udp, IpProtocol.fromByte(17));
    try std.testing.expectEqual(IpProtocol.icmp, IpProtocol.fromByte(1));
    try std.testing.expectEqual(IpProtocol.unknown, IpProtocol.fromByte(255));
}

test "EthernetHeader parse" {
    const data = [_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst MAC (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00, // IPv4
    };

    const hdr = EthernetHeader.parse(&data).?;
    try std.testing.expect(hdr.isBroadcast());
    try std.testing.expectEqual(EtherType.ipv4, hdr.ether_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, &hdr.src_mac);
}

test "EthernetHeader serialize" {
    const hdr = EthernetHeader{
        .dst_mac = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        .src_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .ether_type = .arp,
    };

    var buffer: [20]u8 = undefined;
    const len = try hdr.serialize(&buffer);
    try std.testing.expectEqual(@as(usize, 14), len);
    try std.testing.expectEqual(@as(u8, 0x08), buffer[12]);
    try std.testing.expectEqual(@as(u8, 0x06), buffer[13]);
}

test "Ipv4Header parse" {
    const data = [_]u8{
        0x45, 0x00, // version, IHL, DSCP
        0x00, 0x3C, // total length
        0x1C, 0x46, // identification
        0x40, 0x00, // flags, fragment
        0x40, 0x06, // TTL, protocol (TCP)
        0x00, 0x00, // checksum
        0xC0, 0xA8, 0x01, 0x01, // src: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x02, // dst: 192.168.1.2
    };

    const hdr = Ipv4Header.parse(&data).?;
    try std.testing.expectEqual(@as(u8, 20), hdr.getHeaderLength());
    try std.testing.expectEqual(IpProtocol.tcp, hdr.protocol);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), hdr.src_ip);
    try std.testing.expectEqual(@as(u32, 0xC0A80102), hdr.dst_ip);
}

test "ArpHeader parse" {
    const data = [_]u8{
        0x00, 0x01, // hardware type (Ethernet)
        0x08, 0x00, // protocol type (IPv4)
        0x06, 0x04, // hw len, proto len
        0x00, 0x01, // operation (request)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender MAC
        0xC0, 0xA8, 0x01, 0x01, // sender IP
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC
        0xC0, 0xA8, 0x01, 0x02, // target IP
    };

    const hdr = ArpHeader.parse(&data).?;
    try std.testing.expectEqual(ArpHeader.ArpOperation.request, hdr.operation);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), hdr.sender_ip);
    try std.testing.expectEqual(@as(u32, 0xC0A80102), hdr.target_ip);
}

test "classifyPacket ARP request" {
    var data: [42]u8 = undefined;
    // Ethernet header
    @memset(data[0..6], 0xFF); // broadcast
    @memcpy(data[6..12], &[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 });
    data[12] = 0x08;
    data[13] = 0x06; // ARP
    // ARP header
    data[14] = 0x00;
    data[15] = 0x01;
    data[16] = 0x08;
    data[17] = 0x00;
    data[18] = 0x06;
    data[19] = 0x04;
    data[20] = 0x00;
    data[21] = 0x01; // request
    @memset(data[22..42], 0);

    const info = classifyPacket(&data);
    try std.testing.expectEqual(PacketClass.arp_request, info.class);
    try std.testing.expectEqual(EtherType.arp, info.ether_type);
}

test "PacketInfo initialization" {
    const info = PacketInfo.init();
    try std.testing.expectEqual(PacketClass.unknown, info.class);
    try std.testing.expect(info.src_mac == null);
    try std.testing.expect(info.dst_ip == null);
}

test "PacketQueue basic operations" {
    var queue = PacketQueue.init(std.testing.allocator);
    defer queue.deinit();

    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), queue.len());

    try queue.enqueue(&[_]u8{ 1, 2, 3 }, 0);
    try std.testing.expect(!queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 1), queue.len());

    const pkt = queue.dequeue().?;
    defer std.testing.allocator.free(pkt.data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, pkt.data);

    try std.testing.expect(queue.isEmpty());
}

test "PacketProcessor initialization" {
    var proc = PacketProcessor.init(std.testing.allocator);
    defer proc.deinit();

    try std.testing.expectEqual(@as(u64, 0), proc.packets_processed);
    try std.testing.expect(proc.gateway_mac == null);
}

test "PacketProcessor configure" {
    var proc = PacketProcessor.init(std.testing.allocator);
    defer proc.deinit();

    proc.configure(.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, 0xC0A80101, 0xC0A80101);

    try std.testing.expectEqual(@as(u32, 0xC0A80101), proc.local_ip);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, &proc.local_mac);
}

test "PacketProcessor setGatewayMac" {
    var proc = PacketProcessor.init(std.testing.allocator);
    defer proc.deinit();

    try std.testing.expect(proc.gateway_mac == null);
    proc.setGatewayMac(.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    try std.testing.expect(proc.gateway_mac != null);
}

test "EthernetHeader multicast detection" {
    const hdr = EthernetHeader{
        .dst_mac = .{ 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 }, // Multicast
        .src_mac = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 },
        .ether_type = .ipv4,
    };

    try std.testing.expect(hdr.isMulticast());
    try std.testing.expect(!hdr.isBroadcast());
}
