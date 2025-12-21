//! SoftEther VPN Connection Layer
//!
//! Manages TCP connections for VPN sessions.
//! Handles connection establishment, reconnection, and multiple TCP streams.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const session = @import("session.zig");

// Local crypto helpers
fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

fn randomU32() u32 {
    var buf: [4]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return mem.readInt(u32, &buf, .little);
}

// ============================================================================
// Connection Configuration
// ============================================================================

/// Connection configuration constants
pub const Config = struct {
    /// Maximum concurrent TCP connections
    pub const max_connections: usize = 32;

    /// Default connection timeout (ms)
    pub const default_timeout_ms: u64 = 30_000;

    /// Connect timeout (ms)
    pub const connect_timeout_ms: u64 = 15_000;

    /// Maximum send queue size (bytes)
    pub const max_send_queue_size: usize = 32 * 1024 * 1024;

    /// Maximum buffered packet size
    pub const max_buffering_packet_size: usize = 1024 * 1024;

    /// Signature for SoftEther protocol
    pub const protocol_signature = "SE Vu";

    /// Protocol version
    pub const protocol_version: u32 = 0x00000413;
};

// ============================================================================
// Connection Direction
// ============================================================================

/// TCP connection direction
pub const TcpDirection = enum(u32) {
    /// Bidirectional
    both = 0,
    /// Server to client only
    server_to_client = 1,
    /// Client to server only
    client_to_server = 2,
};

// ============================================================================
// Connection State
// ============================================================================

/// Connection state
pub const ConnectionState = enum(u32) {
    /// Not connected
    disconnected = 0,
    /// Connecting
    connecting = 1,
    /// Connected
    connected = 2,
    /// Disconnecting
    disconnecting = 3,
};

// ============================================================================
// TCP Socket Info
// ============================================================================

/// Information about a TCP socket in the connection
pub const TcpSocketInfo = struct {
    /// Socket ID
    id: u32,
    /// Direction of this socket
    direction: TcpDirection,
    /// Is this socket connected
    connected: bool,
    /// Creation time
    created_time: i64,
    /// Last send time
    last_send_time: i64,
    /// Last recv time
    last_recv_time: i64,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,

    pub fn init(id: u32, direction: TcpDirection) TcpSocketInfo {
        const now = std.time.milliTimestamp();
        return .{
            .id = id,
            .direction = direction,
            .connected = false,
            .created_time = now,
            .last_send_time = now,
            .last_recv_time = now,
            .bytes_sent = 0,
            .bytes_received = 0,
        };
    }
};

// ============================================================================
// Block (Data Unit)
// ============================================================================

/// Data block for send/receive
pub const Block = struct {
    /// Block data
    data: []u8,
    /// Data size
    size: usize,
    /// Is priority packet
    priority: bool,
    /// Compression flag
    compressed: bool,
    /// Original size (before compression)
    original_size: usize,

    pub fn init(allocator: Allocator, data: []const u8, priority: bool) !Block {
        const buf = try allocator.dupe(u8, data);
        return .{
            .data = buf,
            .size = data.len,
            .priority = priority,
            .compressed = false,
            .original_size = data.len,
        };
    }

    pub fn deinit(self: *Block, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ============================================================================
// Block Queue
// ============================================================================

/// Queue of blocks for send/receive
pub const BlockQueue = struct {
    allocator: Allocator,
    blocks: std.ArrayListUnmanaged(Block),
    total_size: usize,

    pub fn init(allocator: Allocator) BlockQueue {
        return .{
            .allocator = allocator,
            .blocks = .{},
            .total_size = 0,
        };
    }

    pub fn deinit(self: *BlockQueue) void {
        for (self.blocks.items) |*block| {
            block.deinit(self.allocator);
        }
        self.blocks.deinit(self.allocator);
    }

    pub fn enqueue(self: *BlockQueue, data: []const u8, priority: bool) !void {
        const block = try Block.init(self.allocator, data, priority);
        errdefer @constCast(&block).deinit(self.allocator);
        try self.blocks.append(self.allocator, block);
        self.total_size += data.len;
    }

    pub fn dequeue(self: *BlockQueue) ?Block {
        if (self.blocks.items.len == 0) {
            return null;
        }
        const block = self.blocks.orderedRemove(0);
        self.total_size -= block.size;
        return block;
    }

    pub fn isEmpty(self: *const BlockQueue) bool {
        return self.blocks.items.len == 0;
    }

    pub fn len(self: *const BlockQueue) usize {
        return self.blocks.items.len;
    }
};

// ============================================================================
// Connection
// ============================================================================

/// VPN Connection
pub const Connection = struct {
    allocator: Allocator,

    /// Connection name
    name: [64]u8,

    /// Current state
    state: ConnectionState,

    /// Connection ID
    id: u32,

    /// Server information
    server_name: [256]u8,
    server_port: u16,

    /// Protocol version
    protocol_version: u32,

    /// Error code
    err: u32,

    /// Is client connection
    is_client: bool,

    /// Use encryption
    use_encrypt: bool,

    /// Use compression
    use_compress: bool,

    /// Half connection mode
    half_connection: bool,

    /// Maximum number of TCP connections
    max_connections: u32,

    /// Current number of TCP connections
    num_connections: u32,

    /// TCP sockets info
    tcp_sockets: [Config.max_connections]?TcpSocketInfo,

    /// Send queue
    send_blocks: BlockQueue,

    /// Receive queue
    recv_blocks: BlockQueue,

    /// Current send queue size
    current_send_queue_size: usize,

    /// Timing
    created_time: i64,
    connected_time: i64,
    last_comm_time: i64,

    /// Server random (for authentication)
    server_random: [20]u8,

    /// Client random
    client_random: [20]u8,

    /// Connection established successfully
    connect_succeed: bool,

    /// Retry count
    retry_count: u32,

    /// Create a new connection
    pub fn init(allocator: Allocator, is_client: bool) Connection {
        var conn = Connection{
            .allocator = allocator,
            .name = [_]u8{0} ** 64,
            .state = .disconnected,
            .id = randomU32(),
            .server_name = [_]u8{0} ** 256,
            .server_port = 443,
            .protocol_version = Config.protocol_version,
            .err = 0,
            .is_client = is_client,
            .use_encrypt = true,
            .use_compress = false,
            .half_connection = false,
            .max_connections = 1,
            .num_connections = 0,
            .tcp_sockets = [_]?TcpSocketInfo{null} ** Config.max_connections,
            .send_blocks = BlockQueue.init(allocator),
            .recv_blocks = BlockQueue.init(allocator),
            .current_send_queue_size = 0,
            .created_time = std.time.milliTimestamp(),
            .connected_time = 0,
            .last_comm_time = 0,
            .server_random = undefined,
            .client_random = undefined,
            .connect_succeed = false,
            .retry_count = 0,
        };

        // Generate client random
        randomBytes(&conn.client_random);

        return conn;
    }

    /// Clean up connection
    pub fn deinit(self: *Connection) void {
        self.send_blocks.deinit();
        self.recv_blocks.deinit();
    }

    /// Set server information
    pub fn setServer(self: *Connection, hostname: []const u8, port: u16) void {
        const len = @min(hostname.len, self.server_name.len - 1);
        @memset(&self.server_name, 0);
        @memcpy(self.server_name[0..len], hostname[0..len]);
        self.server_port = port;
    }

    /// Get protocol signature
    pub fn getSignature() []const u8 {
        return Config.protocol_signature;
    }

    /// Build protocol signature with version
    pub fn buildSignaturePacket() [9]u8 {
        var packet: [9]u8 = undefined;
        @memcpy(packet[0..5], Config.protocol_signature);
        mem.writeInt(u32, packet[5..9], Config.protocol_version, .big);
        return packet;
    }

    /// Check if signature packet is valid
    pub fn isValidSignature(data: []const u8) bool {
        if (data.len < 5) return false;
        return mem.eql(u8, data[0..5], Config.protocol_signature);
    }

    /// Parse protocol version from signature
    pub fn parseVersion(data: []const u8) ?u32 {
        if (data.len < 9) return null;
        return mem.readInt(u32, data[5..9], .big);
    }

    /// Add a TCP socket to the connection
    pub fn addSocket(self: *Connection, direction: TcpDirection) ?u32 {
        if (self.num_connections >= self.max_connections) {
            return null;
        }

        // Find empty slot
        for (&self.tcp_sockets, 0..) |*slot, i| {
            if (slot.* == null) {
                const id: u32 = @intCast(i);
                slot.* = TcpSocketInfo.init(id, direction);
                self.num_connections += 1;
                return id;
            }
        }

        return null;
    }

    /// Remove a TCP socket
    pub fn removeSocket(self: *Connection, id: u32) void {
        if (id < Config.max_connections) {
            if (self.tcp_sockets[id] != null) {
                self.tcp_sockets[id] = null;
                self.num_connections -= 1;
            }
        }
    }

    /// Set socket as connected
    pub fn setSocketConnected(self: *Connection, id: u32) void {
        if (id < Config.max_connections) {
            if (self.tcp_sockets[id]) |*sock| {
                sock.connected = true;
            }
        }
    }

    /// Queue data for sending
    pub fn sendData(self: *Connection, data: []const u8, priority: bool) !void {
        if (self.current_send_queue_size + data.len > Config.max_send_queue_size) {
            // Queue full, drop
            return;
        }

        try self.send_blocks.enqueue(data, priority);
        self.current_send_queue_size += data.len;
    }

    /// Get next block to send
    pub fn getNextSendBlock(self: *Connection) ?Block {
        if (self.send_blocks.dequeue()) |block| {
            self.current_send_queue_size -= block.size;
            return block;
        }
        return null;
    }

    /// Queue received data
    pub fn receiveData(self: *Connection, data: []const u8) !void {
        try self.recv_blocks.enqueue(data, false);
        self.last_comm_time = std.time.milliTimestamp();
    }

    /// Get next received block
    pub fn getNextRecvBlock(self: *Connection) ?Block {
        return self.recv_blocks.dequeue();
    }

    /// Update connection state
    pub fn setState(self: *Connection, state: ConnectionState) void {
        self.state = state;
        if (state == .connected) {
            self.connected_time = std.time.milliTimestamp();
            self.connect_succeed = true;
        }
    }

    /// Check if connection is established
    pub fn isConnected(self: *const Connection) bool {
        return self.state == .connected;
    }

    /// Get active socket count
    pub fn getActiveSocketCount(self: *const Connection) u32 {
        var count: u32 = 0;
        for (self.tcp_sockets) |slot| {
            if (slot) |sock| {
                if (sock.connected) {
                    count += 1;
                }
            }
        }
        return count;
    }

    /// Get server hostname
    pub fn getServerName(self: *const Connection) []const u8 {
        const end = mem.indexOfScalar(u8, &self.server_name, 0) orelse self.server_name.len;
        return self.server_name[0..end];
    }
};

// ============================================================================
// Error Codes (compatible with SoftEther)
// ============================================================================

pub const ErrorCode = struct {
    pub const no_error: u32 = 0;
    pub const protocol_error: u32 = 1;
    pub const disconnected: u32 = 2;
    pub const proxy_connect_failed: u32 = 3;
    pub const proxy_error: u32 = 4;
    pub const user_cancel: u32 = 5;
    pub const auth_failed: u32 = 6;
    pub const hub_not_found: u32 = 7;
    pub const user_not_found: u32 = 8;
    pub const access_denied: u32 = 9;
    pub const session_timeout: u32 = 10;
    pub const invalid_certificate: u32 = 11;
    pub const device_driver_error: u32 = 12;
    pub const suspending: u32 = 13;
    pub const server_too_busy: u32 = 14;
    pub const hub_is_busy: u32 = 15;
    pub const server_cant_accept: u32 = 16;
    pub const license_error: u32 = 17;
    pub const internal_error: u32 = 18;
};

// ============================================================================
// Tests
// ============================================================================

test "Connection creation" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();

    try testing.expect(conn.is_client);
    try testing.expectEqual(ConnectionState.disconnected, conn.state);
    try testing.expectEqual(@as(u32, 0), conn.num_connections);
}

test "Connection server setup" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();

    conn.setServer("vpn.example.com", 443);

    try testing.expectEqualStrings("vpn.example.com", conn.getServerName());
    try testing.expectEqual(@as(u16, 443), conn.server_port);
}

test "Connection signature" {
    const sig = Connection.buildSignaturePacket();

    try testing.expect(Connection.isValidSignature(&sig));
    try testing.expectEqual(Config.protocol_version, Connection.parseVersion(&sig).?);

    // Invalid signature
    try testing.expect(!Connection.isValidSignature("XXXX"));
}

test "Connection socket management" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();

    conn.max_connections = 4;

    // Add sockets
    const id1 = conn.addSocket(.both).?;
    const id2 = conn.addSocket(.server_to_client).?;

    try testing.expectEqual(@as(u32, 2), conn.num_connections);

    // Set connected
    conn.setSocketConnected(id1);
    try testing.expectEqual(@as(u32, 1), conn.getActiveSocketCount());

    // Remove socket
    conn.removeSocket(id2);
    try testing.expectEqual(@as(u32, 1), conn.num_connections);
}

test "Connection state transitions" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();

    conn.setState(.connecting);
    try testing.expectEqual(ConnectionState.connecting, conn.state);

    conn.setState(.connected);
    try testing.expect(conn.isConnected());
    try testing.expect(conn.connect_succeed);
    try testing.expect(conn.connected_time > 0);
}

test "BlockQueue operations" {
    var queue = BlockQueue.init(testing.allocator);
    defer queue.deinit();

    const data1 = &[_]u8{ 0x01, 0x02, 0x03 };
    const data2 = &[_]u8{ 0x04, 0x05, 0x06, 0x07 };

    try queue.enqueue(data1, false);
    try queue.enqueue(data2, true);

    try testing.expectEqual(@as(usize, 2), queue.len());
    try testing.expectEqual(@as(usize, 7), queue.total_size);

    var block1 = queue.dequeue().?;
    defer block1.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, data1, block1.data);
    try testing.expect(!block1.priority);

    var block2 = queue.dequeue().?;
    defer block2.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, data2, block2.data);
    try testing.expect(block2.priority);

    try testing.expect(queue.isEmpty());
}

test "Connection send/receive queues" {
    var conn = Connection.init(testing.allocator, true);
    defer conn.deinit();

    const data = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    // Test send queue
    try conn.sendData(data, false);
    try testing.expectEqual(@as(usize, 4), conn.current_send_queue_size);

    var send_block = conn.getNextSendBlock().?;
    defer send_block.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, data, send_block.data);
    try testing.expectEqual(@as(usize, 0), conn.current_send_queue_size);

    // Test receive queue
    try conn.receiveData(data);

    var recv_block = conn.getNextRecvBlock().?;
    defer recv_block.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, data, recv_block.data);
}
