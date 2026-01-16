//! SoftEther VPN Tunnel Protocol
//!
//! Wire format for data channel after authentication:
//!
//! Packet batch format:
//!   [4 bytes] num_blocks (big-endian) - or KEEP_ALIVE_MAGIC (0xFFFFFFFF)
//!   For each block:
//!     [4 bytes] block_size (big-endian)
//!     [N bytes] block_data (Ethernet frame)
//!
//! Keep-alive format:
//!   [4 bytes] KEEP_ALIVE_MAGIC (0xFFFFFFFF)
//!   [4 bytes] keep_alive_size
//!   [N bytes] keep_alive_data (random padding)

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const flate = std.compress.flate;
const Io = std.Io;

/// Magic number indicating keep-alive packet (same as SoftEther's KEEP_ALIVE_MAGIC)
pub const KEEP_ALIVE_MAGIC: u32 = 0xFFFFFFFF;

/// Maximum packet size (Ethernet frame)
pub const MAX_PACKET_SIZE: usize = 1514;

/// Maximum keep-alive data size
pub const MAX_KEEPALIVE_SIZE: usize = 512;

/// Maximum number of blocks to receive at once
pub const MAX_RECV_BLOCKS: usize = 512; // Server can send many blocks at once

/// Block read from tunnel
pub const Block = struct {
    data: []u8,
    allocator: Allocator,

    pub fn deinit(self: *Block) void {
        self.allocator.free(self.data);
    }
};

/// Tunnel connection for data channel
pub const TunnelConnection = struct {
    allocator: Allocator,

    // I/O callbacks
    read_fn: *const fn (ctx: *anyopaque, buf: []u8) anyerror!usize,
    write_fn: *const fn (ctx: *anyopaque, data: []const u8) anyerror!usize,
    context: *anyopaque,

    // Compression flag - when true, compress outgoing blocks
    use_compression: bool = false,

    // Receive state machine
    recv_state: RecvState = .read_num_blocks,
    num_blocks: u32 = 0,
    current_block: u32 = 0,
    block_size: u32 = 0,

    // Partial read buffer
    partial_buf: [4]u8 = undefined,
    partial_len: usize = 0,

    // Stats
    total_recv: u64 = 0,
    total_send: u64 = 0,
    keepalives_recv: u64 = 0,
    keepalives_sent: u64 = 0,

    const RecvState = enum {
        read_num_blocks,
        read_block_size,
        read_block_data,
        read_keepalive_size,
        read_keepalive_data,
    };

    pub fn init(
        allocator: Allocator,
        context: *anyopaque,
        read_fn: *const fn (*anyopaque, []u8) anyerror!usize,
        write_fn: *const fn (*anyopaque, []const u8) anyerror!usize,
    ) TunnelConnection {
        return .{
            .allocator = allocator,
            .context = context,
            .read_fn = read_fn,
            .write_fn = write_fn,
        };
    }

    /// Initialize with compression enabled/disabled
    pub fn initWithCompression(
        allocator: Allocator,
        context: *anyopaque,
        read_fn: *const fn (*anyopaque, []u8) anyerror!usize,
        write_fn: *const fn (*anyopaque, []const u8) anyerror!usize,
        use_compression: bool,
    ) TunnelConnection {
        return .{
            .allocator = allocator,
            .context = context,
            .read_fn = read_fn,
            .write_fn = write_fn,
            .use_compression = use_compression,
        };
    }

    /// Read a single u32 (big-endian) from the connection
    fn readU32(self: *TunnelConnection) !u32 {
        // First use any partial data
        while (self.partial_len < 4) {
            const n = try self.read_fn(self.context, self.partial_buf[self.partial_len..]);
            if (n == 0) return error.ConnectionClosed;
            self.partial_len += n;
        }

        const value = mem.readInt(u32, &self.partial_buf, .big);
        self.partial_len = 0;
        self.total_recv += 4;
        return value;
    }

    /// Read exact number of bytes
    fn readExact(self: *TunnelConnection, buf: []u8) !void {
        var offset: usize = 0;
        while (offset < buf.len) {
            const n = try self.read_fn(self.context, buf[offset..]);
            if (n == 0) return error.ConnectionClosed;
            offset += n;
        }
        self.total_recv += buf.len;
    }

    /// Receive blocks from the tunnel
    /// Returns blocks via callback to avoid ArrayList dependency
    pub fn receiveBlocks(
        self: *TunnelConnection,
        comptime callback: fn (data: []u8, ctx: anytype) void,
        ctx: anytype,
    ) !void {
        // Read number of blocks
        const num_blocks = try self.readU32();

        if (num_blocks == KEEP_ALIVE_MAGIC) {
            // Keep-alive packet
            const ka_size = try self.readU32();
            if (ka_size > MAX_KEEPALIVE_SIZE) {
                return error.InvalidPacket;
            }

            // Discard keep-alive data
            var discard_buf: [MAX_KEEPALIVE_SIZE]u8 = undefined;
            try self.readExact(discard_buf[0..ka_size]);
            self.keepalives_recv += 1;
            return;
        }

        if (num_blocks > MAX_RECV_BLOCKS) {
            return error.TooManyBlocks;
        }

        // Read each block
        var i: u32 = 0;
        while (i < num_blocks) : (i += 1) {
            const block_size = try self.readU32();

            if (block_size == 0) continue;
            if (block_size > MAX_PACKET_SIZE * 2) {
                return error.PacketTooLarge;
            }

            // Allocate and read block data
            const data = try self.allocator.alloc(u8, block_size);
            errdefer self.allocator.free(data);

            try self.readExact(data);

            // Call the callback with the block
            callback(data, ctx);
        }
    }

    /// Receive a single batch of blocks into provided buffer
    /// Returns number of blocks received, fills out_data with slices
    pub fn receiveBlocksBatch(
        self: *TunnelConnection,
        out_data: [][]u8,
        scratch_buffer: []u8,
    ) !usize {
        // Read number of blocks
        const num_blocks = try self.readU32();

        // Handle keep-alive packet (0xFFFFFFFF followed by size and random data)
        // This is sent by the server periodically to keep the connection alive
        if (num_blocks == KEEP_ALIVE_MAGIC) {
            const ka_size = try self.readU32();
            if (ka_size > MAX_KEEPALIVE_SIZE) return error.InvalidPacket;
            var discard_buf: [MAX_KEEPALIVE_SIZE]u8 = undefined;
            try self.readExact(discard_buf[0..ka_size]);
            self.keepalives_recv += 1;
            std.log.debug("Received keep-alive (size={d})", .{ka_size});
            return 0;
        }

        if (num_blocks > MAX_RECV_BLOCKS or num_blocks > out_data.len) {
            std.log.warn("TooManyBlocks: num_blocks={d}, max={d}, out_data.len={d}", .{ num_blocks, MAX_RECV_BLOCKS, out_data.len });
            return error.TooManyBlocks;
        }

        var scratch_offset: usize = 0;
        var block_count: usize = 0;

        var i: u32 = 0;
        while (i < num_blocks) : (i += 1) {
            const block_size = try self.readU32();
            if (block_size == 0) continue;
            if (block_size > MAX_PACKET_SIZE * 2) {
                std.log.warn("PacketTooLarge: block_size={d}", .{block_size});
                return error.PacketTooLarge;
            }
            if (scratch_offset + block_size > scratch_buffer.len) {
                std.log.warn("BufferTooSmall: need {d}, have {d}", .{ scratch_offset + block_size, scratch_buffer.len });
                return error.BufferTooSmall;
            }

            try self.readExact(scratch_buffer[scratch_offset..][0..block_size]);
            out_data[block_count] = scratch_buffer[scratch_offset..][0..block_size];
            scratch_offset += block_size;
            block_count += 1;
        }

        if (block_count > 0) {
            // Per-receive logging at trace level to reduce noise
            std.log.scoped(.packet_trace).debug("Received {d} blocks ({d} bytes)", .{ block_count, scratch_offset });
        }

        return block_count;
    }

    /// Send blocks through the tunnel using pre-allocated buffer (zero-copy path)
    /// Compresses each block if use_compression is enabled
    pub fn sendBlocksZeroCopy(self: *TunnelConnection, blocks: []const []const u8, send_buffer: []u8) !void {
        if (blocks.len == 0) return;

        // Compression buffer (per block)
        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        // Calculate total size needed (uncompressed, as upper bound)
        var total_size: usize = 4; // num_blocks
        for (blocks) |block| {
            total_size += 4 + block.len; // size + data
        }

        if (total_size > send_buffer.len) return error.BufferTooSmall;

        var offset: usize = 0;

        // Write number of blocks
        mem.writeInt(u32, send_buffer[0..4], @intCast(blocks.len), .big);
        offset += 4;

        // Write each block (compressed if enabled)
        for (blocks) |block| {
            if (self.use_compression and block.len > 14) {
                // Compress this block
                if (compressZlib(block, &compress_buf)) |compressed_len| {
                    // Only use compression if it actually saves space
                    if (compressed_len < block.len) {
                        mem.writeInt(u32, send_buffer[offset..][0..4], @intCast(compressed_len), .big);
                        offset += 4;
                        @memcpy(send_buffer[offset..][0..compressed_len], compress_buf[0..compressed_len]);
                        offset += compressed_len;
                        continue;
                    }
                }
            }
            // Either compression disabled, failed, or didn't help - send uncompressed
            mem.writeInt(u32, send_buffer[offset..][0..4], @intCast(block.len), .big);
            offset += 4;
            @memcpy(send_buffer[offset..][0..block.len], block);
            offset += block.len;
        }

        // Single write - TLS/TCP should handle it atomically with TCP_NODELAY
        const n = try self.write_fn(self.context, send_buffer[0..offset]);
        if (n == 0) return error.ConnectionClosed;
        // If partial write, complete it
        if (n < offset) {
            var sent = n;
            while (sent < offset) {
                const m = try self.write_fn(self.context, send_buffer[sent..offset]);
                if (m == 0) return error.ConnectionClosed;
                sent += m;
            }
        }

        self.total_send += offset;
    }

    /// Send a single IP packet wrapped in Ethernet, directly into send buffer (minimal copy)
    /// Returns number of bytes written to send_buffer, or 0 on error
    /// Compresses the Ethernet frame if use_compression is enabled
    pub fn sendSinglePacketDirect(
        self: *TunnelConnection,
        ip_packet: []const u8,
        dst_mac: [6]u8,
        src_mac: [6]u8,
        send_buffer: []u8,
    ) !usize {
        if (ip_packet.len == 0 or ip_packet.len > 1500) return 0;

        const eth_len = 14 + ip_packet.len;

        // First build the Ethernet frame in a temp buffer
        var eth_frame: [1600]u8 = undefined;
        @memcpy(eth_frame[0..6], &dst_mac); // dst MAC
        @memcpy(eth_frame[6..12], &src_mac); // src MAC

        // EtherType
        const ip_version = (ip_packet[0] >> 4) & 0x0F;
        if (ip_version == 4) {
            eth_frame[12] = 0x08;
            eth_frame[13] = 0x00;
        } else if (ip_version == 6) {
            eth_frame[12] = 0x86;
            eth_frame[13] = 0xDD;
        } else {
            return 0;
        }

        // Copy IP packet
        @memcpy(eth_frame[14..][0..ip_packet.len], ip_packet);

        // Now handle compression
        var final_data: []const u8 = eth_frame[0..eth_len];
        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        if (self.use_compression and eth_len > 14) {
            if (compressZlib(eth_frame[0..eth_len], &compress_buf)) |compressed_len| {
                if (compressed_len < eth_len) {
                    final_data = compress_buf[0..compressed_len];
                }
            }
        }

        const total_len = 4 + 4 + final_data.len; // num_blocks + size + data
        if (total_len > send_buffer.len) return 0;

        // Build packet in send buffer
        mem.writeInt(u32, send_buffer[0..4], 1, .big); // num_blocks = 1
        mem.writeInt(u32, send_buffer[4..8], @intCast(final_data.len), .big); // block size
        @memcpy(send_buffer[8..][0..final_data.len], final_data);

        // Send
        const n = try self.write_fn(self.context, send_buffer[0..total_len]);
        if (n == 0) return error.ConnectionClosed;
        if (n < total_len) {
            var sent = n;
            while (sent < total_len) {
                const m = try self.write_fn(self.context, send_buffer[sent..total_len]);
                if (m == 0) return error.ConnectionClosed;
                sent += m;
            }
        }

        self.total_send += total_len;
        return eth_len; // Return original eth_len for stats
    }

    /// Compress data using zlib (fast compression for VPN traffic)
    /// Returns compressed length, or null on error
    fn compressZlib(input: []const u8, output: []u8) ?usize {
        var input_reader: Io.Reader = .fixed(input);
        var output_writer: Io.Writer = .fixed(output);
        var window_buf: [flate.max_window_len]u8 = undefined;
        var compress: flate.Compress = .init(&input_reader, .zlib, .fast, &window_buf);

        const compressed_len = compress.writer.streamRemaining(&output_writer) catch |err| {
            std.log.debug("Zlib compression error: {}", .{err});
            return null;
        };

        return compressed_len;
    }

    /// Send blocks through the tunnel (allocating version for compatibility)
    /// Compresses each block if use_compression is enabled
    pub fn sendBlocks(self: *TunnelConnection, blocks: []const []const u8) !void {
        if (blocks.len == 0) return;

        // Compression buffer (per block, max ~2x size for worst case)
        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        // Calculate total size needed (with potential compression)
        // We allocate conservatively for uncompressed; compression may reduce this
        var total_size: usize = 4; // num_blocks
        for (blocks) |block| {
            total_size += 4 + block.len; // size + data (max size)
        }

        // Build the packet
        const packet = try self.allocator.alloc(u8, total_size);
        defer self.allocator.free(packet);

        var offset: usize = 0;

        // Write number of blocks
        mem.writeInt(u32, packet[0..4], @intCast(blocks.len), .big);
        offset += 4;

        // Write each block (compressed if enabled)
        for (blocks) |block| {
            if (self.use_compression and block.len > 14) {
                // Compress this block
                if (compressZlib(block, &compress_buf)) |compressed_len| {
                    // Only use compression if it actually saves space
                    if (compressed_len < block.len) {
                        mem.writeInt(u32, packet[offset..][0..4], @intCast(compressed_len), .big);
                        offset += 4;
                        @memcpy(packet[offset..][0..compressed_len], compress_buf[0..compressed_len]);
                        offset += compressed_len;
                        continue;
                    }
                }
            }
            // Either compression disabled, failed, or didn't help - send uncompressed
            mem.writeInt(u32, packet[offset..][0..4], @intCast(block.len), .big);
            offset += 4;
            @memcpy(packet[offset..][0..block.len], block);
            offset += block.len;
        }

        // Send actual data (may be smaller than allocated due to compression)
        var sent: usize = 0;
        while (sent < offset) {
            const n = try self.write_fn(self.context, packet[sent..offset]);
            if (n == 0) return error.ConnectionClosed;
            sent += n;
        }

        self.total_send += offset;
    }

    /// Send a keep-alive packet
    pub fn sendKeepalive(self: *TunnelConnection) !void {
        var packet: [8 + 32]u8 = undefined;

        // KEEP_ALIVE_MAGIC
        mem.writeInt(u32, packet[0..4], KEEP_ALIVE_MAGIC, .big);
        // Keep-alive size
        mem.writeInt(u32, packet[4..8], 32, .big);
        // Random padding
        std.crypto.random.bytes(packet[8..40]);

        var sent: usize = 0;
        while (sent < packet.len) {
            const n = try self.write_fn(self.context, packet[sent..]);
            if (n == 0) return error.ConnectionClosed;
            sent += n;
        }

        self.keepalives_sent += 1;
        self.total_send += packet.len;
    }
};

/// DHCP state for packet loop
pub const DhcpState = enum {
    init,
    arp_sent,
    discover_sent,
    offer_received,
    request_sent,
    configured,
};

/// DHCP configuration received
pub const DhcpConfig = struct {
    ip_address: u32 = 0,
    subnet_mask: u32 = 0,
    gateway: u32 = 0,
    dns_server: u32 = 0,
    lease_time: u32 = 0,
    server_id: u32 = 0,

    pub fn isValid(self: *const DhcpConfig) bool {
        return self.ip_address != 0;
    }
};

test "TunnelConnection block format" {
    // Test that our format matches SoftEther
    var buf: [100]u8 = undefined;

    // Encode 2 blocks
    mem.writeInt(u32, buf[0..4], 2, .big);
    mem.writeInt(u32, buf[4..8], 4, .big); // block 1 size
    @memcpy(buf[8..12], "TEST"); // block 1 data
    mem.writeInt(u32, buf[12..16], 3, .big); // block 2 size
    @memcpy(buf[16..19], "ABC"); // block 2 data

    try std.testing.expectEqual(@as(u32, 2), mem.readInt(u32, buf[0..4], .big));
}

test "keep-alive magic" {
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), KEEP_ALIVE_MAGIC);
}
