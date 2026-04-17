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
const c = @cImport(@cInclude("zlib.h"));

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

    // Compression
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

            if (self.use_compression) {
                // Read compressed data
                const compressed = try self.allocator.alloc(u8, block_size);
                defer self.allocator.free(compressed);
                try self.readExact(compressed);

                // Decompress
                var decompress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;
                const decompressed = self.decompressBlock(compressed, &decompress_buf) catch continue;

                const data = try self.allocator.alloc(u8, decompressed.len);
                @memcpy(data, decompressed);
                callback(data, ctx);
            } else {
                // Allocate and read block data
                const data = try self.allocator.alloc(u8, block_size);
                errdefer self.allocator.free(data);
                try self.readExact(data);
                callback(data, ctx);
            }
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

            if (self.use_compression) {
                // Read compressed data into temp area at end of scratch buffer
                const compressed_start = scratch_buffer.len - block_size;
                if (compressed_start <= scratch_offset) {
                    std.log.warn("BufferTooSmall for compressed block", .{});
                    return error.BufferTooSmall;
                }
                try self.readExact(scratch_buffer[compressed_start..][0..block_size]);

                // Decompress into scratch buffer at current offset
                const remaining = scratch_buffer[scratch_offset..compressed_start];
                const decompressed = self.decompressBlock(
                    scratch_buffer[compressed_start..][0..block_size],
                    remaining,
                ) catch {
                    continue;
                };

                out_data[block_count] = decompressed;
                scratch_offset += decompressed.len;
            } else {
                // Uncompressed block — read directly
                if (scratch_offset + block_size > scratch_buffer.len) {
                    std.log.warn("BufferTooSmall: need {d}, have {d}", .{ scratch_offset + block_size, scratch_buffer.len });
                    return error.BufferTooSmall;
                }

                try self.readExact(scratch_buffer[scratch_offset..][0..block_size]);
                out_data[block_count] = scratch_buffer[scratch_offset..][0..block_size];
                scratch_offset += block_size;
            }
            block_count += 1;
        }

        if (block_count > 0) {
            // Per-receive logging at trace level to reduce noise
            std.log.scoped(.packet_trace).debug("Received {d} blocks ({d} bytes)", .{ block_count, scratch_offset });
        }

        return block_count;
    }

    /// Send blocks through the tunnel using pre-allocated buffer (zero-copy path)
    pub fn sendBlocksZeroCopy(self: *TunnelConnection, blocks: []const []const u8, send_buffer: []u8) !void {
        if (blocks.len == 0) return;

        var offset: usize = 0;

        // Write number of blocks
        mem.writeInt(u32, send_buffer[0..4], @intCast(blocks.len), .big);
        offset += 4;

        // Temp buffer for compression
        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        // Write each block
        for (blocks) |block| {
            if (self.use_compression) {
                const compressed = compressBlock(&compress_buf, block) catch block;
                mem.writeInt(u32, send_buffer[offset..][0..4], @intCast(compressed.len), .big);
                offset += 4;
                @memcpy(send_buffer[offset..][0..compressed.len], compressed);
                offset += compressed.len;
            } else {
                mem.writeInt(u32, send_buffer[offset..][0..4], @intCast(block.len), .big);
                offset += 4;
                @memcpy(send_buffer[offset..][0..block.len], block);
                offset += block.len;
            }
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
    pub fn sendSinglePacketDirect(
        self: *TunnelConnection,
        ip_packet: []const u8,
        dst_mac: [6]u8,
        src_mac: [6]u8,
        send_buffer: []u8,
    ) !usize {
        if (ip_packet.len == 0 or ip_packet.len > 1500) return 0;

        const eth_len = 14 + ip_packet.len;
        const total_len = 4 + 4 + eth_len; // num_blocks + size + eth_frame

        if (total_len > send_buffer.len) return 0;

        // Build Ethernet frame in a temp area first (for potential compression)
        var eth_frame_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        // Ethernet header (14 bytes)
        @memcpy(eth_frame_buf[0..6], &dst_mac); // dst MAC
        @memcpy(eth_frame_buf[6..12], &src_mac); // src MAC

        // EtherType
        const ip_version = (ip_packet[0] >> 4) & 0x0F;
        if (ip_version == 4) {
            eth_frame_buf[12] = 0x08;
            eth_frame_buf[13] = 0x00;
        } else if (ip_version == 6) {
            eth_frame_buf[12] = 0x86;
            eth_frame_buf[13] = 0xDD;
        } else {
            return 0;
        }

        // IP packet
        @memcpy(eth_frame_buf[14..][0..ip_packet.len], ip_packet);

        const eth_frame = eth_frame_buf[0..eth_len];

        // Try compression
        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;
        var actual_len: usize = undefined;

        if (self.use_compression) {
            const compressed = compressBlock(&compress_buf, eth_frame) catch eth_frame;
            mem.writeInt(u32, send_buffer[0..4], 1, .big);
            mem.writeInt(u32, send_buffer[4..8], @intCast(compressed.len), .big);
            @memcpy(send_buffer[8..][0..compressed.len], compressed);
            actual_len = 8 + compressed.len;
        } else {
            mem.writeInt(u32, send_buffer[0..4], 1, .big);
            mem.writeInt(u32, send_buffer[4..8], @intCast(eth_len), .big);
            @memcpy(send_buffer[8..][0..eth_len], eth_frame);
            actual_len = 8 + eth_len;
        }

        // Send
        const n = try self.write_fn(self.context, send_buffer[0..actual_len]);
        if (n == 0) return error.ConnectionClosed;
        if (n < actual_len) {
            var sent = n;
            while (sent < actual_len) {
                const m = try self.write_fn(self.context, send_buffer[sent..actual_len]);
                if (m == 0) return error.ConnectionClosed;
                sent += m;
            }
        }

        self.total_send += actual_len;
        return eth_len;
    }

    /// Send blocks through the tunnel (allocating version for compatibility)
    pub fn sendBlocks(self: *TunnelConnection, blocks: []const []const u8) !void {
        if (blocks.len == 0) return;

        // Calculate max total size needed (uncompressed worst case)
        var total_size: usize = 4; // num_blocks
        for (blocks) |block| {
            total_size += 4 + block.len; // size + data
        }

        // Build the packet
        const packet = try self.allocator.alloc(u8, total_size);
        defer self.allocator.free(packet);

        var offset: usize = 0;

        // Write number of blocks
        mem.writeInt(u32, packet[0..4], @intCast(blocks.len), .big);
        offset += 4;

        // Temp buffer for compression
        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        // Write each block
        for (blocks) |block| {
            if (self.use_compression) {
                if (compressBlock(&compress_buf, block) catch null) |compressed| {
                    mem.writeInt(u32, packet[offset..][0..4], @intCast(compressed.len), .big);
                    offset += 4;
                    @memcpy(packet[offset..][0..compressed.len], compressed);
                    offset += compressed.len;
                    continue;
                }
            }
            mem.writeInt(u32, packet[offset..][0..4], @intCast(block.len), .big);
            offset += 4;
            @memcpy(packet[offset..][0..block.len], block);
            offset += block.len;
        }

        // Send all at once (may be smaller than allocated due to compression)
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

    /// Decompress a zlib-compressed block using C zlib uncompress()
    fn decompressBlock(_: *TunnelConnection, compressed: []const u8, out_buf: []u8) ![]u8 {
        var dest_len: c.uLong = @intCast(out_buf.len);
        const ret = c.uncompress(out_buf.ptr, &dest_len, compressed.ptr, @intCast(compressed.len));
        if (ret != c.Z_OK) return error.DecompressionFailed;
        return out_buf[0..@intCast(dest_len)];
    }

    /// Compress a block using C zlib compress2() with Z_DEFAULT_COMPRESSION
    fn compressBlock(compressed_buf: []u8, data: []const u8) ![]const u8 {
        var dest_len: c.uLong = @intCast(compressed_buf.len);
        const ret = c.compress2(compressed_buf.ptr, &dest_len, data.ptr, @intCast(data.len), c.Z_DEFAULT_COMPRESSION);
        if (ret != c.Z_OK) return error.CompressionFailed;
        return compressed_buf[0..@intCast(dest_len)];
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
