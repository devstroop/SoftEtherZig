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

    // Receive state machine (resumable across read_fn returning error.WouldBlock)
    recv_state: RecvState = .read_num_blocks,
    num_blocks: u32 = 0,
    current_block: u32 = 0,
    block_size: u32 = 0,

    // Partial read buffer (for u32 fields)
    partial_buf: [4]u8 = undefined,
    partial_len: usize = 0,

    // Per-call output progress (carried across receiveBlocksBatch resumes)
    rx_block_count: usize = 0,
    rx_scratch_offset: usize = 0,

    // Per-block partial body buffer (for resumable readExact of one block's data)
    rx_block_buf: [MAX_PACKET_SIZE * 2]u8 = undefined,
    rx_block_have: u32 = 0,

    // Per-keepalive partial data
    rx_ka_size: u32 = 0,
    rx_ka_have: u32 = 0,
    rx_ka_buf: [MAX_KEEPALIVE_SIZE]u8 = undefined,

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

    /// Try to read a u32 (big-endian). Returns null if read_fn returned
    /// error.WouldBlock partway through; partial bytes are stashed in
    /// partial_buf for the next call to resume.
    fn tryReadU32(self: *TunnelConnection) !?u32 {
        while (self.partial_len < 4) {
            const n = self.read_fn(self.context, self.partial_buf[self.partial_len..]) catch |err| switch (err) {
                error.WouldBlock => return null,
                else => return err,
            };
            if (n == 0) return error.ConnectionClosed;
            self.partial_len += n;
        }
        const value = mem.readInt(u32, &self.partial_buf, .big);
        self.partial_len = 0;
        self.total_recv += 4;
        return value;
    }

    /// Try to fill `buf[have.*..]`. Returns true if buf is fully read,
    /// false if read_fn returned error.WouldBlock; `have.*` is updated to
    /// reflect what was read so far so the next call resumes.
    fn tryReadInto(self: *TunnelConnection, buf: []u8, have: *u32) !bool {
        while (have.* < buf.len) {
            const n = self.read_fn(self.context, buf[have.*..]) catch |err| switch (err) {
                error.WouldBlock => return false,
                else => return err,
            };
            if (n == 0) return error.ConnectionClosed;
            have.* += @intCast(n);
        }
        self.total_recv += buf.len;
        return true;
    }

    /// Read a single u32 (big-endian) from the connection.
    /// LEGACY: spin-loops on WouldBlock (only used by legacy receiveBlocks).
    fn readU32(self: *TunnelConnection) !u32 {
        while (true) {
            if (try self.tryReadU32()) |v| return v;
        }
    }

    /// Read exact number of bytes.
    /// LEGACY: spin-loops on WouldBlock (only used by legacy receiveBlocks).
    fn readExact(self: *TunnelConnection, buf: []u8) !void {
        var have: u32 = 0;
        while (true) {
            if (try self.tryReadInto(buf, &have)) return;
        }
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

    /// Receive a single batch of blocks into provided buffer.
    /// Returns number of blocks received, fills out_data with slices into
    /// scratch_buffer.
    ///
    /// Resumable: if the underlying read_fn returns error.WouldBlock partway
    /// through a message, this returns error.WouldBlock and stashes parsing
    /// state inside `self`. The next call resumes from exactly where it left
    /// off; the caller must pass the SAME scratch_buffer between resumes if
    /// it intends to consume blocks across iterations (note: in practice the
    /// data pump consumes the returned blocks immediately and then moves on,
    /// so this is a single-shot completion model — partial state is reset
    /// only when a full message is fully consumed).
    ///
    /// Callers should treat error.WouldBlock as a normal "no full message
    /// yet" signal, NOT as a fatal error.
    pub fn receiveBlocksBatch(
        self: *TunnelConnection,
        out_data: [][]u8,
        scratch_buffer: []u8,
    ) !usize {
        // Drive the state machine until a full message is parsed (return
        // count) or the underlying socket would block (return WouldBlock).
        while (true) {
            switch (self.recv_state) {
                .read_num_blocks => {
                    const n = (try self.tryReadU32()) orelse return error.WouldBlock;
                    if (n == KEEP_ALIVE_MAGIC) {
                        self.recv_state = .read_keepalive_size;
                        continue;
                    }
                    if (n > MAX_RECV_BLOCKS or n > out_data.len) {
                        std.log.warn("TooManyBlocks: num_blocks={d}, max={d}, out_data.len={d}", .{ n, MAX_RECV_BLOCKS, out_data.len });
                        // Reset state — drop this message
                        self.recv_state = .read_num_blocks;
                        return error.TooManyBlocks;
                    }
                    self.num_blocks = n;
                    self.current_block = 0;
                    self.rx_block_count = 0;
                    self.rx_scratch_offset = 0;
                    if (n == 0) {
                        // Empty message; nothing to do
                        self.recv_state = .read_num_blocks;
                        return 0;
                    }
                    self.recv_state = .read_block_size;
                },

                .read_block_size => {
                    if (self.current_block >= self.num_blocks) {
                        // Message complete
                        const cnt = self.rx_block_count;
                        self.recv_state = .read_num_blocks;
                        if (cnt > 0) {
                            std.log.scoped(.packet_trace).debug("Received {d} blocks ({d} bytes)", .{ cnt, self.rx_scratch_offset });
                        }
                        return cnt;
                    }
                    const bs = (try self.tryReadU32()) orelse return error.WouldBlock;
                    if (bs == 0) {
                        self.current_block += 1;
                        continue;
                    }
                    if (bs > MAX_PACKET_SIZE * 2) {
                        std.log.warn("PacketTooLarge: block_size={d}", .{bs});
                        // Reset state — connection is now desynced; caller should disconnect
                        self.recv_state = .read_num_blocks;
                        return error.PacketTooLarge;
                    }
                    self.block_size = bs;
                    self.rx_block_have = 0;
                    self.recv_state = .read_block_data;
                },

                .read_block_data => {
                    const done = try self.tryReadInto(self.rx_block_buf[0..self.block_size], &self.rx_block_have);
                    if (!done) return error.WouldBlock;

                    // Block body fully read; place into scratch.
                    if (self.use_compression) {
                        const remaining = scratch_buffer[self.rx_scratch_offset..];
                        const decompressed = self.decompressBlock(
                            self.rx_block_buf[0..self.block_size],
                            remaining,
                        ) catch {
                            // Decompression failed — skip this block, continue parsing
                            self.current_block += 1;
                            self.recv_state = .read_block_size;
                            continue;
                        };
                        out_data[self.rx_block_count] = decompressed;
                        self.rx_scratch_offset += decompressed.len;
                    } else {
                        if (self.rx_scratch_offset + self.block_size > scratch_buffer.len) {
                            std.log.warn("BufferTooSmall: need {d}, have {d}", .{ self.rx_scratch_offset + self.block_size, scratch_buffer.len });
                            self.recv_state = .read_num_blocks;
                            return error.BufferTooSmall;
                        }
                        @memcpy(
                            scratch_buffer[self.rx_scratch_offset..][0..self.block_size],
                            self.rx_block_buf[0..self.block_size],
                        );
                        out_data[self.rx_block_count] = scratch_buffer[self.rx_scratch_offset..][0..self.block_size];
                        self.rx_scratch_offset += self.block_size;
                    }
                    self.rx_block_count += 1;
                    self.current_block += 1;
                    self.recv_state = .read_block_size;
                },

                .read_keepalive_size => {
                    const ka = (try self.tryReadU32()) orelse return error.WouldBlock;
                    if (ka > MAX_KEEPALIVE_SIZE) {
                        self.recv_state = .read_num_blocks;
                        return error.InvalidPacket;
                    }
                    self.rx_ka_size = ka;
                    self.rx_ka_have = 0;
                    if (ka == 0) {
                        self.keepalives_recv += 1;
                        self.recv_state = .read_num_blocks;
                        return 0;
                    }
                    self.recv_state = .read_keepalive_data;
                },

                .read_keepalive_data => {
                    const done = try self.tryReadInto(self.rx_ka_buf[0..self.rx_ka_size], &self.rx_ka_have);
                    if (!done) return error.WouldBlock;
                    self.keepalives_recv += 1;
                    std.log.debug("Received keep-alive (size={d})", .{self.rx_ka_size});
                    self.recv_state = .read_num_blocks;
                    return 0;
                },
            }
        }
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
                    if (compressed.len < block.len) {
                        mem.writeInt(u32, packet[offset..][0..4], @intCast(compressed.len), .big);
                        offset += 4;
                        @memcpy(packet[offset..][0..compressed.len], compressed);
                        offset += compressed.len;
                        continue;
                    }
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
