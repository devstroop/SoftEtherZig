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
    use_compress: bool = false,

    // Streaming zlib state (persistent across blocks, avoids alloc/free per call)
    deflate_stream: c.z_stream = undefined,
    inflate_stream: c.z_stream = undefined,
    compression_initialized: bool = false,

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

    /// Initialize streaming zlib compression/decompression state.
    /// Must be called after use_compress=true.
    /// Safe to call multiple times (no-op if already initialized).
    pub fn initCompression(self: *TunnelConnection) void {
        if (self.compression_initialized) return;
        if (!self.use_compress) return;

        self.deflate_stream = std.mem.zeroes(c.z_stream);
        if (c.deflateInit(&self.deflate_stream, c.Z_DEFAULT_COMPRESSION) != c.Z_OK) {
            std.log.err("zlib deflateInit failed", .{});
            self.use_compress = false;
            return;
        }

        self.inflate_stream = std.mem.zeroes(c.z_stream);
        if (c.inflateInit(&self.inflate_stream) != c.Z_OK) {
            std.log.err("zlib inflateInit failed", .{});
            _ = c.deflateEnd(&self.deflate_stream);
            self.use_compress = false;
            return;
        }
        self.compression_initialized = true;
    }

    /// Clean up zlib compression state.
    pub fn deinit(self: *TunnelConnection) void {
        if (self.compression_initialized) {
            _ = c.deflateEnd(&self.deflate_stream);
            _ = c.inflateEnd(&self.inflate_stream);
            self.compression_initialized = false;
        }
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

            if (self.use_compress) {
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
                        self.recv_state = .read_num_blocks;
                        return error.TooManyBlocks;
                    }
                    self.num_blocks = n;
                    self.current_block = 0;
                    self.rx_block_count = 0;
                    self.rx_scratch_offset = 0;
                    if (n == 0) {
                        self.recv_state = .read_num_blocks;
                        return 0;
                    }
                    self.recv_state = .read_block_size;
                },

                .read_block_size => {
                    if (self.current_block >= self.num_blocks) {
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

                    if (self.use_compress) {
                        const decompressed = self.decompressBlock(
                            self.rx_block_buf[0..self.block_size],
                            scratch_buffer[self.rx_scratch_offset..],
                        ) catch {
                            self.current_block += 1;
                            self.recv_state = .read_block_size;
                            continue;
                        };
                        if (self.rx_scratch_offset + decompressed.len > scratch_buffer.len) {
                            std.log.warn("BufferTooSmall: need {d}, have {d}", .{ self.rx_scratch_offset + decompressed.len, scratch_buffer.len });
                            self.recv_state = .read_num_blocks;
                            return error.BufferTooSmall;
                        }
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

        mem.writeInt(u32, send_buffer[0..4], @intCast(blocks.len), .big);
        offset += 4;

        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        for (blocks) |block| {
            if (self.use_compress) {
                const compressed = try self.compressBlock(&compress_buf, block);
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

        const total = offset;
        if (total > 0) {
            std.log.debug("SEND-DBG blocks={d} total_bytes={d} compressed={}", .{ blocks.len, total, self.use_compress });
        }

        const n = try self.write_fn(self.context, send_buffer[0..offset]);
        if (n == 0) return error.ConnectionClosed;
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
        const total_len = 4 + 4 + eth_len;
        if (total_len > send_buffer.len) return 0;

        var eth_frame_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        @memcpy(eth_frame_buf[0..6], &dst_mac);
        @memcpy(eth_frame_buf[6..12], &src_mac);

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

        @memcpy(eth_frame_buf[14..][0..ip_packet.len], ip_packet);

        const eth_frame = eth_frame_buf[0..eth_len];

        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;
        var actual_len: usize = undefined;

        if (self.use_compress) {
            const compressed = try self.compressBlock(&compress_buf, eth_frame);
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

        var total_size: usize = 4;
        for (blocks) |block| {
            // Reserve extra room for zlib compression expansion (headers + worst-case deflate)
            total_size += 4 + block.len + 64;
        }

        const packet = try self.allocator.alloc(u8, total_size);
        defer self.allocator.free(packet);

        var offset: usize = 0;

        mem.writeInt(u32, packet[0..4], @intCast(blocks.len), .big);
        offset += 4;

        var compress_buf: [MAX_PACKET_SIZE * 2]u8 = undefined;

        for (blocks) |block| {
            if (self.use_compress) {
                const compressed = try self.compressBlock(&compress_buf, block);
                mem.writeInt(u32, packet[offset..][0..4], @intCast(compressed.len), .big);
                offset += 4;
                @memcpy(packet[offset..][0..compressed.len], compressed);
                offset += compressed.len;
            } else {
                mem.writeInt(u32, packet[offset..][0..4], @intCast(block.len), .big);
                offset += 4;
                @memcpy(packet[offset..][0..block.len], block);
                offset += block.len;
            }
        }

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

    /// Decompress a zlib-compressed block using persistent inflate stream.
    fn decompressBlock(self: *TunnelConnection, compressed: []const u8, out_buf: []u8) ![]u8 {
        const stream = &self.inflate_stream;
        _ = c.inflateReset(stream);
        stream.next_in = @ptrCast(@constCast(compressed.ptr));
        stream.avail_in = @intCast(compressed.len);
        stream.next_out = @ptrCast(out_buf.ptr);
        stream.avail_out = @intCast(out_buf.len);
        const ret = c.inflate(stream, c.Z_FINISH);
        if (ret != c.Z_STREAM_END) return error.DecompressionFailed;
        return out_buf[0..(out_buf.len - stream.avail_out)];
    }

    /// Compress a block using persistent deflate stream.
    fn compressBlock(self: *TunnelConnection, compressed_buf: []u8, data: []const u8) ![]const u8 {
        const stream = &self.deflate_stream;
        const reset_ret = c.deflateReset(stream);
        if (reset_ret != c.Z_OK) {
            std.log.err("compress: deflateReset failed ret={d}", .{reset_ret});
            return error.CompressionFailed;
        }
        stream.next_in = @ptrCast(@constCast(data.ptr));
        stream.avail_in = @intCast(data.len);
        stream.next_out = @ptrCast(compressed_buf.ptr);
        stream.avail_out = @intCast(compressed_buf.len);
        const ret = c.deflate(stream, c.Z_FINISH);
        if (ret != c.Z_STREAM_END) {
            std.log.err("compress: deflate failed ret={d} avail_in={d} avail_out_start={d} avail_out_end={d}", .{ ret, data.len, compressed_buf.len, stream.avail_out });
            return error.CompressionFailed;
        }
        return compressed_buf[0..(compressed_buf.len - stream.avail_out)];
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
    var buf: [100]u8 = undefined;
    mem.writeInt(u32, buf[0..4], 2, .big);
    mem.writeInt(u32, buf[4..8], 4, .big);
    @memcpy(buf[8..12], "TEST");
    mem.writeInt(u32, buf[12..16], 3, .big);
    @memcpy(buf[16..19], "ABC");
    try std.testing.expectEqual(@as(u32, 2), mem.readInt(u32, buf[0..4], .big));
}

test "keep-alive magic" {
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), KEEP_ALIVE_MAGIC);
}

test "compressBlock round-trip zlib" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    const test_data: []const u8 = "Hello SoftEther VPN! Compression test data for round-trip verification.";

    var compress_buf: [2048]u8 = undefined;
    var decompress_buf: [2048]u8 = undefined;

    const compressed = try conn.compressBlock(&compress_buf, test_data);
    try std.testing.expect(compressed.len > 0);
    try std.testing.expect(compressed.len < test_data.len);

    const decompressed = try conn.decompressBlock(compressed, &decompress_buf);
    try std.testing.expectEqualStrings(test_data, decompressed);
}

test "compressBlock empty data round-trip" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    var compress_buf: [128]u8 = undefined;
    var decompress_buf: [128]u8 = undefined;

    const compressed = try conn.compressBlock(&compress_buf, "");
    const decompressed = try conn.decompressBlock(compressed, &decompress_buf);
    try std.testing.expectEqualStrings("", decompressed);
}

test "compressBlock multiple calls work serial re-use" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    var cbuf: [512]u8 = undefined;
    var dbuf: [512]u8 = undefined;

    {
        const compressed1 = try conn.compressBlock(&cbuf, "first payload");
        try std.testing.expect(compressed1.len > 0);
        const d1 = try conn.decompressBlock(compressed1, &dbuf);
        try std.testing.expectEqualStrings("first payload", d1);
    }
    {
        const compressed2 = try conn.compressBlock(&cbuf, "second payload with different content");
        try std.testing.expect(compressed2.len > 0);
        const d2 = try conn.decompressBlock(compressed2, &dbuf);
        try std.testing.expectEqualStrings("second payload with different content", d2);
    }
    {
        const compressed3 = try conn.compressBlock(&cbuf, "third!");
        try std.testing.expect(compressed3.len > 0);
        const d3 = try conn.decompressBlock(compressed3, &dbuf);
        try std.testing.expectEqualStrings("third!", d3);
    }
}

test "batch-level compression wire format" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    var raw: [32]u8 = undefined;
    var off: usize = 0;
    mem.writeInt(u32, raw[off..][0..4], 2, .big);
    off += 4;
    mem.writeInt(u32, raw[off..][0..4], 4, .big);
    off += 4;
    @memcpy(raw[off..][0..4], "test");
    off += 4;
    mem.writeInt(u32, raw[off..][0..4], 3, .big);
    off += 4;
    @memcpy(raw[off..][0..3], "xyz");
    off += 3;

    const raw_slice = raw[0..off];

    var compress_buf: [1024]u8 = undefined;
    const compressed = try conn.compressBlock(&compress_buf, raw_slice);

    var wire: [1024]u8 = undefined;
    mem.writeInt(u32, wire[0..4], @intCast(compressed.len), .big);
    @memcpy(wire[4..][0..compressed.len], compressed);
    const wire_len = 4 + compressed.len;

    try std.testing.expectEqual(@as(u32, @intCast(compressed.len)), mem.readInt(u32, wire[0..4], .big));

    var decompress_buf: [1024]u8 = undefined;
    const decompressed = try conn.decompressBlock(wire[4..wire_len], &decompress_buf);
    try std.testing.expectEqualStrings(raw_slice, decompressed);

    const n_blocks = mem.readInt(u32, decompressed[0..4], .big);
    try std.testing.expectEqual(@as(u32, 2), n_blocks);

    var pos: usize = 4;
    {
        const bs = mem.readInt(u32, decompressed[pos..][0..4], .big);
        pos += 4;
        try std.testing.expectEqual(@as(u32, 4), bs);
        try std.testing.expectEqualStrings("test", decompressed[pos..][0..bs]);
        pos += bs;
    }
    {
        const bs = mem.readInt(u32, decompressed[pos..][0..4], .big);
        pos += 4;
        try std.testing.expectEqual(@as(u32, 3), bs);
        try std.testing.expectEqualStrings("xyz", decompressed[pos..][0..bs]);
        pos += bs;
    }
}

test "compressBlock multiple batches are independent" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    var buf1: [512]u8 = undefined;
    var buf2: [512]u8 = undefined;
    const data = "identical data for both calls";

    const c1 = try conn.compressBlock(&buf1, data);
    const c2 = try conn.compressBlock(&buf2, data);

    try std.testing.expectEqual(c1.len, c2.len);
    try std.testing.expectEqualStrings(c1, c2);

    var dbuf1: [512]u8 = undefined;
    var dbuf2: [512]u8 = undefined;
    const d1 = try conn.decompressBlock(c1, &dbuf1);
    const d2 = try conn.decompressBlock(c2, &dbuf2);
    try std.testing.expectEqualStrings(data, d1);
    try std.testing.expectEqualStrings(data, d2);
}

test "decompressBlock rejects garbage" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    var decompress_buf: [128]u8 = undefined;
    const garbage = &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    try std.testing.expectError(error.DecompressionFailed, conn.decompressBlock(garbage, &decompress_buf));
}

test "sendBlocks produces correct wire format" {
    var captured: [128]u8 = undefined;
    var captured_len: usize = 0;

    const WriteContext = struct {
        buf: *[128]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (data.len > self.buf.len - self.len.*) return error.BufferTooSmall;
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &captured, .len = &captured_len };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = undefined,
        .inflate_stream = undefined,
    };

    const blocks = [_][]const u8{ "ABCD", "XYZ" };
    try conn.sendBlocks(&blocks);

    // Verify wire format: [num_blocks=2][size=4][ABCD][size=3][XYZ]
    try std.testing.expectEqual(@as(usize, 4 + 4 + 4 + 4 + 3), captured_len);
    try std.testing.expectEqual(@as(u32, 2), mem.readInt(u32, captured[0..4], .big));

    var pos: usize = 4;
    {
        const bs = mem.readInt(u32, captured[pos..][0..4], .big);
        pos += 4;
        try std.testing.expectEqual(@as(u32, 4), bs);
        try std.testing.expectEqualStrings("ABCD", captured[pos..][0..4]);
        pos += 4;
    }
    {
        const bs = mem.readInt(u32, captured[pos..][0..4], .big);
        pos += 4;
        try std.testing.expectEqual(@as(u32, 3), bs);
        try std.testing.expectEqualStrings("XYZ", captured[pos..][0..3]);
        pos += 3;
    }
}

test "sendBlocksZeroCopy produces correct wire format" {
    var captured: [128]u8 = undefined;
    var captured_len: usize = 0;

    const WriteContext = struct {
        buf: *[128]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (data.len > self.buf.len - self.len.*) return error.BufferTooSmall;
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &captured, .len = &captured_len };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = undefined,
        .inflate_stream = undefined,
    };

    var send_buf: [128]u8 = undefined;
    const blocks = [_][]const u8{ "HELLO", "WORLD" };
    try conn.sendBlocksZeroCopy(&blocks, &send_buf);

    try std.testing.expectEqual(@as(usize, 4 + 4 + 5 + 4 + 5), captured_len);
    try std.testing.expectEqual(@as(u32, 2), mem.readInt(u32, captured[0..4], .big));

    var pos: usize = 4;
    {
        const bs = mem.readInt(u32, captured[pos..][0..4], .big);
        pos += 4;
        try std.testing.expectEqual(@as(u32, 5), bs);
        try std.testing.expectEqualStrings("HELLO", captured[pos..][0..5]);
        pos += 5;
    }
    {
        const bs = mem.readInt(u32, captured[pos..][0..4], .big);
        pos += 4;
        try std.testing.expectEqual(@as(u32, 5), bs);
        try std.testing.expectEqualStrings("WORLD", captured[pos..][0..5]);
        pos += 5;
    }
}

test "sendSinglePacketDirect produces correct wire format" {
    var captured: [256]u8 = undefined;
    var captured_len: usize = 0;

    const WriteContext = struct {
        buf: *[256]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (data.len > self.buf.len - self.len.*) return error.BufferTooSmall;
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &captured, .len = &captured_len };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = undefined,
        .inflate_stream = undefined,
    };

    var send_buf: [256]u8 = undefined;
    // Build a minimal IPv4 packet (IP header + payload)
    var ip_pkt: [20]u8 = undefined;
    @memset(&ip_pkt, 0);
    ip_pkt[0] = 0x45; // IPv4, IHL=5
    ip_pkt[2] = 0x00;
    ip_pkt[3] = 20; // total length
    // checksum skipped for test

    const dst_mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const src_mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    _ = try conn.sendSinglePacketDirect(&ip_pkt, dst_mac, src_mac, &send_buf);

    // Expected: [4: num_blocks=1][4: eth_len][6: dst_mac][6: src_mac][2: ethertype=0x0800][20: ip_pkt]
    const eth_len: u32 = 14 + 20;
    try std.testing.expectEqual(@as(usize, 4 + 4 + eth_len), captured_len);
    try std.testing.expectEqual(@as(u32, 1), mem.readInt(u32, captured[0..4], .big));
    try std.testing.expectEqual(eth_len, mem.readInt(u32, captured[4..8], .big));

    // Verify Ethernet header
    try std.testing.expectEqual(@as(u32, 0x00112233), mem.readInt(u32, captured[8..12], .big));
    try std.testing.expectEqual(dst_mac[4..6], captured[12..14]);
    try std.testing.expectEqualSlices(u8, &src_mac, captured[14..20]);
    try std.testing.expectEqual(@as(u8, 0x08), captured[20]);
    try std.testing.expectEqual(@as(u8, 0x00), captured[21]);

    // Verify IP packet
    try std.testing.expectEqualStrings(ip_pkt[0..], captured[22..42]);
}

test "receiveBlocksBatch parses uncompressed batch from stream" {
    // Build pre-canned stream data: [num_blocks=2][size=4][ABCD][size=3][XYZ]
    var stream_data: [32]u8 = undefined;
    var off: usize = 0;
    mem.writeInt(u32, stream_data[off..][0..4], 2, .big);
    off += 4;
    mem.writeInt(u32, stream_data[off..][0..4], 4, .big);
    off += 4;
    @memcpy(stream_data[off..][0..4], "ABCD");
    off += 4;
    mem.writeInt(u32, stream_data[off..][0..4], 3, .big);
    off += 4;
    @memcpy(stream_data[off..][0..3], "XYZ");
    off += 3;
    const stream = stream_data[0..off];

    var read_pos: usize = 0;
    const ReadContext = struct {
        data: []const u8,
        pos: *usize,
        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (self.pos.* >= self.data.len) return 0;
            const avail = @min(buf.len, self.data.len - self.pos.*);
            @memcpy(buf[0..avail], self.data[self.pos.*..][0..avail]);
            self.pos.* += avail;
            return avail;
        }
    };

    var rctx = ReadContext{ .data = stream, .pos = &read_pos };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .read_fn = ReadContext.read,
        .context = &rctx,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .use_compress = false,
        .compression_initialized = false,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
        .recv_state = .read_num_blocks,
    };

    var scratch: [256]u8 = undefined;
    var out_slices: [16][]u8 = undefined;

    const count = try conn.receiveBlocksBatch(&out_slices, &scratch);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("ABCD", out_slices[0]);
    try std.testing.expectEqualStrings("XYZ", out_slices[1]);
}

test "receiveBlocksBatch parses compressed blocks" {
    const allocator = std.testing.allocator;
    var conn = TunnelConnection{
        .allocator = allocator,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .context = undefined,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    conn.initCompression();
    defer conn.deinit();

    var cbuf: [256]u8 = undefined;
    const c1 = try conn.compressBlock(&cbuf, "test");
    const c2 = try conn.compressBlock(&cbuf, "hello");

    var wire: [512]u8 = undefined;
    var off: usize = 0;
    mem.writeInt(u32, wire[off..][0..4], 2, .big);
    off += 4;
    mem.writeInt(u32, wire[off..][0..4], @as(u32, @intCast(c1.len)), .big);
    off += 4;
    @memcpy(wire[off..][0..c1.len], c1);
    off += c1.len;
    mem.writeInt(u32, wire[off..][0..4], @as(u32, @intCast(c2.len)), .big);
    off += 4;
    @memcpy(wire[off..][0..c2.len], c2);
    off += c2.len;
    const wire_len = off;

    var read_pos: usize = 0;
    const ReadContext = struct {
        data: []const u8,
        pos: *usize,
        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (self.pos.* >= self.data.len) return 0;
            const avail = @min(buf.len, self.data.len - self.pos.*);
            @memcpy(buf[0..avail], self.data[self.pos.*..][0..avail]);
            self.pos.* += avail;
            return avail;
        }
    };

    var rctx = ReadContext{ .data = wire[0..wire_len], .pos = &read_pos };

    var recv_conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .read_fn = ReadContext.read,
        .context = &rctx,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .use_compress = true,
        .compression_initialized = false,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
        .recv_state = .read_num_blocks,
    };
    recv_conn.initCompression();
    defer recv_conn.deinit();

    var scratch: [256]u8 = undefined;
    var out_slices: [16][]u8 = undefined;

    const count = try recv_conn.receiveBlocksBatch(&out_slices, &scratch);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("test", out_slices[0]);
    try std.testing.expectEqualStrings("hello", out_slices[1]);
}

test "sendBlocks and receiveBlocksBatch compress round-trip" {
    var sent_buf: [1024]u8 = undefined;
    var sent_len: usize = 0;

    const WriteContext = struct {
        buf: *[1024]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &sent_buf, .len = &sent_len };

    var write_conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = true,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
    };
    write_conn.initCompression();
    defer write_conn.deinit();

    const blocks = [_][]const u8{ "compress", "me", "please" };
    try write_conn.sendBlocks(&blocks);
    try std.testing.expect(sent_len < 4 + 4 + 8 + 4 + 2 + 4 + 6);

    var read_pos: usize = 0;
    const ReadContext = struct {
        data: []const u8,
        pos: *usize,
        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (self.pos.* >= self.data.len) return 0;
            const avail = @min(buf.len, self.data.len - self.pos.*);
            @memcpy(buf[0..avail], self.data[self.pos.*..][0..avail]);
            self.pos.* += avail;
            return avail;
        }
    };

    var rctx = ReadContext{ .data = sent_buf[0..sent_len], .pos = &read_pos };

    var read_conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .read_fn = ReadContext.read,
        .context = &rctx,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .use_compress = true,
        .compression_initialized = false,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
        .recv_state = .read_num_blocks,
    };
    read_conn.initCompression();
    defer read_conn.deinit();

    var scratch: [256]u8 = undefined;
    var out_slices: [16][]u8 = undefined;
    const count = try read_conn.receiveBlocksBatch(&out_slices, &scratch);

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("compress", out_slices[0]);
    try std.testing.expectEqualStrings("me", out_slices[1]);
    try std.testing.expectEqualStrings("please", out_slices[2]);
}

test "sendKeepalive produces correct wire format" {
    var captured: [64]u8 = undefined;
    var captured_len: usize = 0;

    const WriteContext = struct {
        buf: *[64]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (data.len > self.buf.len - self.len.*) return error.BufferTooSmall;
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &captured, .len = &captured_len };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = undefined,
        .inflate_stream = undefined,
    };

    try conn.sendKeepalive();

    // Format: [4: KEEP_ALIVE_MAGIC][4: size=32][32: random data]
    try std.testing.expectEqual(@as(usize, 40), captured_len);
    try std.testing.expectEqual(KEEP_ALIVE_MAGIC, mem.readInt(u32, captured[0..4], .big));
    try std.testing.expectEqual(@as(u32, 32), mem.readInt(u32, captured[4..8], .big));
    // Remaining 32 bytes are random, just verify they exist
    try std.testing.expectEqual(@as(usize, 32), captured_len - 8);
}

test "receiveBlocksBatch detects keepalive" {
    // Build a keepalive wire format: [4: KEEP_ALIVE_MAGIC][4: size=8][8: padding]
    var stream_data: [16]u8 = undefined;
    mem.writeInt(u32, stream_data[0..4], KEEP_ALIVE_MAGIC, .big);
    mem.writeInt(u32, stream_data[4..8], 8, .big);
    @memset(stream_data[8..16], 0xAB);

    var read_pos: usize = 0;
    const ReadContext = struct {
        data: []const u8,
        pos: *usize,
        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (self.pos.* >= self.data.len) return 0;
            const avail = @min(buf.len, self.data.len - self.pos.*);
            @memcpy(buf[0..avail], self.data[self.pos.*..][0..avail]);
            self.pos.* += avail;
            return avail;
        }
    };

    var rctx = ReadContext{ .data = stream_data[0..], .pos = &read_pos };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .read_fn = ReadContext.read,
        .context = &rctx,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
        .recv_state = .read_num_blocks,
        .keepalives_recv = 0,
    };

    var scratch: [256]u8 = undefined;
    var out_slices: [16][]u8 = undefined;

    const result = try conn.receiveBlocksBatch(&out_slices, &scratch);
    try std.testing.expectEqual(@as(usize, 0), result);
    try std.testing.expectEqual(@as(u64, 1), conn.keepalives_recv);
}

test "receiveBlocksBatch returns WouldBlock on partial data" {
    // Build incomplete batch: only num_blocks and one block size, no block data
    var stream_data: [8]u8 = undefined;
    mem.writeInt(u32, stream_data[0..4], 2, .big);
    mem.writeInt(u32, stream_data[4..8], 4, .big);

    var read_pos: usize = 0;
    const ReadContext = struct {
        data: []const u8,
        pos: *usize,
        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (self.pos.* >= self.data.len) return 0;
            const avail = @min(buf.len, self.data.len - self.pos.*);
            @memcpy(buf[0..avail], self.data[self.pos.*..][0..avail]);
            self.pos.* += avail;
            return avail;
        }
    };

    var rctx = ReadContext{ .data = stream_data[0..], .pos = &read_pos };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .read_fn = ReadContext.read,
        .context = &rctx,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
        .recv_state = .read_num_blocks,
    };

    var scratch: [256]u8 = undefined;
    var out_slices: [16][]u8 = undefined;

    try std.testing.expectError(error.WouldBlock, conn.receiveBlocksBatch(&out_slices, &scratch));
}

test "total_send and total_recv counters" {
    var captured: [128]u8 = undefined;
    var captured_len: usize = 0;

    const WriteContext = struct {
        buf: *[128]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &captured, .len = &captured_len };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = undefined,
        .inflate_stream = undefined,
        .total_send = 0,
        .total_recv = 0,
    };

    try std.testing.expectEqual(@as(u64, 0), conn.total_send);
    try std.testing.expectEqual(@as(u64, 0), conn.total_recv);

    const blocks = [_][]const u8{"ABCD"};
    try conn.sendBlocks(&blocks);
    // 4 bytes num_blocks + 4 bytes size + 4 bytes data = 12
    try std.testing.expectEqual(@as(u64, 12), conn.total_send);

    var send_buf: [64]u8 = undefined;
    try conn.sendBlocksZeroCopy(&blocks, &send_buf);
    // 4 + 4 + 4 = 12 more
    try std.testing.expectEqual(@as(u64, 24), conn.total_send);
}

test "block format edge cases: zero-length block" {
    var captured: [128]u8 = undefined;
    var captured_len: usize = 0;

    const WriteContext = struct {
        buf: *[128]u8,
        len: *usize,
        fn write(ctx: *anyopaque, data: []const u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            @memcpy(self.buf[self.len.*..][0..data.len], data);
            self.len.* += data.len;
            return data.len;
        }
    };

    var wctx = WriteContext{ .buf = &captured, .len = &captured_len };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .write_fn = WriteContext.write,
        .context = &wctx,
        .read_fn = struct {
            fn f(_: *anyopaque, _: []u8) anyerror!usize {
                return error.WouldBlock;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = undefined,
        .inflate_stream = undefined,
    };

    // Empty blocks list should produce no output
    try conn.sendBlocks(&[_][]const u8{});
    try std.testing.expectEqual(@as(usize, 0), captured_len);

    // Single block with empty data
    const blocks = [_][]const u8{""};
    try conn.sendBlocks(&blocks);
    try std.testing.expectEqual(@as(usize, 4 + 4 + 0), captured_len);
    try std.testing.expectEqual(@as(u32, 1), mem.readInt(u32, captured[0..4], .big));
    try std.testing.expectEqual(@as(u32, 0), mem.readInt(u32, captured[4..8], .big));
}

test "out_data slice length limit in receiveBlocksBatch" {
    var stream_data: [32]u8 = undefined;
    var off: usize = 0;
    mem.writeInt(u32, stream_data[off..][0..4], 10, .big);
    off += 4;
    // Fill rest with plausible-looking block headers
    for (0..10) |_| {
        mem.writeInt(u32, stream_data[off..][0..4], 4, .big);
        off += 4;
    }
    const stream = stream_data[0..off];

    var read_pos: usize = 0;
    const ReadContext = struct {
        data: []const u8,
        pos: *usize,
        fn read(ctx: *anyopaque, buf: []u8) anyerror!usize {
            const self = @as(*@This(), @ptrCast(@alignCast(ctx)));
            if (self.pos.* >= self.data.len) return 0;
            const avail = @min(buf.len, self.data.len - self.pos.*);
            @memcpy(buf[0..avail], self.data[self.pos.*..][0..avail]);
            self.pos.* += avail;
            return avail;
        }
    };

    var rctx = ReadContext{ .data = stream, .pos = &read_pos };

    var conn = TunnelConnection{
        .allocator = std.testing.allocator,
        .read_fn = ReadContext.read,
        .context = &rctx,
        .write_fn = struct {
            fn f(_: *anyopaque, data: []const u8) anyerror!usize {
                return data.len;
            }
        }.f,
        .use_compress = false,
        .deflate_stream = std.mem.zeroes(c.z_stream),
        .inflate_stream = std.mem.zeroes(c.z_stream),
        .recv_state = .read_num_blocks,
    };

    var scratch: [256]u8 = undefined;
    // out_data has only 5 slots, but batch claims 10 blocks
    var out_slices: [5][]u8 = undefined;

    try std.testing.expectError(error.TooManyBlocks, conn.receiveBlocksBatch(&out_slices, &scratch));
}
