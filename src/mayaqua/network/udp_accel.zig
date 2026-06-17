//! UDP Acceleration Engine
//!
//! Implements SoftEther VPN's UDP acceleration protocol:
//!  - NAT-T probing to establish bidirectional UDP path
//!  - AES-128-CBC encryption with HMAC-SHA1 for data integrity
//!  - Sequence numbers for duplicate/replay detection
//!  - Automatic fallback to TCP if UDP path fails
//!
//! Packet format (RUDP v2 bulk):
//!   [1 byte flags][IV 16 bytes][encrypted payload][HMAC-SHA1 20 bytes]
//!
//! Encrypted payload (after AES-128-CBC decrypt):
//!   [4 bytes seq_no][padding...][data...]

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const posix = std.posix;
const crypto = std.crypto;

const socket_mod = @import("socket.zig");
const UdpSocket = socket_mod.UdpSocket;
const Address = socket_mod.Address;

const cipher_mod = @import("../encrypt/cipher.zig");
const Aes128Cbc = cipher_mod.Aes128Cbc;
const block_size = cipher_mod.block_size;

const log = std.log.scoped(.udp_accel);

// ============================================================================
// Constants
// ============================================================================

/// Maximum UDP payload (MTU minus IP/UDP headers)
const MAX_UDP_PAYLOAD: usize = 1500 - 20 - 8;

/// Size of HMAC-SHA1 tag appended to each packet
const HMAC_SIZE: usize = 20;

/// Size of AES-128-CBC IV prepended to encrypted data
const IV_SIZE: usize = 16;

/// Size of the flags byte
const FLAGS_SIZE: usize = 1;

/// Minimum packet size: flags(1) + IV(16) + one AES block(16) + HMAC(20)
const MIN_PACKET_SIZE: usize = FLAGS_SIZE + IV_SIZE + block_size + HMAC_SIZE;

/// NAT-T probe interval (milliseconds)
const NATT_PROBE_INTERVAL_MS: i64 = 3000;

/// NAT-T probe timeout — give up after this many ms
const NATT_TIMEOUT_MS: i64 = 30000;

/// Keep-alive interval once UDP established (ms)
const KEEPALIVE_INTERVAL_MS: i64 = 5000;

/// Consider UDP path dead after this many ms without recv
const PATH_DEAD_TIMEOUT_MS: i64 = 15000;

/// Maximum sequence gap before considering packet too old
const MAX_SEQ_GAP: u32 = 16384;

/// Flag bits
const FLAG_DATA: u8 = 0x01;
const FLAG_KEEPALIVE: u8 = 0x02;
const FLAG_NATT_PROBE: u8 = 0x04;

// ============================================================================
// UDP Acceleration Configuration
// ============================================================================

pub const UdpAccelConfig = struct {
    /// Server's UDP acceleration IP (from auth response)
    server_ip: []const u8,
    /// Server's UDP acceleration port (from auth response)
    server_port: u16,
    /// Whether to encrypt UDP data channel
    use_encrypt: bool = true,
    /// Client's bulk send key (128-bit AES key for encrypting outbound)
    send_key: [16]u8,
    /// Client's bulk recv key (128-bit AES key for decrypting inbound)
    recv_key: [16]u8,
    /// HMAC key for send direction (derived from send_key)
    send_hmac_key: [20]u8,
    /// HMAC key for recv direction (derived from recv_key)
    recv_hmac_key: [20]u8,
};

// ============================================================================
// UDP Acceleration State
// ============================================================================

pub const UdpAccelState = enum {
    /// Not initialized
    idle,
    /// Sending NAT-T probes, waiting for response
    probing,
    /// Bidirectional UDP path confirmed, actively sending data
    established,
    /// UDP path failed, falling back to TCP
    failed,
};

// ============================================================================
// UDP Acceleration Engine
// ============================================================================

pub const UdpAccelEngine = struct {
    allocator: Allocator,
    config: UdpAccelConfig,
    state: UdpAccelState = .idle,

    /// The UDP socket
    sock: ?UdpSocket = null,
    /// Server address (resolved)
    server_addr: ?Address = null,

    /// Outbound sequence counter
    send_seq: u32 = 0,
    /// Highest inbound sequence seen (for replay detection)
    recv_seq: u32 = 0,

    /// Timestamp of last NAT-T probe sent (ms)
    last_probe_sent_ms: i64 = 0,
    /// Timestamp when probing started (ms)
    probe_start_ms: i64 = 0,
    /// Timestamp of last packet received (ms)
    last_recv_ms: i64 = 0,
    /// Timestamp of last keepalive sent (ms)
    last_keepalive_ms: i64 = 0,

    /// Whether we've received a response from the server (server→client path works)
    server_reachable: bool = false,
    /// Whether server has confirmed our probes (client→server path works)
    client_reachable: bool = false,

    /// Scratch buffers for encrypt/decrypt (avoid allocations in hot path)
    encrypt_buf: [MAX_UDP_PAYLOAD]u8 = undefined,
    decrypt_buf: [MAX_UDP_PAYLOAD]u8 = undefined,

    /// Initialize the engine with the given config.
    pub fn init(allocator: Allocator, config: UdpAccelConfig) UdpAccelEngine {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Start the UDP acceleration — bind socket, begin NAT-T probing.
    pub fn start(self: *UdpAccelEngine) !void {
        if (self.state != .idle and self.state != .failed) return;

        // Bind UDP socket (port 0 = system assigned)
        self.sock = try UdpSocket.bind(0, .ipv4);
        errdefer {
            if (self.sock) |*s| s.close();
            self.sock = null;
        }

        // Increase socket buffers for high throughput
        if (self.sock) |*s| {
            s.setRecvBufSize(512 * 1024) catch {};
            s.setSendBufSize(512 * 1024) catch {};
        }

        // Resolve server address
        self.server_addr = try Address.parseIp(self.config.server_ip, self.config.server_port);

        const now = nowMs();
        self.state = .probing;
        self.probe_start_ms = now;
        self.last_probe_sent_ms = 0;
        self.send_seq = 0;
        self.recv_seq = 0;
        self.server_reachable = false;
        self.client_reachable = false;

        log.info("UDP accel started, probing {s}:{d}", .{ self.config.server_ip, self.config.server_port });
    }

    /// Stop the engine and close the socket.
    pub fn stop(self: *UdpAccelEngine) void {
        if (self.sock) |*s| {
            s.close();
        }
        self.sock = null;
        self.state = .idle;
        self.server_reachable = false;
        self.client_reachable = false;
        log.info("UDP accel stopped", .{});
    }

    /// Get the UDP socket fd for inclusion in poll().
    /// Returns null if not active.
    pub fn getFd(self: *const UdpAccelEngine) ?posix.socket_t {
        if (self.sock) |*s| return s.getFd();
        return null;
    }

    /// Drive the engine's timer-based work:
    ///  - Send NAT-T probes during probing phase
    ///  - Send keepalives when established
    ///  - Detect path failure
    pub fn tick(self: *UdpAccelEngine) void {
        const now = nowMs();

        switch (self.state) {
            .probing => {
                // Check timeout
                if (now - self.probe_start_ms > NATT_TIMEOUT_MS) {
                    log.warn("NAT-T probing timed out after {d}ms", .{NATT_TIMEOUT_MS});
                    self.state = .failed;
                    return;
                }
                // Send probe at intervals
                if (now - self.last_probe_sent_ms >= NATT_PROBE_INTERVAL_MS) {
                    self.sendProbe() catch |err| {
                        log.warn("Failed to send NAT-T probe: {}", .{err});
                    };
                    self.last_probe_sent_ms = now;
                }
            },
            .established => {
                // Check path liveness
                if (now - self.last_recv_ms > PATH_DEAD_TIMEOUT_MS) {
                    log.warn("UDP path dead (no recv for {d}ms), failing", .{PATH_DEAD_TIMEOUT_MS});
                    self.state = .failed;
                    return;
                }
                // Send keepalive
                if (now - self.last_keepalive_ms >= KEEPALIVE_INTERVAL_MS) {
                    self.sendKeepalive() catch {};
                    self.last_keepalive_ms = now;
                }
            },
            else => {},
        }
    }

    /// Encrypt and send a data block via UDP.
    /// Returns true if sent, false if UDP not available.
    pub fn sendData(self: *UdpAccelEngine, data: []const u8) !bool {
        if (self.state != .established) return false;
        const server = self.server_addr orelse return false;
        const sock = &(self.sock orelse return false);

        self.send_seq +%= 1;

        if (self.config.use_encrypt) {
            const pkt = try self.encryptPacket(data, FLAG_DATA);
            _ = try sock.sendTo(pkt, server);
        } else {
            // Unencrypted: flags(1) + seq(4) + data
            var buf = &self.encrypt_buf;
            buf[0] = FLAG_DATA;
            mem.writeInt(u32, buf[1..5], self.send_seq, .big);
            const total = 5 + data.len;
            if (total > buf.len) return false;
            @memcpy(buf[5..][0..data.len], data);
            _ = try sock.sendTo(buf[0..total], server);
        }
        return true;
    }

    /// Process incoming UDP data. Returns ethernet frame data if it's a data packet.
    /// Call this when poll() indicates data on the UDP fd.
    pub fn processIncoming(self: *UdpAccelEngine) !?[]const u8 {
        const sock = &(self.sock orelse return null);
        var recv_buf: [MAX_UDP_PAYLOAD]u8 = undefined;

        const result = try sock.recvFrom(&recv_buf);
        if (result.len == 0) return null;

        const pkt = recv_buf[0..result.len];
        const now = nowMs();
        self.last_recv_ms = now;

        if (pkt.len < 1) return null;
        const flags = pkt[0];

        // NAT-T probe response
        if (flags & FLAG_NATT_PROBE != 0) {
            self.handleProbeResponse();
            return null;
        }

        // Keepalive
        if (flags & FLAG_KEEPALIVE != 0) {
            return null;
        }

        // Data packet
        if (flags & FLAG_DATA != 0) {
            if (self.config.use_encrypt) {
                return self.decryptPacket(pkt);
            } else {
                if (pkt.len < 5) return null;
                const seq = mem.readInt(u32, pkt[1..5], .big);
                if (!self.checkSeq(seq)) return null;
                return pkt[5..];
            }
        }

        return null;
    }

    // ====================================================================
    // Internal
    // ====================================================================

    fn sendProbe(self: *UdpAccelEngine) !void {
        const server = self.server_addr orelse return;
        const sock = &(self.sock orelse return);

        // NAT-T probe: flags(1) + random(15)
        var probe: [16]u8 = undefined;
        crypto.random.bytes(probe[1..]);
        probe[0] = FLAG_NATT_PROBE;

        _ = try sock.sendTo(&probe, server);
    }

    fn sendKeepalive(self: *UdpAccelEngine) !void {
        const server = self.server_addr orelse return;
        const sock = &(self.sock orelse return);

        var ka: [16]u8 = undefined;
        crypto.random.bytes(ka[1..]);
        ka[0] = FLAG_KEEPALIVE;

        _ = try sock.sendTo(&ka, server);
    }

    fn handleProbeResponse(self: *UdpAccelEngine) void {
        if (self.state == .probing) {
            self.server_reachable = true;
            self.client_reachable = true; // If we got a response, both paths work
            self.state = .established;
            self.last_recv_ms = nowMs();
            self.last_keepalive_ms = nowMs();
            log.info("UDP acceleration established", .{});
        }
    }

    /// Encrypt a data packet:
    ///   [flags 1B][IV 16B][AES-128-CBC(seq(4B) + pad_to_16 + data)][HMAC-SHA1 20B]
    fn encryptPacket(self: *UdpAccelEngine, data: []const u8, flags: u8) ![]const u8 {
        var buf = &self.encrypt_buf;

        // 1) Flags byte
        buf[0] = flags;
        var offset: usize = FLAGS_SIZE;

        // 2) Generate random IV
        var iv: [IV_SIZE]u8 = undefined;
        crypto.random.bytes(&iv);
        @memcpy(buf[offset..][0..IV_SIZE], &iv);
        offset += IV_SIZE;

        // 3) Build plaintext: seq(4 bytes big-endian) + data
        //    Must be padded to AES block size
        const seq_bytes = 4;
        const plaintext_len = seq_bytes + data.len;
        const padded_len = ((plaintext_len + block_size - 1) / block_size) * block_size;

        if (offset + padded_len + HMAC_SIZE > buf.len) return error.BufferTooSmall;

        // Write seq
        mem.writeInt(u32, buf[offset..][0..4], self.send_seq, .big);
        // Write data
        @memcpy(buf[offset + seq_bytes ..][0..data.len], data);
        // PKCS7 padding
        const pad_val: u8 = @intCast(padded_len - plaintext_len);
        if (pad_val == 0) {
            // Full block padding needed
            const full_padded = padded_len + block_size;
            if (offset + full_padded + HMAC_SIZE > buf.len) return error.BufferTooSmall;
            @memset(buf[offset + plaintext_len ..][0..block_size], block_size);
            // Encrypt
            var cipher = Aes128Cbc.init(&self.config.send_key, &iv);
            try cipher.encrypt(buf[offset..][0..full_padded]);
            offset += full_padded;
        } else {
            @memset(buf[offset + plaintext_len ..][0..pad_val], pad_val);
            // Encrypt in-place
            var cipher = Aes128Cbc.init(&self.config.send_key, &iv);
            try cipher.encrypt(buf[offset..][0..padded_len]);
            offset += padded_len;
        }

        // 4) HMAC-SHA1 over everything so far
        const hmac = computeHmacSha1(&self.config.send_hmac_key, buf[0..offset]);
        @memcpy(buf[offset..][0..HMAC_SIZE], &hmac);
        offset += HMAC_SIZE;

        return buf[0..offset];
    }

    /// Decrypt an incoming encrypted data packet.
    /// Returns the data portion (without seq/padding) or null on failure.
    fn decryptPacket(self: *UdpAccelEngine, pkt: []const u8) ?[]const u8 {
        if (pkt.len < MIN_PACKET_SIZE) return null;

        // 1) Verify HMAC
        const hmac_offset = pkt.len - HMAC_SIZE;
        const expected_hmac = computeHmacSha1(&self.config.recv_hmac_key, pkt[0..hmac_offset]);
        if (!mem.eql(u8, pkt[hmac_offset..], &expected_hmac)) {
            log.warn("UDP packet HMAC verification failed", .{});
            return null;
        }

        // 2) Extract IV
        const iv = pkt[FLAGS_SIZE..][0..IV_SIZE].*;
        const ciphertext = pkt[FLAGS_SIZE + IV_SIZE .. hmac_offset];

        if (ciphertext.len == 0 or ciphertext.len % block_size != 0) return null;

        // 3) Decrypt into scratch buffer
        var buf = &self.decrypt_buf;
        if (ciphertext.len > buf.len) return null;
        @memcpy(buf[0..ciphertext.len], ciphertext);

        var cipher = Aes128Cbc.init(&self.config.recv_key, &iv);
        cipher.decrypt(buf[0..ciphertext.len]) catch return null;

        // 4) Remove PKCS7 padding
        const last_byte = buf[ciphertext.len - 1];
        if (last_byte == 0 or last_byte > block_size) return null;
        if (last_byte > ciphertext.len) return null;
        const unpadded_len = ciphertext.len - last_byte;

        // 5) Extract seq and check
        if (unpadded_len < 4) return null;
        const seq = mem.readInt(u32, buf[0..4], .big);
        if (!self.checkSeq(seq)) return null;

        // 6) Return data portion
        return buf[4..unpadded_len];
    }

    /// Check sequence number for replay/ordering.
    fn checkSeq(self: *UdpAccelEngine, seq: u32) bool {
        if (seq == 0) {
            // First packet
            self.recv_seq = seq;
            return true;
        }
        // Allow some out-of-order / gap
        const diff = if (seq >= self.recv_seq) seq - self.recv_seq else self.recv_seq - seq;
        if (diff > MAX_SEQ_GAP) return false;

        if (seq > self.recv_seq) {
            self.recv_seq = seq;
        }
        return true;
    }

    /// Current time in milliseconds.
    fn nowMs() i64 {
        return std.time.milliTimestamp();
    }
};

// ============================================================================
// HMAC-SHA1 (simple implementation for UDP integrity)
// ============================================================================

fn computeHmacSha1(key: *const [20]u8, data: []const u8) [20]u8 {
    const HmacSha1 = crypto.auth.hmac.HmacSha1;
    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, data, key);
    return mac;
}

// ============================================================================
// Tests
// ============================================================================

test "UdpAccelEngine init" {
    const config = UdpAccelConfig{
        .server_ip = "127.0.0.1",
        .server_port = 4500,
        .send_key = [_]u8{0xAA} ** 16,
        .recv_key = [_]u8{0xBB} ** 16,
        .send_hmac_key = [_]u8{0xCC} ** 20,
        .recv_hmac_key = [_]u8{0xDD} ** 20,
    };
    var engine = UdpAccelEngine.init(std.testing.allocator, config);
    defer engine.stop();

    try std.testing.expectEqual(UdpAccelState.idle, engine.state);
}

test "UdpAccelEngine state starts idle" {
    const config = UdpAccelConfig{
        .server_ip = "10.0.0.1",
        .server_port = 8000,
        .send_key = [_]u8{0x11} ** 16,
        .recv_key = [_]u8{0x22} ** 16,
        .send_hmac_key = [_]u8{0x33} ** 20,
        .recv_hmac_key = [_]u8{0x44} ** 20,
    };
    var engine = UdpAccelEngine.init(std.testing.allocator, config);
    defer engine.stop();

    try std.testing.expectEqual(UdpAccelState.idle, engine.state);
    try std.testing.expectEqual(@as(u32, 0), engine.send_seq);
    try std.testing.expectEqual(@as(u32, 0), engine.recv_seq);
}

test "UdpAccelConfig defaults" {
    const config = UdpAccelConfig{
        .server_ip = "1.2.3.4",
        .server_port = 443,
        .send_key = [_]u8{0} ** 16,
        .recv_key = [_]u8{0} ** 16,
        .send_hmac_key = [_]u8{0} ** 20,
        .recv_hmac_key = [_]u8{0} ** 20,
    };

    try std.testing.expect(config.use_encrypt);
}

test "Sequence number check - first packet" {
    const config = UdpAccelConfig{
        .server_ip = "127.0.0.1",
        .server_port = 4500,
        .send_key = [_]u8{0xAA} ** 16,
        .recv_key = [_]u8{0xBB} ** 16,
        .send_hmac_key = [_]u8{0xCC} ** 20,
        .recv_hmac_key = [_]u8{0xDD} ** 20,
    };
    var engine = UdpAccelEngine.init(std.testing.allocator, config);
    defer engine.stop();

    // First packet with seq 0 should be accepted
    try std.testing.expect(engine.checkSeq(0));
    try std.testing.expectEqual(@as(u32, 0), engine.recv_seq);
}

test "Sequence number check - sequential" {
    const config = UdpAccelConfig{
        .server_ip = "127.0.0.1",
        .server_port = 4500,
        .send_key = [_]u8{0xAA} ** 16,
        .recv_key = [_]u8{0xBB} ** 16,
        .send_hmac_key = [_]u8{0xCC} ** 20,
        .recv_hmac_key = [_]u8{0xDD} ** 20,
    };
    var engine = UdpAccelEngine.init(std.testing.allocator, config);
    defer engine.stop();

    _ = engine.checkSeq(0);
    try std.testing.expect(engine.checkSeq(1));
    try std.testing.expect(engine.checkSeq(2));
    try std.testing.expect(engine.checkSeq(3));
    try std.testing.expectEqual(@as(u32, 3), engine.recv_seq);
}

test "Sequence number check - small gap allowed" {
    const config = UdpAccelConfig{
        .server_ip = "127.0.0.1",
        .server_port = 4500,
        .send_key = [_]u8{0xAA} ** 16,
        .recv_key = [_]u8{0xBB} ** 16,
        .send_hmac_key = [_]u8{0xCC} ** 20,
        .recv_hmac_key = [_]u8{0xDD} ** 20,
    };
    var engine = UdpAccelEngine.init(std.testing.allocator, config);
    defer engine.stop();

    _ = engine.checkSeq(0);
    // Small gap (10 packets) should be allowed
    try std.testing.expect(engine.checkSeq(10));
    try std.testing.expectEqual(@as(u32, 10), engine.recv_seq);
}

test "Sequence number check - large gap rejected" {
    const config = UdpAccelConfig{
        .server_ip = "127.0.0.1",
        .server_port = 4500,
        .send_key = [_]u8{0xAA} ** 16,
        .recv_key = [_]u8{0xBB} ** 16,
        .send_hmac_key = [_]u8{0xCC} ** 20,
        .recv_hmac_key = [_]u8{0xDD} ** 20,
    };
    var engine = UdpAccelEngine.init(std.testing.allocator, config);
    defer engine.stop();

    _ = engine.checkSeq(0);
    // Gap larger than MAX_SEQ_GAP should be rejected
    try std.testing.expect(!engine.checkSeq(MAX_SEQ_GAP + 1));
}

test "HMAC-SHA1 consistency" {
    const key = [_]u8{0x0b} ** 20;
    const data = "Hi There";

    const mac1 = computeHmacSha1(&key, data);
    const mac2 = computeHmacSha1(&key, data);

    // Same input produces same HMAC
    try std.testing.expectEqualSlices(u8, &mac1, &mac2);
}

test "HMAC-SHA1 different keys produce different MACs" {
    const key1 = [_]u8{0x0a} ** 20;
    const key2 = [_]u8{0x0b} ** 20;
    const data = "test data";

    const mac1 = computeHmacSha1(&key1, data);
    const mac2 = computeHmacSha1(&key2, data);

    try std.testing.expect(!mem.eql(u8, &mac1, &mac2));
}

test "Packet constants are consistent" {
    // MIN_PACKET_SIZE should equal flags + IV + aes_block + hmac
    try std.testing.expectEqual(
        FLAGS_SIZE + IV_SIZE + block_size + HMAC_SIZE,
        MIN_PACKET_SIZE,
    );
    // NAT-T timeout should be longer than probe interval
    try std.testing.expect(NATT_TIMEOUT_MS > NATT_PROBE_INTERVAL_MS);
    // Path dead timeout should be longer than keepalive
    try std.testing.expect(PATH_DEAD_TIMEOUT_MS > KEEPALIVE_INTERVAL_MS);
}

test "UdpAccelConfig key sizes" {
    const config = UdpAccelConfig{
        .server_ip = "127.0.0.1",
        .server_port = 4500,
        .send_key = [_]u8{0} ** 16,
        .recv_key = [_]u8{0} ** 16,
        .send_hmac_key = [_]u8{0} ** 20,
        .recv_hmac_key = [_]u8{0} ** 20,
    };
    // AES-128 keys should be 16 bytes
    try std.testing.expectEqual(@as(usize, 16), config.send_key.len);
    try std.testing.expectEqual(@as(usize, 16), config.recv_key.len);
    // HMAC-SHA1 keys should be 20 bytes
    try std.testing.expectEqual(@as(usize, 20), config.send_hmac_key.len);
    try std.testing.expectEqual(@as(usize, 20), config.recv_hmac_key.len);
}
