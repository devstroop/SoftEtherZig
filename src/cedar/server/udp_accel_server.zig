//! Server-side UDP acceleration engine.
//!
//! Implements the server role for SoftEther's UDP acceleration data channel,
//! supporting three wire formats:
//!
//! - **V1** (C SoftEther): RC4 encryption, 20-byte IV, SHA-1 key derivation,
//!   cookie+tick header, 0-32 byte padding, 20-byte zero-verify trailer.
//! - **V2** (C SoftEther): ChaCha20-Poly1305 AEAD, 12-byte IV, same header.
//! - **Zig format** (Zig client): AES-128-CBC, 16-byte IV, u32 sequence
//!   numbers, HMAC-SHA1 integrity.
//!
//! The format is negotiated at session init based on the client's
//! `udp_acceleration_version` / `udp_acceleration_max_version` fields.
//!
//! C reference: `UdpAccel` (UdpAccel.c / UdpAccel.h).
//!
//! ## NAT-T
//!
//! The server responds to NAT-T probe packets from clients.  When a probe is
//! received (FLAG_NATT_PROBE set), the server echoes the client's observed
//! IP/port back so the client can learn its external endpoint.  No background
//! thread is needed — probes are handled inline in the poll loop.
//!
//! ## Port allocation
//!
//! The server binds a UDP socket in the range 40000-44999 (C:
//! `UDP_SERVER_PORT_LOWER` / `UDP_SERVER_PORT_HIGHER`).  If the range is
//! exhausted, falls back to OS-assigned port (0).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const posix = std.posix;
const crypto = std.crypto;
const log = std.log.scoped(.udp_accel_server);

const socket_mod = @import("../../mayaqua/network/socket.zig");
const UdpSocket = socket_mod.UdpSocket;
const Address = socket_mod.Address;

const cipher_mod = @import("../../mayaqua/encrypt/cipher.zig");
const Aes128Cbc = cipher_mod.Aes128Cbc;
const ChaCha20Poly1305 = cipher_mod.ChaCha20Poly1305;
const aes_block_size = cipher_mod.block_size;

const hash_mod = @import("../../mayaqua/encrypt/hash.zig");
const sha1 = hash_mod.sha1;
const sha256 = hash_mod.sha256;
const hmacSha1 = hash_mod.hmacSha1;

const rc4_mod = @import("../../mayaqua/encrypt/rc4.zig");
const Rc4 = rc4_mod.Rc4;

// ============================================================================
// Constants
// ============================================================================

/// Server UDP port range (C: `UDP_SERVER_PORT_LOWER` / `UDP_SERVER_PORT_HIGHER`).
pub const UDP_SERVER_PORT_LOWER: u16 = 40000;
pub const UDP_SERVER_PORT_HIGHER: u16 = 44999;

/// Maximum UDP payload (MTU 1500 minus IP + UDP headers).
const MAX_UDP_PAYLOAD: usize = 1500 - 20 - 8;

/// V1 common key size (C: `UDP_ACCELERATION_COMMON_KEY_SIZE_V1`).
const KEY_SIZE_V1: usize = 20;
/// V1 per-packet key size.
const PACKET_KEY_SIZE_V1: usize = 20;
/// V1 IV size (C: `UDP_ACCELERATION_PACKET_IV_SIZE_V1`).
const IV_SIZE_V1: usize = 20;
/// V1 verify trailer size (20 zero bytes).
const VERIFY_SIZE_V1: usize = 20;
/// V1 max padding (C: `UDP_ACCELERATION_MAX_PADDING_SIZE`).
const MAX_PADDING_V1: usize = 32;

/// V2 common key size (C: `UDP_ACCELERATION_COMMON_KEY_SIZE_V2`).
const KEY_SIZE_V2: usize = 128;
/// V2 IV size (C: `UDP_ACCELERATION_PACKET_IV_SIZE_V2`).
const IV_SIZE_V2: usize = 12;
/// V2 AEAD tag size (Poly1305).
const MAC_SIZE_V2: usize = 16;

/// Zig format: AES-128-CBC IV size.
const IV_SIZE_ZIG: usize = 16;
/// Zig format: AES key size.
const KEY_SIZE_ZIG: usize = 16;
/// Zig format: HMAC-SHA1 tag size.
const HMAC_SIZE_ZIG: usize = 20;
/// Zig format: flags byte size.
const FLAGS_SIZE_ZIG: usize = 1;
/// Zig format: minimum packet size.
const MIN_PACKET_ZIG: usize = FLAGS_SIZE_ZIG + IV_SIZE_ZIG + aes_block_size + HMAC_SIZE_ZIG;

/// Protocol version constants.
pub const VERSION_ZIG: u8 = 0;
pub const VERSION_V1: u8 = 1;
pub const VERSION_V2: u8 = 2;

/// Tick window: reject packets with my_tick more than 30s behind
/// (C: `UDP_ACCELERATION_WINDOW_SIZE_MSEC` = 30000).
const TICK_WINDOW_MS: u64 = 30000;

/// Keepalive interval in ms (C: 2000 ms in normal mode).
const KEEPALIVE_INTERVAL_MS: i64 = 2000;

/// Consider path dead after this many ms without recv (C: 9000 ms).
const PATH_DEAD_TIMEOUT_MS: i64 = 9000;

/// NAT-T probe interval in ms.
const NATT_PROBE_INTERVAL_MS: i64 = 3000;

/// Nagle-compatible tick rate: 10 ms per tick (C: `UDP_ACCEL_TICK` = 10).
const TICK_INTERVAL_MS: i64 = 10;

/// V1 flag bits.
const FLAG_V1_DATA: u8 = 0x01;
const FLAG_V1_KEEPALIVE: u8 = 0x02;

/// Zig format flag bits.
const FLAG_ZIG_DATA: u8 = 0x01;
const FLAG_ZIG_KEEPALIVE: u8 = 0x02;
const FLAG_ZIG_NATT_PROBE: u8 = 0x04;

// ============================================================================
// Format dispatch helpers
// ============================================================================

/// Derive a V1 per-packet RC4 key: `SHA1(common_key || iv)`.
fn v1CalcKey(common_key: *const [KEY_SIZE_V1]u8, iv: *const [IV_SIZE_V1]u8) [PACKET_KEY_SIZE_V1]u8 {
    var tmp: [KEY_SIZE_V1 + IV_SIZE_V1]u8 = undefined;
    @memcpy(tmp[0..KEY_SIZE_V1], common_key);
    @memcpy(tmp[KEY_SIZE_V1..][0..IV_SIZE_V1], iv);
    return sha1(&tmp);
}

// ============================================================================
// UdpAccelServer
// ============================================================================

pub const UdpAccelServer = struct {
    allocator: Allocator,

    /// The UDP socket.
    sock: UdpSocket,
    /// Local port (may differ from requested if OS-assigned).
    my_port: u16,

    // ---- Client endpoint (set by initServer) ----

    client_ip: u32 = 0,
    client_port: u16 = 0,
    inited: bool = false,

    // ---- Negotiated format ----

    version: u8 = VERSION_ZIG,

    // ---- V1 fields ----

    /// Server's V1 send-direction common key.
    my_key_v1: [KEY_SIZE_V1]u8 = undefined,
    /// Client's V1 recv-direction common key (set by initServer).
    your_key_v1: [KEY_SIZE_V1]u8 = undefined,
    /// My cookie (random, non-zero).
    my_cookie_v1: u32 = 0,
    /// Peer's cookie (random, non-zero, != my_cookie).
    your_cookie_v1: u32 = 0,
    /// Next IV for outbound V1 packets.
    next_iv_v1: [IV_SIZE_V1]u8 = undefined,

    // ---- V2 fields ----

    /// Server's V2 send-direction common key.
    my_key_v2: [KEY_SIZE_V2]u8 = undefined,
    /// Client's V2 recv-direction common key.
    your_key_v2: [KEY_SIZE_V2]u8 = undefined,
    /// Next IV for outbound V2 packets.
    next_iv_v2: [IV_SIZE_V2]u8 = undefined,

    // ---- Zig format fields ----

    /// Server's send key (for encrypting outbound to client).
    send_key_zig: [KEY_SIZE_ZIG]u8 = undefined,
    /// Client's recv key (for decrypting inbound from client).
    recv_key_zig: [KEY_SIZE_ZIG]u8 = undefined,
    /// HMAC key for send direction (derived from send_key_zig).
    send_hmac_key_zig: [20]u8 = undefined,
    /// HMAC key for recv direction (derived from recv_key_zig).
    recv_hmac_key_zig: [20]u8 = undefined,

    // ---- Common state ----

    /// Outbound sequence counter (Zig format) / tick counter.
    send_seq: u32 = 0,
    /// Highest inbound sequence seen (Zig format).
    recv_seq: u32 = 0,

    /// Current tick (milliseconds since creation).
    now_tick: u64 = 0,
    /// Last received opponent tick.
    last_recv_your_tick: u64 = 0,
    /// Last received "my tick" echo.
    last_recv_my_tick: u64 = 0,

    /// Timestamp of last data recv (ms).
    last_recv_ms: i64 = 0,
    /// Timestamp of last keepalive sent (ms).
    last_keepalive_ms: i64 = 0,
    /// Tick when the object was created (ms).
    created_ms: i64 = 0,
    /// Tick when first stable receive happened (for 10s warmup).
    first_stable_recv_ms: i64 = 0,
    /// Whether we've received at least one valid packet.
    reached_once: bool = false,

    /// Whether the UDP path is active and ready for data.
    is_using_udp: bool = false,

    // ---- Scratch buffers ----

    encrypt_buf: [MAX_UDP_PAYLOAD]u8 = undefined,
    decrypt_buf: [MAX_UDP_PAYLOAD]u8 = undefined,

    /// Whether the server is in plain-text mode (no encryption).
    plain_text_mode: bool = false,

    // ====================================================================
    // Lifecycle
    // ====================================================================

    /// Create a new server-side UDP acceleration object.
    ///
    /// Binds a UDP socket in port range 40000-44999.  Generates random keys
    /// for all three formats and random cookies (V1/V2).
    pub fn init(allocator: Allocator) !UdpAccelServer {
        const sock = try bindPort(allocator);
        const now = nowMs();

        // Generate random cookies (non-zero, distinct).
        var my_cookie = crypto.random.int(u32);
        while (my_cookie == 0) my_cookie = crypto.random.int(u32);
        var your_cookie = crypto.random.int(u32);
        while (your_cookie == 0 or your_cookie == my_cookie) your_cookie = crypto.random.int(u32);

        // Generate random V1 keys and IV.
        var my_key_v1: [KEY_SIZE_V1]u8 = undefined;
        var next_iv_v1: [IV_SIZE_V1]u8 = undefined;
        crypto.random.bytes(&my_key_v1);
        crypto.random.bytes(&next_iv_v1);

        // Generate random V2 keys and IV.
        var my_key_v2: [KEY_SIZE_V2]u8 = undefined;
        var next_iv_v2: [IV_SIZE_V2]u8 = undefined;
        crypto.random.bytes(&my_key_v2);
        crypto.random.bytes(&next_iv_v2);

        // Generate random Zig keys and derive HMAC keys.
        var send_key_zig: [KEY_SIZE_ZIG]u8 = undefined;
        var recv_key_zig: [KEY_SIZE_ZIG]u8 = undefined;
        crypto.random.bytes(&send_key_zig);
        crypto.random.bytes(&recv_key_zig);
        const send_hmac_key = deriveHmacKey(&send_key_zig);
        const recv_hmac_key = deriveHmacKey(&recv_key_zig);

        return .{
            .allocator = allocator,
            .sock = sock,
            .my_port = sock.bound_port,
            .my_key_v1 = my_key_v1,
            .my_cookie_v1 = my_cookie,
            .your_cookie_v1 = your_cookie,
            .next_iv_v1 = next_iv_v1,
            .my_key_v2 = my_key_v2,
            .next_iv_v2 = next_iv_v2,
            .send_key_zig = send_key_zig,
            .recv_key_zig = recv_key_zig,
            .send_hmac_key_zig = send_hmac_key,
            .recv_hmac_key_zig = recv_hmac_key,
            .created_ms = now,
        };
    }

    /// Initialize the server with the client's keys and endpoint.
    ///
    /// Called after parsing the client's auth pack.  `version` determines the
    /// negotiated wire format.  `client_key_*` are the keys the client sent
    /// (may be empty slices if that format is not supported by the client).
    pub fn initServer(
        self: *UdpAccelServer,
        client_ip: u32,
        client_port: u16,
        version: u8,
        client_key_v1: []const u8,
        client_key_v2: []const u8,
        client_key_zig: []const u8,
    ) void {
        self.client_ip = client_ip;
        self.client_port = client_port;
        self.version = version;

        switch (version) {
            VERSION_V1 => {
                if (client_key_v1.len >= KEY_SIZE_V1) {
                    @memcpy(self.your_key_v1[0..KEY_SIZE_V1], client_key_v1[0..KEY_SIZE_V1]);
                }
            },
            VERSION_V2 => {
                if (client_key_v2.len >= KEY_SIZE_V2) {
                    @memcpy(self.your_key_v2[0..KEY_SIZE_V2], client_key_v2[0..KEY_SIZE_V2]);
                }
            },
            else => { // VERSION_ZIG
                if (client_key_zig.len >= KEY_SIZE_ZIG) {
                    @memcpy(self.recv_key_zig[0..KEY_SIZE_ZIG], client_key_zig[0..KEY_SIZE_ZIG]);
                    // Derive HMAC key from client's key for recv direction.
                    self.recv_hmac_key_zig = deriveHmacKey(&self.recv_key_zig);
                }
            },
        }

        self.inited = true;
        self.now_tick = 0;
        self.last_recv_ms = self.created_ms;
        self.last_keepalive_ms = self.created_ms;
        log.info("UDP accel server inited: version={d} client={any}:{d} port={d}", .{
            version, client_ip, client_port, self.my_port,
        });
    }

    /// Clean up and close the socket.
    pub fn deinit(self: *UdpAccelServer) void {
        self.sock.close();
        log.info("UDP accel server deinit, port={d}", .{self.my_port});
    }

    // ====================================================================
    // Poll / Send
    // ====================================================================

    /// Get the UDP socket fd for poll().
    pub fn getFd(self: *const UdpAccelServer) ?posix.socket_t {
        return self.sock.getFd();
    }

    /// Poll for incoming UDP data.  Returns a decrypted data block, or null
    /// if no data is ready (keepalive / probe / empty).
    pub fn poll(self: *UdpAccelServer) ?[]u8 {
        const now = nowMs();
        self.updateTick(now);

        // Drain all pending datagrams.
        while (true) {
            var recv_buf: [MAX_UDP_PAYLOAD]u8 = undefined;
            const result = self.sock.recvFrom(&recv_buf) catch return null;
            if (result.len == 0) return null;

            const pkt = recv_buf[0..result.len];
            const from_ip = ipFromAddr(result.from);
            const from_port = result.from.inner.getPort();

            // Only accept packets from the known client endpoint.
            if (!self.inited) continue;
            if (from_ip != self.client_ip) continue;

            self.last_recv_ms = now;

            // Check for NAT-T probe (Zig format only).
            if (self.version == VERSION_ZIG and pkt.len >= 1 and
                pkt[0] & FLAG_ZIG_NATT_PROBE != 0)
            {
                self.handleNatTProbe(from_port, pkt);
                continue;
            }

            // Process the packet and return data block.
            if (self.processPacket(pkt)) |block| {
                return block;
            }
        }
    }

    /// Send a data block via UDP.  Returns true if sent successfully.
    pub fn sendBlock(self: *UdpAccelServer, data: []const u8, compressed: bool) bool {
        if (!self.isSendReady()) return false;

        return switch (self.version) {
            VERSION_V1 => blk: {
                self.sendV1(data, compressed) catch break :blk false;
                break :blk true;
            },
            VERSION_V2 => blk: {
                self.sendV2(data, compressed) catch break :blk false;
                break :blk true;
            },
            else => blk: {
                self.sendZig(data, compressed) catch break :blk false;
                break :blk true;
            },
        };
    }

    /// Send a keepalive (zero-payload packet).
    pub fn sendKeepalive(self: *UdpAccelServer) void {
        if (!self.inited) return;

        switch (self.version) {
            VERSION_V1 => self.sendV1(&.{}, false) catch {},
            VERSION_V2 => self.sendV2(&.{}, false) catch {},
            else => self.sendZigKeepalive() catch {},
        }
    }

    /// Check if the UDP path is active and ready for sending.
    ///
    /// Requires: inited, client endpoint known, last recv within keepalive
    /// window, and first stable receive at least 10s ago (C:
    /// `UDP_ACCELERATION_REQUIRE_CONTINUOUS`).
    pub fn isSendReady(self: *const UdpAccelServer) bool {
        if (!self.inited) return false;
        if (self.client_port == 0) return false;
        if (self.plain_text_mode and false) return false; // plaintext is still "ready"

        const now = nowMs();
        const elapsed = now - self.last_recv_ms;

        // Must have received at least one packet.
        if (!self.reached_once) return false;

        // Must have had stable receive for at least 10 seconds (C: 10000 ms).
        if (self.first_stable_recv_ms == 0) return false;
        const stable_time = now - self.first_stable_recv_ms;
        if (stable_time < 10000) return false;

        // Must be within keepalive timeout.
        if (self.version == VERSION_ZIG) {
            return elapsed < PATH_DEAD_TIMEOUT_MS;
        } else {
            // V1/V2: C uses 9000 ms for non-fast mode.
            return elapsed < PATH_DEAD_TIMEOUT_MS;
        }
    }

    /// Drive timer-based work: keepalive, dead detection.
    pub fn tick(self: *UdpAccelServer) void {
        const now = nowMs();
        self.updateTick(now);

        if (!self.inited) return;

        // Check path liveness.
        if (self.reached_once) {
            const elapsed = now - self.last_recv_ms;
            if (elapsed > PATH_DEAD_TIMEOUT_MS) {
                if (self.is_using_udp) {
                    log.warn("UDP accel path dead (no recv for {d}ms)", .{elapsed});
                    self.is_using_udp = false;
                }
            }
        }

        // Send keepalive.
        if (now - self.last_keepalive_ms >= KEEPALIVE_INTERVAL_MS) {
            self.sendKeepalive();
            self.last_keepalive_ms = now;
        }
    }

    /// Calculate the optimal MSS for the UDP path.
    pub fn calcMss(self: *const UdpAccelServer) u32 {
        const max_payload: u32 = switch (self.version) {
            VERSION_V1 => MAX_UDP_PAYLOAD - IV_SIZE_V1 - 4 - 8 - 8 - 2 - 1 - VERIFY_SIZE_V1 - MAX_PADDING_V1,
            VERSION_V2 => MAX_UDP_PAYLOAD - IV_SIZE_V2 - 4 - 8 - 8 - 2 - 1 - MAC_SIZE_V2,
            else => MAX_UDP_PAYLOAD - FLAGS_SIZE_ZIG - IV_SIZE_ZIG - 4 - HMAC_SIZE_ZIG,
        };
        // Subtract framing overhead.
        return @max(max_payload - 64, 512);
    }

    // ====================================================================
    // Packet processing (receive side)
    // ====================================================================

    /// Process a received packet and return the data block, or null.
    fn processPacket(self: *UdpAccelServer, pkt: []const u8) ?[]u8 {
        return switch (self.version) {
            VERSION_V1 => self.processV1(pkt),
            VERSION_V2 => self.processV2(pkt),
            else => self.processZig(pkt),
        };
    }

    // ---- V1 processing ----

    fn processV1(self: *UdpAccelServer, pkt: []const u8) ?[]u8 {
        if (pkt.len < IV_SIZE_V1 + 4 + 8 + 8 + 2 + 1 + VERIFY_SIZE_V1) return null;

        // 1) Extract IV.
        const iv = pkt[0..IV_SIZE_V1].*;

        // 2) Derive decryption key: SHA1(YourKey || iv).
        const key = v1CalcKey(&self.your_key_v1, &iv);

        // 3) Copy ciphertext for decryption.
        const cipher_len = pkt.len - IV_SIZE_V1;
        if (cipher_len > self.decrypt_buf.len) return null;
        @memcpy(self.decrypt_buf[0..cipher_len], pkt[IV_SIZE_V1..][0..cipher_len]);

        // 4) RC4-decrypt.
        var rc4 = Rc4.init(&key);
        rc4.apply(self.decrypt_buf[0..cipher_len]);

        // 5) Parse: cookie(4) + my_tick(8) + your_tick(8) + data_size(2) + flag(1) + payload + padding + verify(20).
        const buf = self.decrypt_buf[0..cipher_len];
        var pos: usize = 0;

        const cookie = mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;
        const my_tick = mem.readInt(u64, buf[pos..][0..8], .big);
        pos += 8;
        const your_tick = mem.readInt(u64, buf[pos..][0..8], .big);
        pos += 8;
        const data_size = mem.readInt(u16, buf[pos..][0..2], .big);
        pos += 2;
        pos += 1; // skip flag byte

        // 6) Validate cookie.
        if (cookie != self.my_cookie_v1) {
            log.warn("V1 UDP cookie mismatch: got {x}, expected {x}", .{ cookie, self.my_cookie_v1 });
            return null;
        }

        // 7) Tick window check.
        if (my_tick < self.last_recv_your_tick) {
            const gap = self.last_recv_your_tick - my_tick;
            if (gap > TICK_WINDOW_MS) {
                log.warn("V1 UDP tick window exceeded: gap={d}ms", .{gap});
                return null;
            }
        }
        self.last_recv_your_tick = @max(self.last_recv_your_tick, my_tick);
        self.last_recv_my_tick = @max(self.last_recv_my_tick, your_tick);

        // 8) Verify trailer (last 20 bytes must be all zeros).
        if (buf.len < VERIFY_SIZE_V1) return null;
        const verify_start = buf.len - VERIFY_SIZE_V1;
        for (buf[verify_start..]) |b| {
            if (b != 0) {
                log.warn("V1 UDP verify failed", .{});
                return null;
            }
        }

        // 9) Extract payload.
        if (pos + data_size > verify_start) return null;
        const payload = buf[pos..][0..data_size];

        // Keepalive if payload is empty.
        if (data_size == 0) return null;

        self.markStableRecv();
        return payload;
    }

    // ---- V2 processing ----

    fn processV2(self: *UdpAccelServer, pkt: []const u8) ?[]u8 {
        if (pkt.len < IV_SIZE_V2 + 4 + 8 + 8 + 2 + 1 + MAC_SIZE_V2) return null;

        // 1) Extract IV.
        const iv = pkt[0..IV_SIZE_V2];

        // 2) The rest is AEAD ciphertext + tag.
        const ciphertext = pkt[IV_SIZE_V2..];
        if (ciphertext.len < MAC_SIZE_V2) return null;

        // 3) Decrypt with ChaCha20-Poly1305.
        // Key = SHA-256(common_key) → 32 bytes. Nonce = first 12 bytes of IV.
        const key_material = sha256(&self.your_key_v2);
        const aead_key = key_material[0..32];
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, iv[0..12]);

        var plaintext: [MAX_UDP_PAYLOAD]u8 = undefined;
        const plaintext_len = ciphertext.len - MAC_SIZE_V2;
        if (plaintext_len > plaintext.len) return null;

        const aad = iv; // AAD = IV (12 bytes)
        const tag_val = ciphertext[plaintext_len..][0..MAC_SIZE_V2].*;
        const ct = ciphertext[0..plaintext_len];

        ChaCha20Poly1305.decrypt(plaintext[0..plaintext_len], ct, tag_val, aad, nonce, aead_key.*) catch {
            log.warn("V2 UDP AEAD decryption failed", .{});
            return null;
        };

        // 4) Parse header.
        const buf = plaintext[0..plaintext_len];
        var pos: usize = 0;

        const cookie = mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;
        const my_tick = mem.readInt(u64, buf[pos..][0..8], .big);
        pos += 8;
        const your_tick = mem.readInt(u64, buf[pos..][0..8], .big);
        pos += 8;
        const data_size = mem.readInt(u16, buf[pos..][0..2], .big);
        pos += 2;
        const flag = buf[pos];
        pos += 1;
        _ = flag;

        // 5) Validate cookie.
        if (cookie != self.my_cookie_v1) { // V2 uses same cookies as V1
            log.warn("V2 UDP cookie mismatch", .{});
            return null;
        }

        // 6) Tick window check.
        if (my_tick < self.last_recv_your_tick) {
            const gap = self.last_recv_your_tick - my_tick;
            if (gap > TICK_WINDOW_MS) {
                log.warn("V2 UDP tick window exceeded", .{});
                return null;
            }
        }
        self.last_recv_your_tick = @max(self.last_recv_your_tick, my_tick);
        self.last_recv_my_tick = @max(self.last_recv_my_tick, your_tick);

        // 7) Extract payload.
        if (pos + data_size > plaintext_len) return null;
        const payload = buf[pos..][0..data_size];

        if (data_size == 0) return null;

        self.markStableRecv();
        return payload;
    }

    // ---- Zig format processing ----

    fn processZig(self: *UdpAccelServer, pkt: []const u8) ?[]u8 {
        if (pkt.len < MIN_PACKET_ZIG) return null;

        const flags = pkt[0];

        // NAT-T probe is handled in poll() before calling this.
        if (flags & FLAG_ZIG_KEEPALIVE != 0) return null;

        if (flags & FLAG_ZIG_DATA == 0) return null;

        if (self.plain_text_mode) {
            if (pkt.len < FLAGS_SIZE_ZIG + 4) return null;
            const seq = mem.readInt(u32, pkt[FLAGS_SIZE_ZIG..][0..4], .big);
            if (!self.checkSeqZig(seq)) return null;
            return self.allocator.dupe(u8, pkt[FLAGS_SIZE_ZIG + 4 ..]) catch null;
        }

        // 1) Verify HMAC.
        const hmac_offset = pkt.len - HMAC_SIZE_ZIG;
        const expected_hmac = hmacSha1(&self.recv_hmac_key_zig, pkt[0..hmac_offset]);
        if (!mem.eql(u8, pkt[hmac_offset..][0..HMAC_SIZE_ZIG], &expected_hmac)) {
            log.warn("Zig UDP HMAC verification failed", .{});
            return null;
        }

        // 2) Extract IV.
        const iv = pkt[FLAGS_SIZE_ZIG..][0..IV_SIZE_ZIG].*;
        const ciphertext = pkt[FLAGS_SIZE_ZIG + IV_SIZE_ZIG .. hmac_offset];

        if (ciphertext.len == 0 or ciphertext.len % aes_block_size != 0) return null;
        if (ciphertext.len > self.decrypt_buf.len) return null;

        // 3) Decrypt.
        @memcpy(self.decrypt_buf[0..ciphertext.len], ciphertext);
        var cipher = Aes128Cbc.init(&self.recv_key_zig, &iv);
        cipher.decrypt(self.decrypt_buf[0..ciphertext.len]) catch return null;

        // 4) Remove PKCS7 padding.
        const last_byte = self.decrypt_buf[ciphertext.len - 1];
        if (last_byte == 0 or last_byte > aes_block_size) return null;
        if (last_byte > ciphertext.len) return null;
        const unpadded_len = ciphertext.len - last_byte;

        // 5) Extract seq and check.
        if (unpadded_len < 4) return null;
        const seq = mem.readInt(u32, self.decrypt_buf[0..4], .big);
        if (!self.checkSeqZig(seq)) return null;

        // 6) Return data portion (caller must free).
        return self.allocator.dupe(u8, self.decrypt_buf[4..unpadded_len]) catch null;
    }

    // ====================================================================
    // Send (V1)
    // ====================================================================

    fn sendV1(self: *UdpAccelServer, data: []const u8, compressed: bool) !void {
        const client = Address{ .inner = std.net.Address.initIp4(.{
            @intCast(self.client_ip & 0xFF),
            @intCast((self.client_ip >> 8) & 0xFF),
            @intCast((self.client_ip >> 16) & 0xFF),
            @intCast((self.client_ip >> 24) & 0xFF),
        }, self.client_port) };

        // Build plaintext: cookie(4) + my_tick(8) + your_tick(8) + data_size(2) + flag(1) + payload + padding + verify(20).
        var buf: [MAX_UDP_PAYLOAD]u8 = undefined;
        var pos: usize = 0;

        // Write IV at the front (cleartext).
        @memcpy(buf[0..IV_SIZE_V1], &self.next_iv_v1);
        pos = IV_SIZE_V1;

        // Header (will be encrypted).
        mem.writeInt(u32, buf[pos..][0..4], self.your_cookie_v1, .big);
        pos += 4;
        const now_val: u64 = if (self.now_tick == 0) 1 else self.now_tick;
        mem.writeInt(u64, buf[pos..][0..8], now_val, .big);
        pos += 8;
        mem.writeInt(u64, buf[pos..][0..8], self.last_recv_your_tick, .big);
        pos += 8;
        mem.writeInt(u16, buf[pos..][0..2], @intCast(data.len), .big);
        pos += 2;
        buf[pos] = if (compressed) 1 else 0;
        pos += 1;

        // Payload.
        @memcpy(buf[pos..][0..data.len], data);
        pos += data.len;

        // Padding (random, 0..32 bytes).
        const pad_size = if (data.len == 0) 0 else blk: {
            const max_total = self.calcMss() + IV_SIZE_V1 + 4 + 8 + 8 + 2 + 1 + VERIFY_SIZE_V1;
            const current = pos;
            const room = if (max_total > current) max_total - current else 0;
            break :blk @min(room, MAX_PADDING_V1);
        };
        if (pad_size > 0) {
            crypto.random.bytes(buf[pos..][0..pad_size]);
            pos += pad_size;
        }

        // Verify (20 zero bytes).
        @memset(buf[pos..][0..VERIFY_SIZE_V1], 0);
        pos += VERIFY_SIZE_V1;

        // Derive per-packet RC4 key: SHA1(MyKey || NextIv).
        const key = v1CalcKey(&self.my_key_v1, &self.next_iv_v1);

        // RC4-encrypt everything after IV.
        var rc4 = Rc4.init(&key);
        rc4.apply(buf[IV_SIZE_V1..pos]);

        // Update NextIv: last 20 bytes of encrypted region.
        const enc_end = pos;
        const iv_src_start = enc_end - IV_SIZE_V1;
        @memcpy(&self.next_iv_v1, buf[iv_src_start..][0..IV_SIZE_V1]);

        _ = try self.sock.sendTo(buf[0..enc_end], client);
    }

    // ====================================================================
    // Send (V2)
    // ====================================================================

    fn sendV2(self: *UdpAccelServer, data: []const u8, compressed: bool) !void {
        const client = Address{ .inner = std.net.Address.initIp4(.{
            @intCast(self.client_ip & 0xFF),
            @intCast((self.client_ip >> 8) & 0xFF),
            @intCast((self.client_ip >> 16) & 0xFF),
            @intCast((self.client_ip >> 24) & 0xFF),
        }, self.client_port) };

        // Build plaintext: cookie(4) + my_tick(8) + your_tick(8) + data_size(2) + flag(1) + payload + padding.
        var plaintext: [MAX_UDP_PAYLOAD]u8 = undefined;
        var pos: usize = 0;

        mem.writeInt(u32, plaintext[pos..][0..4], self.your_cookie_v1, .big); // V2 uses same cookies
        pos += 4;
        const now_val_v2: u64 = if (self.now_tick == 0) 1 else self.now_tick;
        mem.writeInt(u64, plaintext[pos..][0..8], now_val_v2, .big);
        pos += 8;
        mem.writeInt(u64, plaintext[pos..][0..8], self.last_recv_your_tick, .big);
        pos += 8;
        mem.writeInt(u16, plaintext[pos..][0..2], @intCast(data.len), .big);
        pos += 2;
        plaintext[pos] = if (compressed) 1 else 0;
        pos += 1;

        @memcpy(plaintext[pos..][0..data.len], data);
        pos += data.len;

        // Padding.
        const pad_size = if (data.len == 0) 0 else blk: {
            const max_total = self.calcMss() + IV_SIZE_V2 + 4 + 8 + 8 + 2 + 1 + MAC_SIZE_V2;
            const room = if (max_total > pos) max_total - pos else 0;
            break :blk @min(room, MAX_PADDING_V1);
        };
        if (pad_size > 0) {
            crypto.random.bytes(plaintext[pos..][0..pad_size]);
            pos += pad_size;
        }

        // Generate random IV.
        var iv: [IV_SIZE_V2]u8 = undefined;
        crypto.random.bytes(&iv);

        // Derive AEAD key from V2 common key via SHA-256.
        const key_material = sha256(&self.my_key_v2);
        const aead_key = key_material[0..32];
        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, iv[0..12]);

        // Encrypt with ChaCha20-Poly1305.
        var ct_out: [MAX_UDP_PAYLOAD]u8 = undefined;
        var tag_out: [MAC_SIZE_V2]u8 = undefined;
        const ct_len = pos;
        ChaCha20Poly1305.encrypt(
            ct_out[0..ct_len],
            &tag_out,
            plaintext[0..ct_len],
            &.{}, // no AAD
            nonce,
            aead_key.*,
        );

        // Build packet: IV(12) + ciphertext + tag(16).
        var pkt: [MAX_UDP_PAYLOAD + MAC_SIZE_V2 + IV_SIZE_V2]u8 = undefined;
        @memcpy(pkt[0..IV_SIZE_V2], &iv);
        @memcpy(pkt[IV_SIZE_V2..][0..ct_len], ct_out[0..ct_len]);
        @memcpy(pkt[IV_SIZE_V2 + ct_len ..][0..MAC_SIZE_V2], &tag_out);

        _ = try self.sock.sendTo(pkt[0..IV_SIZE_V2 + ct_len + MAC_SIZE_V2], client);
    }

    // ====================================================================
    // Send (Zig format)
    // ====================================================================

    fn sendZig(self: *UdpAccelServer, data: []const u8, _: bool) !void {
        const client = Address{ .inner = std.net.Address.initIp4(.{
            @intCast(self.client_ip & 0xFF),
            @intCast((self.client_ip >> 8) & 0xFF),
            @intCast((self.client_ip >> 16) & 0xFF),
            @intCast((self.client_ip >> 24) & 0xFF),
        }, self.client_port) };

        self.send_seq +%= 1;

        if (self.plain_text_mode) {
            var buf = &self.encrypt_buf;
            buf[0] = FLAG_ZIG_DATA;
            mem.writeInt(u32, buf[1..5], self.send_seq, .big);
            const total = 5 + data.len;
            if (total > buf.len) return;
            @memcpy(buf[5..][0..data.len], data);
            _ = try self.sock.sendTo(buf[0..total], client);
            return;
        }

        var buf = &self.encrypt_buf;

        // 1) Flags byte.
        buf[0] = FLAG_ZIG_DATA;
        var offset: usize = FLAGS_SIZE_ZIG;

        // 2) Random IV.
        var iv: [IV_SIZE_ZIG]u8 = undefined;
        crypto.random.bytes(&iv);
        @memcpy(buf[offset..][0..IV_SIZE_ZIG], &iv);
        offset += IV_SIZE_ZIG;

        // 3) Plaintext: seq(4) + data, padded to AES block size.
        const seq_bytes = 4;
        const plaintext_len = seq_bytes + data.len;
        const padded_len = ((plaintext_len + aes_block_size - 1) / aes_block_size) * aes_block_size;

        if (offset + padded_len + HMAC_SIZE_ZIG > buf.len) return;

        mem.writeInt(u32, buf[offset..][0..4], self.send_seq, .big);
        @memcpy(buf[offset + seq_bytes ..][0..data.len], data);
        const pad_val: u8 = @intCast(padded_len - plaintext_len);
        if (pad_val == 0) {
            const full_padded = padded_len + aes_block_size;
            if (offset + full_padded + HMAC_SIZE_ZIG > buf.len) return;
            @memset(buf[offset + plaintext_len ..][0..aes_block_size], @intCast(aes_block_size));
            var cipher = Aes128Cbc.init(&self.send_key_zig, &iv);
            try cipher.encrypt(buf[offset..][0..full_padded]);
            offset += full_padded;
        } else {
            @memset(buf[offset + plaintext_len ..][0..pad_val], pad_val);
            var cipher = Aes128Cbc.init(&self.send_key_zig, &iv);
            try cipher.encrypt(buf[offset..][0..padded_len]);
            offset += padded_len;
        }

        // 4) HMAC-SHA1.
        const hmac = hmacSha1(&self.send_hmac_key_zig, buf[0..offset]);
        @memcpy(buf[offset..][0..HMAC_SIZE_ZIG], &hmac);
        offset += HMAC_SIZE_ZIG;

        _ = try self.sock.sendTo(buf[0..offset], client);
    }

    /// Send a Zig-format keepalive.
    fn sendZigKeepalive(self: *UdpAccelServer) !void {
        const client = Address{ .inner = std.net.Address.initIp4(.{
            @intCast(self.client_ip & 0xFF),
            @intCast((self.client_ip >> 8) & 0xFF),
            @intCast((self.client_ip >> 16) & 0xFF),
            @intCast((self.client_ip >> 24) & 0xFF),
        }, self.client_port) };

        var ka: [16]u8 = undefined;
        crypto.random.bytes(ka[1..]);
        ka[0] = FLAG_ZIG_KEEPALIVE;

        _ = try self.sock.sendTo(&ka, client);
    }

    // ====================================================================
    // NAT-T
    // ====================================================================

    /// Handle a NAT-T probe: echo the client's observed IP/port back.
    fn handleNatTProbe(self: *UdpAccelServer, observed_port: u16, pkt: []const u8) void {
        // Echo the probe back to the client (the client uses this to learn
        // its external port).  For simplicity, we just echo the packet as-is;
        // the client can read the source port from the response.
        const client = Address{ .inner = std.net.Address.initIp4(.{
            @intCast(self.client_ip & 0xFF),
            @intCast((self.client_ip >> 8) & 0xFF),
            @intCast((self.client_ip >> 16) & 0xFF),
            @intCast((self.client_ip >> 24) & 0xFF),
        }, self.client_port) };

        _ = self.sock.sendTo(pkt, client) catch {};
        log.debug("NAT-T probe echoed, observed port={d}", .{observed_port});
    }

    // ====================================================================
    // Internal helpers
    // ====================================================================

    fn updateTick(self: *UdpAccelServer, now: i64) void {
        const elapsed: u64 = @intCast(@max(now - self.created_ms, 0));
        self.now_tick = elapsed;
    }

    fn markStableRecv(self: *UdpAccelServer) void {
        if (!self.reached_once) {
            self.reached_once = true;
            self.first_stable_recv_ms = nowMs();
            self.is_using_udp = true;
        }
    }

    fn checkSeqZig(self: *UdpAccelServer, seq: u32) bool {
        if (seq == 0) {
            self.recv_seq = seq;
            return true;
        }
        const diff = if (seq >= self.recv_seq) seq - self.recv_seq else self.recv_seq - seq;
        if (diff > 16384) return false;
        if (seq > self.recv_seq) {
            self.recv_seq = seq;
        }
        return true;
    }
};

// ============================================================================
// Port allocation
// ============================================================================

/// Bind a UDP socket in the server port range, or fallback to OS-assigned.
fn bindPort(allocator: Allocator) !UdpSocket {
    _ = allocator;
    // Try the C reference range first.
    for (UDP_SERVER_PORT_LOWER..UDP_SERVER_PORT_HIGHER + 1) |port| {
        return UdpSocket.bind(@intCast(port), .ipv4) catch continue;
    }
    // Fallback: OS-assigned port.
    return UdpSocket.bind(0, .ipv4);
}

// ============================================================================
// Utility
// ============================================================================

/// Derive a 20-byte HMAC key from an AES key by hashing it.
fn deriveHmacKey(aes_key: *const [KEY_SIZE_ZIG]u8) [20]u8 {
    return sha1(aes_key);
}

/// Extract a u32 IP from an Address (host byte order).
fn ipFromAddr(addr: Address) u32 {
    const in = addr.inner.in;
    return @as(u32, @intCast(in.sa.addr));
}

/// Current time in milliseconds.
fn nowMs() i64 {
    return std.time.milliTimestamp();
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "UdpAccelServer init" {
    var server = try UdpAccelServer.init(testing.allocator);
    defer server.deinit();

    try testing.expect(server.my_port >= UDP_SERVER_PORT_LOWER or server.my_port == 0);
    try testing.expect(server.inited == false);
    try testing.expect(server.my_cookie_v1 != 0);
    try testing.expect(server.your_cookie_v1 != 0);
    try testing.expect(server.my_cookie_v1 != server.your_cookie_v1);
}

test "V1 key derivation is deterministic" {
    const common_key = [_]u8{0xAA} ** KEY_SIZE_V1;
    const iv = [_]u8{0xBB} ** IV_SIZE_V1;

    const k1 = v1CalcKey(&common_key, &iv);
    const k2 = v1CalcKey(&common_key, &iv);
    try testing.expectEqualSlices(u8, &k1, &k2);
}

test "V1 key derivation changes with different IV" {
    const common_key = [_]u8{0xAA} ** KEY_SIZE_V1;
    const iv1 = [_]u8{0xBB} ** IV_SIZE_V1;
    const iv2 = [_]u8{0xCC} ** IV_SIZE_V1;

    const k1 = v1CalcKey(&common_key, &iv1);
    const k2 = v1CalcKey(&common_key, &iv2);
    try testing.expect(!mem.eql(u8, &k1, &k2));
}

test "V1 key derivation changes with different key" {
    const key1 = [_]u8{0xAA} ** KEY_SIZE_V1;
    const key2 = [_]u8{0xBB} ** KEY_SIZE_V1;
    const iv = [_]u8{0xCC} ** IV_SIZE_V1;

    const k1 = v1CalcKey(&key1, &iv);
    const k2 = v1CalcKey(&key2, &iv);
    try testing.expect(!mem.eql(u8, &k1, &k2));
}

test "RC4 encrypt/decrypt roundtrip" {
    const key = [_]u8{0x42} ** 16;
    const data = "Hello, UDP acceleration!";

    var rc4_enc = Rc4.init(&key);
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..data.len], data);
    rc4_enc.apply(buf[0..data.len]);

    var rc4_dec = Rc4.init(&key);
    rc4_dec.apply(buf[0..data.len]);

    try testing.expectEqualStrings(data, buf[0..data.len]);
}

test "Zig HMAC key derivation" {
    const key = [_]u8{0x42} ** KEY_SIZE_ZIG;
    const hmac_key = deriveHmacKey(&key);
    try testing.expectEqual(@as(usize, 20), hmac_key.len);
}

test "Sequence check - first packet" {
    var server = try UdpAccelServer.init(testing.allocator);
    defer server.deinit();
    server.inited = true;

    try testing.expect(server.checkSeqZig(0));
    try testing.expectEqual(@as(u32, 0), server.recv_seq);
}

test "Sequence check - sequential" {
    var server = try UdpAccelServer.init(testing.allocator);
    defer server.deinit();
    server.inited = true;

    _ = server.checkSeqZig(0);
    try testing.expect(server.checkSeqZig(1));
    try testing.expect(server.checkSeqZig(2));
    try testing.expect(server.checkSeqZig(3));
    try testing.expectEqual(@as(u32, 3), server.recv_seq);
}

test "Sequence check - large gap rejected" {
    var server = try UdpAccelServer.init(testing.allocator);
    defer server.deinit();
    server.inited = true;

    _ = server.checkSeqZig(0);
    try testing.expect(!server.checkSeqZig(20000));
}

test "isSendReady - not inited" {
    var server = try UdpAccelServer.init(testing.allocator);
    defer server.deinit();
    try testing.expect(!server.isSendReady());
}

test "MSS calculation" {
    var server = try UdpAccelServer.init(testing.allocator);
    defer server.deinit();

    const mss_v1 = server.calcMss();
    server.version = VERSION_V1;
    try testing.expect(mss_v1 > 512);

    server.version = VERSION_V2;
    const mss_v2 = server.calcMss();
    try testing.expect(mss_v2 > 512);

    server.version = VERSION_ZIG;
    const mss_zig = server.calcMss();
    try testing.expect(mss_zig > 512);
}

test "ipFromAddr roundtrip" {
    const addr = try Address.parseIp4("192.168.1.100", 443);
    const ip = ipFromAddr(addr);
    const b: [4]u8 = @bitCast(ip);
    try testing.expectEqual(@as(u8, 192), b[0]);
    try testing.expectEqual(@as(u8, 168), b[1]);
    try testing.expectEqual(@as(u8, 1), b[2]);
    try testing.expectEqual(@as(u8, 100), b[3]);
}
