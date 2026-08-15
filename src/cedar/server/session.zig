//! Server-side session keys + data-channel encryption.
//!
//! C reference (4.44):
//! - `NewSessionKey` (Session.c:2195) — random 20-byte session key + u32
//! - `GenerateRC4KeyPair` (Protocol.c:8485) — random RC4 key pair
//! - encryption negotiation (Protocol.c:3958-3962, 4188-4195)
//! - `InitTcpSockRc4Key` (Connection.c:2881-2906) — the direction swap
//! - `PackWelcome` (Protocol.c:6442-6500) — the welcome fields
//!
//! ## Encryption modes
//!
//! Matches the Zig client (`cedar/session/session.zig`), which is the wire
//! target for M1:
//!
//! - `use_encrypt && use_fast_rc4` → **fast RC4**: both peers hold the same
//!   two RC4 keys; the direction swap picks which each side uses:
//!   client: send = client_to_server, recv = server_to_client
//!   server: send = server_to_client, recv = client_to_server
//!   RC4 is symmetric, so both peers advance the same keystream per direction.
//!   The keystream is stateful per TCP socket (C creates a `CRYPT` per socket
//!   via `InitTcpSockRc4Key`), so the cipher state lives on `ConnectionCipher`.
//! - `use_encrypt && !use_fast_rc4` → **AES-256-CBC (classic)**: keys are
//!   SHA-256(session_key ‖ server HELLO random ‖ direction byte), exactly as
//!   the client's `SessionKeys.deriveFromAuth`; every packet carries its own
//!   16-byte random IV, PKCS#7 padded. This is the path a default-config Zig
//!   client takes. NOTE: C 4.44 instead sets `use_ssl_data_encryption` and
//!   leaves the data channel to TLS; the Zig client runs classic AES here, so
//!   the Zig server follows the Zig client (documented deviation).
//! - encryption off → passthrough copies.
//!
//! `ServerSession` holds session-level material (keys, negotiation, welcome
//! fields); `ConnectionCipher` holds per-connection cipher state and is the
//! object the data plane uses for each TCP socket.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const Rc4 = @import("../../mayaqua/encrypt/rc4.zig").Rc4;
const Pack = @import("../protocol/pack.zig").Pack;
const Protocol = @import("../protocol/softether_protocol.zig").Protocol;
const session_mod = @import("../session/session.zig");
const ClientSession = session_mod.Session;
const Aes256Cbc = session_mod.Aes256Cbc;
const SessionKeys = session_mod.SessionKeys;

/// How the data channel is protected for a session.
pub const EncryptionMode = enum {
    /// No application-layer encryption; data rides the (TLS) transport.
    none,
    /// Classic AES-256-CBC, per-packet random IV (client's default path).
    aes_cbc,
    /// Legacy fast RC4, stateful stream cipher.
    fast_rc4,
};

/// RC4 key pair delivered in the Welcome pack (C: `RC4_KEY_PAIR`,
/// `GenerateRC4KeyPair` Protocol.c:8485). Generated fresh per session when
/// the client negotiated fast RC4.
pub const Rc4KeyPair = struct {
    pub const key_size: usize = 16;

    /// Key for client→server traffic (the server decrypts with it).
    client_to_server: [key_size]u8,

    /// Key for server→client traffic (the client decrypts with it).
    server_to_client: [key_size]u8,

    pub fn generate() Rc4KeyPair {
        var pair: Rc4KeyPair = undefined;
        std.crypto.random.bytes(&pair.client_to_server);
        std.crypto.random.bytes(&pair.server_to_client);
        return pair;
    }
};

/// Session creation options (server side). Policy the server applies to a
/// session; encryption (`use_encrypt`/`use_fast_rc4`) is *not* an option —
/// it is negotiated from the client's request via `ServerSession.negotiate`.
pub const SessionOptions = struct {
    use_compress: bool = false,
    half_connection: bool = false,
    max_connection: u32 = 1,
    timeout: u32 = 0,
    qos: bool = true,
    vlan_id: u32 = 0,
};

/// Server-perspective session key material and encryption.
///
/// Creation mirrors `NewServerSessionEx` (Session.c:2219) + `NewSessionKey`
/// (Session.c:2195): a fresh random session key that the Welcome pack carries
/// to the client. `hello_random` must be the server's own HELLO random
/// (generated when the client's HELLO was answered) — it feeds the classic
/// AES key derivation on both peers. Encryption is negotiated from the
/// client's auth request (`use_encrypt` / `use_fast_rc4`, C
/// Protocol.c:3958-3962).
pub const ServerSession = struct {
    allocator: Allocator,

    /// Random session key (C: `SessionKey`, 20 bytes SHA-1 size).
    session_key: [Protocol.sha1_size]u8,

    /// Random u32 session key, sent as `session_key_32` in the Welcome pack.
    session_key_32: u32,

    /// The server's own HELLO random (C: `s->FirstSock->HelloRandom`).
    hello_random: [Protocol.sha1_size]u8,

    /// Encryption negotiated with the client (C: `UseEncrypt`).
    use_encrypt: bool = false,

    /// Fast RC4 data-channel encryption (C: `UseFastRC4`).
    use_fast_rc4: bool = false,

    /// Block compression (C: `UseCompress`).
    use_compress: bool = false,

    /// Half-connection mode (C: `HalfConnection`).
    half_connection: bool = false,

    /// Max TCP connections per session (C: `MaxConnection`).
    max_connection: u32 = 1,

    /// Session timeout in ms, 0 = infinite (C: `Timeout`).
    timeout: u32 = 0,

    /// QoS on/off (C: `QoS`).
    qos: bool = true,

    /// VLAN ID (C: `VLanId`).
    vlan_id: u32 = 0,

    /// RC4 key pair; present only when fast RC4 was negotiated.
    rc4_key_pair: ?Rc4KeyPair = null,

    /// Classic AES keys, derived at negotiation from session_key + hello_random
    /// (client's `SessionKeys.deriveFromAuth`). Server sends with the
    /// server→client key and receives with the client→server key.
    aes_send_key: ?[32]u8 = null,
    aes_recv_key: ?[32]u8 = null,

    /// Create a session with default options and a fresh random hello random
    /// (for standalone use; the server data path passes its real HELLO value).
    pub fn init(allocator: Allocator) ServerSession {
        var hello_random: [Protocol.sha1_size]u8 = undefined;
        std.crypto.random.bytes(&hello_random);
        return ServerSession.initWithOptions(allocator, &hello_random, .{});
    }

    /// Create a session with server policy options.
    ///
    /// `hello_random` is the server's own HELLO random — the same bytes sent
    /// to the client during the HELLO exchange.
    pub fn initWithOptions(
        allocator: Allocator,
        hello_random: *const [Protocol.sha1_size]u8,
        options: SessionOptions,
    ) ServerSession {
        var self = ServerSession{
            .allocator = allocator,
            .hello_random = hello_random.*,
            .session_key = undefined,
            .session_key_32 = 0,
            .use_compress = options.use_compress,
            .half_connection = options.half_connection,
            .max_connection = options.max_connection,
            .timeout = options.timeout,
            .qos = options.qos,
            .vlan_id = options.vlan_id,
        };
        std.crypto.random.bytes(&self.session_key);

        var key32_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&key32_bytes);
        self.session_key_32 = mem.readInt(u32, &key32_bytes, .little);

        return self;
    }

    /// Apply the client's encryption request (C: Protocol.c:3958-3962): fast
    /// RC4 is only honored when encryption is on. Fast RC4 generates the key
    /// pair; otherwise an encrypted session uses classic AES-256-CBC (the Zig
    /// client's behavior when no RC4 keys are negotiated).
    pub fn negotiate(self: *ServerSession, client_use_encrypt: bool, client_use_fast_rc4: bool) void {
        self.use_encrypt = client_use_encrypt;
        self.use_fast_rc4 = client_use_encrypt and client_use_fast_rc4;

        if (self.use_fast_rc4) {
            self.rc4_key_pair = Rc4KeyPair.generate();
            self.aes_send_key = null;
            self.aes_recv_key = null;
            return;
        }

        self.rc4_key_pair = null;
        if (self.use_encrypt) {
            var c2s: [32]u8 = undefined;
            var s2c: [32]u8 = undefined;
            deriveAesKey(&self.session_key, &self.hello_random, 0x01, &c2s);
            deriveAesKey(&self.session_key, &self.hello_random, 0x02, &s2c);
            self.aes_recv_key = c2s;
            self.aes_send_key = s2c;
        } else {
            self.aes_send_key = null;
            self.aes_recv_key = null;
        }
    }

    /// How the data channel is protected after negotiation.
    pub fn mode(self: *const ServerSession) EncryptionMode {
        if (self.use_fast_rc4) return .fast_rc4;
        if (self.use_encrypt) return .aes_cbc;
        return .none;
    }

    /// Create a per-TCP-socket cipher object from this session's key material
    /// (C: `InitTcpSockRc4Key(ts, true)` for each socket, Connection.c:2881).
    /// Each connection gets its own stream state; do not share a cipher
    /// across connections.
    pub fn newConnectionCipher(self: *const ServerSession) ConnectionCipher {
        return switch (self.mode()) {
            .none => .{ .mode = .none },
            .fast_rc4 => .{
                .mode = .fast_rc4,
                .send_rc4 = Rc4.init(&self.rc4_key_pair.?.server_to_client),
                .recv_rc4 = Rc4.init(&self.rc4_key_pair.?.client_to_server),
            },
            .aes_cbc => .{
                .mode = .aes_cbc,
                .aes_send_key = self.aes_send_key.?,
                .aes_recv_key = self.aes_recv_key.?,
            },
        };
    }

    /// Populate the Welcome pack fields that carry the session key and the
    /// negotiated encryption parameters (C: `PackWelcome` Protocol.c:6442-6500,
    /// plus the RC4 keys added at Protocol.c:4121-4138). Other welcome fields
    /// (policy, UDP keys, node info, messages) are added by the caller.
    pub fn addWelcomeFields(
        self: *const ServerSession,
        pack: *Pack,
        session_name: []const u8,
        connection_name: []const u8,
    ) !void {
        try pack.addStr("session_name", session_name);
        try pack.addStr("connection_name", connection_name);

        try pack.addInt("max_connection", self.max_connection);
        try pack.addInt("use_encrypt", @intFromBool(self.use_encrypt));
        try pack.addInt("use_fast_rc4", @intFromBool(self.use_fast_rc4));
        try pack.addInt("use_compress", @intFromBool(self.use_compress));
        try pack.addInt("half_connection", @intFromBool(self.half_connection));
        try pack.addInt("timeout", self.timeout);
        try pack.addInt("qos", @intFromBool(self.qos));
        try pack.addInt("vlan_id", self.vlan_id);

        try pack.addData("session_key", &self.session_key);
        try pack.addInt("session_key_32", self.session_key_32);

        if (self.rc4_key_pair) |pair| {
            try pack.addData("rc4_key_client_to_server", &pair.client_to_server);
            try pack.addData("rc4_key_server_to_client", &pair.server_to_client);
        }
    }
};

/// Per-connection data-channel encryption state. One instance per TCP socket,
/// created from the session's key material via `ServerSession.newConnectionCipher`.
pub const ConnectionCipher = struct {
    mode: EncryptionMode,

    /// Fast RC4 stream ciphers — stateful, advance with every packet.
    send_rc4: ?Rc4 = null,
    recv_rc4: ?Rc4 = null,

    /// Classic AES keys (session-level, copied here for convenience).
    aes_send_key: ?[32]u8 = null,
    aes_recv_key: ?[32]u8 = null,

    /// Encrypt an outbound data-channel packet (server → client). Fast RC4
    /// advances the per-connection keystream; classic AES prepends a fresh
    /// random IV per packet; otherwise a passthrough copy.
    pub fn encryptSend(self: *ConnectionCipher, allocator: Allocator, plaintext: []const u8) ![]u8 {
        switch (self.mode) {
            .none => return allocator.dupe(u8, plaintext),
            .fast_rc4 => {
                const result = try allocator.dupe(u8, plaintext);
                self.send_rc4.?.apply(result);
                return result;
            },
            .aes_cbc => {
                var iv: [16]u8 = undefined;
                std.crypto.random.bytes(&iv);
                var cipher = Aes256Cbc.init(&self.aes_send_key.?, &iv);
                const ciphertext = try cipher.encrypt(allocator, plaintext);
                defer allocator.free(ciphertext);
                const result = try allocator.alloc(u8, iv.len + ciphertext.len);
                errdefer allocator.free(result);
                @memcpy(result[0..iv.len], &iv);
                @memcpy(result[iv.len..], ciphertext);
                return result;
            },
        }
    }

    /// Decrypt an inbound data-channel packet (client → server). RC4 is
    /// symmetric and stateful; AES reads the per-packet IV.
    pub fn decryptRecv(self: *ConnectionCipher, allocator: Allocator, ciphertext: []const u8) ![]u8 {
        switch (self.mode) {
            .none => return allocator.dupe(u8, ciphertext),
            .fast_rc4 => {
                const result = try allocator.dupe(u8, ciphertext);
                self.recv_rc4.?.apply(result);
                return result;
            },
            .aes_cbc => {
                if (ciphertext.len < 16) return error.InvalidCiphertext;
                var iv: [16]u8 = ciphertext[0..16].*;
                var cipher = Aes256Cbc.init(&self.aes_recv_key.?, &iv);
                return cipher.decrypt(allocator, ciphertext[16..]);
            },
        }
    }
};

/// Classic AES key derivation — identical to the client's
/// `SessionKeys.deriveFromAuth`: SHA-256(session_key ‖ hello_random ‖ dir).
fn deriveAesKey(
    session_key: *const [20]u8,
    hello_random: *const [20]u8,
    direction: u8,
    out: *[32]u8,
) void {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(session_key);
    sha.update(hello_random);
    sha.update(&[_]u8{direction});
    sha.final(out);
}

// ============================================================================
// Tests
// ============================================================================

test "server.session key pair generation" {
    const a = Rc4KeyPair.generate();
    const b = Rc4KeyPair.generate();

    try testing.expect(!std.mem.eql(u8, &a.client_to_server, &b.client_to_server));
    try testing.expect(!std.mem.eql(u8, &a.server_to_client, &b.server_to_client));
    try testing.expect(!std.mem.eql(u8, &a.client_to_server, &a.server_to_client));
}

test "server.session session key generation" {
    var a = ServerSession.init(testing.allocator);
    var b = ServerSession.init(testing.allocator);

    try testing.expect(!std.mem.eql(u8, &a.session_key, &b.session_key));
    try testing.expect(a.session_key_32 != 0 or b.session_key_32 != 0);
}

test "server.session options are applied" {
    const opts = SessionOptions{
        .use_compress = true,
        .half_connection = true,
        .max_connection = 4,
        .timeout = 300000,
        .qos = false,
        .vlan_id = 3,
    };
    var hello: [20]u8 = undefined;
    std.crypto.random.bytes(&hello);

    var s = ServerSession.initWithOptions(testing.allocator, &hello, opts);
    try testing.expect(s.use_compress);
    try testing.expect(s.half_connection);
    try testing.expectEqual(@as(u32, 4), s.max_connection);
    try testing.expectEqual(@as(u32, 300000), s.timeout);
    try testing.expect(!s.qos);
    try testing.expectEqual(@as(u32, 3), s.vlan_id);
    try testing.expectEqualSlices(u8, &hello, &s.hello_random);
}

test "server.session encryption negotiation" {
    var s = ServerSession.init(testing.allocator);

    // Encrypt on, fast RC4 off → classic AES-256-CBC (the Zig client's path
    // when no RC4 keys are negotiated; C 4.44 would use the TLS layer).
    s.negotiate(true, false);
    try testing.expect(s.use_encrypt);
    try testing.expect(!s.use_fast_rc4);
    try testing.expectEqual(EncryptionMode.aes_cbc, s.mode());
    try testing.expect(s.rc4_key_pair == null);
    try testing.expect(s.aes_send_key != null);
    try testing.expect(s.aes_recv_key != null);

    // Encrypt on, fast RC4 on → RC4 key pair; cipher state is per connection.
    s.negotiate(true, true);
    try testing.expect(s.use_encrypt);
    try testing.expect(s.use_fast_rc4);
    try testing.expectEqual(EncryptionMode.fast_rc4, s.mode());
    try testing.expect(s.rc4_key_pair != null);

    // Encrypt off → fast RC4 is never honored, no encryption at all.
    s.negotiate(false, true);
    try testing.expect(!s.use_encrypt);
    try testing.expect(!s.use_fast_rc4);
    try testing.expectEqual(EncryptionMode.none, s.mode());
    try testing.expect(s.rc4_key_pair == null);
    try testing.expect(s.aes_send_key == null);
    try testing.expect(s.aes_recv_key == null);
}

test "server.session aes keys match client derivation" {
    var s = ServerSession.init(testing.allocator);
    s.negotiate(true, false);

    const keys = SessionKeys.deriveFromAuth(&s.session_key, &s.hello_random);
    try testing.expectEqualSlices(u8, &keys.send_key, &s.aes_recv_key.?);
    try testing.expectEqualSlices(u8, &keys.recv_key, &s.aes_send_key.?);
}

test "server.session aes cbc wire round-trip" {
    var server = ServerSession.init(testing.allocator);
    server.negotiate(true, false);

    // Simulate the real client: with no fast-RC4 keys negotiated it derives
    // AES-256-CBC keys from the Welcome session_key + the server's HELLO
    // random (session_setup.zig → initEncryption → deriveFromAuth).
    var client = ClientSession.init(testing.allocator, .{
        .host = "zig-server.example",
        .hub = "VPN",
        .username = "user",
        .use_encrypt = true,
        .use_fast_rc4 = false,
    });
    defer client.deinit();
    client.initEncryption(&server.session_key, &server.hello_random);

    var cipher = server.newConnectionCipher();

    // Client→server: client encrypts with its send key, server decrypts with
    // its recv key (the same derived c2s key).
    const c2s_plain = "client to server AES payload";
    const c2s_enc = try client.encryptPacket(c2s_plain);
    defer testing.allocator.free(c2s_enc);
    const c2s_dec = try cipher.decryptRecv(testing.allocator, c2s_enc);
    defer testing.allocator.free(c2s_dec);
    try testing.expectEqualStrings(c2s_plain, c2s_dec);

    // Server→client: server encrypts with its send key (s2c), client decrypts
    // with its recv key.
    const s2c_plain = "server to client AES reply";
    const s2c_enc = try cipher.encryptSend(testing.allocator, s2c_plain);
    defer testing.allocator.free(s2c_enc);
    const s2c_dec = try client.decryptPacket(s2c_enc);
    defer testing.allocator.free(s2c_dec);
    try testing.expectEqualStrings(s2c_plain, s2c_dec);

    // Every AES packet carries its own random IV.
    const enc2 = try cipher.encryptSend(testing.allocator, s2c_plain);
    defer testing.allocator.free(enc2);
    try testing.expect(!std.mem.eql(u8, s2c_enc, enc2));
}

test "server.session fast rc4 wire round-trip" {
    var server = ServerSession.init(testing.allocator);
    server.negotiate(true, true);
    const pair = server.rc4_key_pair.?;

    // Simulate the real client session (cedar/session/session.zig) configured
    // from the Welcome pack, exactly as session_setup.zig does.
    var client = ClientSession.init(testing.allocator, .{
        .host = "zig-server.example",
        .hub = "VPN",
        .username = "user",
        .use_encrypt = true,
        .use_fast_rc4 = true,
    });
    defer client.deinit();
    client.initFastRc4(&pair.client_to_server, &pair.server_to_client);

    var cipher = server.newConnectionCipher();

    // Client→server: encrypted with the client→server key, decrypted with the
    // server's recv key (same key — RC4 is symmetric).
    const c2s_plain = "client to server payload";
    const c2s_enc = try client.encryptPacket(c2s_plain);
    defer testing.allocator.free(c2s_enc);
    const c2s_dec = try cipher.decryptRecv(testing.allocator, c2s_enc);
    defer testing.allocator.free(c2s_dec);
    try testing.expectEqualStrings(c2s_plain, c2s_dec);

    // Server→client: encrypted with the server's send key (server→client
    // key), decrypted with the client's recv key.
    const s2c_plain = "server to client reply";
    const s2c_enc = try cipher.encryptSend(testing.allocator, s2c_plain);
    defer testing.allocator.free(s2c_enc);
    const s2c_dec = try client.decryptPacket(s2c_enc);
    defer testing.allocator.free(s2c_dec);
    try testing.expectEqualStrings(s2c_plain, s2c_dec);

    // The RC4 keystream is continuous across packets: a second message in the
    // same direction must still round-trip after the state advanced.
    const second = "second packet after state advanced";
    const second_enc = try client.encryptPacket(second);
    defer testing.allocator.free(second_enc);
    const second_dec = try cipher.decryptRecv(testing.allocator, second_enc);
    defer testing.allocator.free(second_dec);
    try testing.expectEqualStrings(second, second_dec);
}

test "server.session connection ciphers are independent" {
    var server = ServerSession.init(testing.allocator);
    server.negotiate(true, true);

    // Each TCP socket gets its own cipher state (C: InitTcpSockRc4Key per
    // socket) — sharing one stream across connections would corrupt packets.
    var c1 = server.newConnectionCipher();
    var c2 = server.newConnectionCipher();

    const payload = "same plaintext on both connections";

    // Fresh ciphers from the same session start at the same keystream
    // position — a shared stream would already differ here.
    const e1a = try c1.encryptSend(testing.allocator, payload);
    defer testing.allocator.free(e1a);
    const e2a = try c2.encryptSend(testing.allocator, payload);
    defer testing.allocator.free(e2a);
    try testing.expectEqualSlices(u8, e1a, e2a);

    // After c1 advances past another packet, its stream diverges from c2's,
    // proving each connection carries its own keystream position.
    const extra = "a second packet only on connection one, to advance its stream";
    const e1b = try c1.encryptSend(testing.allocator, extra);
    defer testing.allocator.free(e1b);

    const e2b = try c2.encryptSend(testing.allocator, payload);
    defer testing.allocator.free(e2b);
    try testing.expect(!std.mem.eql(u8, e1b, e2b));

    // The same payload again on c1 (stream advanced further) also differs
    // from what c2 produced for it at its own position.
    const e1c = try c1.encryptSend(testing.allocator, payload);
    defer testing.allocator.free(e1c);
    try testing.expect(!std.mem.eql(u8, e1c, e2b));
}

test "server.session welcome fields" {
    var s = ServerSession.init(testing.allocator);
    s.negotiate(true, true);
    s.max_connection = 2;
    s.half_connection = true;
    s.use_compress = true;
    s.qos = true;
    s.timeout = 1800000;
    s.vlan_id = 0;

    var pack = Pack.init(testing.allocator);
    defer pack.deinit();
    try s.addWelcomeFields(&pack, "SES_TEST", "CONN_TEST");

    try testing.expectEqualStrings("SES_TEST", pack.getStr("session_name").?);
    try testing.expectEqualStrings("CONN_TEST", pack.getStr("connection_name").?);
    try testing.expectEqual(@as(u32, 2), pack.getInt("max_connection").?);
    try testing.expectEqual(@as(u32, 1), pack.getInt("use_encrypt").?);
    try testing.expectEqual(@as(u32, 1), pack.getInt("use_fast_rc4").?);
    try testing.expectEqual(@as(u32, 1), pack.getInt("use_compress").?);
    try testing.expectEqual(@as(u32, 1), pack.getInt("half_connection").?);
    try testing.expectEqual(s.timeout, pack.getInt("timeout").?);
    try testing.expectEqual(@as(u32, 1), pack.getInt("qos").?);
    try testing.expectEqual(@as(u32, 0), pack.getInt("vlan_id").?);

    const sk = pack.getData("session_key").?;
    try testing.expectEqualSlices(u8, &s.session_key, sk);
    try testing.expectEqual(s.session_key_32, pack.getInt("session_key_32").?);

    const pair = s.rc4_key_pair.?;
    try testing.expectEqualSlices(u8, &pair.client_to_server, pack.getData("rc4_key_client_to_server").?);
    try testing.expectEqualSlices(u8, &pair.server_to_client, pack.getData("rc4_key_server_to_client").?);
}

test "server.session welcome fields without rc4" {
    var s = ServerSession.init(testing.allocator);
    s.negotiate(true, false);

    var pack = Pack.init(testing.allocator);
    defer pack.deinit();
    try s.addWelcomeFields(&pack, "SES_TLS", "CONN_TLS");

    try testing.expectEqual(@as(u32, 1), pack.getInt("use_encrypt").?);
    try testing.expectEqual(@as(u32, 0), pack.getInt("use_fast_rc4").?);
    try testing.expect(pack.getData("rc4_key_client_to_server") == null);
    try testing.expect(pack.getData("rc4_key_server_to_client") == null);
    try testing.expect(pack.getData("session_key") != null);
}

test "server.session passthrough without encryption" {
    var server = ServerSession.init(testing.allocator);
    server.negotiate(false, false);

    var cipher = server.newConnectionCipher();

    const data = "plaintext data channel";
    const enc = try cipher.encryptSend(testing.allocator, data);
    defer testing.allocator.free(enc);
    const dec = try cipher.decryptRecv(testing.allocator, enc);
    defer testing.allocator.free(dec);

    try testing.expectEqualStrings(data, enc);
    try testing.expectEqualStrings(data, dec);
}
