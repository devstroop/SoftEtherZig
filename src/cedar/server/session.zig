//! Server-side session keys + data-channel encryption.
//!
//! C reference (4.44):
//! - `NewSessionKey` (Session.c:2195) — random 20-byte session key + u32
//! - `GenerateRC4KeyPair` (Protocol.c:8485) — random RC4 key pair
//! - encryption negotiation (Protocol.c:3958-3962, 4188-4195)
//! - `InitTcpSockRc4Key` (Connection.c:2881-2906) — the direction swap
//! - `PackWelcome` (Protocol.c:6442-6500) — the welcome fields
//!
//! Both peers hold the same two RC4 keys. The direction swap picks which key
//! each side uses for send vs recv:
//!
//!   client: send = client_to_server,  recv = server_to_client
//!   server: send = server_to_client,  recv = client_to_server
//!
//! RC4 is symmetric, so both peers advance the same keystream per direction.
//!
//! Modern encrypted sessions (no fast RC4) leave the data channel to the TLS
//! layer (`use_ssl_data_encryption`); no app-level cipher runs on the wire.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const Rc4 = @import("../../mayaqua/encrypt/rc4.zig").Rc4;
const Pack = @import("../protocol/pack.zig").Pack;
const Protocol = @import("../protocol/softether_protocol.zig").Protocol;
const ClientSession = @import("../session/session.zig").Session;

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

/// Server-perspective session key material and encryption.
///
/// Creation mirrors `NewServerSessionEx` (Session.c:2219) + `NewSessionKey`
/// (Session.c:2195): a fresh random session key that the Welcome pack carries
/// to the client. Encryption is negotiated from the client's auth pack request
/// (`use_encrypt` / `use_fast_rc4`, C Protocol.c:3958-3962); fast RC4 adds the
/// key pair + direction-swapped ciphers exactly as `InitTcpSockRc4Key(ts, true)`
/// does for the first TCP socket (Connection.c:2881-2906).
pub const ServerSession = struct {
    allocator: Allocator,

    /// Random session key (C: `SessionKey`, 20 bytes SHA-1 size).
    session_key: [Protocol.sha1_size]u8,

    /// Random u32 session key, sent as `session_key_32` in the Welcome pack.
    session_key_32: u32,

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
    qos: bool = false,

    /// VLAN ID (C: `VLanId`).
    vlan_id: u32 = 0,

    /// RC4 key pair; present only when fast RC4 was negotiated.
    rc4_key_pair: ?Rc4KeyPair = null,

    /// Direction-swapped RC4 ciphers (C: `InitTcpSockRc4Key(ts, true)`):
    /// server sends with `server_to_client`, receives with `client_to_server`.
    send_rc4: ?Rc4 = null,
    recv_rc4: ?Rc4 = null,

    /// TLS layer carries the data channel (C: `UseSSLDataEncryption`,
    /// Protocol.c:4188-4195) — set when encryption is on but RC4 is not.
    use_ssl_data_encryption: bool = false,

    pub fn init(allocator: Allocator) ServerSession {
        var self = ServerSession{
            .allocator = allocator,
            .session_key = undefined,
            .session_key_32 = 0,
        };
        std.crypto.random.bytes(&self.session_key);

        var key32_bytes: [4]u8 = undefined;
        std.crypto.random.bytes(&key32_bytes);
        self.session_key_32 = mem.readInt(u32, &key32_bytes, .little);

        return self;
    }

    /// Apply the client's encryption request (C: Protocol.c:3958-3962): fast
    /// RC4 is only honored when encryption is on. When fast RC4 is active the
    /// key pair is generated and the direction-swapped ciphers are initialized;
    /// otherwise encrypted sessions run over the TLS layer.
    pub fn negotiate(self: *ServerSession, client_use_encrypt: bool, client_use_fast_rc4: bool) void {
        self.use_encrypt = client_use_encrypt;
        self.use_fast_rc4 = client_use_encrypt and client_use_fast_rc4;

        if (self.use_fast_rc4) {
            const pair = Rc4KeyPair.generate();
            self.rc4_key_pair = pair;
            self.send_rc4 = Rc4.init(&pair.server_to_client);
            self.recv_rc4 = Rc4.init(&pair.client_to_server);
            self.use_ssl_data_encryption = false;
        } else {
            self.rc4_key_pair = null;
            self.send_rc4 = null;
            self.recv_rc4 = null;
            self.use_ssl_data_encryption = self.use_encrypt;
        }
    }

    /// Encrypt an outbound data-channel packet (server → client). The RC4
    /// keystream is stateful across packets (C `Encrypt` on the socket key);
    /// when not in fast-RC4 mode the TLS layer handles encryption, so this is
    /// a passthrough copy.
    pub fn encryptSend(self: *ServerSession, allocator: Allocator, plaintext: []const u8) ![]u8 {
        if (!self.use_fast_rc4) {
            return allocator.dupe(u8, plaintext);
        }
        const result = try allocator.dupe(u8, plaintext);
        self.send_rc4.?.apply(result);
        return result;
    }

    /// Decrypt an inbound data-channel packet (client → server). RC4 is
    /// symmetric; the keystream continues across packets.
    pub fn decryptRecv(self: *ServerSession, allocator: Allocator, ciphertext: []const u8) ![]u8 {
        if (!self.use_fast_rc4) {
            return allocator.dupe(u8, ciphertext);
        }
        const result = try allocator.dupe(u8, ciphertext);
        self.recv_rc4.?.apply(result);
        return result;
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

/// Session creation options (server side).
pub const SessionOptions = struct {
    use_encrypt: bool = true,
    use_fast_rc4: bool = false,
    use_compress: bool = false,
    half_connection: bool = false,
    max_connection: u32 = 1,
    timeout: u32 = 0,
    qos: bool = true,
    vlan_id: u32 = 0,
};

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

test "server.session encryption negotiation" {
    var s = ServerSession.init(testing.allocator);

    // Encrypt on, fast RC4 off → TLS layer carries the data channel.
    s.negotiate(true, false);
    try testing.expect(s.use_encrypt);
    try testing.expect(!s.use_fast_rc4);
    try testing.expect(s.use_ssl_data_encryption);
    try testing.expect(s.rc4_key_pair == null);

    // Encrypt on, fast RC4 on → RC4 key pair + direction-swapped ciphers.
    s.negotiate(true, true);
    try testing.expect(s.use_encrypt);
    try testing.expect(s.use_fast_rc4);
    try testing.expect(!s.use_ssl_data_encryption);
    try testing.expect(s.rc4_key_pair != null);
    try testing.expect(s.send_rc4 != null);
    try testing.expect(s.recv_rc4 != null);

    // Encrypt off → fast RC4 is never honored, no encryption at all.
    s.negotiate(false, true);
    try testing.expect(!s.use_encrypt);
    try testing.expect(!s.use_fast_rc4);
    try testing.expect(!s.use_ssl_data_encryption);
    try testing.expect(s.rc4_key_pair == null);
}

test "server.session fast rc4 wire round-trip" {
    // Server negotiates fast RC4 with a client that requests it.
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

    // Client→server: encrypted with the client→server key, decrypted with the
    // server's recv key (same key — RC4 is symmetric).
    const c2s_plain = "client to server payload";
    const c2s_enc = try client.encryptPacket(c2s_plain);
    defer testing.allocator.free(c2s_enc);
    const c2s_dec = try server.decryptRecv(testing.allocator, c2s_enc);
    defer testing.allocator.free(c2s_dec);
    try testing.expectEqualStrings(c2s_plain, c2s_dec);

    // Server→client: encrypted with the server's send key (server→client
    // key), decrypted with the client's recv key.
    const s2c_plain = "server to client reply";
    const s2c_enc = try server.encryptSend(testing.allocator, s2c_plain);
    defer testing.allocator.free(s2c_enc);
    const s2c_dec = try client.decryptPacket(s2c_enc);
    defer testing.allocator.free(s2c_dec);
    try testing.expectEqualStrings(s2c_plain, s2c_dec);

    // The RC4 keystream is continuous across packets: a second message in the
    // same direction must still round-trip after the state advanced.
    const second = "second packet after state advanced";
    const second_enc = try client.encryptPacket(second);
    defer testing.allocator.free(second_enc);
    const second_dec = try server.decryptRecv(testing.allocator, second_enc);
    defer testing.allocator.free(second_dec);
    try testing.expectEqualStrings(second, second_dec);
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
    var s = ServerSession.init(testing.allocator);
    s.negotiate(false, false);

    const data = "plaintext data channel";
    const enc = try s.encryptSend(testing.allocator, data);
    defer testing.allocator.free(enc);
    const dec = try s.decryptRecv(testing.allocator, enc);
    defer testing.allocator.free(dec);

    try testing.expectEqualStrings(data, enc);
    try testing.expectEqualStrings(data, dec);
}
