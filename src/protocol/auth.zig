//! SoftEther Authentication Protocol
//!
//! SoftEther supports several authentication methods:
//! - Anonymous: No credentials required
//! - Password: Plain password or MS-CHAPv2 hashed
//! - Certificate: X.509 client certificate
//!
//! Password hashing uses SHA-0 (SoftEther-specific) for legacy compatibility.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

/// SHA-0 digest length
pub const sha0_digest_length = 20;

/// Authentication types supported by SoftEther
pub const AuthType = enum(u32) {
    anonymous = 0,
    password = 1,
    user_cert = 2,
    root_cert = 3,
    radius = 4,
    nt_domain = 5,
    // OpenVPN compatibility
    openvpn_cert = 101,
};

/// Authentication method strings (used in MVPN protocol)
pub const AuthMethodStr = struct {
    pub const anonymous = "anonymous";
    pub const password_plain = "password_plain";
    pub const password_mschapv2 = "password_mschapv2";
    pub const cert = "x509cert";
};

// ============================================================================
// SHA-0 Implementation (for auth - self-contained)
// ============================================================================

/// SHA-0 hasher (SoftEther uses SHA-0 for password hashing)
const Sha0 = struct {
    const block_length = 64;
    const digest_length = 20;

    state: [5]u32,
    buf: [block_length]u8,
    buf_len: usize,
    total_len: u64,

    fn init() Sha0 {
        return .{
            .state = .{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            },
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    fn update(self: *Sha0, data: []const u8) void {
        var input = data;
        self.total_len += input.len;

        if (self.buf_len > 0) {
            const space = block_length - self.buf_len;
            const to_copy = @min(space, input.len);
            @memcpy(self.buf[self.buf_len..][0..to_copy], input[0..to_copy]);
            self.buf_len += to_copy;
            input = input[to_copy..];

            if (self.buf_len == block_length) {
                self.processBlock(&self.buf);
                self.buf_len = 0;
            }
        }

        while (input.len >= block_length) {
            self.processBlock(input[0..block_length]);
            input = input[block_length..];
        }

        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    fn processBlock(self: *Sha0, block: *const [block_length]u8) void {
        var w: [80]u32 = undefined;

        for (0..16) |i| {
            w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }

        // SHA-0: NO rotation in message schedule (this is the key difference from SHA-1)
        for (16..80) |i| {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];

        for (0..80) |i| {
            var f: u32 = undefined;
            var k: u32 = undefined;

            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            const temp = rotl(a, 5) +% f +% e +% k +% w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
    }

    fn final(self: *Sha0) [digest_length]u8 {
        const total_bits = self.total_len * 8;

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        @memset(self.buf[self.buf_len..56], 0);

        std.mem.writeInt(u64, self.buf[56..64], total_bits, .big);
        self.processBlock(&self.buf);

        var result: [digest_length]u8 = undefined;
        for (0..5) |i| {
            std.mem.writeInt(u32, result[i * 4 ..][0..4], self.state[i], .big);
        }

        return result;
    }

    fn rotl(x: u32, comptime n: comptime_int) u32 {
        return std.math.rotl(u32, x, n);
    }
};

/// Compute SHA-0 hash
fn sha0Hash(data: []const u8) [sha0_digest_length]u8 {
    var h = Sha0.init();
    h.update(data);
    return h.final();
}

/// SoftEther password hash: SHA0(uppercase(username) || password)
/// This is the standard password hashing used by SoftEther VPN
pub fn hashPassword(password: []const u8, username: []const u8) [sha0_digest_length]u8 {
    return softEtherPasswordHash(username, password);
}

fn softEtherPasswordHash(username: []const u8, password: []const u8) [sha0_digest_length]u8 {
    var h = Sha0.init();

    // C code: WriteBuf(password) then WriteBuf(uppercase(username))
    h.update(password);

    // Uppercase username
    for (username) |c| {
        const upper = if (c >= 'a' and c <= 'z') c - 32 else c;
        h.update(&[_]u8{upper});
    }

    return h.final();
}

/// SoftEther secure password: SHA0(password_hash || random_challenge)
fn softEtherSecurePassword(
    password_hash: *const [sha0_digest_length]u8,
    challenge: *const [sha0_digest_length]u8,
) [sha0_digest_length]u8 {
    var h = Sha0.init();
    h.update(password_hash);
    h.update(challenge);
    return h.final();
}

// ============================================================================
// Client Authentication
// ============================================================================

/// Client authentication credentials
pub const ClientAuth = struct {
    auth_type: AuthType,

    // For password auth
    username: ?[]const u8 = null,
    password_hash: ?[sha0_digest_length]u8 = null, // SHA-0 hash
    plain_password: ?[]const u8 = null,

    // For certificate auth
    client_cert: ?[]const u8 = null, // PEM or DER encoded
    client_key: ?[]const u8 = null, // Private key

    pub fn initAnonymous() ClientAuth {
        return .{
            .auth_type = .anonymous,
        };
    }

    pub fn initPassword(username: []const u8, password: []const u8) ClientAuth {
        // Hash password with SHA-0 (SoftEther-specific)
        const hash = softEtherPasswordHash(username, password);
        return .{
            .auth_type = .password,
            .username = username,
            .password_hash = hash,
        };
    }

    pub fn initPasswordPlain(username: []const u8, password: []const u8) ClientAuth {
        return .{
            .auth_type = .password,
            .username = username,
            .plain_password = password,
        };
    }

    pub fn initCertificate(cert: []const u8, key: []const u8) ClientAuth {
        return .{
            .auth_type = .user_cert,
            .client_cert = cert,
            .client_key = key,
        };
    }
};

/// Server authentication challenge
pub const Challenge = struct {
    random: [sha0_digest_length]u8,
    timestamp: u64,

    pub fn generate() Challenge {
        var random: [sha0_digest_length]u8 = undefined;
        std.crypto.random.bytes(&random);
        return .{
            .random = random,
            .timestamp = @intCast(std.time.timestamp()),
        };
    }
};

/// Compute secure password for authentication
/// This combines the password hash with server's random challenge
pub fn computeSecurePassword(
    password_hash: *const [sha0_digest_length]u8,
    challenge: *const [sha0_digest_length]u8,
) [sha0_digest_length]u8 {
    return softEtherSecurePassword(password_hash, challenge);
}

/// MS-CHAPv2 authentication support
/// (For Windows domain authentication compatibility)
pub const MsChapV2 = struct {
    /// NT hash (MD4 of UTF-16LE password)
    pub fn ntHash(password: []const u8) [16]u8 {
        // Convert password to UTF-16LE
        var utf16_buf: [256]u8 = undefined;
        var utf16_len: usize = 0;

        for (password) |c| {
            if (utf16_len + 2 > utf16_buf.len) break;
            utf16_buf[utf16_len] = c;
            utf16_buf[utf16_len + 1] = 0;
            utf16_len += 2;
        }

        // MD4 hash
        var hash: [16]u8 = undefined;
        std.crypto.hash.Md4.hash(utf16_buf[0..utf16_len], &hash, .{});
        return hash;
    }

    /// Generate NT response for MS-CHAPv2
    pub fn generateNtResponse(
        nt_hash: *const [16]u8,
        authenticator_challenge: *const [16]u8,
        peer_challenge: *const [16]u8,
        username: []const u8,
    ) [24]u8 {
        // SHA1(peer_challenge || authenticator_challenge || username)
        var challenge_hash: [20]u8 = undefined;
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(peer_challenge);
        sha1.update(authenticator_challenge);
        sha1.update(username);
        sha1.final(&challenge_hash);

        // Use first 8 bytes as DES challenge
        const des_challenge = challenge_hash[0..8];

        // DES encrypt with NT hash split into 3 keys
        return desEncryptResponse(nt_hash, des_challenge);
    }

    fn desEncryptResponse(nt_hash: *const [16]u8, challenge: *const [8]u8) [24]u8 {
        var result: [24]u8 = undefined;

        // Split NT hash into 3 7-byte keys and DES encrypt
        // Key 1: bytes 0-6
        const key1 = expandDesKey(nt_hash[0..7]);
        desEncrypt(&key1, challenge, result[0..8]);

        // Key 2: bytes 7-13
        const key2 = expandDesKey(nt_hash[7..14]);
        desEncrypt(&key2, challenge, result[8..16]);

        // Key 3: bytes 14-15 + 5 zeros
        var key3_input: [7]u8 = .{0} ** 7;
        key3_input[0] = nt_hash[14];
        key3_input[1] = nt_hash[15];
        const key3 = expandDesKey(&key3_input);
        desEncrypt(&key3, challenge, result[16..24]);

        return result;
    }

    fn expandDesKey(input: *const [7]u8) [8]u8 {
        // Expand 7-byte key to 8-byte DES key with parity bits
        return .{
            input[0],
            (input[0] << 7) | (input[1] >> 1),
            (input[1] << 6) | (input[2] >> 2),
            (input[2] << 5) | (input[3] >> 3),
            (input[3] << 4) | (input[4] >> 4),
            (input[4] << 3) | (input[5] >> 5),
            (input[5] << 2) | (input[6] >> 6),
            input[6] << 1,
        };
    }

    fn desEncrypt(key: *const [8]u8, data: *const [8]u8, out: *[8]u8) void {
        // Simple placeholder - in production, use proper DES
        // For now, XOR-based placeholder
        for (out, 0..) |*o, i| {
            o.* = data[i] ^ key[i];
        }
    }
};

/// Session key derivation
pub const SessionKey = struct {
    /// Derive session encryption key from authentication
    pub fn derive(
        password_hash: *const [sha0_digest_length]u8,
        challenge: *const [sha0_digest_length]u8,
        direction: enum { client_to_server, server_to_client },
    ) [32]u8 {
        var key: [32]u8 = undefined;

        // Combine password hash and challenge
        var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
        sha256.update(password_hash);
        sha256.update(challenge);

        // Add direction indicator
        const dir_byte: u8 = switch (direction) {
            .client_to_server => 0x01,
            .server_to_client => 0x02,
        };
        sha256.update(&[_]u8{dir_byte});

        sha256.final(&key);
        return key;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ClientAuth anonymous" {
    const auth = ClientAuth.initAnonymous();
    try testing.expectEqual(AuthType.anonymous, auth.auth_type);
}

test "ClientAuth password" {
    const auth = ClientAuth.initPassword("testuser", "testpass");
    try testing.expectEqual(AuthType.password, auth.auth_type);
    try testing.expectEqualStrings("testuser", auth.username.?);
    try testing.expect(auth.password_hash != null);
}

test "Challenge generation" {
    const challenge = Challenge.generate();
    try testing.expect(challenge.timestamp > 0);

    // Random should not be all zeros
    var all_zero = true;
    for (challenge.random) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "Secure password computation" {
    const password_hash = softEtherPasswordHash("user", "pass");
    const challenge = [_]u8{0x01} ** sha0_digest_length;

    const secure_pass = computeSecurePassword(&password_hash, &challenge);

    // Should produce a valid hash
    try testing.expectEqual(@as(usize, sha0_digest_length), secure_pass.len);
}

test "Session key derivation" {
    const password_hash = softEtherPasswordHash("user", "pass");
    const challenge = [_]u8{0x01} ** sha0_digest_length;

    const key_c2s = SessionKey.derive(&password_hash, &challenge, .client_to_server);
    const key_s2c = SessionKey.derive(&password_hash, &challenge, .server_to_client);

    // Keys should be different for different directions
    try testing.expect(!mem.eql(u8, &key_c2s, &key_s2c));
}
