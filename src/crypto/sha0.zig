//! SHA-0 Implementation
//!
//! SoftEther VPN uses SHA-0 (not SHA-1!) for password hashing.
//! SHA-0 differs from SHA-1 only in the message schedule - no rotation.
//! This is a critical compatibility requirement.

const std = @import("std");
const testing = std.testing;

/// SHA-0 hash output size in bytes
pub const digest_length = 20;

/// SHA-0 block size in bytes
pub const block_length = 64;

/// SHA-0 hasher state
pub const Sha0 = struct {
    const Self = @This();

    /// Initial hash values (same as SHA-1)
    const iv = [5]u32{
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    };

    /// Round constants
    const k = [4]u32{
        0x5A827999, // rounds 0-19
        0x6ED9EBA1, // rounds 20-39
        0x8F1BBCDC, // rounds 40-59
        0xCA62C1D6, // rounds 60-79
    };

    state: [5]u32 = iv,
    buf: [block_length]u8 = undefined,
    buf_len: usize = 0,
    total_len: u64 = 0,

    pub fn init() Self {
        return .{};
    }

    pub fn update(self: *Self, data: []const u8) void {
        var input = data;

        // Process any buffered data first
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

        // Process full blocks
        while (input.len >= block_length) {
            self.processBlock(input[0..block_length]);
            input = input[block_length..];
        }

        // Buffer remaining
        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }

        self.total_len += data.len;
    }

    fn processBlock(self: *Self, block: *const [block_length]u8) void {
        var w: [80]u32 = undefined;

        // Message schedule (SHA-0 differs here - no rotation!)
        for (0..16) |i| {
            w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }

        // SHA-0: XOR without rotation (this is the key difference from SHA-1)
        for (16..80) |i| {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            // SHA-1 would do: w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];

        for (0..80) |i| {
            const f: u32 = switch (i / 20) {
                0 => (b & c) | ((~b) & d),
                1 => b ^ c ^ d,
                2 => (b & c) | (b & d) | (c & d),
                3 => b ^ c ^ d,
                else => unreachable,
            };

            const ki = k[i / 20];
            const temp = rotl(a, 5) +% f +% e +% ki +% w[i];

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

    pub fn final(self: *Self) [digest_length]u8 {
        // Padding
        const total_bits = self.total_len * 8;

        // Add 1 bit followed by zeros
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If not enough space for length, process block and start new one
        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        // Pad with zeros up to length field
        @memset(self.buf[self.buf_len..56], 0);

        // Append length in bits (big-endian)
        std.mem.writeInt(u64, self.buf[56..64], total_bits, .big);
        self.processBlock(&self.buf);

        // Output hash
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

/// One-shot SHA-0 hash
pub fn hash(data: []const u8) [digest_length]u8 {
    var h = Sha0.init();
    h.update(data);
    return h.final();
}

/// Format hash as hex string
pub fn hashToHex(digest: *const [digest_length]u8) [digest_length * 2]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [digest_length * 2]u8 = undefined;

    for (digest, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    return result;
}

// ============================================================================
// SoftEther password hashing
// ============================================================================

/// SoftEther password hash format
/// Hash = SHA0(password + username)
pub fn softEtherPasswordHash(username: []const u8, password: []const u8) [digest_length]u8 {
    var h = Sha0.init();
    h.update(password);
    h.update(username);
    return h.final();
}

/// SoftEther secure password with challenge
/// Hash = SHA0(SHA0(password + username) + challenge)
pub fn softEtherSecurePassword(
    username: []const u8,
    password: []const u8,
    challenge: []const u8,
) [digest_length]u8 {
    const password_hash = softEtherPasswordHash(username, password);
    var h = Sha0.init();
    h.update(&password_hash);
    h.update(challenge);
    return h.final();
}

// ============================================================================
// Tests
// ============================================================================

test "SHA-0 empty string" {
    const result = hash("");
    const hex = hashToHex(&result);
    // SHA-0("") known value
    try testing.expectEqualStrings("f96cea198ad1dd5617ac084a3d92c6107708c0ef", &hex);
}

test "SHA-0 abc" {
    const result = hash("abc");
    const hex = hashToHex(&result);
    // SHA-0("abc") known value
    try testing.expectEqualStrings("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", &hex);
}

test "SHA-0 longer message" {
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const result = hash(msg);
    const hex = hashToHex(&result);
    // SHA-0 known value for this message
    try testing.expectEqualStrings("d2516ee1acfa5baf33dfc1c471e438449ef134c8", &hex);
}

test "SHA-0 incremental" {
    var h = Sha0.init();
    h.update("abc");
    h.update("def");
    const result = h.final();

    const single = hash("abcdef");
    try testing.expectEqualSlices(u8, &single, &result);
}

test "SoftEther password hash" {
    // Test that password hashing works
    const pw_hash = softEtherPasswordHash("testuser", "testpass");
    try testing.expectEqual(@as(usize, 20), pw_hash.len);

    // Same input should give same output
    const pw_hash2 = softEtherPasswordHash("testuser", "testpass");
    try testing.expectEqualSlices(u8, &pw_hash, &pw_hash2);
}

test "SoftEther secure password" {
    const challenge = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const secure = softEtherSecurePassword("user", "pass", &challenge);
    try testing.expectEqual(@as(usize, 20), secure.len);
}
