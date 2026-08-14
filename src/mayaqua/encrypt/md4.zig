//! MD4 Implementation (RFC 1320)
//!
//! SoftEther VPN uses MD4 for the NTLM / NT password hash path
//! (`GenerateNtPasswordHash` in Mayaqua/TcpIp.c, `GenerateNtPasswordHashHash`
//! in Cedar/IPsec_PPP.c, both via `HashMd4` in Mayaqua/Encrypt.c).
//!
//! # SECURITY WARNING — Broken Algorithm
//!
//! MD4 is cryptographically broken (collision attacks demonstrated since
//! 1995). Do NOT use for any purpose outside SoftEther protocol
//! compatibility. This implementation exists solely to interoperate with
//! existing SoftEther VPN servers that use NTLM password hashes.
//!
//! Wire note: the NT hash is MD4 of the UTF-16LE password, and
//! `GenerateNtPasswordHashHash` is MD4 of that NT hash — NOT SHA1 (the C
//! reference at IPsec_PPP.c:2713 calls `HashMd4(dst, src, 16)`).

const std = @import("std");
const testing = std.testing;

/// MD4 hash output size in bytes
pub const digest_length = 16;

/// MD4 block size in bytes
pub const block_length = 64;

/// MD4 hasher state
pub const Md4 = struct {
    const Self = @This();

    /// Initial hash values (RFC 1320)
    const iv = [4]u32{
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
    };

    /// Round constants
    const k = [3]u32{
        0x00000000, // round 1
        0x5A827999, // round 2
        0x6ED9EBA1, // round 3
    };

    /// Message word indexes per round (RFC 1320)
    const x_index = [3][16]usize{
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 },
        .{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 },
    };

    /// Shift amounts per round (RFC 1320)
    const s = [3][4]u5{
        .{ 3, 7, 11, 19 },
        .{ 3, 5, 9, 13 },
        .{ 3, 9, 11, 15 },
    };

    /// Boolean functions per round (RFC 1320): round 1 F, round 2 G, round 3 H
    const RoundFn = *const fn (u32, u32, u32) u32;
    const round_fns = [3]RoundFn{ f, g, h };

    state: [4]u32 = iv,
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

    fn f(x: u32, y: u32, z: u32) u32 {
        return (x & y) | ((~x) & z);
    }

    fn g(x: u32, y: u32, z: u32) u32 {
        return (x & y) | (x & z) | (y & z);
    }

    fn h(x: u32, y: u32, z: u32) u32 {
        return x ^ y ^ z;
    }

    fn rotl(x: u32, amt: u5) u32 {
        return (x << amt) | (x >> @as(u5, @intCast(32 - @as(u6, amt))));
    }

    fn processBlock(self: *Self, block: *const [block_length]u8) void {
        var x: [16]u32 = undefined;

        // Message words are little-endian (RFC 1320)
        for (0..16) |i| {
            x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];

        for (0..3) |round| {
            const shift = s[round];
            const constant = k[round];
            const fn_i = round_fns[round];
            for (0..16) |step| {
                const wi = x[x_index[round][step]];
                const shift_amt = shift[step % 4];
                switch (step % 4) {
                    0 => a = rotl(a +% fn_i(b, c, d) +% wi +% constant, shift_amt),
                    1 => d = rotl(d +% fn_i(a, b, c) +% wi +% constant, shift_amt),
                    2 => c = rotl(c +% fn_i(d, a, b) +% wi +% constant, shift_amt),
                    3 => b = rotl(b +% fn_i(c, d, a) +% wi +% constant, shift_amt),
                    else => unreachable,
                }
            }
        }

        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
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

        // Append length in bits (little-endian)
        std.mem.writeInt(u64, self.buf[56..64], total_bits, .little);
        self.processBlock(&self.buf);

        // Output hash (little-endian)
        var result: [digest_length]u8 = undefined;
        for (0..4) |i| {
            std.mem.writeInt(u32, result[i * 4 ..][0..4], self.state[i], .little);
        }

        return result;
    }
};

/// One-shot MD4 hash
pub fn md4(data: []const u8) [digest_length]u8 {
    var h = Md4.init();
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
// NTLM / NT password hash (SoftEther compatibility)
// ============================================================================

/// NT hash of a password: MD4(UTF-16LE(password)).
/// Mirrors C `GenerateNtPasswordHash` (Mayaqua/TcpIp.c:4514).
pub fn generateNtPasswordHash(password: []const u8) [digest_length]u8 {
    // Convert password bytes to UTF-16LE (each byte becomes 2 bytes, LE)
    var utf16_buf: [512]u8 = undefined;
    var utf16_len: usize = 0;

    for (password) |byte| {
        if (utf16_len + 2 > utf16_buf.len) break;
        utf16_buf[utf16_len] = byte;
        utf16_buf[utf16_len + 1] = 0;
        utf16_len += 2;
    }

    return md4(utf16_buf[0..utf16_len]);
}

/// Hash of an NT hash: MD4(nt_hash).
/// Mirrors C `GenerateNtPasswordHashHash` (Cedar/IPsec_PPP.c:2705), which
/// calls `HashMd4(dst_hash, src_hash, 16)` — the output is MD4, NOT SHA1.
pub fn generateNtPasswordHashHash(nt_hash: *const [digest_length]u8) [digest_length]u8 {
    return md4(nt_hash[0..digest_length]);
}

// ============================================================================
// Tests
// ============================================================================

test "MD4 empty string (RFC 1320)" {
    const result = hashToHex(&md4(""));
    try testing.expectEqualStrings("31d6cfe0d16ae931b73c59d7e0c089c0", &result);
}

test "MD4 a (RFC 1320)" {
    const result = hashToHex(&md4("a"));
    try testing.expectEqualStrings("bde52cb31de33e46245e05fbdbd6fb24", &result);
}

test "MD4 abc (RFC 1320)" {
    const result = hashToHex(&md4("abc"));
    try testing.expectEqualStrings("a448017aaf21d8525fc10ae87aa6729d", &result);
}

test "MD4 message digest (RFC 1320)" {
    const result = hashToHex(&md4("message digest"));
    try testing.expectEqualStrings("d9130a8164549fe818874806e1c7014b", &result);
}

test "MD4 alphabet (RFC 1320)" {
    const result = hashToHex(&md4("abcdefghijklmnopqrstuvwxyz"));
    try testing.expectEqualStrings("d79e1c308aa5bbcdeea8ed63df412da9", &result);
}

test "MD4 alphanumeric (RFC 1320)" {
    const result = hashToHex(&md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
    try testing.expectEqualStrings("043f8582f241db351ce627e153e7f0e4", &result);
}

test "MD4 80 digits (RFC 1320)" {
    const result = hashToHex(&md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890"));
    try testing.expectEqualStrings("e33b4ddc9c38f2199c3e7b164fcc0536", &result);
}

test "MD4 incremental" {
    var h = Md4.init();
    h.update("abc");
    h.update("def");
    const result = h.final();

    const single = md4("abcdef");
    try testing.expectEqualSlices(u8, &single, &result);
}

test "MD4 cross-block input" {
    // Input length 55, 56, 63, 64, 65 exercises all padding boundary cases
    for ([_]usize{ 55, 56, 63, 64, 65, 119, 120, 128 }) |len| {
        var input: [128]u8 = undefined;
        for (0..len) |i| input[i] = @intCast(i);
        var h = Md4.init();
        h.update(input[0..len]);
        const result = h.final();
        const single = md4(input[0..len]);
        try testing.expectEqualSlices(u8, &single, &result);
    }
}

test "NT hash empty password" {
    // Well-known NT hash of the empty password: MD4("") — matches C behavior
    // since UTF-16LE("") is empty.
    const result = hashToHex(&generateNtPasswordHash(""));
    try testing.expectEqualStrings("31d6cfe0d16ae931b73c59d7e0c089c0", &result);
}

test "NT hash matches UTF-16LE MD4" {
    // NT hash of "abc" must equal MD4("a\0b\0c\0")
    const nt = generateNtPasswordHash("abc");
    const utf16 = "a\x00b\x00c\x00";
    const direct = md4(utf16);
    try testing.expectEqualSlices(u8, &direct, &nt);
}

test "GenerateNtPasswordHashHash is MD4 of NT hash" {
    const nt = generateNtPasswordHash("password");
    const hash_hash = generateNtPasswordHashHash(&nt);
    const direct = md4(&nt);
    try testing.expectEqualSlices(u8, &direct, &hash_hash);
}
