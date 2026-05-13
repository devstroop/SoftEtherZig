//! Cryptographic Hash Functions
//!
//! Wrappers around Zig std crypto hashes plus custom SHA-0.

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

pub const sha0 = @import("sha0.zig");

// Re-export standard hashes
pub const Sha1 = crypto.hash.Sha1;
pub const Sha256 = crypto.hash.sha2.Sha256;
pub const Sha384 = crypto.hash.sha2.Sha384;
pub const Sha512 = crypto.hash.sha2.Sha512;
pub const Md5 = crypto.hash.Md5;

test "sha1 one-shot" {
    const input = "hello";
    const expected = [_]u8{
        0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2,
        0xda, 0xbe, 0xde, 0x0f, 0x3b, 0x48, 0x2c, 0xd9,
        0xae, 0xa9, 0x43, 0x4d,
    };
    const result = sha1(input);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "sha256 one-shot" {
    const input = "hello";
    const expected = [_]u8{
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    };
    const result = sha256(input);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "sha512 one-shot" {
    const input = "hello";
    const expected = [_]u8{
        0x9b, 0x71, 0xd2, 0x24, 0xbd, 0x62, 0xf3, 0x78,
        0x5d, 0x96, 0xd4, 0x6a, 0xd3, 0xea, 0x3d, 0x73,
        0x31, 0x9b, 0xfb, 0xc2, 0x89, 0x0c, 0xaa, 0xda,
        0xe2, 0xdf, 0xf7, 0x25, 0x19, 0x67, 0x3c, 0xa7,
        0x23, 0x23, 0xc3, 0xd9, 0x9b, 0xa5, 0xc1, 0x1d,
        0x7c, 0x7a, 0xcc, 0x6e, 0x14, 0xb8, 0xc5, 0xda,
        0x0c, 0x46, 0x63, 0x47, 0x5c, 0x2e, 0x5c, 0x3a,
        0xde, 0xf4, 0x6f, 0x73, 0xbc, 0xde, 0xc0, 0x43,
    };
    const result = sha512(input);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "md5 one-shot" {
    const input = "hello";
    const expected = [_]u8{
        0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76,
        0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92,
    };
    const result = md5(input);
    try testing.expectEqualSlices(u8, &expected, &result);
}

/// SHA-1 one-shot hash
pub fn sha1(data: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    Sha1.hash(data, &out, .{});
    return out;
}

/// SHA-256 one-shot hash
pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

/// SHA-512 one-shot hash
pub fn sha512(data: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    Sha512.hash(data, &out, .{});
    return out;
}

/// MD5 one-shot hash (for legacy compatibility only)
pub fn md5(data: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    Md5.hash(data, &out, .{});
    return out;
}

/// HMAC implementation
pub fn Hmac(comptime Hash: type) type {
    return crypto.auth.hmac.Hmac(Hash);
}

pub const HmacSha1 = Hmac(Sha1);
pub const HmacSha256 = Hmac(Sha256);
pub const HmacMd5 = Hmac(Md5);

/// Compute HMAC-SHA1
pub fn hmacSha1(key: []const u8, data: []const u8) [20]u8 {
    var mac: [20]u8 = undefined;
    HmacSha1.create(&mac, data, key);
    return mac;
}

/// Compute HMAC-SHA256
pub fn hmacSha256(key: []const u8, data: []const u8) [32]u8 {
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, data, key);
    return mac;
}

// ============================================================================
// PBKDF2 for key derivation
// ============================================================================

/// PBKDF2-HMAC-SHA256
pub fn pbkdf2Sha256(
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    output: []u8,
) void {
    crypto.pwhash.pbkdf2(output, password, salt, iterations, .sha256);
}

// ============================================================================
// Utility functions
// ============================================================================

/// Compare two hashes in constant time (timing-safe)
pub fn constTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var result: u8 = 0;
    for (a, b) |x, y| {
        result |= x ^ y;
    }
    return result == 0;
}

/// Format hash as lowercase hex string
pub fn toHex(digest: []const u8, output: []u8) []u8 {
    const hex_chars = "0123456789abcdef";
    for (digest, 0..) |byte, i| {
        output[i * 2] = hex_chars[byte >> 4];
        output[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return output[0 .. digest.len * 2];
}

/// Parse hex string to bytes
pub fn fromHex(hex: []const u8, output: []u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;
    if (output.len < hex.len / 2) return error.BufferTooSmall;

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const high = hexVal(hex[i]) orelse return error.InvalidHexChar;
        const low = hexVal(hex[i + 1]) orelse return error.InvalidHexChar;
        output[i / 2] = (high << 4) | low;
    }

    return output[0 .. hex.len / 2];
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "sha1 hash" {
    const result = sha1("abc");
    var hex: [40]u8 = undefined;
    const hex_str = toHex(&result, &hex);
    try testing.expectEqualStrings("a9993e364706816aba3e25717850c26c9cd0d89d", hex_str);
}

test "sha256 hash" {
    const result = sha256("abc");
    var hex: [64]u8 = undefined;
    const hex_str = toHex(&result, &hex);
    try testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex_str);
}

test "md5 hash" {
    const result = md5("abc");
    var hex: [32]u8 = undefined;
    const hex_str = toHex(&result, &hex);
    try testing.expectEqualStrings("900150983cd24fb0d6963f7d28e17f72", hex_str);
}

test "hmac-sha1" {
    const mac = hmacSha1("key", "The quick brown fox jumps over the lazy dog");
    var hex: [40]u8 = undefined;
    const hex_str = toHex(&mac, &hex);
    try testing.expectEqualStrings("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", hex_str);
}

test "constant time comparison" {
    const a = [_]u8{ 1, 2, 3, 4 };
    const b = [_]u8{ 1, 2, 3, 4 };
    const c = [_]u8{ 1, 2, 3, 5 };

    try testing.expect(constTimeEql(&a, &b));
    try testing.expect(!constTimeEql(&a, &c));
}

test "hex conversion roundtrip" {
    const original = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var hex_buf: [8]u8 = undefined;
    const hex = toHex(&original, &hex_buf);

    var decoded: [4]u8 = undefined;
    const result = try fromHex(hex, &decoded);

    try testing.expectEqualSlices(u8, &original, result);
}
