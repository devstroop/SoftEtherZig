//! Symmetric Encryption Module
//!
//! AES encryption for SoftEther VPN data channels.

const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;

/// AES block size (always 16 bytes)
pub const block_size = 16;

// ============================================================================
// AES-CBC mode (used by SoftEther for some operations)
// ============================================================================

/// AES-128-CBC encryption - manual implementation
pub const Aes128Cbc = struct {
    const Self = @This();
    const Aes128 = crypto.core.aes.Aes128;

    key: [16]u8,
    iv: [block_size]u8,

    pub fn init(key: *const [16]u8, iv: *const [block_size]u8) Self {
        return .{
            .key = key.*,
            .iv = iv.*,
        };
    }

    /// Encrypt data in-place (must be multiple of block_size)
    pub fn encrypt(self: *Self, data: []u8) !void {
        if (data.len == 0) return;
        if (data.len % block_size != 0) return error.InvalidBlockSize;

        const enc = Aes128.initEnc(self.key);
        var prev: [block_size]u8 = self.iv;
        var i: usize = 0;

        while (i < data.len) : (i += block_size) {
            const block_ptr = data[i..][0..block_size];

            // XOR with previous ciphertext (or IV for first block)
            for (0..block_size) |j| {
                block_ptr[j] ^= prev[j];
            }

            // Encrypt
            enc.encrypt(block_ptr, block_ptr);
            prev = block_ptr.*;
        }

        // Update IV for next operation
        self.iv = prev;
    }

    /// Decrypt data in-place (must be multiple of block_size)
    pub fn decrypt(self: *Self, data: []u8) !void {
        if (data.len == 0) return;
        if (data.len % block_size != 0) return error.InvalidBlockSize;

        const dec = Aes128.initDec(self.key);
        var prev: [block_size]u8 = self.iv;
        var i: usize = 0;

        while (i < data.len) : (i += block_size) {
            const block_ptr = data[i..][0..block_size];
            const temp: [block_size]u8 = block_ptr.*;

            // Decrypt
            dec.decrypt(block_ptr, block_ptr);

            // XOR with previous ciphertext (or IV for first block)
            for (0..block_size) |j| {
                block_ptr[j] ^= prev[j];
            }

            prev = temp;
        }

        // Update IV for next operation
        self.iv = prev;
    }
};

/// AES-256-CBC encryption - manual implementation
pub const Aes256Cbc = struct {
    const Self = @This();
    const Aes256 = crypto.core.aes.Aes256;

    key: [32]u8,
    iv: [block_size]u8,

    pub fn init(key: *const [32]u8, iv: *const [block_size]u8) Self {
        return .{
            .key = key.*,
            .iv = iv.*,
        };
    }

    /// Encrypt data in-place (must be multiple of block_size)
    pub fn encrypt(self: *Self, data: []u8) !void {
        if (data.len == 0) return;
        if (data.len % block_size != 0) return error.InvalidBlockSize;

        const enc = Aes256.initEnc(self.key);
        var prev: [block_size]u8 = self.iv;
        var i: usize = 0;

        while (i < data.len) : (i += block_size) {
            const block_ptr = data[i..][0..block_size];

            for (0..block_size) |j| {
                block_ptr[j] ^= prev[j];
            }

            enc.encrypt(block_ptr, block_ptr);
            prev = block_ptr.*;
        }

        self.iv = prev;
    }

    /// Decrypt data in-place (must be multiple of block_size)
    pub fn decrypt(self: *Self, data: []u8) !void {
        if (data.len == 0) return;
        if (data.len % block_size != 0) return error.InvalidBlockSize;

        const dec = Aes256.initDec(self.key);
        var prev: [block_size]u8 = self.iv;
        var i: usize = 0;

        while (i < data.len) : (i += block_size) {
            const block_ptr = data[i..][0..block_size];
            const temp: [block_size]u8 = block_ptr.*;

            dec.decrypt(block_ptr, block_ptr);

            for (0..block_size) |j| {
                block_ptr[j] ^= prev[j];
            }

            prev = temp;
        }

        self.iv = prev;
    }
};

// ============================================================================
// PKCS7 padding
// ============================================================================

/// Add PKCS7 padding
pub fn pkcs7Pad(data: []const u8, output: []u8) ![]u8 {
    const padded_len = ((data.len / block_size) + 1) * block_size;
    if (output.len < padded_len) return error.BufferTooSmall;

    @memcpy(output[0..data.len], data);

    const pad_byte: u8 = @intCast(padded_len - data.len);
    @memset(output[data.len..padded_len], pad_byte);

    return output[0..padded_len];
}

/// Remove PKCS7 padding
pub fn pkcs7Unpad(data: []u8) ![]u8 {
    if (data.len == 0 or data.len % block_size != 0) {
        return error.InvalidPadding;
    }

    const pad_byte = data[data.len - 1];
    if (pad_byte == 0 or pad_byte > block_size) {
        return error.InvalidPadding;
    }

    // Verify all padding bytes
    const pad_len: usize = @intCast(pad_byte);
    for (data[data.len - pad_len ..]) |b| {
        if (b != pad_byte) return error.InvalidPadding;
    }

    return data[0 .. data.len - pad_len];
}

// ============================================================================
// AES-GCM (authenticated encryption)
// ============================================================================

pub const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
pub const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

/// Encrypt with AES-128-GCM
pub fn aes128GcmEncrypt(
    plaintext: []const u8,
    additional_data: []const u8,
    key: *const [16]u8,
    nonce: *const [12]u8,
    ciphertext: []u8,
    tag: *[16]u8,
) void {
    Aes128Gcm.encrypt(ciphertext, tag, plaintext, additional_data, nonce.*, key.*);
}

/// Decrypt with AES-128-GCM
pub fn aes128GcmDecrypt(
    ciphertext: []const u8,
    additional_data: []const u8,
    key: *const [16]u8,
    nonce: *const [12]u8,
    tag: *const [16]u8,
    plaintext: []u8,
) !void {
    Aes128Gcm.decrypt(plaintext, ciphertext, tag.*, additional_data, nonce.*, key.*) catch {
        return error.AuthenticationFailed;
    };
}

// ============================================================================
// ChaCha20-Poly1305 (alternative to AES-GCM)
// ============================================================================

pub const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

// ============================================================================
// Random number generation
// ============================================================================

/// Generate cryptographically secure random bytes
pub fn randomBytes(buffer: []u8) void {
    crypto.random.bytes(buffer);
}

/// Generate random u32
pub fn randomU32() u32 {
    return crypto.random.int(u32);
}

/// Generate random u64
pub fn randomU64() u64 {
    return crypto.random.int(u64);
}

// ============================================================================
// Tests
// ============================================================================

test "AES-128-CBC encrypt/decrypt" {
    const key = [_]u8{0x00} ** 16;
    const iv = [_]u8{0x00} ** 16;

    var cbc = Aes128Cbc.init(&key, &iv);

    // Test data (must be block-aligned)
    var data = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const original = data;

    try cbc.encrypt(&data);
    try testing.expect(!std.mem.eql(u8, &data, &original));

    // Reset IV for decryption
    cbc.iv = iv;
    try cbc.decrypt(&data);
    try testing.expectEqualSlices(u8, &original, &data);
}

test "PKCS7 padding" {
    const data = "Hello";
    var output: [16]u8 = undefined;

    const padded = try pkcs7Pad(data, &output);
    try testing.expectEqual(@as(usize, 16), padded.len);

    // Last byte should be the pad length (11)
    try testing.expectEqual(@as(u8, 11), padded[15]);

    var padded_mut: [16]u8 = undefined;
    @memcpy(&padded_mut, padded);

    const unpadded = try pkcs7Unpad(&padded_mut);
    try testing.expectEqualStrings(data, unpadded);
}

test "AES-128-GCM encrypt/decrypt" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 12;
    const plaintext = "Hello, World!";
    const aad = "additional data";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    aes128GcmEncrypt(plaintext, aad, &key, &nonce, &ciphertext, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try aes128GcmDecrypt(&ciphertext, aad, &key, &nonce, &tag, &decrypted);

    try testing.expectEqualStrings(plaintext, &decrypted);
}

test "random bytes" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    randomBytes(&buf1);
    randomBytes(&buf2);

    // Extremely unlikely to be equal
    try testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}
