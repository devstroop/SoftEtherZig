// RC4 stream cipher implementation for SoftEther VPN tunnel encryption.
//
// SoftEther uses RC4 for "fast encryption" mode (UseFastRC4).
// Each TCP socket has separate SendKey and RecvKey contexts.
//
// Based on SoftEther's Encrypt.c implementation.

const std = @import("std");

/// RC4 key size used by SoftEther (16 bytes).
pub const RC4_KEY_SIZE: usize = 16;

/// RC4 stream cipher state.
///
/// This is a streaming cipher - each call to `process()` continues
/// from where the last call left off. Do NOT reset between packets.
pub const Rc4 = struct {
    state: [256]u8,
    i: u8,
    j: u8,

    /// Create a new RC4 cipher with the given key.
    ///
    /// Key can be 1-256 bytes, but SoftEther uses 16-byte keys.
    pub fn init(key: []const u8) Rc4 {
        std.debug.assert(key.len > 0 and key.len <= 256);

        var state: [256]u8 = undefined;

        // Initialize state array (KSA - Key Scheduling Algorithm)
        for (0..256) |i| {
            state[i] = @intCast(i);
        }

        // Key scheduling
        var j_ks: u8 = 0;
        for (0..256) |i| {
            j_ks = j_ks +% state[i] +% key[i % key.len];
            std.mem.swap(u8, &state[i], &state[j_ks]);
        }

        return Rc4{
            .state = state,
            .i = 0,
            .j = 0,
        };
    }

    /// Process data in-place (encrypt or decrypt - RC4 is symmetric).
    ///
    /// This modifies the internal state, so subsequent calls continue
    /// the keystream. This is correct for SoftEther's streaming usage.
    pub fn process(self: *Rc4, data: []u8) void {
        for (data) |*byte| {
            self.i = self.i +% 1;
            self.j = self.j +% self.state[self.i];
            std.mem.swap(u8, &self.state[self.i], &self.state[self.j]);

            const k = self.state[self.state[self.i] +% self.state[self.j]];
            byte.* ^= k;
        }
    }

    /// Process data from source to destination.
    ///
    /// Source and destination can be the same slice for in-place operation.
    pub fn processTo(self: *Rc4, src: []const u8, dst: []u8) void {
        std.debug.assert(src.len == dst.len);

        for (src, 0..) |s, idx| {
            self.i = self.i +% 1;
            self.j = self.j +% self.state[self.i];
            std.mem.swap(u8, &self.state[self.i], &self.state[self.j]);

            const k = self.state[self.state[self.i] +% self.state[self.j]];
            dst[idx] = s ^ k;
        }
    }

    /// Skip n bytes of keystream without processing any data.
    ///
    /// Useful for synchronizing state if bytes were lost.
    pub fn skip(self: *Rc4, n: usize) void {
        for (0..n) |_| {
            self.i = self.i +% 1;
            self.j = self.j +% self.state[self.i];
            std.mem.swap(u8, &self.state[self.i], &self.state[self.j]);
        }
    }
};

/// RC4 key pair for SoftEther tunnel encryption.
///
/// SoftEther uses separate keys for each direction:
/// - ClientToServerKey: Client uses for sending, server uses for receiving
/// - ServerToClientKey: Server uses for sending, client uses for receiving
pub const Rc4KeyPair = struct {
    /// Key for client-to-server direction (16 bytes).
    client_to_server: [RC4_KEY_SIZE]u8,
    /// Key for server-to-client direction (16 bytes).
    server_to_client: [RC4_KEY_SIZE]u8,

    /// Create from raw key data.
    pub fn init(c2s: [RC4_KEY_SIZE]u8, s2c: [RC4_KEY_SIZE]u8) Rc4KeyPair {
        return Rc4KeyPair{
            .client_to_server = c2s,
            .server_to_client = s2c,
        };
    }

    /// Create RC4 ciphers for client mode.
    ///
    /// Returns (send_cipher, recv_cipher) for the client.
    /// - Send cipher uses client_to_server key
    /// - Recv cipher uses server_to_client key
    pub fn createClientCiphers(self: *const Rc4KeyPair) struct { send: Rc4, recv: Rc4 } {
        return .{
            .send = Rc4.init(&self.client_to_server),
            .recv = Rc4.init(&self.server_to_client),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "RC4 encrypt decrypt" {
    const key = "0123456789abcdef";
    const plaintext = "Hello, SoftEther VPN!";

    // Encrypt
    var encrypt = Rc4.init(key);
    var ciphertext: [plaintext.len]u8 = undefined;
    @memcpy(&ciphertext, plaintext);
    encrypt.process(&ciphertext);

    // Ciphertext should be different from plaintext
    try std.testing.expect(!std.mem.eql(u8, &ciphertext, plaintext));

    // Decrypt with fresh cipher (same key)
    var decrypt = Rc4.init(key);
    decrypt.process(&ciphertext);

    // Should get back plaintext
    try std.testing.expectEqualStrings(plaintext, &ciphertext);
}

test "RC4 streaming" {
    // RC4 is a streaming cipher - processing in chunks should give same result
    const key = "test_key_16bytes";
    const data = "This is a longer message that we'll process in chunks";

    // Process all at once
    var cipher1 = Rc4.init(key);
    var result1: [data.len]u8 = undefined;
    @memcpy(&result1, data);
    cipher1.process(&result1);

    // Process in chunks
    var cipher2 = Rc4.init(key);
    var result2: [data.len]u8 = undefined;
    @memcpy(&result2, data);
    cipher2.process(result2[0..10]);
    cipher2.process(result2[10..25]);
    cipher2.process(result2[25..]);

    // Results should be identical
    try std.testing.expectEqualSlices(u8, &result1, &result2);
}

test "RC4 RFC6229 vector" {
    // Key: 0102030405
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var cipher = Rc4.init(&key);

    // First 16 bytes of keystream
    var output: [16]u8 = [_]u8{0} ** 16;
    cipher.process(&output);

    // Expected keystream (first 16 bytes)
    const expected = [_]u8{
        0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
        0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
    };

    try std.testing.expectEqualSlices(u8, &expected, &output);
}
