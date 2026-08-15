//! RC4 stream cipher (legacy SoftEther session encryption)
//!
//! Wire-compatible with the C server's RC4 path: `NewCrypt`/`Encrypt`
//! (Mayaqua/Encrypt.c:5290-5319) use OpenSSL's `RC4_set_key`/`RC4`. RC4 is a
//! symmetric stream cipher — encryption and decryption are the same operation.
//!
//! # SECURITY WARNING — Broken Algorithm
//!
//! RC4 is cryptographically broken (biased keystream; public cryptanalysis
//! since 2001). Do NOT use outside SoftEther legacy protocol compatibility.
//! SoftEther only negotiates this path when a legacy client requests
//! `use_fast_rc4`; modern sessions run over TLS with AES-256-CBC.

const std = @import("std");
const testing = std.testing;

/// Maximum key length RC4 accepts (256). Matches OpenSSL's `RC4_set_key`.
pub const max_key_size = 256;

/// Stateful RC4 stream cipher.
///
/// One instance per direction (send / recv), matching the C `CRYPT` object
/// created by `NewCrypt`. The keystream continues across `apply` calls, so
/// packets are processed against the ongoing cipher state.
pub const Rc4 = struct {
    const Self = @This();

    /// S-box (keystream state)
    state: [256]u8,
    i: u8,
    j: u8,

    /// Initialize with a key using the key-scheduling algorithm (KSA).
    /// Matches OpenSSL `RC4_set_key` for key lengths 1..256. A zero-length
    /// key is accepted (no key contribution), mirroring OpenSSL.
    pub fn init(key: []const u8) Self {
        std.debug.assert(key.len <= max_key_size);

        var self: Self = .{ .state = undefined, .i = 0, .j = 0 };
        for (0..256) |k| {
            self.state[k] = @intCast(k);
        }

        var j: u8 = 0;
        if (key.len > 0) {
            for (0..256) |k| {
                j = j +% self.state[k] +% key[k % key.len];
                std.mem.swap(u8, &self.state[k], &self.state[j]);
            }
        } else {
            for (0..256) |k| {
                j = j +% self.state[k];
                std.mem.swap(u8, &self.state[k], &self.state[j]);
            }
        }
        // OpenSSL's `RC4_set_key` resets the PRGA counters to zero after the
        // key-scheduling algorithm; the final `j` of the KSA is discarded.
        self.i = 0;
        self.j = 0;
        return self;
    }

    /// Apply the keystream to `data` in place (PRGA).
    ///
    /// RC4 is symmetric: `apply` both encrypts and decrypts. The cipher state
    /// advances, so the keystream is continuous across calls.
    pub fn apply(self: *Self, data: []u8) void {
        var i: u8 = self.i;
        var j: u8 = self.j;
        for (data) |*b| {
            i +%= 1;
            j +%= self.state[i];
            std.mem.swap(u8, &self.state[i], &self.state[j]);
            const t = self.state[i] +% self.state[j];
            b.* ^= self.state[t];
        }
        self.i = i;
        self.j = j;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "RC4 key 'Key' vector (RFC 6229 known answer)" {
    // Well-known: RC4(key="Key") applied to "Plaintext" yields BBF316E8D940AF0AD3
    var rc4 = Rc4.init("Key");
    var data: [9]u8 = .{ 'P', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't' };
    rc4.apply(&data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3 }, &data);
}

test "RC4 key 'Secret' vector" {
    // Known answer: RC4(key="Secret") applied to "Attack at dawn" yields
    // 45A01F645FC35B383552544B9BF5
    var rc4 = Rc4.init("Secret");
    var data: [14]u8 = .{ 'A', 't', 't', 'a', 'c', 'k', ' ', 'a', 't', ' ', 'd', 'a', 'w', 'n' };
    rc4.apply(&data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5 }, &data);
}

test "RC4 128-bit key first keystream block (RFC 6229)" {
    // RFC 6229 key length 128, key 0102030405060708090a0b0c0d0e0f10,
    // all-zero 16-byte data → 9AC7CC9A609D1EF7B2932899CDE41B97
    const key = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    var rc4 = Rc4.init(&key);
    var data = [_]u8{0} ** 16;
    rc4.apply(&data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x9A, 0xC7, 0xCC, 0x9A, 0x60, 0x9D, 0x1E, 0xF7, 0xB2, 0x93, 0x28, 0x99, 0xCD, 0xE4, 0x1B, 0x97 }, &data);
}

test "RC4 encrypt/decrypt symmetric" {
    var enc = Rc4.init("password");
    var dec = Rc4.init("password");

    const msg = "SoftEther session data";
    var cipher = [_]u8{0} ** msg.len;
    @memcpy(&cipher, msg);

    enc.apply(&cipher);
    try testing.expect(!std.mem.eql(u8, msg, &cipher));

    dec.apply(&cipher);
    try testing.expectEqualStrings(msg, &cipher);
}

test "RC4 keystream continuous across calls" {
    // Applying in two chunks must equal applying once (state continuity).
    var one = Rc4.init("chunk-test-key");
    var two = Rc4.init("chunk-test-key");

    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    for (0..32) |i| {
        a[i] = @intCast(i);
        b[i] = @intCast(i);
    }

    one.apply(&a);
    two.apply(b[0..12]);
    two.apply(b[12..]);

    try testing.expectEqualSlices(u8, &a, &b);
}

test "RC4 zero-length key" {
    // OpenSSL accepts a 0-length key (no key contribution). Exercise it.
    var rc4 = Rc4.init("");
    var data = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    rc4.apply(&data);
    // Just ensure it runs and mutates (keystream from identity schedule)
    try testing.expect(!std.mem.eql(u8, &[_]u8{ 0x00, 0x01, 0x02, 0x03 }, &data));
}

test "RC4 16-byte key full cycle" {
    // 16-byte key (the SoftEther wire key size) round-trip
    var key: [16]u8 = undefined;
    for (0..16) |i| key[i] = @intCast(i * 7);

    var enc = Rc4.init(&key);
    var dec = Rc4.init(&key);

    var data = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const original = data;

    enc.apply(&data);
    try testing.expect(!std.mem.eql(u8, &original, &data));

    dec.apply(&data);
    try testing.expectEqualSlices(u8, &original, &data);
}
