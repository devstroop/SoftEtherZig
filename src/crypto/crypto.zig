//! SoftEther VPN Cryptography Library
//!
//! This module provides cryptographic primitives.
//! Phase 3 of the C-to-Zig migration.

pub const sha0 = @import("sha0.zig");
pub const hash = @import("hash.zig");
pub const cipher = @import("cipher.zig");

// Re-export commonly used types and functions

// SHA-0 (SoftEther-specific)
pub const Sha0 = sha0.Sha0;
pub const sha0Hash = sha0.hash;
pub const softEtherPasswordHash = sha0.softEtherPasswordHash;
pub const softEtherSecurePassword = sha0.softEtherSecurePassword;

// Standard hashes
pub const Sha1 = hash.Sha1;
pub const Sha256 = hash.Sha256;
pub const Sha512 = hash.Sha512;
pub const Md5 = hash.Md5;
pub const sha1 = hash.sha1;
pub const sha256 = hash.sha256;
pub const sha512 = hash.sha512;
pub const md5 = hash.md5;

// HMAC
pub const HmacSha1 = hash.HmacSha1;
pub const HmacSha256 = hash.HmacSha256;
pub const hmacSha1 = hash.hmacSha1;
pub const hmacSha256 = hash.hmacSha256;

// Symmetric encryption
pub const Aes128Cbc = cipher.Aes128Cbc;
pub const Aes256Cbc = cipher.Aes256Cbc;
pub const Aes128Gcm = cipher.Aes128Gcm;
pub const Aes256Gcm = cipher.Aes256Gcm;
pub const ChaCha20Poly1305 = cipher.ChaCha20Poly1305;

// Utilities
pub const randomBytes = cipher.randomBytes;
pub const randomU32 = cipher.randomU32;
pub const randomU64 = cipher.randomU64;
pub const constTimeEql = hash.constTimeEql;
pub const toHex = hash.toHex;
pub const fromHex = hash.fromHex;

// Padding
pub const pkcs7Pad = cipher.pkcs7Pad;
pub const pkcs7Unpad = cipher.pkcs7Unpad;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
