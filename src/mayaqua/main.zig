//! Mayaqua — Platform Abstraction Layer
//!
//! Mirrors SoftEtherVPN's Mayaqua/ module: OS abstraction, crypto, networking,
//! and core utilities. NO VPN protocol logic lives here.
//!
//! ## Modules
//! - `encrypt/` — Cryptography (SHA-0, SHA-1, SHA-256, AES-CBC)
//! - `kernel/`  — Core types, errors, IP utilities
//! - `network/` — Socket I/O, TLS, HTTP, DNS, SOCKS

pub const encrypt = struct {
    pub usingnamespace @import("encrypt/crypto.zig");
    pub const cipher = @import("encrypt/cipher.zig");
    pub const hash = @import("encrypt/hash.zig");
    pub const sha0 = @import("encrypt/sha0.zig");
    pub const md4 = @import("md4");
    pub const rc4 = @import("encrypt/rc4.zig");
};

pub const kernel = @import("kernel/mod.zig");

pub const network = @import("network/net.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
