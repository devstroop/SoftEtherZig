//! Server — SoftEther VPN server modules.
//!
//! Mirrors SoftEtherVPN's server-side Cedar code. Contains NO platform-specific
//! code; sockets/crypto come from mayaqua/ and protocol types from cedar/.
//!
//! ## Sub-modules
//! - `session.zig` — session keys + data-channel encryption (direction swap)

pub const session = @import("session.zig");

// Re-export commonly used types
pub const Rc4KeyPair = session.Rc4KeyPair;
pub const ServerSession = session.ServerSession;
pub const SessionOptions = session.SessionOptions;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
