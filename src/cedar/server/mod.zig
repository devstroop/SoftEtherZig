//! Server — SoftEther VPN server modules.
//!
//! Mirrors SoftEtherVPN's server-side Cedar code. Contains NO platform-specific
//! code; sockets/crypto come from mayaqua/ and protocol types from cedar/.
//!
//! ## Sub-modules
//! - `auth.zig`     — Security Accounts Manager (Sam.c): hub users, password
//!   /anonymous auth, plain-password interop, pack dispatch
//! - `session.zig` — session keys + data-channel encryption (direction swap,
//!   fast RC4 / classic AES, per-connection cipher state)
//! - `session_main.zig` — SessionMain data loop: ConnectionReceive/Send
//!   framing orchestration over a TunnelConnection + hub PacketAdapter

pub const auth = @import("auth.zig");
pub const session = @import("session.zig");
pub const session_main = @import("session_main.zig");

// Re-export commonly used types
pub const Hub = auth.Hub;
pub const User = auth.User;
pub const UserAuthType = auth.UserAuthType;
pub const AuthResult = auth.AuthResult;
pub const hashPassword = auth.hashPassword;
pub const securePassword = auth.securePassword;
pub const EncryptionMode = session.EncryptionMode;
pub const Rc4KeyPair = session.Rc4KeyPair;
pub const ServerSession = session.ServerSession;
pub const ConnectionCipher = session.ConnectionCipher;
pub const SessionOptions = session.SessionOptions;
pub const SessionMain = session_main.SessionMain;
pub const SessionConfig = session_main.SessionConfig;
pub const SessionStats = session_main.SessionStats;
pub const PacketAdapter = session_main.PacketAdapter;
pub const SessionEnd = session_main.SessionEnd;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
