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
//! - `hub.zig` — Virtual Hub L2 switch: StorePacket (MAC/IP tables, unicast
//!   + flood), per-session SessionPa PacketAdapter
//! - `listener.zig` — Listener layer: per-port accept threads, DoS gate,
//!   listener registry
//! - `accept.zig` — connection accept: TLS handshake, signature upload, hello,
//!   auth + welcome, then the session data plane (issue #78)
//! - `config/cfg.zig` — Cfg text-format configuration tree: declare/{}/typed
//!   items, Base64 byte, escaping, CFG_RW save/load with backup (issue #85)

pub const auth = @import("auth.zig");
pub const session = @import("session.zig");
pub const session_main = @import("session_main.zig");
pub const hub = @import("hub.zig");
pub const listener = @import("listener.zig");
pub const accept = @import("accept.zig");
pub const cfg = @import("config/cfg.zig");

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
pub const SwitchHub = hub.Hub;
pub const SessionPa = hub.SessionPa;
pub const parseEthernet = hub.parseEthernet;
pub const Listener = listener.Listener;
pub const ListenerOptions = listener.ListenerOptions;
pub const ListenerRegistry = listener.ListenerRegistry;
pub const Protocol = listener.Protocol;
pub const Status = listener.Status;
pub const DosTable = listener.DosTable;
pub const AcceptHandler = listener.AcceptHandler;
pub const ServerContext = accept.ServerContext;
pub const acceptConnection = accept.acceptConnection;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
