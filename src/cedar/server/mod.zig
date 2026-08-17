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
//! - `session_registry.zig` — live session/connection registry + force-stop
//!   (feeds the admin RPC dispatcher, issue #88)
//! - `listener.zig` — Listener layer: per-port accept threads, DoS gate,
//!   listener registry
//! - `hub.zig` — Virtual Hub L2 switch: StorePacket (MAC/IP tables, unicast
//!   + flood), per-session SessionPa PacketAdapter
//! - `accept.zig` — connection accept: TLS handshake, signature upload, hello,
//!   auth + welcome, then the session data plane (issue #78)
//! - `config/cfg.zig` — Cfg text-format configuration tree: declare/{}/typed
//!   items, Base64 byte, escaping, CFG_RW save/load with backup (issue #85)
//! - `config/vpn_server_config.zig` — vpn_server.config load/save + autosave
//!   thread: default config (hub DEFAULT, admin Administrator), C-faithful
//!   item names, CFG_RW backup (issue #86)
//! - `admin/rpc.zig` — admin RPC transport: TLS connection, `[u32 size][Pack]`
//!   frames, dispatch on `function_name`, error/error_code replies (issue #87)
//! - `admin/structs.zig` — admin RPC `RPC_*` structs + Pack (de)serialization
//!   in dispatch order: Core, Listeners, Hubs (issue #89)
//! - `admin/dispatch.zig` — admin RPC dispatch: server state model + the St*
//!   handlers for the Core/Listeners/Hubs endpoints (issue #88)

pub const auth = @import("auth.zig");
pub const session = @import("session.zig");
pub const session_main = @import("session_main.zig");
pub const session_registry = @import("session_registry.zig");
pub const listener = @import("listener.zig");
pub const hub = @import("hub.zig");
pub const accept = @import("accept.zig");
pub const cfg = @import("config/cfg.zig");
pub const vpn_server_config = @import("config/vpn_server_config.zig");
pub const admin_rpc = @import("admin/rpc.zig");
pub const admin_structs = @import("admin/structs.zig");
pub const admin_dispatch = @import("admin/dispatch.zig");
pub const dhcp_server = @import("dhcp_server.zig");
pub const virtual_host = @import("virtual_host.zig");

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
