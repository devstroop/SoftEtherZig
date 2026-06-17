//! Cedar — VPN Protocol Layer
//!
//! Mirrors SoftEtherVPN's Cedar/ module: VPN protocol logic, session management,
//! tunnel framing, and client orchestration. Depends on mayaqua/ for platform
//! abstraction but contains NO platform-specific code.
//!
//! ## Sub-modules
//! - `protocol/` — Wire protocol (tunnel framing, auth, pack, watermark)
//! - `session/` — Session state, encryption keys
//! - `tunnel/`  — ARP, DHCP, data loop state machine

pub const protocol = @import("protocol/protocol.zig");
pub const session = @import("session/mod.zig");
pub const tunnel = @import("tunnel/mod.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
