//! SoftEther VPN Protocol Implementation
//!
//! This module implements the SoftEther VPN protocol.
//! Phase 4 of the C-to-Zig migration.
//!
//! Components:
//! - pack.zig: Pack serialization format (SoftEther's binary RPC format)
//! - rpc.zig: RPC protocol over HTTP/HTTPS
//! - auth.zig: Authentication methods (password, certificate, anonymous)
//! - softether_protocol.zig: Full SoftEther handshake protocol

pub const pack = @import("pack.zig");
pub const rpc = @import("rpc.zig");
pub const auth = @import("auth.zig");
pub const softether = @import("softether_protocol.zig");

// Re-export commonly used types

// Pack format
pub const Pack = pack.Pack;
pub const Element = pack.Element;
pub const Value = pack.Value;
pub const ValueType = pack.ValueType;

// RPC
pub const Request = rpc.Request;
pub const Response = rpc.Response;
pub const Method = rpc.Method;
pub const Protocol = rpc.Protocol;
pub const buildHttpRequest = rpc.buildHttpRequest;
pub const parseHttpResponse = rpc.parseHttpResponse;

// Authentication
pub const AuthType = auth.AuthType;
pub const ClientAuth = auth.ClientAuth;
pub const Challenge = auth.Challenge;
pub const computeSecurePassword = auth.computeSecurePassword;
pub const SessionKey = auth.SessionKey;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
