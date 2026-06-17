//! SoftEther VPN Session Layer
//!
//! VPN session management implementation.
//! Phase 5 of the C-to-Zig migration.
//!
//! Components:
//! - session.zig: Session state machine and packet handling
//! - connection.zig: TCP connection management

pub const session = @import("session.zig");
pub const connection = @import("connection.zig");
pub const wrapper = @import("wrapper.zig");

// Wrapper
pub const SessionWrapper = wrapper.SessionWrapper;

// Re-export commonly used types

// Session
pub const Session = session.Session;
pub const SessionState = session.SessionState;
pub const SessionError = session.SessionError;
pub const SessionOptions = session.SessionOptions;
pub const SessionKeys = session.SessionKeys;
pub const SessionPolicy = session.SessionPolicy;
pub const ClientStatus = session.ClientStatus;
pub const TrafficStats = session.TrafficStats;
pub const TrafficCounters = session.TrafficCounters;
pub const NodeInfo = session.NodeInfo;
pub const VpnPacket = session.VpnPacket;
pub const PacketQueue = session.PacketQueue;
pub const Config = session.Config;

// Connection
pub const Connection = connection.Connection;
pub const ConnectionState = connection.ConnectionState;
pub const TcpDirection = connection.TcpDirection;
pub const TcpSocketInfo = connection.TcpSocketInfo;
pub const Block = connection.Block;
pub const BlockQueue = connection.BlockQueue;
pub const ErrorCode = connection.ErrorCode;

// Keep-alive
pub const createKeepAlivePacket = session.createKeepAlivePacket;
pub const isKeepAlivePacket = session.isKeepAlivePacket;
pub const KEEP_ALIVE_STRING = session.KEEP_ALIVE_STRING;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
