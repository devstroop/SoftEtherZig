//! Core Module
//!
//! Shared utilities, types, and constants used across the codebase.

pub const ip = @import("ip.zig");
pub const types = @import("types.zig");
pub const errors = @import("errors.zig");

// Re-export commonly used functions
pub const parseIpv4 = ip.parseIpv4;
pub const formatIpv4 = ip.formatIpv4;
pub const ipToBytes = ip.ipToBytes;
pub const bytesToIp = ip.bytesToIp;

// Re-export common types
pub const IpAddress = types.IpAddress;
pub const MacAddress = types.MacAddress;
pub const ConnectionStatus = types.ConnectionStatus;

// Re-export errors
pub const VpnError = errors.VpnError;
pub const errorMessage = errors.errorMessage;

test {
    @import("std").testing.refAllDecls(@This());
}
