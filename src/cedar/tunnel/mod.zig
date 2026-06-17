//! Tunnel Module
//!
//! Data channel tunnel handling for VPN connections.
//! Includes DHCP state machine, ARP handling, and packet processing.

const std = @import("std");

// Submodules
pub const dhcp = @import("dhcp.zig");
pub const arp = @import("arp.zig");
pub const data_loop = @import("data_loop.zig");

// Re-export main types
pub const DhcpState = dhcp.DhcpState;
pub const DhcpConfig = dhcp.DhcpConfig;
pub const DhcpHandler = dhcp.DhcpHandler;
pub const ArpHandler = arp.ArpHandler;
pub const DataLoopState = data_loop.DataLoopState;
pub const DataLoopConfig = data_loop.DataLoopConfig;
pub const DataLoopCallbacks = data_loop.DataLoopCallbacks;
pub const LoopResult = data_loop.LoopResult;
pub const TimingState = data_loop.TimingState;
pub const Ipv4Info = data_loop.Ipv4Info;

// Re-export utility functions
pub const formatIpForLog = data_loop.formatIpForLog;
pub const wrapIpInEthernet = data_loop.wrapIpInEthernet;
pub const unwrapEthernetToIp = data_loop.unwrapEthernetToIp;
pub const isArpPacket = data_loop.isArpPacket;
pub const getArpOperation = data_loop.getArpOperation;
pub const parseIpv4Header = data_loop.parseIpv4Header;
pub const getArpSenderIp = data_loop.getArpSenderIp;
pub const getArpSenderMac = data_loop.getArpSenderMac;
pub const getArpTargetIp = data_loop.getArpTargetIp;

// ============================================================================
// Tests
// ============================================================================

test {
    std.testing.refAllDecls(@This());
}

// ============================================================================
// Tests
// ============================================================================

test {
    std.testing.refAllDecls(@This());
}
