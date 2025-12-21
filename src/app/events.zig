//! VPN Event Handler
//!
//! Handles VPN client events and displays them to the user.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const client = @import("../client/mod.zig");
const state_mod = @import("state.zig");
const AppState = state_mod.AppState;

/// Handle VPN client events
pub fn handleVpnEvent(event: client.ClientEvent, user_data: ?*anyopaque) void {
    const s: *AppState = @ptrCast(@alignCast(user_data orelse return));

    switch (event) {
        .state_changed => |sc| {
            cli.display.info(&s.display, "State: {s} → {s}", .{
                @tagName(sc.old_state),
                @tagName(sc.new_state),
            });
        },
        .connected => |c| {
            var ip_buf: [16]u8 = undefined;
            var gw_buf: [16]u8 = undefined;
            cli.display.success(&s.display, "Connected!", .{});
            cli.display.info(&s.display, "  Assigned IP: {s}", .{
                cli.display.formatIpv4(c.assigned_ip, &ip_buf),
            });
            cli.display.info(&s.display, "  Gateway: {s}", .{
                cli.display.formatIpv4(c.gateway_ip, &gw_buf),
            });
        },
        .disconnected => |d| {
            cli.display.warning(&s.display, "Disconnected: {s}", .{@tagName(d.reason)});
        },
        .error_occurred => |e| {
            cli.display.failure(&s.display, "Error: {s}", .{e.message});
        },
        .stats_updated => {},
        .dhcp_configured => |dhcp| {
            var ip_buf: [16]u8 = undefined;
            cli.display.info(&s.display, "DHCP configured: {s}", .{
                cli.display.formatIpv4(dhcp.ip, &ip_buf),
            });
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

test "handleVpnEvent with null user_data does not crash" {
    // Should safely return without doing anything
    handleVpnEvent(.{ .stats_updated = {} }, null);
}
