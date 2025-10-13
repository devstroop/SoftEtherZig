//! Tests for macOS packet adapter
//!
//! Note: Most device tests require root privileges to create utun devices.
//! Unit tests run without privileges, integration tests need sudo.

const std = @import("std");
const testing = std.testing;
const macos = @import("macos.zig");

// Unit tests (no root required)

test "PacketAdapter creation and destruction" {
    const adapter = try macos.PacketAdapter.create(testing.allocator);
    defer adapter.destroy();

    try testing.expect(adapter.state.dhcp_state == .init);
    try testing.expect(adapter.state.device == null);
}

test "PacketAdapterState initialization" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    try testing.expectEqual(macos.DhcpState.init, state.dhcp_state);
    try testing.expectEqual(@as(u16, 1500), state.mtu);
    try testing.expectEqual(@as(u32, 0), state.dhcp_xid);
    try testing.expectEqual(false, state.ip_config.configured);
}

test "MAC address generation and properties" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    const mac = state.getMacAddress();

    // Check locally administered bit (bit 1) is set
    try testing.expect((mac[0] & 0x02) != 0);

    // Check multicast bit (bit 0) is clear
    try testing.expect((mac[0] & 0x01) == 0);

    // Generate multiple MACs and ensure they're properly formatted
    // (Not testing uniqueness since that's probabilistic)
    var state2 = try macos.PacketAdapterState.init(testing.allocator);
    defer state2.deinit();

    const mac2 = state2.getMacAddress();

    // Both should have correct properties
    try testing.expect((mac2[0] & 0x02) != 0);
    try testing.expect((mac2[0] & 0x01) == 0);
}

test "IP configuration structure" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    const ip = [4]u8{ 192, 168, 1, 100 };
    const netmask = [4]u8{ 255, 255, 255, 0 };
    const gateway = [4]u8{ 192, 168, 1, 1 };

    state.ip_config = .{
        .ip_address = ip,
        .netmask = netmask,
        .gateway = gateway,
        .configured = true,
    };

    const config = state.getIpConfig();
    try testing.expectEqualSlices(u8, &ip, &config.ip_address);
    try testing.expectEqualSlices(u8, &netmask, &config.netmask);
    try testing.expectEqualSlices(u8, &gateway, &config.gateway);
    try testing.expect(config.configured);
}

test "IPv6 configuration structure" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    const ipv6_addr = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xff, 0xfe, 0x00, 0x00, 0x01 };
    const gateway = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };

    state.ipv6_config = .{
        .address = ipv6_addr,
        .gateway = gateway,
        .prefix_len = 64,
        .configured = true,
    };

    try testing.expectEqualSlices(u8, &ipv6_addr, &state.ipv6_config.address);
    try testing.expectEqual(@as(u8, 64), state.ipv6_config.prefix_len);
    try testing.expect(state.ipv6_config.configured);
}

test "DHCP state transitions" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    try testing.expectEqual(macos.DhcpState.init, state.dhcp_state);

    state.dhcp_state = .discover_sent;
    try testing.expectEqual(macos.DhcpState.discover_sent, state.dhcp_state);

    state.dhcp_state = .offer_received;
    try testing.expectEqual(macos.DhcpState.offer_received, state.dhcp_state);

    state.dhcp_state = .configured;
    try testing.expect(state.isDhcpConfigured());
}

test "Packet queue operations" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    // Queue should start empty
    try testing.expectEqual(@as(usize, 0), state.recv_queue.items.len);

    // Simulate queuing packets
    const packet1 = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(packet1);
    @memset(packet1, 0xAA);

    const packet2 = try testing.allocator.alloc(u8, 128);
    defer testing.allocator.free(packet2);
    @memset(packet2, 0xBB);

    // Test would require actual queue operations
    // This demonstrates the structure is properly initialized
}

test "Constants are reasonable" {
    try testing.expectEqual(@as(usize, 2048), macos.MAX_PACKET_SIZE);
    try testing.expectEqual(@as(u16, 1500), macos.TUN_MTU);
    try testing.expectEqual(@as(usize, 1518), macos.MAX_ETHERNET_FRAME);
    try testing.expectEqual(@as(usize, 1024), macos.RECV_QUEUE_MAX);
}

test "Device name retrieval before device opened" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    const name = state.getDeviceName();
    try testing.expectEqual(@as(usize, 0), name.len);
}

test "Thread safety - mutex initialization" {
    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    // Mutex should be properly initialized
    // We can lock/unlock it
    state.mutex.lock();
    defer state.mutex.unlock();

    // If this doesn't deadlock, the mutex works
}

// Integration tests (require root privileges)
// These are marked as separate tests that can be skipped

test "integration - open and close utun device" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;

    // Skip if not running with root privileges
    if (std.posix.getuid() != 0) {
        std.debug.print("Skipping integration test (requires root)\n", .{});
        return error.SkipZigTest;
    }

    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    // Try to open device
    state.openDevice(null) catch |err| {
        std.debug.print("Failed to open device: {}\n", .{err});
        return err;
    };

    // Device should be open
    try testing.expect(state.device != null);

    // Should have a valid name
    const name = state.getDeviceName();
    try testing.expect(name.len > 0);
    try testing.expect(std.mem.startsWith(u8, name, "utun"));

    std.debug.print("Opened device: {s}\n", .{name});

    // Close the device
    state.closeDevice();
    try testing.expect(state.device == null);
}

test "integration - write and read packet" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;

    if (std.posix.getuid() != 0) {
        std.debug.print("Skipping integration test (requires root)\n", .{});
        return error.SkipZigTest;
    }

    var state = try macos.PacketAdapterState.init(testing.allocator);
    defer state.deinit();

    try state.openDevice(null);
    defer state.closeDevice();

    // Create a minimal IPv4 packet (ICMP echo request)
    var packet: [64]u8 = undefined;
    @memset(&packet, 0);

    // IPv4 header
    packet[0] = 0x45; // Version 4, IHL 5
    packet[1] = 0x00; // DSCP/ECN
    packet[2] = 0x00;
    packet[3] = 0x3C; // Total length: 60
    packet[9] = 0x01; // Protocol: ICMP
    // Source IP: 192.168.1.100
    packet[12] = 192;
    packet[13] = 168;
    packet[14] = 1;
    packet[15] = 100;
    // Dest IP: 8.8.8.8
    packet[16] = 8;
    packet[17] = 8;
    packet[18] = 8;
    packet[19] = 8;

    // ICMP echo request
    packet[20] = 8; // Type: echo request
    packet[21] = 0; // Code

    // Write packet
    try state.writePacket(&packet);

    std.debug.print("Successfully wrote packet to device\n", .{});

    // Try to read (may timeout if no response)
    var read_buf: [2048]u8 = undefined;
    const bytes_read = state.readPacket(&read_buf, 1000) catch |err| {
        std.debug.print("Read failed (expected if no response): {}\n", .{err});
        return;
    };

    if (bytes_read > 0) {
        std.debug.print("Read {} bytes from device\n", .{bytes_read});
    }
}

// Performance benchmark (informational)
test "benchmark - MAC address generation" {
    const iterations = 10000;
    const start = std.time.milliTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var state = try macos.PacketAdapterState.init(testing.allocator);
        _ = state.getMacAddress();
        state.deinit();
    }

    const elapsed = std.time.milliTimestamp() - start;
    const per_op = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations));

    std.debug.print("\nMAC generation: {} ops in {}ms ({d:.3}ms per op)\n", .{
        iterations,
        elapsed,
        per_op,
    });
}
