//! Comprehensive tests for protocol packet builders
//! Tests DHCP DISCOVER, DHCP REQUEST, ARP packets

const std = @import("std");
const protocol = @import("protocol.zig");
const testing = std.testing;

test "build DHCP DISCOVER packet" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x10, 0x20, 0x30 };
    const xid: u32 = 0x12345678;
    var buffer: [512]u8 = undefined;

    const size = try protocol.buildDhcpDiscover(mac, xid, &buffer);

    // Verify packet structure
    try testing.expect(size > 0);
    try testing.expect(size == 292); // Expected DHCP DISCOVER size

    // Check Ethernet header (broadcast)
    try testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 6, buffer[0..6]); // Dest MAC: broadcast
    try testing.expectEqualSlices(u8, &mac, buffer[6..12]); // Src MAC
    try testing.expectEqual(@as(u16, 0x0800), std.mem.readInt(u16, buffer[12..14], .big)); // EtherType: IPv4

    // Check IP header
    try testing.expectEqual(@as(u8, 0x45), buffer[14]); // Version 4, IHL 5
    try testing.expectEqual(@as(u8, 17), buffer[23]); // Protocol: UDP

    // Check UDP ports
    const udp_start = 14 + 20;
    try testing.expectEqual(@as(u16, 68), std.mem.readInt(u16, buffer[udp_start .. udp_start + 2], .big)); // Src port
    try testing.expectEqual(@as(u16, 67), std.mem.readInt(u16, buffer[udp_start + 2 .. udp_start + 4], .big)); // Dst port

    // Check BOOTP header
    const bootp_start = udp_start + 8;
    try testing.expectEqual(@as(u8, 1), buffer[bootp_start]); // op: BOOTREQUEST
    try testing.expectEqual(@as(u8, 1), buffer[bootp_start + 1]); // htype: Ethernet
    try testing.expectEqual(@as(u8, 6), buffer[bootp_start + 2]); // hlen: 6

    // Check transaction ID
    const bootp_xid = std.mem.readInt(u32, buffer[bootp_start + 4 .. bootp_start + 8], .big);
    try testing.expectEqual(xid, bootp_xid);

    // Check DHCP magic cookie
    const magic_offset = bootp_start + 236;
    try testing.expectEqual(@as(u32, 0x63825363), std.mem.readInt(u32, buffer[magic_offset .. magic_offset + 4], .big));
}

test "build DHCP REQUEST packet" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x10, 0x20, 0x30 };
    const xid: u32 = 0x12345678;
    const requested_ip: u32 = 0x0A150001; // 10.21.0.1
    const server_ip: u32 = 0x0A150002; // 10.21.0.2
    var buffer: [512]u8 = undefined;

    const size = try protocol.buildDhcpRequest(mac, xid, requested_ip, server_ip, &buffer);

    try testing.expect(size > 0);
    try testing.expect(size == 304); // Expected DHCP REQUEST size

    // Verify it has DHCP message type option (53) set to REQUEST (3)
    // Option 53 should be in the options section after magic cookie
    const bootp_start = 14 + 20 + 8;
    const options_start = bootp_start + 240; // After magic cookie

    // Search for option 53 (message type)
    var found_msgtype = false;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        if (buffer[options_start + i] == 53) {
            // Found message type option
            try testing.expectEqual(@as(u8, 1), buffer[options_start + i + 1]); // Length = 1
            try testing.expectEqual(@as(u8, 3), buffer[options_start + i + 2]); // Type = REQUEST
            found_msgtype = true;
            break;
        }
    }
    try testing.expect(found_msgtype);
}

test "build Gratuitous ARP packet" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x10, 0x20, 0x30 };
    const ip: u32 = 0x0A150001; // 10.21.0.1
    var buffer: [512]u8 = undefined;

    const size = try protocol.buildGratuitousArp(mac, ip, &buffer);

    try testing.expect(size > 0);
    try testing.expectEqual(@as(usize, 42), size); // Ethernet(14) + ARP(28)

    // Check Ethernet header (broadcast for GARP)
    try testing.expectEqualSlices(u8, &[_]u8{0xFF} ** 6, buffer[0..6]); // Dest MAC: broadcast
    try testing.expectEqualSlices(u8, &mac, buffer[6..12]); // Src MAC
    try testing.expectEqual(@as(u16, 0x0806), std.mem.readInt(u16, buffer[12..14], .big)); // EtherType: ARP

    // Check ARP header
    const arp_start = 14;
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buffer[arp_start .. arp_start + 2], .big)); // Hardware type: Ethernet
    try testing.expectEqual(@as(u16, 0x0800), std.mem.readInt(u16, buffer[arp_start + 2 .. arp_start + 4], .big)); // Protocol: IPv4
    try testing.expectEqual(@as(u8, 6), buffer[arp_start + 4]); // Hardware size
    try testing.expectEqual(@as(u8, 4), buffer[arp_start + 5]); // Protocol size
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, buffer[arp_start + 6 .. arp_start + 8], .big)); // Opcode: REQUEST

    // For GARP, sender IP == target IP
    const sender_ip = std.mem.readInt(u32, buffer[arp_start + 14 .. arp_start + 18], .big);
    const target_ip = std.mem.readInt(u32, buffer[arp_start + 24 .. arp_start + 28], .big);
    try testing.expectEqual(ip, sender_ip);
    try testing.expectEqual(ip, target_ip);
}

test "build ARP REQUEST packet" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x10, 0x20, 0x30 };
    const src_ip: u32 = 0x0A150064; // 10.21.0.100
    const target_ip: u32 = 0x0A150001; // 10.21.0.1
    var buffer: [512]u8 = undefined;

    const size = try protocol.buildArpRequest(mac, src_ip, target_ip, &buffer);

    try testing.expectEqual(@as(usize, 42), size);

    // Check target MAC is broadcast
    const arp_start = 14;
    try testing.expectEqualSlices(u8, &[_]u8{0x00} ** 6, buffer[arp_start + 18 .. arp_start + 24]); // Target MAC: zeros

    // Verify IPs
    const sender_ip = std.mem.readInt(u32, buffer[arp_start + 14 .. arp_start + 18], .big);
    const tgt_ip = std.mem.readInt(u32, buffer[arp_start + 24 .. arp_start + 28], .big);
    try testing.expectEqual(src_ip, sender_ip);
    try testing.expectEqual(target_ip, tgt_ip);
}

test "build ARP REPLY packet" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x10, 0x20, 0x30 };
    const src_ip: u32 = 0x0A150001; // 10.21.0.1
    const target_mac = [_]u8{ 0x82, 0x5C, 0x48, 0x46, 0xB6, 0xA2 };
    const target_ip: u32 = 0x0A150064; // 10.21.0.100
    var buffer: [512]u8 = undefined;

    const size = try protocol.buildArpReply(mac, src_ip, target_mac, target_ip, &buffer);

    try testing.expectEqual(@as(usize, 42), size);

    // Check Ethernet dest is target MAC
    try testing.expectEqualSlices(u8, &target_mac, buffer[0..6]);

    // Check ARP opcode is REPLY (2)
    const arp_start = 14;
    try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, buffer[arp_start + 6 .. arp_start + 8], .big));

    // Verify target MAC in ARP body
    try testing.expectEqualSlices(u8, &target_mac, buffer[arp_start + 18 .. arp_start + 24]);
}

test "protocol builder error handling" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x10, 0x20, 0x30 };
    const xid: u32 = 0x12345678;

    // Buffer too small
    var tiny_buffer: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, protocol.buildDhcpDiscover(mac, xid, &tiny_buffer));
}
