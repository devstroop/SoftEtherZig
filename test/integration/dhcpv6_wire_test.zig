//! DHCPv6 wire-format tests (RFC 8415).
//!
//! Golden-byte tests that validate the byte layout of DHCPv6 messages
//! without any sockets or live server. These catch wire-format bugs
//! (misencoded options, wrong lengths, byte-order mistakes) that would
//! cause silent interop failures with real DHCPv6 servers.
//!
//! The fixture pattern mirrors handshake_fixture_test.zig — scripted
//! transport, no infrastructure, CI-friendly.

const std = @import("std");
const testing = std.testing;

const dhcpv6 = @import("dhcpv6");
const Dhcpv6Client = dhcpv6.Dhcpv6Client;
const Dhcpv6MessageType = dhcpv6.Dhcpv6MessageType;

const Allocator = std.mem.Allocator;

// ============================================================================
// Test: Solicit byte layout matches RFC 8415 §16 example structure
// ============================================================================

test "DHCPv6 Solicit pack matches RFC 8415 byte layout" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    var client = Dhcpv6Client.init(testing.allocator, mac);

    var buffer: [512]u8 = undefined;
    const len = try client.buildSolicit(&buffer);

    // === Byte 0: Message type = 1 (Solicit) ===
    try testing.expectEqual(@as(u8, 1), buffer[0]);

    // === Bytes 1-3: Transaction ID (3 bytes, big-endian) ===
    const xid = (@as(u32, buffer[1]) << 16) |
        (@as(u32, buffer[2]) << 8) |
        buffer[3];
    try testing.expectEqual(client.transaction_id, xid);

    // === Byte 4-7: Rapid Commit option (option code 14, length 0) ===
    try testing.expectEqual(@as(u8, 0x00), buffer[4]); // option code high
    try testing.expectEqual(@as(u8, 14), buffer[5]); // option code low
    try testing.expectEqual(@as(u8, 0x00), buffer[6]); // length high
    try testing.expectEqual(@as(u8, 0x00), buffer[7]); // length low

    // === Bytes 8-11: Client Identifier option header ===
    const client_id_code = (@as(u16, buffer[8]) << 8) | buffer[9];
    try testing.expectEqual(@as(u16, 1), client_id_code); // option 1 = Client ID
    const client_id_len = (@as(u16, buffer[10]) << 8) | buffer[11];
    try testing.expectEqual(@as(u16, 14), client_id_len); // DUID-LLT = 14 bytes

    // === DUID-LLT format (bytes 12-25) ===
    // Type: 2 (DUID-LLT)
    try testing.expectEqual(@as(u8, 0x00), buffer[12]);
    try testing.expectEqual(@as(u8, 0x02), buffer[13]);
    // Hardware type: 1 (Ethernet)
    try testing.expectEqual(@as(u8, 0x00), buffer[14]);
    try testing.expectEqual(@as(u8, 0x01), buffer[15]);
    // Timestamp: 4 bytes (seconds since 2000-01-01)
    // MAC address at offset 20-25
    try testing.expectEqual(@as(u8, 0x02), buffer[20]);
    try testing.expectEqual(@as(u8, 0x00), buffer[21]);
    try testing.expectEqual(@as(u8, 0x5E), buffer[22]);
    try testing.expectEqual(@as(u8, 0x11), buffer[23]);
    try testing.expectEqual(@as(u8, 0x22), buffer[24]);
    try testing.expectEqual(@as(u8, 0x33), buffer[25]);

    // === Client ID option ends at byte 26 (8 + 4 + 14 = 26) ===
    // === IA_NA option starts at byte 26 ===
    const ia_na_code = (@as(u16, buffer[26]) << 8) | buffer[27];
    try testing.expectEqual(@as(u16, 3), ia_na_code); // option 3 = IA_NA

    // IA_NA data length (after the 4-byte option header)
    const ia_na_len = (@as(u16, buffer[28]) << 8) | buffer[29];
    // IA_NA must be >= 12 bytes (IAID + T1 + T2 + sub-options)
    try testing.expect(ia_na_len >= 12);

    // IAID (4 bytes) at offset 30
    const iaid = (@as(u32, buffer[30]) << 24) |
        (@as(u32, buffer[31]) << 16) |
        (@as(u32, buffer[32]) << 8) |
        buffer[33];
    try testing.expectEqual(client.iaid, iaid);

    // T1 = 0 at offset 34
    try testing.expectEqual(@as(u32, 0), (@as(u32, buffer[34]) << 24) |
        (@as(u32, buffer[35]) << 16) |
        (@as(u32, buffer[36]) << 8) |
        buffer[37]);

    // T2 = 0 at offset 38
    try testing.expectEqual(@as(u32, 0), (@as(u32, buffer[38]) << 24) |
        (@as(u32, buffer[39]) << 16) |
        (@as(u32, buffer[40]) << 8) |
        buffer[41]);

    // === Option Request Option (ORO) follows IA_NA ===
    const oro_offset = 26 + 4 + ia_na_len;
    const oro_code = (@as(u16, buffer[oro_offset]) << 8) | buffer[oro_offset + 1];
    try testing.expectEqual(@as(u16, 6), oro_code); // option 6 = ORO

    const oro_len = (@as(u16, buffer[oro_offset + 2]) << 8) | buffer[oro_offset + 3];
    try testing.expectEqual(@as(u16, 6), oro_len); // 3 requested options × 2 bytes

    // ORO should request DNS (23), Domain Search (24), SIP (21)
    try testing.expectEqual(@as(u8, 0x00), buffer[oro_offset + 4]);
    try testing.expectEqual(@as(u8, 23), buffer[oro_offset + 5]);
    try testing.expectEqual(@as(u8, 0x00), buffer[oro_offset + 6]);
    try testing.expectEqual(@as(u8, 24), buffer[oro_offset + 7]);
    try testing.expectEqual(@as(u8, 0x00), buffer[oro_offset + 8]);
    try testing.expectEqual(@as(u8, 21), buffer[oro_offset + 9]);

    // Total message should be reasonable: header(4) + rapid_commit(4) + client_id(18)
    //   + ia_na(~16) + oro(10) = ~52 bytes minimum
    try testing.expect(len >= 50);
    try testing.expect(len <= buffer.len);
}

// ============================================================================
// Test: DUID-LLT format validation
// ============================================================================

test "DUID-LLT format: type=2, hwtype=1 (Ethernet), time anchored to 2000-01-01" {
    const mac = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const client = Dhcpv6Client.init(testing.allocator, mac);

    // DUID-LLT structure (14 bytes total):
    // [0-1]  duid-type: 0x0002
    // [2-3]  hw-type: 0x0001 (Ethernet)
    // [4-7]  time: seconds since 2000-01-01T00:00:00 UTC
    // [8-13] link-layer address: MAC

    try testing.expectEqual(@as(u8, 0x00), client.duid[0]);
    try testing.expectEqual(@as(u8, 0x02), client.duid[1]);

    try testing.expectEqual(@as(u8, 0x00), client.duid[2]);
    try testing.expectEqual(@as(u8, 0x01), client.duid[3]);

    // Timestamp: at time of test, should be non-zero and reasonable
    const hw_time = (@as(u32, client.duid[4]) << 24) |
        (@as(u32, client.duid[5]) << 16) |
        (@as(u32, client.duid[6]) << 8) |
        client.duid[7];
    // Should be > 0 (we're past 2000) and < ~2 billion (year 2063)
    try testing.expect(hw_time > 0);
    try testing.expect(hw_time < 2_000_000_000);

    // MAC at offset 8-13
    try testing.expectEqual(@as(u8, 0xAA), client.duid[8]);
    try testing.expectEqual(@as(u8, 0xBB), client.duid[9]);
    try testing.expectEqual(@as(u8, 0xCC), client.duid[10]);
    try testing.expectEqual(@as(u8, 0xDD), client.duid[11]);
    try testing.expectEqual(@as(u8, 0xEE), client.duid[12]);
    try testing.expectEqual(@as(u8, 0xFF), client.duid[13]);
}

// ============================================================================
// Test: Request pack includes Server ID and IAADDR sub-option
// ============================================================================

test "DHCPv6 Request pack includes Server ID + IAADDR sub-option" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    const client = Dhcpv6Client.init(testing.allocator, mac);

    const server_duid = [_]u8{ 0x00, 0x03, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03 };
    const offered_addr = [_]u8{ 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    var buffer: [512]u8 = undefined;
    const len = try client.buildRequest(&buffer, &server_duid, offered_addr);

    // Sanity: Request must be non-trivial size
    try testing.expect(len > 40);

    // Byte 0: Message type = 3 (Request)
    try testing.expectEqual(@as(u8, 3), buffer[0]);

    // Bytes 1-3: Transaction ID
    const xid = (@as(u32, buffer[1]) << 16) |
        (@as(u32, buffer[2]) << 8) |
        buffer[3];
    try testing.expectEqual(client.transaction_id, xid);

    // Bytes 4-7: Server Identifier option (code 2)
    const srv_id_code = (@as(u16, buffer[4]) << 8) | buffer[5];
    try testing.expectEqual(@as(u16, 2), srv_id_code);

    const srv_id_len = (@as(u16, buffer[6]) << 8) | buffer[7];
    try testing.expectEqual(@as(u16, 12), srv_id_len); // matches server_duid.len

    // Server DUID at offset 8-19
    try testing.expectEqualSlices(u8, &server_duid, buffer[8..20]);

    // Client Identifier follows (code 1)
    const clt_id_code = (@as(u16, buffer[20]) << 8) | buffer[21];
    try testing.expectEqual(@as(u16, 1), clt_id_code);

    // IA_NA follows
    // Find IA_NA by scanning (it's after Client ID)
    const clt_id_len = (@as(u16, buffer[22]) << 8) | buffer[23];
    const ia_na_offset = 20 + 4 + clt_id_len;

    const ia_na_code = (@as(u16, buffer[ia_na_offset]) << 8) | buffer[ia_na_offset + 1];
    try testing.expectEqual(@as(u16, 3), ia_na_code);

    // Inside IA_NA, find IAADDR sub-option (code 5)
    // IA_NA data starts at ia_na_offset + 4
    const ia_na_data = buffer[ia_na_offset + 4 ..][0..(@as(u16, buffer[ia_na_offset + 2]) << 8 | buffer[ia_na_offset + 3])];

    // Skip IAID(4) + T1(4) + T2(4) = 12 bytes
    const iaaddr_code = (@as(u16, ia_na_data[12]) << 8) | ia_na_data[13];
    try testing.expectEqual(@as(u16, 5), iaaddr_code); // IAADDR

    const iaaddr_len = (@as(u16, ia_na_data[14]) << 8) | ia_na_data[15];
    try testing.expectEqual(@as(u16, 24), iaaddr_len); // addr(16) + pref(4) + valid(4)

    // Address at ia_na_data[16..32]
    try testing.expectEqualSlices(u8, &offered_addr, ia_na_data[16..32]);
}

// ============================================================================
// Test: Parse Reply with IAADDR + DNS + search list
// ============================================================================

test "DHCPv6 Reply parser extracts IAADDR + DNS + search-list" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    var client = Dhcpv6Client.init(testing.allocator, mac);

    // Build a synthetic Reply message (type 7)
    var reply: [256]u8 = undefined;
    var pos: usize = 0;

    // Message type: Reply (7)
    reply[pos] = 7;
    pos += 1;

    // Transaction ID (must match client's)
    reply[pos] = @intCast((client.transaction_id >> 16) & 0xFF);
    reply[pos + 1] = @intCast((client.transaction_id >> 8) & 0xFF);
    reply[pos + 2] = @intCast(client.transaction_id & 0xFF);
    pos += 3;

    // Option: Server ID (code 2, len 4)
    reply[pos] = 0;
    reply[pos + 1] = 2;
    reply[pos + 2] = 0;
    reply[pos + 3] = 4;
    pos += 4;
    // Fake server DUID bytes
    reply[pos] = 0xDE;
    reply[pos + 1] = 0xAD;
    reply[pos + 2] = 0xBE;
    reply[pos + 3] = 0xEF;
    pos += 4;

    // Option: IA_NA (code 3)
    const ia_na_start = pos;
    pos += 4; // skip header
    const ia_na_data_start = pos;

    // IAID (4 bytes)
    reply[pos] = 0;
    reply[pos + 1] = 0;
    reply[pos + 2] = 0;
    reply[pos + 3] = 0;
    pos += 4;
    // T1 = 3600
    reply[pos] = 0;
    reply[pos + 1] = 0;
    reply[pos + 2] = 0x0E;
    reply[pos + 3] = 0x10;
    pos += 4;
    // T2 = 5400
    reply[pos] = 0;
    reply[pos + 1] = 0;
    reply[pos + 2] = 0x15;
    reply[pos + 3] = 0x18;
    pos += 4;

    // IAADDR sub-option (code 5, len 24)
    reply[pos] = 0;
    reply[pos + 1] = 5;
    reply[pos + 2] = 0;
    reply[pos + 3] = 24;
    pos += 4;
    // Address: 2001:db8::1
    const expected_addr = [_]u8{ 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    @memcpy(reply[pos..][0..16], &expected_addr);
    pos += 16;
    // Preferred lifetime = 1800
    reply[pos] = 0;
    reply[pos + 1] = 0;
    reply[pos + 2] = 0x07;
    reply[pos + 3] = 0x08;
    pos += 4;
    // Valid lifetime = 3600
    reply[pos] = 0;
    reply[pos + 1] = 0;
    reply[pos + 2] = 0x0E;
    reply[pos + 3] = 0x10;
    pos += 4;

    // Backfill IA_NA option length
    const ia_na_len = @as(u16, @intCast(pos - ia_na_data_start));
    reply[ia_na_start] = 0;
    reply[ia_na_start + 1] = 3;
    reply[ia_na_start + 2] = @intCast((ia_na_len >> 8) & 0xFF);
    reply[ia_na_start + 3] = @intCast(ia_na_len & 0xFF);

    // Option: DNS Recursive Name Server (code 23, 1 address = 16 bytes)
    reply[pos] = 0;
    reply[pos + 1] = 23;
    reply[pos + 2] = 0;
    reply[pos + 3] = 16;
    pos += 4;
    // DNS: 2001:4860:4860::8888 (Google)
    const dns_addr = [_]u8{ 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88 };
    @memcpy(reply[pos..][0..16], &dns_addr);
    pos += 16;

    // Option: Domain Search List (code 24, len 28)
    reply[pos] = 0;
    reply[pos + 1] = 24;
    reply[pos + 2] = 0;
    reply[pos + 3] = 28;
    pos += 4;
    // Search list: "example.com\0" + "vpn.example.com\0"
    const search1 = "example.com";
    const search2 = "vpn.example.com";
    @memcpy(reply[pos..][0..search1.len], search1);
    pos += search1.len;
    reply[pos] = 0;
    pos += 1;
    @memcpy(reply[pos..][0..search2.len], search2);
    pos += search2.len;
    reply[pos] = 0;
    pos += 1;

    // Parse the reply
    const result = try client.parseResponse(reply[0..pos]);
    try testing.expect(result != null);

    const parsed = result.?;
    try testing.expectEqual(Dhcpv6MessageType.reply, parsed.msg_type);
    try testing.expect(parsed.server_duid != null);

    // Verify assigned address
    try testing.expect(client.config.isValid());
    try testing.expectEqualSlices(u8, &expected_addr, &client.config.address);

    // Verify preferred/valid lifetimes
    try testing.expectEqual(@as(u32, 1800), client.config.preferred_lifetime);
    try testing.expectEqual(@as(u32, 3600), client.config.valid_lifetime);
    try testing.expectEqual(@as(u8, 128), client.config.prefix_len);

    // Verify DNS
    try testing.expectEqual(@as(u8, 1), client.config.dns_count);
    try testing.expectEqualSlices(u8, &dns_addr, &client.config.dns_servers[0]);

    // Verify search list
    try testing.expect(client.config.search_list_len > 0);
    try testing.expectEqual(@as(u8, 0), client.config.search_list[search1.len]); // null separator
    try testing.expectEqual(@as(u8, 0), client.config.search_list[search1.len + 1 + search2.len]); // null terminator
}

// ============================================================================
// Test: Transaction ID mismatch is rejected
// ============================================================================

test "DHCPv6 Reply with wrong transaction ID is rejected" {
    const mac = [_]u8{ 0x02, 0x00, 0x5E, 0x11, 0x22, 0x33 };
    var client = Dhcpv6Client.init(testing.allocator, mac);

    // Build a Reply with a DIFFERENT transaction ID
    var reply: [64]u8 = undefined;
    reply[0] = 7; // Reply
    reply[1] = 0xFF; // wrong XID byte 0
    reply[2] = 0xFF; // wrong XID byte 1
    reply[3] = 0xFF; // wrong XID byte 2
    reply[4] = 0;
    reply[5] = 2; // Server ID option
    reply[6] = 0;
    reply[7] = 2;
    reply[8] = 0xAA;
    reply[9] = 0xBB;

    const result = try client.parseResponse(reply[0..10]);
    try testing.expect(result == null); // Should reject due to XID mismatch
}
