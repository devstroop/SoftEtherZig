//! Phase 9: Parallel Comparison Tests
//!
//! These tests compare the pure Zig implementation against the C bridge
//! to ensure compatibility before C bridge removal.
//!
//! Run with: zig build test-comparison

const std = @import("std");
const testing = std.testing;

// Pure Zig modules
const crypto = @import("crypto");
const protocol = @import("protocol");
const session_mod = @import("session");
const lib = @import("lib");
const client = @import("client");
const cli = @import("cli");

// ============================================================================
// Password Hash Comparison Tests
// ============================================================================

test "password hash: SHA0(password + UPPERCASE(username))" {
    // Test vector: user="devstroop", pass="devstroop111222"
    // Expected hash from C implementation: T2kl2mB84H5y2tn7n9qf65/8jXI=
    const expected_hash = "T2kl2mB84H5y2tn7n9qf65/8jXI=";

    const hash = computePasswordHash("devstroop", "devstroop111222");
    try testing.expectEqualStrings(expected_hash, &hash);
}

test "password hash: empty password" {
    // SHA0("" + "USER") = SHA0("USER")
    const hash = computePasswordHash("user", "");
    try testing.expectEqual(@as(usize, 28), hash.len); // Base64 of 20 bytes
}

test "password hash: empty username" {
    // SHA0("password" + "") = SHA0("password")
    const hash = computePasswordHash("", "password");
    try testing.expectEqual(@as(usize, 28), hash.len);
}

test "password hash: case sensitivity" {
    // Username should be uppercased, password should not
    const hash1 = computePasswordHash("user", "Password");
    const hash2 = computePasswordHash("USER", "Password");
    const hash3 = computePasswordHash("user", "password");

    // user and USER should produce same hash (username uppercased)
    try testing.expectEqualStrings(&hash1, &hash2);
    // Different password case should produce different hash
    try testing.expect(!std.mem.eql(u8, &hash1, &hash3));
}

test "password hash: unicode username" {
    // Test with non-ASCII characters (treated as bytes)
    const hash = computePasswordHash("用户", "密码");
    try testing.expectEqual(@as(usize, 28), hash.len);
}

test "password hash: long credentials" {
    // Test with reasonable-length credentials (64 chars each)
    var long_user: [64]u8 = undefined;
    var long_pass: [64]u8 = undefined;
    @memset(&long_user, 'u');
    @memset(&long_pass, 'p');

    const hash = computePasswordHash(&long_user, &long_pass);
    try testing.expectEqual(@as(usize, 28), hash.len);
}

// Helper to compute SoftEther password hash
fn computePasswordHash(username: []const u8, password: []const u8) [28]u8 {
    var input_buf: [512]u8 = undefined;
    var username_upper: [256]u8 = undefined;

    const pass_len = @min(password.len, 256);
    const user_len = @min(username.len, 256);

    // Copy password first
    @memcpy(input_buf[0..pass_len], password[0..pass_len]);

    // Convert username to uppercase and append
    for (username[0..user_len], 0..) |c, i| {
        username_upper[i] = std.ascii.toUpper(c);
    }
    @memcpy(input_buf[pass_len..][0..user_len], username_upper[0..user_len]);

    const input_len = pass_len + user_len;
    const hash = crypto.sha0.hash(input_buf[0..input_len]);

    // Base64 encode
    const base64 = std.base64.standard;
    var b64_buf: [28]u8 = undefined;
    _ = base64.Encoder.encode(&b64_buf, &hash);
    return b64_buf;
}

// ============================================================================
// SHA-0 Implementation Tests (vs reference vectors)
// ============================================================================

test "SHA0: empty string" {
    const hash = crypto.sha0.hash("");
    const hex = bytesToHex(&hash);
    // SHA-0("") reference value
    try testing.expectEqualStrings("f96cea198ad1dd5617ac084a3d92c6107708c0ef", &hex);
}

test "SHA0: 'abc'" {
    const hash = crypto.sha0.hash("abc");
    const hex = bytesToHex(&hash);
    // SHA-0("abc") reference value
    try testing.expectEqualStrings("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", &hex);
}

test "SHA0: long message" {
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const hash = crypto.sha0.hash(msg);
    const hex = bytesToHex(&hash);
    // SHA-0 reference value for this message
    try testing.expectEqualStrings("d2516ee1acfa5baf33dfc1c471e438449ef134c8", &hex);
}

fn bytesToHex(bytes: []const u8) [40]u8 {
    var hex: [40]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        hex[i * 2] = hex_chars[b >> 4];
        hex[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return hex;
}

// ============================================================================
// Pack Serialization Tests
// ============================================================================

test "Pack: element types" {
    var pack = protocol.Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.addInt("port", 443);
    try pack.addStr("host", "test.com");
    try pack.addBool("enabled", true);

    try testing.expectEqual(@as(u32, 443), pack.getInt("port").?);
    try testing.expectEqualStrings("test.com", pack.getStr("host").?);
    try testing.expect(pack.getBool("enabled").?);
}

test "Pack: round-trip serialization" {
    var pack = protocol.Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.addInt("version", 0x0413);
    try pack.addStr("client_str", "SoftEther Zig Client");
    try pack.addInt64("timestamp", 1703088000);

    const serialized = try pack.toBytes(testing.allocator);
    defer testing.allocator.free(serialized);

    var parsed = try protocol.Pack.fromBytes(testing.allocator, serialized);
    defer parsed.deinit();

    try testing.expectEqual(@as(u32, 0x0413), parsed.getInt("version").?);
    try testing.expectEqualStrings("SoftEther Zig Client", parsed.getStr("client_str").?);
}

test "Pack: binary format header" {
    var pack = protocol.Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.addInt("test", 1);

    const serialized = try pack.toBytes(testing.allocator);
    defer testing.allocator.free(serialized);

    // First 4 bytes should be element count (big-endian)
    const count = std.mem.readInt(u32, serialized[0..4], .big);
    try testing.expectEqual(@as(u32, 1), count);
}

// ============================================================================
// String Library Tests
// ============================================================================

test "strings: toUpper" {
    const upper = try lib.strings.toUpper(testing.allocator, "hello");
    defer testing.allocator.free(upper);
    try testing.expectEqualStrings("HELLO", upper);
}

test "strings: toLower" {
    const lower = try lib.strings.toLower(testing.allocator, "HELLO");
    defer testing.allocator.free(lower);
    try testing.expectEqualStrings("hello", lower);
}

test "strings: trim" {
    try testing.expectEqualStrings("hello", lib.strings.trim("  hello  "));
    try testing.expectEqualStrings("world", lib.strings.trim("\t\nworld\r\n"));
}

// ============================================================================
// Memory Tests
// ============================================================================

test "TrackingAllocator: allocation stats" {
    var tracker = lib.memory.TrackingAllocator.init(testing.allocator);

    const slice = try tracker.wrap(u8, 100);
    try testing.expectEqual(@as(usize, 1), tracker.allocations);
    try testing.expectEqual(@as(usize, 100), tracker.current_bytes);

    tracker.unwrap(u8, slice);
    try testing.expectEqual(@as(usize, 1), tracker.deallocations);
    try testing.expectEqual(@as(usize, 0), tracker.current_bytes);
    try testing.expect(!tracker.checkLeaks());
}

// ============================================================================
// Unicode Tests
// ============================================================================

test "Unicode: UTF-8 validation" {
    try testing.expect(lib.unicode.isValidUtf8("Hello"));
    try testing.expect(lib.unicode.isValidUtf8("日本語"));
    try testing.expect(!lib.unicode.isValidUtf8(&[_]u8{ 0xFF, 0xFE }));
}

test "Unicode: UTF-8 to UTF-16 LE" {
    const utf8 = "Hello";
    const utf16 = try lib.unicode.utf8ToUtf16Le(testing.allocator, utf8);
    defer testing.allocator.free(utf16);

    // "Hello" in UTF-16 LE should be 5 code units
    try testing.expectEqual(@as(usize, 5), utf16.len);
}

// ============================================================================
// Time Tests
// ============================================================================

test "Timer: basic functionality" {
    var timer = lib.time.Timer.begin();

    std.Thread.sleep(10 * std.time.ns_per_ms);

    const elapsed = timer.readMs();
    try testing.expect(elapsed >= 10);
    try testing.expect(elapsed < 200); // Should be close to 10ms, allow margin
}

// ============================================================================
// Integration Readiness Tests
// ============================================================================

test "Integration: VpnClient can be created" {
    const config = client.ClientConfig{
        .server_host = "192.168.1.1",
        .hub_name = "TEST",
        .auth = .{ .anonymous = {} },
    };

    var vpn = client.VpnClient.init(testing.allocator, config);
    defer vpn.deinit();

    try testing.expectEqual(client.ClientState.disconnected, vpn.getState());
    try testing.expect(!vpn.isConnected());
}

test "Integration: Config builder pattern" {
    var builder = client.ClientConfigBuilder.init("vpn.example.com", "VPN");
    _ = builder.setPort(443);
    _ = builder.setPasswordAuth("user", "pass");
    _ = builder.setReconnect(true, 5);
    const config = builder.build();

    try testing.expectEqualStrings("vpn.example.com", config.server_host);
    try testing.expectEqual(@as(u16, 443), config.server_port);
    try testing.expectEqualStrings("VPN", config.hub_name);
    try testing.expect(config.reconnect.enabled);
}

test "Integration: CLI args struct" {
    var args = cli.CliArgs{
        .server = "test.com",
        .hub = "HUB",
        .username = "user",
        .password = "pass",
        .port = 443,
    };
    defer args.deinit();

    try testing.expectEqualStrings("test.com", args.server.?);
    try testing.expectEqual(@as(u16, 443), args.port);
}
