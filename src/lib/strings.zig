//! String Utilities Module
//!
//! Pure Zig replacement for Mayaqua/Str.c
//! Provides string manipulation, formatting, and parsing utilities.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Maximum reasonable string length for network data
pub const MAX_STRING_LEN = 65535;

/// String comparison (case-sensitive)
pub fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// String comparison (case-insensitive)
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

/// Check if string starts with prefix
pub fn startsWith(str: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, str, prefix);
}

/// Check if string ends with suffix
pub fn endsWith(str: []const u8, suffix: []const u8) bool {
    return std.mem.endsWith(u8, str, suffix);
}

/// Check if string starts with prefix (case-insensitive)
pub fn startsWithIgnoreCase(str: []const u8, prefix: []const u8) bool {
    if (str.len < prefix.len) return false;
    return eqlIgnoreCase(str[0..prefix.len], prefix);
}

/// Trim whitespace from both ends
pub fn trim(str: []const u8) []const u8 {
    return std.mem.trim(u8, str, &std.ascii.whitespace);
}

/// Trim whitespace from left
pub fn trimLeft(str: []const u8) []const u8 {
    return std.mem.trimLeft(u8, str, &std.ascii.whitespace);
}

/// Trim whitespace from right
pub fn trimRight(str: []const u8) []const u8 {
    return std.mem.trimRight(u8, str, &std.ascii.whitespace);
}

/// Convert to uppercase (allocates)
pub fn toUpper(allocator: Allocator, str: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, str.len);
    for (str, 0..) |c, i| {
        result[i] = std.ascii.toUpper(c);
    }
    return result;
}

/// Convert to lowercase (allocates)
pub fn toLower(allocator: Allocator, str: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, str.len);
    for (str, 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return result;
}

/// Split string by delimiter
pub fn split(str: []const u8, delimiter: u8) std.mem.SplitIterator(u8, .scalar) {
    return std.mem.splitScalar(u8, str, delimiter);
}

/// Split string by any of the delimiter bytes
pub fn splitAny(str: []const u8, delimiters: []const u8) std.mem.SplitIterator(u8, .any) {
    return std.mem.splitAny(u8, str, delimiters);
}

/// Tokenize (skip empty)
pub fn tokenize(str: []const u8, delimiters: []const u8) std.mem.TokenIterator(u8, .any) {
    return std.mem.tokenizeAny(u8, str, delimiters);
}

/// Find first occurrence of needle
pub fn indexOf(haystack: []const u8, needle: []const u8) ?usize {
    return std.mem.indexOf(u8, haystack, needle);
}

/// Find last occurrence of needle
pub fn lastIndexOf(haystack: []const u8, needle: []const u8) ?usize {
    return std.mem.lastIndexOf(u8, haystack, needle);
}

/// Count occurrences of needle
pub fn count(haystack: []const u8, needle: []const u8) usize {
    return std.mem.count(u8, haystack, needle);
}

/// Replace all occurrences (allocates)
pub fn replace(allocator: Allocator, str: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, allocator, str, needle, replacement);
}

/// Join strings with separator (allocates)
pub fn join(allocator: Allocator, strings: []const []const u8, separator: []const u8) ![]u8 {
    return std.mem.join(allocator, separator, strings);
}

/// Concatenate strings (allocates)
pub fn concat(allocator: Allocator, strings: []const []const u8) ![]u8 {
    return std.mem.concat(allocator, u8, strings);
}

/// Duplicate string (allocates)
pub fn dupe(allocator: Allocator, str: []const u8) ![]u8 {
    return allocator.dupe(u8, str);
}

/// Format string (allocates)
pub fn format(allocator: Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return std.fmt.allocPrint(allocator, fmt, args);
}

// ============================================================================
// Parsing utilities
// ============================================================================

/// Parse integer from string
pub fn parseInt(comptime T: type, str: []const u8, radix: u8) !T {
    return std.fmt.parseInt(T, str, radix);
}

/// Parse unsigned integer
pub fn parseUnsigned(comptime T: type, str: []const u8, radix: u8) !T {
    return std.fmt.parseUnsigned(T, str, radix);
}

/// Parse float
pub fn parseFloat(comptime T: type, str: []const u8) !T {
    return std.fmt.parseFloat(T, str);
}

/// Parse boolean ("true", "false", "1", "0", "yes", "no")
pub fn parseBool(str: []const u8) !bool {
    const trimmed = trim(str);
    if (eqlIgnoreCase(trimmed, "true") or eqlIgnoreCase(trimmed, "yes") or eql(trimmed, "1")) {
        return true;
    }
    if (eqlIgnoreCase(trimmed, "false") or eqlIgnoreCase(trimmed, "no") or eql(trimmed, "0")) {
        return false;
    }
    return error.InvalidBoolean;
}

// ============================================================================
// Network address parsing
// ============================================================================

/// Parse IP:Port string (e.g., "192.168.1.1:443")
pub const HostPort = struct {
    host: []const u8,
    port: u16,
};

pub fn parseHostPort(str: []const u8) !HostPort {
    // Check for IPv6 with brackets [::1]:port
    if (str.len > 0 and str[0] == '[') {
        const bracket_end = indexOf(str, "]") orelse return error.InvalidFormat;
        const host = str[1..bracket_end];

        if (bracket_end + 1 >= str.len or str[bracket_end + 1] != ':') {
            return error.InvalidFormat;
        }

        const port_str = str[bracket_end + 2 ..];
        const port = try parseUnsigned(u16, port_str, 10);
        return .{ .host = host, .port = port };
    }

    // IPv4 or hostname
    const colon_pos = lastIndexOf(str, ":") orelse return error.InvalidFormat;
    const host = str[0..colon_pos];
    const port_str = str[colon_pos + 1 ..];

    if (host.len == 0) return error.InvalidFormat;

    const port = try parseUnsigned(u16, port_str, 10);
    return .{ .host = host, .port = port };
}

// ============================================================================
// Hex encoding/decoding
// ============================================================================

/// Encode bytes to hex string
pub fn hexEncode(allocator: Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    const result = try allocator.alloc(u8, data.len * 2);

    for (data, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0f];
    }

    return result;
}

/// Decode hex string to bytes
pub fn hexDecode(allocator: Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexLength;

    const result = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(result);

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const high = hexCharToNibble(hex[i]) orelse return error.InvalidHexChar;
        const low = hexCharToNibble(hex[i + 1]) orelse return error.InvalidHexChar;
        result[i / 2] = (high << 4) | low;
    }

    return result;
}

fn hexCharToNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ============================================================================
// Base64 encoding/decoding (for certificate/key data)
// ============================================================================

pub const base64 = std.base64.standard;

/// Encode to Base64 (allocates)
pub fn base64Encode(allocator: Allocator, data: []const u8) ![]u8 {
    const encoded_len = base64.Encoder.calcSize(data.len);
    const result = try allocator.alloc(u8, encoded_len);
    _ = base64.Encoder.encode(result, data);
    return result;
}

/// Decode from Base64 (allocates)
pub fn base64Decode(allocator: Allocator, encoded: []const u8) ![]u8 {
    const decoded_len = try base64.Decoder.calcSizeForSlice(encoded);
    const result = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(result);
    try base64.Decoder.decode(result, encoded);
    return result;
}

// ============================================================================
// Null-terminated string utilities (for C interop during migration)
// ============================================================================

/// Convert slice to null-terminated (allocates)
pub fn toNullTerminated(allocator: Allocator, str: []const u8) ![:0]u8 {
    return allocator.dupeZ(u8, str);
}

/// Get length of null-terminated string
pub fn strlen(ptr: [*:0]const u8) usize {
    return std.mem.len(ptr);
}

/// Convert null-terminated to slice
pub fn fromNullTerminated(ptr: [*:0]const u8) []const u8 {
    return std.mem.span(ptr);
}

// ============================================================================
// SoftEther-specific string formats
// ============================================================================

/// Parse SoftEther connection string: "hostname/hubname"
pub const ConnectionTarget = struct {
    hostname: []const u8,
    hub_name: []const u8,
    port: u16,
};

pub fn parseConnectionString(str: []const u8) !ConnectionTarget {
    // Format: hostname:port/hubname or hostname/hubname (default port 443)
    const slash_pos = indexOf(str, "/") orelse return error.InvalidFormat;
    const hub_name = str[slash_pos + 1 ..];

    if (hub_name.len == 0) return error.InvalidFormat;

    const host_part = str[0..slash_pos];

    // Check for port
    if (lastIndexOf(host_part, ":")) |colon_pos| {
        const hostname = host_part[0..colon_pos];
        const port_str = host_part[colon_pos + 1 ..];
        const port = try parseUnsigned(u16, port_str, 10);
        return .{ .hostname = hostname, .hub_name = hub_name, .port = port };
    }

    return .{ .hostname = host_part, .hub_name = hub_name, .port = 443 };
}

// ============================================================================
// Tests
// ============================================================================

test "eqlIgnoreCase" {
    try testing.expect(eqlIgnoreCase("Hello", "hello"));
    try testing.expect(eqlIgnoreCase("WORLD", "world"));
    try testing.expect(!eqlIgnoreCase("hello", "world"));
}

test "trim" {
    try testing.expectEqualStrings("hello", trim("  hello  "));
    try testing.expectEqualStrings("hello", trim("\t\nhello\r\n"));
}

test "split" {
    const str = "a,b,c,d";
    var iter = split(str, ',');

    try testing.expectEqualStrings("a", iter.next().?);
    try testing.expectEqualStrings("b", iter.next().?);
    try testing.expectEqualStrings("c", iter.next().?);
    try testing.expectEqualStrings("d", iter.next().?);
    try testing.expect(iter.next() == null);
}

test "parseHostPort IPv4" {
    const result = try parseHostPort("192.168.1.1:443");
    try testing.expectEqualStrings("192.168.1.1", result.host);
    try testing.expectEqual(@as(u16, 443), result.port);
}

test "parseHostPort IPv6" {
    const result = try parseHostPort("[::1]:8443");
    try testing.expectEqualStrings("::1", result.host);
    try testing.expectEqual(@as(u16, 8443), result.port);
}

test "hexEncode and hexDecode" {
    const data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };

    const hex = try hexEncode(testing.allocator, &data);
    defer testing.allocator.free(hex);
    try testing.expectEqualStrings("deadbeef", hex);

    const decoded = try hexDecode(testing.allocator, hex);
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, &data, decoded);
}

test "parseConnectionString" {
    const result = try parseConnectionString("vpn.example.com:5555/MYHUB");
    try testing.expectEqualStrings("vpn.example.com", result.hostname);
    try testing.expectEqualStrings("MYHUB", result.hub_name);
    try testing.expectEqual(@as(u16, 5555), result.port);
}

test "parseConnectionString default port" {
    const result = try parseConnectionString("vpn.example.com/HUB");
    try testing.expectEqualStrings("vpn.example.com", result.hostname);
    try testing.expectEqualStrings("HUB", result.hub_name);
    try testing.expectEqual(@as(u16, 443), result.port);
}

test "parseBool" {
    try testing.expect(try parseBool("true"));
    try testing.expect(try parseBool("TRUE"));
    try testing.expect(try parseBool("yes"));
    try testing.expect(try parseBool("1"));
    try testing.expect(!try parseBool("false"));
    try testing.expect(!try parseBool("no"));
    try testing.expect(!try parseBool("0"));
    try testing.expectError(error.InvalidBoolean, parseBool("maybe"));
}
