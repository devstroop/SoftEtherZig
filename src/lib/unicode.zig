//! Unicode Utilities Module
//!
//! Pure Zig replacement for Mayaqua/Internat.c
//! Provides UTF-8/UTF-16/UTF-32 conversion and Unicode string handling.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// UTF-8 validation and manipulation
// ============================================================================

/// Check if a byte slice is valid UTF-8
pub fn isValidUtf8(bytes: []const u8) bool {
    return std.unicode.utf8ValidateSlice(bytes);
}

/// Get the number of Unicode codepoints in a UTF-8 string
pub fn utf8Len(str: []const u8) !usize {
    return std.unicode.utf8CountCodepoints(str);
}

/// Iterator over UTF-8 codepoints
pub fn utf8Iterator(str: []const u8) std.unicode.Utf8Iterator {
    return std.unicode.Utf8Iterator{ .bytes = str, .i = 0 };
}

/// Get the byte length of a UTF-8 codepoint starting at the given index
pub fn utf8ByteLen(first_byte: u8) !u3 {
    return std.unicode.utf8ByteSequenceLength(first_byte);
}

// ============================================================================
// UTF-16 conversion (for Windows interop)
// ============================================================================

/// Convert UTF-8 to UTF-16 LE (allocates)
pub fn utf8ToUtf16Le(allocator: Allocator, utf8: []const u8) ![]u16 {
    const len = std.unicode.calcUtf16LeLen(utf8) catch return error.InvalidUtf8;
    const result = try allocator.alloc(u16, len);
    errdefer allocator.free(result);

    const written = std.unicode.utf8ToUtf16Le(result, utf8) catch return error.InvalidUtf8;
    return result[0..written];
}

/// Convert UTF-16 LE to UTF-8 (allocates)
pub fn utf16LeToUtf8(allocator: Allocator, utf16: []const u16) ![]u8 {
    // Calculate required size
    var size: usize = 0;
    var i: usize = 0;
    while (i < utf16.len) {
        const c = utf16[i];
        if (c < 0x80) {
            size += 1;
        } else if (c < 0x800) {
            size += 2;
        } else if (c >= 0xD800 and c <= 0xDBFF) {
            // Surrogate pair
            size += 4;
            i += 1;
        } else {
            size += 3;
        }
        i += 1;
    }

    const result = try allocator.alloc(u8, size);
    errdefer allocator.free(result);

    const written = std.unicode.utf16LeToUtf8(result, utf16) catch return error.InvalidUtf16;
    return result[0..written];
}

/// Convert a single codepoint to UTF-16
pub fn codepointToUtf16(codepoint: u21) [2]u16 {
    var result: [2]u16 = undefined;
    const len = std.unicode.utf8ToUtf16Le(&result, &[_]u8{
        @intCast((codepoint >> 18) | 0xF0),
        @intCast(((codepoint >> 12) & 0x3F) | 0x80),
        @intCast(((codepoint >> 6) & 0x3F) | 0x80),
        @intCast((codepoint & 0x3F) | 0x80),
    }) catch {
        result[0] = 0xFFFD; // Replacement character
        result[1] = 0;
        return result;
    };
    if (len == 1) result[1] = 0;
    return result;
}

// ============================================================================
// UTF-32 conversion
// ============================================================================

/// Convert UTF-8 to UTF-32 codepoints (allocates)
pub fn utf8ToUtf32(allocator: Allocator, utf8: []const u8) ![]u32 {
    const codepoint_count = try std.unicode.utf8CountCodepoints(utf8);
    const result = try allocator.alloc(u32, codepoint_count);
    errdefer allocator.free(result);

    var iter = std.unicode.Utf8Iterator{ .bytes = utf8, .i = 0 };
    var i: usize = 0;
    while (iter.nextCodepoint()) |cp| {
        result[i] = cp;
        i += 1;
    }

    return result[0..i];
}

/// Convert UTF-32 codepoints to UTF-8 (allocates)
pub fn utf32ToUtf8(allocator: Allocator, codepoints: []const u32) ![]u8 {
    // Calculate required size
    var size: usize = 0;
    for (codepoints) |cp| {
        size += std.unicode.utf8CodepointSequenceLength(@intCast(cp)) catch return error.InvalidCodepoint;
    }

    const result = try allocator.alloc(u8, size);
    errdefer allocator.free(result);

    var pos: usize = 0;
    for (codepoints) |cp| {
        const len = std.unicode.utf8Encode(@intCast(cp), result[pos..]) catch return error.InvalidCodepoint;
        pos += len;
    }

    return result[0..pos];
}

// ============================================================================
// Case conversion (ASCII only - use ICU for full Unicode)
// ============================================================================

/// Convert ASCII characters to uppercase (in-place)
pub fn asciiToUpper(str: []u8) void {
    for (str) |*c| {
        if (c.* >= 'a' and c.* <= 'z') {
            c.* -= 32;
        }
    }
}

/// Convert ASCII characters to lowercase (in-place)
pub fn asciiToLower(str: []u8) void {
    for (str) |*c| {
        if (c.* >= 'A' and c.* <= 'Z') {
            c.* += 32;
        }
    }
}

/// Convert ASCII to uppercase (allocates)
pub fn asciiToUpperAlloc(allocator: Allocator, str: []const u8) ![]u8 {
    const result = try allocator.dupe(u8, str);
    asciiToUpper(result);
    return result;
}

/// Convert ASCII to lowercase (allocates)
pub fn asciiToLowerAlloc(allocator: Allocator, str: []const u8) ![]u8 {
    const result = try allocator.dupe(u8, str);
    asciiToLower(result);
    return result;
}

// ============================================================================
// String normalization (basic - for full NFC/NFD use external lib)
// ============================================================================

/// Remove BOM from UTF-8 string
pub fn stripBom(str: []const u8) []const u8 {
    if (str.len >= 3 and str[0] == 0xEF and str[1] == 0xBB and str[2] == 0xBF) {
        return str[3..];
    }
    return str;
}

/// Check for BOM
pub fn hasBom(str: []const u8) bool {
    return str.len >= 3 and str[0] == 0xEF and str[1] == 0xBB and str[2] == 0xBF;
}

// ============================================================================
// Character classification
// ============================================================================

/// Check if codepoint is ASCII
pub fn isAscii(codepoint: u21) bool {
    return codepoint <= 0x7F;
}

/// Check if codepoint is a control character
pub fn isControl(codepoint: u21) bool {
    return codepoint < 0x20 or (codepoint >= 0x7F and codepoint <= 0x9F);
}

/// Check if codepoint is printable
pub fn isPrintable(codepoint: u21) bool {
    if (codepoint < 0x20) return false;
    if (codepoint >= 0x7F and codepoint <= 0x9F) return false;
    return true;
}

/// Check if codepoint is whitespace
pub fn isWhitespace(codepoint: u21) bool {
    return switch (codepoint) {
        0x0009, // Tab
        0x000A, // LF
        0x000B, // VT
        0x000C, // FF
        0x000D, // CR
        0x0020, // Space
        0x0085, // NEL
        0x00A0, // NBSP
        0x1680, // Ogham space
        0x2000...0x200A, // Various spaces
        0x2028, // Line separator
        0x2029, // Paragraph separator
        0x202F, // Narrow NBSP
        0x205F, // Medium math space
        0x3000, // Ideographic space
        => true,
        else => false,
    };
}

// ============================================================================
// Encoding detection (heuristic)
// ============================================================================

pub const Encoding = enum {
    utf8,
    utf16_le,
    utf16_be,
    utf32_le,
    utf32_be,
    ascii,
    unknown,
};

/// Detect encoding from BOM or content analysis
pub fn detectEncoding(data: []const u8) Encoding {
    if (data.len == 0) return .unknown;

    // Check BOM
    if (data.len >= 4) {
        if (data[0] == 0xFF and data[1] == 0xFE and data[2] == 0x00 and data[3] == 0x00) {
            return .utf32_le;
        }
        if (data[0] == 0x00 and data[1] == 0x00 and data[2] == 0xFE and data[3] == 0xFF) {
            return .utf32_be;
        }
    }

    if (data.len >= 3) {
        if (data[0] == 0xEF and data[1] == 0xBB and data[2] == 0xBF) {
            return .utf8;
        }
    }

    if (data.len >= 2) {
        if (data[0] == 0xFF and data[1] == 0xFE) {
            return .utf16_le;
        }
        if (data[0] == 0xFE and data[1] == 0xFF) {
            return .utf16_be;
        }
    }

    // Check if valid UTF-8
    if (isValidUtf8(data)) {
        // Check if pure ASCII
        var is_ascii = true;
        for (data) |byte| {
            if (byte > 0x7F) {
                is_ascii = false;
                break;
            }
        }
        return if (is_ascii) .ascii else .utf8;
    }

    return .unknown;
}

// ============================================================================
// SoftEther-specific Unicode handling
// ============================================================================

/// Convert SoftEther wchar_t string to UTF-8
/// SoftEther uses UTF-16 LE internally on Windows
pub fn softEtherWcharToUtf8(allocator: Allocator, wchar_data: []const u8) ![]u8 {
    if (wchar_data.len % 2 != 0) return error.InvalidLength;

    // Reinterpret as u16 slice
    const u16_slice = std.mem.bytesAsSlice(u16, @alignCast(wchar_data));
    return utf16LeToUtf8(allocator, u16_slice);
}

/// Convert UTF-8 to SoftEther wchar_t format
pub fn utf8ToSoftEtherWchar(allocator: Allocator, utf8: []const u8) ![]u8 {
    const utf16 = try utf8ToUtf16Le(allocator, utf8);
    defer allocator.free(utf16);

    // Convert u16 slice to bytes
    const result = try allocator.alloc(u8, utf16.len * 2);
    @memcpy(result, std.mem.sliceAsBytes(utf16));
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "isValidUtf8" {
    try testing.expect(isValidUtf8("Hello, World!"));
    try testing.expect(isValidUtf8("こんにちは")); // Japanese
    try testing.expect(isValidUtf8("🎉")); // Emoji
    try testing.expect(!isValidUtf8(&[_]u8{ 0xFF, 0xFE })); // Invalid
}

test "utf8Len" {
    try testing.expectEqual(@as(usize, 5), try utf8Len("Hello"));
    try testing.expectEqual(@as(usize, 5), try utf8Len("こんにちは"));
    try testing.expectEqual(@as(usize, 1), try utf8Len("🎉"));
}

test "utf8ToUtf16Le roundtrip" {
    const original = "Hello, 世界! 🌍";

    const utf16 = try utf8ToUtf16Le(testing.allocator, original);
    defer testing.allocator.free(utf16);

    const back = try utf16LeToUtf8(testing.allocator, utf16);
    defer testing.allocator.free(back);

    try testing.expectEqualStrings(original, back);
}

test "utf8ToUtf32 roundtrip" {
    const original = "Hello, 世界!";

    const utf32 = try utf8ToUtf32(testing.allocator, original);
    defer testing.allocator.free(utf32);

    const back = try utf32ToUtf8(testing.allocator, utf32);
    defer testing.allocator.free(back);

    try testing.expectEqualStrings(original, back);
}

test "stripBom" {
    const with_bom = &[_]u8{ 0xEF, 0xBB, 0xBF, 'H', 'e', 'l', 'l', 'o' };
    const without_bom = stripBom(with_bom);
    try testing.expectEqualStrings("Hello", without_bom);
}

test "detectEncoding" {
    try testing.expectEqual(Encoding.ascii, detectEncoding("Hello"));
    try testing.expectEqual(Encoding.utf8, detectEncoding("こんにちは"));

    const utf8_bom = &[_]u8{ 0xEF, 0xBB, 0xBF, 't', 'e', 's', 't' };
    try testing.expectEqual(Encoding.utf8, detectEncoding(utf8_bom));

    const utf16_le_bom = &[_]u8{ 0xFF, 0xFE, 0x00, 0x00 };
    try testing.expectEqual(Encoding.utf32_le, detectEncoding(utf16_le_bom));
}

test "isWhitespace" {
    try testing.expect(isWhitespace(' '));
    try testing.expect(isWhitespace('\t'));
    try testing.expect(isWhitespace('\n'));
    try testing.expect(isWhitespace(0x3000)); // Ideographic space
    try testing.expect(!isWhitespace('a'));
}

test "asciiToUpper" {
    var str = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    asciiToUpper(&str);
    try testing.expectEqualStrings("HELLO", &str);
}
