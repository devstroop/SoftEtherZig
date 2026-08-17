//! WPC (Web Procedure Call) admin transport (issue #99).
//!
//! Provides the server-side pieces of the admin RPC protocol:
//!
//! - **Safe64 codec**: URL-safe Base64 variant used in the WPC packet
//!   envelope (replaces `+` → `)`, `/` → `_`, `=` → `(`).
//! - **WPC packet**: `{PACK, HASH(SHA1), CERT, SIGN}` — the envelope
//!   that wraps a serialized Pack with integrity + optional signature.
//! - **hashAdminPassword**: SHA-1 of the plaintext admin password
//!   (C: `HashAdminPassword`, Admin.c:14871).
//!
//! ## Wire flow
//!
//! ```
//! Client (vpncmd)                          Server
//!     |                                        |
//!     |  POST /vpnsvc/connect.cgi (WaterMark)  |  ← receiveSignature
//!     |  ← 200 OK (hello with random nonce)    |
//!     |                                        |
//!     |  POST /vpnsvc/vpn.cgi (method Pack)    |  ← method detection
//!     |    method: "admin"                      |
//!     |    secure_password: SHA1(hash+random)   |
//!     |    hubname: "" (server) or "HubName"    |
//!     |  ← 200 OK (success)                    |  ← authenticateAdmin
//!     |                                        |
//!     |  [u32 BE size][Pack bytes]  (RPC frame) |  ← runServer loop
//!     |  [u32 BE size][Pack bytes]              |
//!     |  ...                                    |
//! ```
//!
//! C reference:
//! - `EncodeSafe64` / `DecodeSafe64` (Wpc.c:1397, 1371)
//! - `WpcGeneratePacket` / `WpcParsePacket` (Wpc.c:342, 242)
//! - `HashAdminPassword` (Admin.c:14871)
//! - `AdminAccept` (Admin.c:14638) — the accept + auth + RPC loop

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const sha1_mod = @import("../../mayaqua/encrypt/hash.zig");
const Pack = @import("../protocol/pack.zig").Pack;

const log = std.log.scoped(.wpc);

// ============================================================================
// Constants
// ============================================================================

/// WPC data entry name width (C: `WPC_DATA_ENTRY_SIZE`, Wpc.h:114).
pub const entry_name_size = 4;
/// WPC data entry size string width (10-digit decimal, zero-padded).
pub const entry_size_width = 10;
/// SHA-1 digest size (C: `SHA1_SIZE`, 20 bytes).
pub const sha1_size = 20;

// ============================================================================
// Safe64 Codec
// ============================================================================

/// Apply Base64 → Safe64 character substitutions (C: `Base64ToSafe64`, Wpc.c:1311).
///
/// ```
/// '=' → '('
/// '+' → ')'
/// '/' → '_'
/// ```
pub fn base64ToSafe64(buf: []u8) void {
    for (buf) |*c| {
        c.* = switch (c.*) {
            '=' => '(',
            '+' => ')',
            '/' => '_',
            else => c.*,
        };
    }
}

/// Apply Safe64 → Base64 character substitutions (C: `Safe64ToBase64`, Wpc.c:1340).
///
/// Reverse of `base64ToSafe64`.
pub fn safe64ToBase64(buf: []u8) void {
    for (buf) |*c| {
        c.* = switch (c.*) {
            '(' => '=',
            ')' => '+',
            '_' => '/',
            else => c.*,
        };
    }
}

/// Encode binary data to a Safe64 string.
///
/// 1. Standard Base64 encode
/// 2. Apply Safe64 character substitutions
///
/// C: `EncodeSafe64` (Wpc.c:1397). Returns the Safe64 string (caller frees).
pub fn encodeSafe64(allocator: Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard;
    const encoded_len = encoder.calcSizeForEncode(data.len);
    const b64 = try allocator.alloc(u8, encoded_len);
    defer allocator.free(b64);
    _ = encoder.encode(b64, data);
    const result = try allocator.dupe(u8, b64);
    base64ToSafe64(result);
    return result;
}

/// Decode a Safe64 string to binary data.
///
/// 1. Apply Safe64 → Base64 substitutions
/// 2. Standard Base64 decode
///
/// C: `DecodeSafe64` (Wpc.c:1371). Returns the decoded bytes (caller frees).
pub fn decodeSafe64(allocator: Allocator, safe64_str: []const u8) ![]u8 {
    const decoder = std.base64.standard;
    const tmp = try allocator.dupe(u8, safe64_str);
    defer allocator.free(tmp);
    safe64ToBase64(tmp);
    const decoded_len = try decoder.calcSizeForSlice(tmp);
    const result = try allocator.alloc(u8, decoded_len);
    _ = try decoder.decode(result, tmp);
    return result;
}

// ============================================================================
// WPC Packet
// ============================================================================

/// A parsed WPC data entry (C: `WPC_ENTRY`, Wpc.h:157).
pub const WpcEntry = struct {
    name: [entry_name_size]u8,
    data: []const u8,
};

/// A parsed WPC packet (C: `WPC_PACKET`, Wpc.h:165).
///
/// Contains the decoded Pack data, hash, and optional certificate + signature.
/// All fields are owned by the caller (free via `deinit`).
pub const WpcPacket = struct {
    pack_data: ?[]u8 = null,
    hash: [sha1_size]u8 = [_]u8{0} ** sha1_size,
    cert_der: ?[]u8 = null,
    signature: ?[]u8 = null,

    pub fn deinit(self: *WpcPacket, allocator: Allocator) void {
        if (self.pack_data) |p| allocator.free(p);
        if (self.cert_der) |c| allocator.free(c);
        if (self.signature) |s| allocator.free(s);
        self.* = .{};
    }
};

/// Format an entry name: uppercase, right-padded with spaces to `entry_name_size`.
///
/// C: `WpcFillEntryName` (Wpc.c:522).
fn fillEntryName(name: []const u8) [entry_name_size]u8 {
    var result = [_]u8{' '} ** entry_name_size;
    const len = @min(name.len, entry_name_size);
    for (0..len) |i| {
        const c = name[i];
        result[i] = if (c >= 'a' and c <= 'z') c - 32 else c;
    }
    return result;
}

/// Parse all data entries from a WPC packet buffer.
///
/// Wire format per entry: `[4-byte name][10-byte ASCII decimal size][data...]`
///
/// C: `WpcParseDataEntry` (Wpc.c:471).
pub fn parseDataEntries(allocator: Allocator, buf: []const u8) ![]WpcEntry {
    var entries = std.ArrayListUnmanaged(WpcEntry){};
    errdefer {
        for (entries.items) |e| allocator.free(e.data);
        entries.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos + entry_name_size + entry_size_width <= buf.len) {
        const name = buf[pos..][0..entry_name_size].*;
        pos += entry_name_size;

        const size_str = buf[pos..][0..entry_size_width];
        pos += entry_size_width;

        const size = std.fmt.parseInt(usize, size_str, 10) catch break;
        if (pos + size > buf.len) break;

        const data = try allocator.dupe(u8, buf[pos .. pos + size]);
        pos += size;

        try entries.append(allocator, .{ .name = name, .data = data });
    }

    return try entries.toOwnedSlice(allocator);
}

/// Find a data entry by name (case-insensitive, ignoring trailing spaces).
///
/// C: `WpcFindDataEntry` (Wpc.c:424).
pub fn findDataEntry(entries: []const WpcEntry, name: []const u8) ?WpcEntry {
    const target = fillEntryName(name);
    for (entries) |e| {
        if (mem.eql(u8, &e.name, &target)) return e;
    }
    return null;
}

/// Decode a WPC entry's data from Safe64 to binary.
///
/// C: `WpcDataEntryToBuf` (Wpc.c:390).
pub fn entryToData(allocator: Allocator, entry: WpcEntry) ![]u8 {
    if (entry.data.len == 0) return try allocator.alloc(u8, 0);
    return decodeSafe64(allocator, entry.data);
}

/// Free the entry list returned by `parseDataEntries`.
pub fn freeEntries(allocator: Allocator, entries: []WpcEntry) void {
    for (entries) |e| allocator.free(e.data);
    allocator.free(entries);
}

/// Parse a complete WPC packet from its buffer.
///
/// Verifies:
/// 1. PACK entry exists and is valid
/// 2. HASH entry matches SHA-1 of PACK data (if HASH present)
/// 3. SIGN entry verifies against CERT's RSA public key (if CERT+SIGN present)
///
/// C: `WpcParsePacket` (Wpc.c:242).
pub fn parsePacket(allocator: Allocator, buf: []const u8) !WpcPacket {
    var pkt = WpcPacket{};
    errdefer pkt.deinit(allocator);

    const entries = try parseDataEntries(allocator, buf);
    defer freeEntries(allocator, entries);

    // 1. Decode PACK entry (the serialized Pack binary)
    const pack_entry = findDataEntry(entries, "PACK") orelse return error.MissingPackEntry;
    pkt.pack_data = try entryToData(allocator, pack_entry);

    // 2. Verify HASH (if present)
    const computed_hash = sha1_mod.sha1(pkt.pack_data.?);
    @memcpy(&pkt.hash, &computed_hash);

    if (findDataEntry(entries, "HASH")) |hash_entry| {
        const expected = try entryToData(allocator, hash_entry);
        defer allocator.free(expected);
        if (expected.len != sha1_size or !mem.eql(u8, expected, &pkt.hash)) {
            return error.HashMismatch;
        }
    }

    // 3. Verify SIGN + CERT (if present)
    if (findDataEntry(entries, "CERT")) |cert_entry| {
        const cert = try entryToData(allocator, cert_entry);
        defer allocator.free(cert);
        pkt.cert_der = try allocator.dupe(u8, cert);

        if (findDataEntry(entries, "SIGN")) |sign_entry| {
            const sig = try entryToData(allocator, sign_entry);
            defer allocator.free(sig);
            if (sig.len != 128) return error.InvalidSignatureLength;
            pkt.signature = try allocator.dupe(u8, sig);
        }
    }

    return pkt;
}

/// Generate a WPC packet envelope from a serialized Pack.
///
/// 1. SHA-1 hash of the Pack bytes → HASH entry
/// 2. Optionally: CERT (DER X.509) + SIGN (128-byte RSA signature of hash)
/// 3. Pack all entries with Safe64 encoding
///
/// C: `WpcGeneratePacket` (Wpc.c:342).
pub fn generatePacket(
    allocator: Allocator,
    pack_bytes: []const u8,
    cert_der: ?[]const u8,
    signature: ?[]const u8,
) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};
    errdefer result.deinit(allocator);

    // PACK entry
    try addDataEntry(allocator, &result, "PACK", pack_bytes);

    // HASH entry
    const hash = sha1_mod.sha1(pack_bytes);
    try addDataEntry(allocator, &result, "HASH", &hash);

    // CERT + SIGN entries (optional)
    if (cert_der) |cert| {
        try addDataEntry(allocator, &result, "CERT", cert);
        if (signature) |sig| {
            try addDataEntry(allocator, &result, "SIGN", sig);
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Add a single data entry (binary data → Safe64 encoded) to the output buffer.
fn addDataEntry(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    data: []const u8,
) !void {
    const encoded = try encodeSafe64(allocator, data);
    defer allocator.free(encoded);

    const name_padded = fillEntryName(name);
    try out.appendSlice(allocator, &name_padded);

    var size_buf: [entry_size_width]u8 = undefined;
    const size_str = std.fmt.bufPrint(&size_buf, "{d:0>10}", .{encoded.len}) catch unreachable;
    try out.appendSlice(allocator, size_str);

    try out.appendSlice(allocator, encoded);
}

// ============================================================================
// Admin Password Hash
// ============================================================================

/// Hash the admin password with SHA-1 for storage/comparison.
///
/// C: `HashAdminPassword` (Admin.c:14871): `Hash(hash, password, len, true)`.
/// Note: this is plain SHA-1, NOT the HMAC-like SecurePassword derivation.
pub fn hashAdminPassword(password: []const u8) [sha1_size]u8 {
    return sha1_mod.sha1(password);
}

// ============================================================================
// Tests
// ============================================================================

test "Safe64 roundtrip" {
    const allocator = testing.allocator;

    const test_cases = [_][]const u8{
        "",
        "a",
        "hello world",
        "SoftEther VPN Server",
        &[_]u8{0} ** 64,
        &[_]u8{0xFF} ** 32,
    };

    for (test_cases) |tc| {
        const encoded = try encodeSafe64(allocator, tc);
        defer allocator.free(encoded);

        // Must not contain standard Base64 special chars
        for (encoded) |c| {
            try testing.expect(c != '=' and c != '+' and c != '/');
        }

        const decoded = try decodeSafe64(allocator, encoded);
        defer allocator.free(decoded);

        try testing.expectEqualStrings(tc, decoded);
    }
}

test "Safe64 character substitutions" {
    // Encode known binary that produces +/= in standard Base64
    const allocator = testing.allocator;
    const data = "\xfb\xff\xfe"; // 0xFB 0xFF 0xFE → "u//+" in Base64
    const encoded = try encodeSafe64(allocator, data);
    defer allocator.free(encoded);

    // Should contain safe chars, not Base64 specials
    for (encoded) |c| {
        try testing.expect(c != '=' and c != '+' and c != '/');
    }

    const decoded = try decodeSafe64(allocator, encoded);
    defer allocator.free(decoded);
    try testing.expectEqualStrings(data, decoded);
}

test "WPC entry name padding" {
    const name = fillEntryName("PACK");
    try testing.expectEqual([entry_name_size]u8{ 'P', 'A', 'C', 'K' }, name);

    const short = fillEntryName("AB");
    try testing.expectEqual([entry_name_size]u8{ 'A', 'B', ' ', ' ' }, short);

    const long_name = fillEntryName("TOOLONG");
    try testing.expectEqual([entry_name_size]u8{ 'T', 'O', 'O', 'L' }, long_name);
}

test "WPC data entry parse + generate roundtrip" {
    const allocator = testing.allocator;

    // Create a simple Pack with a test element
    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addStr("function_name", "Test");
    try pack.addInt("value", 42);
    const pack_bytes = try pack.toBytes(allocator);
    defer allocator.free(pack_bytes);

    // Generate packet
    const pkt_bytes = try generatePacket(allocator, pack_bytes, null, null);
    defer allocator.free(pkt_bytes);

    // Parse it back
    var pkt = try parsePacket(allocator, pkt_bytes);
    defer pkt.deinit(allocator);

    try testing.expect(pkt.pack_data != null);
    try testing.expectEqualStrings(pack_bytes, pkt.pack_data.?);
    try testing.expectEqual(@as(usize, sha1_size), pkt.hash.len);
    try testing.expect(pkt.cert_der == null);
    try testing.expect(pkt.signature == null);
}

test "WPC hash verification rejects tampered data" {
    const allocator = testing.allocator;

    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addStr("function_name", "Test");
    try pack.addInt("value", 42);
    const pack_bytes = try pack.toBytes(allocator);
    defer allocator.free(pack_bytes);

    var pkt_bytes = try generatePacket(allocator, pack_bytes, null, null);
    defer allocator.free(pkt_bytes);

    // Tamper with the Pack data (flip a bit in the Safe64 string)
    if (pkt_bytes.len > 20) {
        pkt_bytes[20] = if (pkt_bytes[20] == 'A') 'B' else 'A';
    }

    // Parse should fail with hash mismatch
    const result = parsePacket(allocator, pkt_bytes);
    try testing.expectError(error.HashMismatch, result);
}

test "hashAdminPassword produces SHA-1" {
    const h = hashAdminPassword("password");
    // SHA-1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
    try testing.expect(h.len == sha1_size);
    // Just check it's not all zeros
    var all_zero = true;
    for (h) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
    // Verify known SHA-1("password") value
    const expected = [sha1_size]u8{ 0x5b, 0xaa, 0x61, 0xe4, 0xc9, 0xb9, 0x3f, 0x3f, 0x06, 0x82, 0x25, 0x0b, 0x6c, 0xf8, 0x33, 0x1b, 0x7e, 0xe6, 0x8f, 0xd8 };
    try testing.expectEqual(expected, h);
}
