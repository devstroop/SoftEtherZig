//! End-to-end handshake fixture tests.
//!
//! These exercise the SoftEther protocol layer against a scripted in-memory
//! transport instead of a real server. The Reader/Writer interfaces in
//! `protocol/softether_protocol.zig` accept any context, so we plug in a
//! pair of byte buffers: writes go into `client_out`, reads come from
//! `server_out` which we pre-fill with synthesized server frames.
//!
//! What this catches that the unit tests don't:
//!   - HTTP request line / header drift (e.g. accidental method change)
//!   - Pack body framing changes (header + body must arrive contiguously)
//!   - `downloadHello` and `uploadAuth` end-to-end parsing flow
//!   - Field name drift between client serializer and parser
//!
//! What this does NOT catch (deferred to a real-server / mock-TCP harness):
//!   - TLS framing, partial reads, half-closes, timeouts
//!   - Server-side variations (case sensitivity, unexpected fields)
//!
//! New scripted fixtures should always be added here before changing any
//! shared protocol helper.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const proto = @import("proto");
const Pack = proto.Pack;

// ============================================================================
// Scripted transport
// ============================================================================

/// In-memory bidirectional transport for protocol-level tests.
///
/// The client writes into `client_out` (captured for assertions) and reads
/// from `server_out` (pre-filled by the test). Both are simple cursors —
/// there is no socket, no TLS, no thread.
const ScriptedTransport = struct {
    client_out: std.ArrayListUnmanaged(u8) = .{},
    server_out: []const u8 = &.{},
    server_pos: usize = 0,
    allocator: Allocator,

    fn deinit(self: *ScriptedTransport) void {
        self.client_out.deinit(self.allocator);
    }

    fn writeFn(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self = @as(*ScriptedTransport, @ptrCast(@alignCast(ctx)));
        try self.client_out.appendSlice(self.allocator, data);
        return data.len;
    }

    fn readFn(ctx: *anyopaque, buffer: []u8) anyerror!usize {
        const self = @as(*ScriptedTransport, @ptrCast(@alignCast(ctx)));
        const remaining = self.server_out.len - self.server_pos;
        if (remaining == 0) return 0;
        const n = @min(remaining, buffer.len);
        @memcpy(buffer[0..n], self.server_out[self.server_pos .. self.server_pos + n]);
        self.server_pos += n;
        return n;
    }

    fn writer(self: *ScriptedTransport) proto.Writer {
        return .{ .context = @ptrCast(self), .writeFn = writeFn };
    }

    fn reader(self: *ScriptedTransport) proto.Reader {
        return .{ .context = @ptrCast(self), .readFn = readFn };
    }
};

// ============================================================================
// Server response synthesis
// ============================================================================

/// Build a minimal HTTP response carrying a serialized Pack body. The header
/// format matches what `downloadHello` / `uploadAuth` expect.
fn buildPackResponse(allocator: Allocator, pack_bytes: []const u8) ![]u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(allocator);

    var w = buf.writer(allocator);
    try w.writeAll("HTTP/1.1 200 OK\r\n");
    try w.print("Content-Length: {d}\r\n", .{pack_bytes.len});
    try w.writeAll("Content-Type: application/octet-stream\r\n");
    try w.writeAll("\r\n");
    try w.writeAll(pack_bytes);

    return buf.toOwnedSlice(allocator);
}

/// Build the server-side Hello Pack: 20-byte random + version + build + hello string.
fn buildServerHelloPack(allocator: Allocator, random: *const [20]u8, ver: u32, build: u32, hello: []const u8) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addData("random", random);
    try pack.addInt("version", ver);
    try pack.addInt("build", build);
    try pack.addStr("hello", hello);
    return pack.toBytes(allocator);
}

/// Build a successful auth-response Pack (mirrors what a real SoftEther
/// server returns on success — session key + server-side session params).
fn buildAuthSuccessPack(
    allocator: Allocator,
    session_key: *const [20]u8,
    max_conn: u32,
    use_encrypt: bool,
) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addInt("error", 0);
    try pack.addData("SessionKey", session_key);
    try pack.addInt("max_connection", max_conn);
    try pack.addInt("use_encrypt", if (use_encrypt) 1 else 0);
    try pack.addInt("half_connection", 0);
    try pack.addInt("use_compress", 0);
    try pack.addInt("qos", 0);
    try pack.addInt("timeout", 0);
    return pack.toBytes(allocator);
}

/// Build an auth-failure Pack with error code + message.
fn buildAuthFailurePack(allocator: Allocator, err_code: u32, msg: []const u8) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addInt("error", err_code);
    try pack.addStr("error_str", msg);
    return pack.toBytes(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "uploadSignature emits WaterMark with valid HTTP framing" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    try proto.uploadSignature(allocator, transport.writer(), "vpn.example.com");

    const out = transport.client_out.items;

    // The first line must be a POST to the signature endpoint with HTTP/1.1.
    try testing.expect(std.mem.startsWith(u8, out, "POST "));
    try testing.expect(std.mem.indexOf(u8, out, " HTTP/1.1\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "Host: vpn.example.com\r\n") != null);

    // Headers must be terminated by a blank line.
    const split = std.mem.indexOf(u8, out, "\r\n\r\n") orelse {
        try testing.expect(false);
        return;
    };
    const body = out[split + 4 ..];

    // Body must be the full WaterMark signature, byte-identical.
    try testing.expectEqual(proto.WaterMark.len, body.len);
    try testing.expectEqualSlices(u8, proto.WaterMark, body);
}

test "downloadHello parses a scripted server Hello" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    const expected_random: [20]u8 = .{
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10,
    };

    const pack_bytes = try buildServerHelloPack(allocator, &expected_random, 442, 9745, "SoftEther VPN Server");
    defer allocator.free(pack_bytes);

    const http_response = try buildPackResponse(allocator, pack_bytes);
    defer allocator.free(http_response);
    transport.server_out = http_response;

    var hello = try proto.downloadHello(allocator, transport.reader());
    defer hello.deinit(allocator);

    try testing.expectEqualSlices(u8, &expected_random, &hello.random);
    try testing.expectEqual(@as(u32, 442), hello.server_ver);
    try testing.expectEqual(@as(u32, 9745), hello.server_build);
    try testing.expectEqualStrings("SoftEther VPN Server", hello.server_str);
}

test "downloadHello rejects malformed random length" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    var pack = Pack.init(allocator);
    defer pack.deinit();
    // 10 bytes instead of the required 20 — must be rejected.
    try pack.addData("random", &[_]u8{1} ** 10);
    try pack.addInt("version", 1);
    try pack.addInt("build", 1);
    try pack.addStr("hello", "x");
    const pack_bytes = try pack.toBytes(allocator);
    defer allocator.free(pack_bytes);

    const http_response = try buildPackResponse(allocator, pack_bytes);
    defer allocator.free(http_response);
    transport.server_out = http_response;

    try testing.expectError(proto.ProtocolError.InvalidHello, proto.downloadHello(allocator, transport.reader()));
}

test "downloadHello surfaces server error field" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addInt("error", 42);
    try pack.addStr("error_str", "go away");
    const pack_bytes = try pack.toBytes(allocator);
    defer allocator.free(pack_bytes);

    const http_response = try buildPackResponse(allocator, pack_bytes);
    defer allocator.free(http_response);
    transport.server_out = http_response;

    try testing.expectError(proto.ProtocolError.ServerError, proto.downloadHello(allocator, transport.reader()));
}

test "uploadAuth success returns session key and server overrides" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    const expected_session_key: [20]u8 = .{
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
        0xa1, 0xb2, 0xc3, 0xd4,
    };

    const auth_resp = try buildAuthSuccessPack(allocator, &expected_session_key, 4, true);
    defer allocator.free(auth_resp);
    const http_response = try buildPackResponse(allocator, auth_resp);
    defer allocator.free(http_response);
    transport.server_out = http_response;

    // Use a trivial auth pack — uploadAuth only forwards bytes to the writer
    // and parses the server response.
    var stub_auth = Pack.init(allocator);
    defer stub_auth.deinit();
    try stub_auth.addInt("method", 0);
    const auth_pack_bytes = try stub_auth.toBytes(allocator);
    defer allocator.free(auth_pack_bytes);

    var result = try proto.uploadAuth(allocator, transport.writer(), transport.reader(), "vpn.example.com", auth_pack_bytes);
    defer result.deinit(allocator);

    try testing.expect(result.success);
    try testing.expectEqual(@as(u32, 0), result.error_code);
    try testing.expect(result.session_key != null);
    try testing.expectEqualSlices(u8, &expected_session_key, &result.session_key.?);
    try testing.expectEqual(@as(u32, 4), result.server_max_connection);
    try testing.expect(result.server_use_encrypt);
    try testing.expect(result.redirect == null);

    // The wire bytes the client sent must contain a POST + Content-Length
    // matching the auth pack body length, followed by the body itself.
    const out = transport.client_out.items;
    try testing.expect(std.mem.startsWith(u8, out, "POST "));
    const split = std.mem.indexOf(u8, out, "\r\n\r\n").?;
    const body = out[split + 4 ..];
    try testing.expectEqualSlices(u8, auth_pack_bytes, body);
}

test "uploadAuth surfaces auth failure with error code" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    const fail_pack = try buildAuthFailurePack(allocator, 9, "Access denied");
    defer allocator.free(fail_pack);
    const http_response = try buildPackResponse(allocator, fail_pack);
    defer allocator.free(http_response);
    transport.server_out = http_response;

    var stub_auth = Pack.init(allocator);
    defer stub_auth.deinit();
    try stub_auth.addInt("method", 0);
    const auth_pack_bytes = try stub_auth.toBytes(allocator);
    defer allocator.free(auth_pack_bytes);

    var result = try proto.uploadAuth(allocator, transport.writer(), transport.reader(), "vpn.example.com", auth_pack_bytes);
    defer result.deinit(allocator);

    try testing.expect(!result.success);
    try testing.expectEqual(@as(u32, 9), result.error_code);
    try testing.expect(result.session_key == null);
    try testing.expect(result.error_message != null);
    try testing.expectEqualStrings("Access denied", result.error_message.?);
}

test "uploadAuth detects server redirect to cluster member" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    const ticket: [20]u8 = .{0xee} ** 20;
    var redirect = Pack.init(allocator);
    defer redirect.deinit();
    try redirect.addInt("error", 0);
    try redirect.addInt("Redirect", 1);
    try redirect.addInt("Ip", 0x0a000005); // 10.0.0.5 in host byte order
    try redirect.addInt("Port", 8443);
    try redirect.addData("Ticket", &ticket);
    const pack_bytes = try redirect.toBytes(allocator);
    defer allocator.free(pack_bytes);

    const http_response = try buildPackResponse(allocator, pack_bytes);
    defer allocator.free(http_response);
    transport.server_out = http_response;

    var stub_auth = Pack.init(allocator);
    defer stub_auth.deinit();
    try stub_auth.addInt("method", 0);
    const auth_pack_bytes = try stub_auth.toBytes(allocator);
    defer allocator.free(auth_pack_bytes);

    var result = try proto.uploadAuth(allocator, transport.writer(), transport.reader(), "vpn.example.com", auth_pack_bytes);
    defer result.deinit(allocator);

    try testing.expect(result.success);
    try testing.expect(result.redirect != null);
    try testing.expectEqual(@as(u32, 0x0a000005), result.redirect.?.ip);
    try testing.expectEqual(@as(u16, 8443), result.redirect.?.port);
    try testing.expectEqualSlices(u8, &ticket, &result.redirect.?.ticket);
}

test "performHandshake drives signature + hello + auth end-to-end" {
    const allocator = testing.allocator;
    var transport = ScriptedTransport{ .allocator = allocator };
    defer transport.deinit();

    const server_random: [20]u8 = .{0x42} ** 20;
    const session_key: [20]u8 = .{0x77} ** 20;

    // Server sends Hello then auth success, back-to-back on the same stream.
    const hello_pack = try buildServerHelloPack(allocator, &server_random, 444, 9807, "SoftEther VPN Server");
    defer allocator.free(hello_pack);
    const auth_pack = try buildAuthSuccessPack(allocator, &session_key, 1, true);
    defer allocator.free(auth_pack);

    const hello_resp = try buildPackResponse(allocator, hello_pack);
    defer allocator.free(hello_resp);
    const auth_resp = try buildPackResponse(allocator, auth_pack);
    defer allocator.free(auth_resp);

    var combined = std.ArrayListUnmanaged(u8){};
    defer combined.deinit(allocator);
    try combined.appendSlice(allocator, hello_resp);
    try combined.appendSlice(allocator, auth_resp);
    transport.server_out = combined.items;

    var result = try proto.performHandshake(
        allocator,
        transport.writer(),
        transport.reader(),
        "vpn.example.com",
        "DEFAULT",
        "anonymous",
        null, // anonymous auth
        false,
    );
    defer result.hello.deinit(allocator);
    defer result.auth.deinit(allocator);

    try testing.expectEqualSlices(u8, &server_random, &result.hello.random);
    try testing.expectEqual(@as(u32, 444), result.hello.server_ver);
    try testing.expect(result.auth.success);
    try testing.expect(result.auth.session_key != null);
    try testing.expectEqualSlices(u8, &session_key, &result.auth.session_key.?);

    // The client must have written exactly: signature POST + auth POST.
    // Both go to the VPN connect endpoint; the signature POST goes first.
    const out = transport.client_out.items;
    const first_post = std.mem.indexOf(u8, out, "POST ").?;
    try testing.expectEqual(@as(usize, 0), first_post);
    // There must be at least one more POST further along (the auth pack).
    try testing.expect(std.mem.indexOfPos(u8, out, first_post + 4, "POST ") != null);
}
