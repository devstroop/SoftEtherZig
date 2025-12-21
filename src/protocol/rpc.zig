//! SoftEther RPC (Remote Procedure Call) Protocol
//!
//! SoftEther uses a custom RPC protocol over HTTP/HTTPS for client-server
//! communication. The protocol sends Pack-serialized requests and responses.
//!
//! HTTP Request Format:
//! - POST to /vpnsvc/connect.cgi
//! - Content-Type: application/octet-stream
//! - Body: Pack-serialized request
//!
//! Initial handshake:
//! 1. Client sends HTTP POST with "method" = "hello"
//! 2. Server responds with random challenge
//! 3. Client authenticates with signed challenge
//! 4. Session established

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const pack = @import("pack.zig");
const Pack = pack.Pack;

/// RPC error types
pub const RpcError = error{
    ConnectionFailed,
    AuthenticationFailed,
    InvalidResponse,
    ProtocolError,
    Timeout,
    ServerError,
    OutOfMemory,
};

/// RPC method names used in SoftEther protocol
pub const Method = struct {
    pub const hello = "Hello";
    pub const auth = "Auth";
    pub const connect = "Connect";
    pub const disconnect = "Disconnect";
    pub const get_config = "GetConfig";
    pub const create_session = "CreateSession";
    pub const get_status = "GetStatus";
};

/// SoftEther protocol constants
pub const Protocol = struct {
    /// HTTP endpoint for RPC
    pub const endpoint = "/vpnsvc/connect.cgi";

    /// Content type for Pack data
    pub const content_type = "application/octet-stream";

    /// HTTP method
    pub const http_method = "POST";

    /// Connection timeout (ms)
    pub const connect_timeout_ms = 30000;

    /// Read timeout (ms)
    pub const read_timeout_ms = 60000;

    /// Protocol version
    pub const version: u32 = 1;

    /// Max pack size
    pub const max_pack_size = 128 * 1024 * 1024;
};

/// RPC request builder
pub const Request = struct {
    const Self = @This();

    allocator: Allocator,
    pack: Pack,

    pub fn init(allocator: Allocator, method: []const u8) !Self {
        var req = Self{
            .allocator = allocator,
            .pack = Pack.init(allocator),
        };
        try req.pack.addStr("method", method);
        return req;
    }

    pub fn deinit(self: *Self) void {
        self.pack.deinit();
    }

    /// Add an integer parameter
    pub fn addInt(self: *Self, name: []const u8, value: u32) !void {
        try self.pack.addInt(name, value);
    }

    /// Add a 64-bit integer parameter
    pub fn addInt64(self: *Self, name: []const u8, value: u64) !void {
        try self.pack.addInt64(name, value);
    }

    /// Add a string parameter
    pub fn addStr(self: *Self, name: []const u8, value: []const u8) !void {
        try self.pack.addStr(name, value);
    }

    /// Add a Unicode string parameter
    pub fn addUniStr(self: *Self, name: []const u8, value: []const u8) !void {
        try self.pack.addUniStr(name, value);
    }

    /// Add binary data parameter
    pub fn addData(self: *Self, name: []const u8, value: []const u8) !void {
        try self.pack.addData(name, value);
    }

    /// Add a boolean parameter
    pub fn addBool(self: *Self, name: []const u8, value: bool) !void {
        try self.pack.addBool(name, value);
    }

    /// Serialize request to bytes
    pub fn toBytes(self: *Self) ![]u8 {
        return self.pack.toBytes(self.allocator);
    }
};

/// RPC response parser
pub const Response = struct {
    const Self = @This();

    allocator: Allocator,
    pack: Pack,

    pub fn fromBytes(allocator: Allocator, data: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .pack = try Pack.fromBytes(allocator, data),
        };
    }

    pub fn deinit(self: *Self) void {
        self.pack.deinit();
    }

    /// Check if the response indicates success
    pub fn isSuccess(self: *const Self) bool {
        const error_code = self.pack.getInt("error") orelse return true;
        return error_code == 0;
    }

    /// Get error code
    pub fn getErrorCode(self: *const Self) ?u32 {
        return self.pack.getInt("error");
    }

    /// Get error message
    pub fn getErrorMessage(self: *const Self) ?[]const u8 {
        return self.pack.getStr("error_str");
    }

    /// Get an integer value
    pub fn getInt(self: *const Self, name: []const u8) ?u32 {
        return self.pack.getInt(name);
    }

    /// Get a 64-bit integer value
    pub fn getInt64(self: *const Self, name: []const u8) ?u64 {
        return self.pack.getInt64(name);
    }

    /// Get a string value
    pub fn getStr(self: *const Self, name: []const u8) ?[]const u8 {
        return self.pack.getStr(name);
    }

    /// Get a Unicode string value
    pub fn getUniStr(self: *const Self, name: []const u8) ?[]const u8 {
        return self.pack.getUniStr(name);
    }

    /// Get binary data
    pub fn getData(self: *const Self, name: []const u8) ?[]const u8 {
        return self.pack.getData(name);
    }

    /// Get a boolean value
    pub fn getBool(self: *const Self, name: []const u8) ?bool {
        return self.pack.getBool(name);
    }
};

/// Build HTTP request headers for RPC
pub fn buildHttpRequest(
    allocator: Allocator,
    host: []const u8,
    port: u16,
    body_len: usize,
) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    const writer = list.writer(allocator);

    try writer.print("{s} {s} HTTP/1.1\r\n", .{ Protocol.http_method, Protocol.endpoint });
    try writer.print("Host: {s}:{d}\r\n", .{ host, port });
    try writer.print("Content-Type: {s}\r\n", .{Protocol.content_type});
    try writer.print("Content-Length: {d}\r\n", .{body_len});
    try writer.writeAll("Connection: keep-alive\r\n");
    try writer.writeAll("Accept: */*\r\n");
    try writer.writeAll("\r\n");

    return list.toOwnedSlice(allocator);
}

/// Parse HTTP response, return body start offset and content length
pub fn parseHttpResponse(data: []const u8) !struct { body_offset: usize, content_length: usize, status_code: u16 } {
    // Find end of headers
    const header_end = mem.indexOf(u8, data, "\r\n\r\n") orelse return error.InvalidResponse;
    const body_offset = header_end + 4;

    const headers = data[0..header_end];

    // Parse status line
    const status_line_end = mem.indexOf(u8, headers, "\r\n") orelse return error.InvalidResponse;
    const status_line = headers[0..status_line_end];

    // Parse "HTTP/1.x NNN ..."
    if (!mem.startsWith(u8, status_line, "HTTP/1.")) return error.InvalidResponse;

    var parts = mem.splitScalar(u8, status_line, ' ');
    _ = parts.next(); // HTTP/1.x
    const status_str = parts.next() orelse return error.InvalidResponse;
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch return error.InvalidResponse;

    // Parse Content-Length
    var content_length: usize = 0;
    var lines = mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (mem.startsWith(u8, line, "Content-Length:") or mem.startsWith(u8, line, "content-length:")) {
            const value_start = mem.indexOf(u8, line, ":").? + 1;
            const value = mem.trim(u8, line[value_start..], " ");
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidResponse;
            break;
        }
    }

    return .{
        .body_offset = body_offset,
        .content_length = content_length,
        .status_code = status_code,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "Request creation and serialization" {
    const allocator = testing.allocator;

    var req = try Request.init(allocator, Method.hello);
    defer req.deinit();

    try req.addStr("client_str", "SoftEther VPN Client");
    try req.addInt("client_ver", 1);
    try req.addInt("client_build", 9999);

    const bytes = try req.toBytes();
    defer allocator.free(bytes);

    try testing.expect(bytes.len > 0);

    // Verify we can parse it back
    var resp = try Response.fromBytes(allocator, bytes);
    defer resp.deinit();

    try testing.expectEqualStrings("Hello", resp.getStr("method").?);
}

test "HTTP request building" {
    const allocator = testing.allocator;

    const request = try buildHttpRequest(allocator, "vpn.example.com", 443, 256);
    defer allocator.free(request);

    try testing.expect(mem.indexOf(u8, request, "POST /vpnsvc/connect.cgi HTTP/1.1") != null);
    try testing.expect(mem.indexOf(u8, request, "Host: vpn.example.com:443") != null);
    try testing.expect(mem.indexOf(u8, request, "Content-Length: 256") != null);
}

test "HTTP response parsing" {
    const response_data =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/octet-stream\r\n" ++
        "Content-Length: 42\r\n" ++
        "\r\n" ++
        "0123456789012345678901234567890123456789XX";

    const result = try parseHttpResponse(response_data);
    try testing.expectEqual(@as(u16, 200), result.status_code);
    try testing.expectEqual(@as(usize, 42), result.content_length);
    try testing.expect(result.body_offset > 0);
}
