//! HTTP Module
//!
//! HTTP client utilities for SoftEther VPN connections.
//! Handles HTTP CONNECT proxy and initial HTTP handshake.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const socket = @import("socket.zig");
const TcpSocket = socket.TcpSocket;

/// HTTP method
pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    CONNECT,
    PATCH,

    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .CONNECT => "CONNECT",
            .PATCH => "PATCH",
        };
    }
};

/// HTTP status code
pub const StatusCode = enum(u16) {
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    proxy_auth_required = 407,
    request_timeout = 408,
    internal_server_error = 500,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    _,

    pub fn isSuccess(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 200 and code < 300;
    }

    pub fn isRedirect(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 300 and code < 400;
    }

    pub fn isClientError(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 400 and code < 500;
    }

    pub fn isServerError(self: StatusCode) bool {
        const code = @intFromEnum(self);
        return code >= 500;
    }
};

/// HTTP version
pub const Version = enum {
    http_1_0,
    http_1_1,

    pub fn toString(self: Version) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
        };
    }
};

/// HTTP header
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP request builder
pub const Request = struct {
    method: Method,
    path: []const u8,
    version: Version = .http_1_1,
    headers: std.ArrayListUnmanaged(Header),
    body: ?[]const u8 = null,
    allocator: Allocator,

    pub fn init(allocator: Allocator, method: Method, path: []const u8) Request {
        return .{
            .method = method,
            .path = path,
            .headers = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Request) void {
        self.headers.deinit(self.allocator);
    }

    pub fn addHeader(self: *Request, name: []const u8, value: []const u8) !void {
        try self.headers.append(self.allocator, .{ .name = name, .value = value });
    }

    pub fn setBody(self: *Request, body: []const u8) void {
        self.body = body;
    }

    /// Format request to buffer
    pub fn format(self: *const Request, buf: []u8) ![]u8 {
        var stream = std.io.fixedBufferStream(buf);
        const writer = stream.writer();

        // Request line
        try writer.print("{s} {s} {s}\r\n", .{
            self.method.toString(),
            self.path,
            self.version.toString(),
        });

        // Headers
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // Content-Length if body present
        if (self.body) |body| {
            try writer.print("Content-Length: {d}\r\n", .{body.len});
        }

        // End of headers
        try writer.writeAll("\r\n");

        // Body
        if (self.body) |body| {
            try writer.writeAll(body);
        }

        return buf[0..stream.pos];
    }
};

/// HTTP response parser
pub const Response = struct {
    version: Version,
    status_code: StatusCode,
    status_text: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    raw_data: []u8,
    allocator: Allocator,

    pub fn deinit(self: *Response) void {
        self.headers.deinit();
        self.allocator.free(self.raw_data);
    }

    /// Get header value (case-insensitive)
    pub fn getHeader(self: *const Response, name: []const u8) ?[]const u8 {
        // Headers are stored lowercased
        var lower_name: [256]u8 = undefined;
        const lower = toLowerBuf(name, &lower_name) catch return null;
        return self.headers.get(lower);
    }

    pub fn getContentLength(self: *const Response) ?usize {
        const value = self.getHeader("content-length") orelse return null;
        return std.fmt.parseInt(usize, value, 10) catch null;
    }

    pub fn isChunked(self: *const Response) bool {
        const encoding = self.getHeader("transfer-encoding") orelse return false;
        return std.mem.indexOf(u8, encoding, "chunked") != null;
    }
};

/// Parse HTTP response from socket
pub fn parseResponse(allocator: Allocator, reader: anytype) !Response {
    var raw = std.ArrayListUnmanaged(u8){};
    errdefer raw.deinit(allocator);

    // Read until we find \r\n\r\n (end of headers)
    var found_end = false;
    var buf: [4096]u8 = undefined;
    var header_end: usize = 0;

    while (!found_end) {
        const n = try reader.read(&buf);
        if (n == 0) return error.ConnectionClosed;

        const start_search = if (raw.items.len >= 3) raw.items.len - 3 else 0;
        try raw.appendSlice(allocator, buf[0..n]);

        // Look for \r\n\r\n
        for (start_search..raw.items.len -| 3) |i| {
            if (std.mem.eql(u8, raw.items[i .. i + 4], "\r\n\r\n")) {
                found_end = true;
                header_end = i + 4;
                break;
            }
        }

        if (raw.items.len > 64 * 1024) {
            return error.ResponseTooLarge;
        }
    }

    const raw_data = try raw.toOwnedSlice(allocator);
    errdefer allocator.free(raw_data);

    // Parse status line
    const status_line_end = std.mem.indexOf(u8, raw_data, "\r\n") orelse return error.InvalidResponse;
    const status_line = raw_data[0..status_line_end];

    // Parse "HTTP/1.1 200 OK"
    var parts = std.mem.tokenizeScalar(u8, status_line, ' ');
    const version_str = parts.next() orelse return error.InvalidResponse;
    const status_str = parts.next() orelse return error.InvalidResponse;
    const status_text = parts.rest();

    const version: Version = if (std.mem.eql(u8, version_str, "HTTP/1.0"))
        .http_1_0
    else if (std.mem.eql(u8, version_str, "HTTP/1.1"))
        .http_1_1
    else
        return error.UnsupportedHttpVersion;

    const status_code: StatusCode = @enumFromInt(std.fmt.parseInt(u16, status_str, 10) catch return error.InvalidStatusCode);

    // Parse headers
    var headers = std.StringHashMap([]const u8).init(allocator);
    errdefer headers.deinit();

    const headers_data = raw_data[status_line_end + 2 .. header_end - 2];
    var lines = std.mem.splitSequence(u8, headers_data, "\r\n");

    while (lines.next()) |line| {
        if (line.len == 0) continue;

        const colon = std.mem.indexOf(u8, line, ":") orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " ");
        const value = std.mem.trim(u8, line[colon + 1 ..], " ");

        // Store lowercase header name
        var lower_name: [256]u8 = undefined;
        const lower = try toLowerBuf(name, &lower_name);

        // Store reference to data in raw_data
        try headers.put(lower, value);
    }

    return .{
        .version = version,
        .status_code = status_code,
        .status_text = status_text,
        .headers = headers,
        .body = raw_data[header_end..],
        .raw_data = raw_data,
        .allocator = allocator,
    };
}

fn toLowerBuf(str: []const u8, buf: []u8) ![]u8 {
    if (str.len > buf.len) return error.BufferTooSmall;
    for (str, 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..str.len];
}

// ============================================================================
// HTTP CONNECT proxy support (for SoftEther through proxy)
// ============================================================================

/// HTTP proxy configuration
pub const ProxyConfig = struct {
    host: []const u8,
    port: u16,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
};

/// Connect through HTTP CONNECT proxy
pub fn connectViaProxy(
    allocator: Allocator,
    proxy: ProxyConfig,
    target_host: []const u8,
    target_port: u16,
) !TcpSocket {
    // Connect to proxy
    var tcp = try TcpSocket.connectHost(proxy.host, proxy.port, 30000);
    errdefer tcp.close();

    // Build CONNECT request
    var req = Request.init(allocator, .CONNECT, target_host);
    defer req.deinit();

    // Host header with port
    var host_buf: [256]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "{s}:{d}", .{ target_host, target_port });
    try req.addHeader("Host", host);

    // Proxy auth if needed
    if (proxy.username) |username| {
        if (proxy.password) |password| {
            // Base64 encode username:password
            var auth_buf: [512]u8 = undefined;
            const auth_str = try std.fmt.bufPrint(&auth_buf, "{s}:{s}", .{ username, password });

            var encoded_buf: [1024]u8 = undefined;
            const encoded_len = std.base64.standard.Encoder.calcSize(auth_str.len);
            const encoded = encoded_buf[0..encoded_len];
            _ = std.base64.standard.Encoder.encode(encoded, auth_str);

            var auth_header: [1100]u8 = undefined;
            const auth_value = try std.fmt.bufPrint(&auth_header, "Basic {s}", .{encoded});
            try req.addHeader("Proxy-Authorization", auth_value);
        }
    }

    // Send request
    var send_buf: [2048]u8 = undefined;
    const request_data = try req.format(&send_buf);
    try tcp.writeAll(request_data);

    // Read response
    var response = try parseResponse(allocator, tcp.stream.reader());
    defer response.deinit();

    if (!response.status_code.isSuccess()) {
        if (response.status_code == .proxy_auth_required) {
            return error.ProxyAuthRequired;
        }
        return error.ProxyConnectionFailed;
    }

    return tcp;
}

// ============================================================================
// SoftEther HTTP layer handshake
// ============================================================================

/// SoftEther initial HTTP-like handshake format
pub const SoftEtherHttpHandshake = struct {
    /// Send SoftEther HTTP-style client hello
    pub fn sendClientHello(
        writer: anytype,
        hub_name: []const u8,
        client_str: []const u8,
    ) !void {
        // SoftEther uses a POST request with specific headers
        try writer.print("POST /vpnsvc/connect.cgi HTTP/1.1\r\n", .{});
        try writer.print("Host: vpn\r\n", .{});
        try writer.print("Content-Type: application/octet-stream\r\n", .{});
        try writer.print("X-VPN-Hub: {s}\r\n", .{hub_name});
        try writer.print("User-Agent: {s}\r\n", .{client_str});
        try writer.print("Connection: Keep-Alive\r\n", .{});
        try writer.print("Content-Length: 0\r\n", .{});
        try writer.print("\r\n", .{});
    }

    /// Parse SoftEther HTTP-style server response
    pub fn parseServerResponse(reader: anytype) !bool {
        var buf: [1024]u8 = undefined;
        const line = (try reader.readUntilDelimiterOrEof(&buf, '\n')) orelse return false;

        // Expect "HTTP/1.1 200 OK" or similar
        return std.mem.startsWith(u8, line, "HTTP/1.1 200") or
            std.mem.startsWith(u8, line, "HTTP/1.0 200");
    }
};

// ============================================================================
// Tests
// ============================================================================

test "StatusCode classifications" {
    try testing.expect(StatusCode.ok.isSuccess());
    try testing.expect(StatusCode.found.isRedirect());
    try testing.expect(StatusCode.not_found.isClientError());
    try testing.expect(StatusCode.internal_server_error.isServerError());
}

test "Request formatting" {
    var req = Request.init(testing.allocator, .GET, "/api/test");
    defer req.deinit();

    try req.addHeader("Host", "example.com");
    try req.addHeader("Accept", "*/*");

    var buf: [1024]u8 = undefined;
    const formatted = try req.format(&buf);

    try testing.expect(std.mem.startsWith(u8, formatted, "GET /api/test HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, formatted, "Host: example.com\r\n") != null);
}

test "Method toString" {
    try testing.expectEqualStrings("GET", Method.GET.toString());
    try testing.expectEqualStrings("POST", Method.POST.toString());
    try testing.expectEqualStrings("CONNECT", Method.CONNECT.toString());
}
