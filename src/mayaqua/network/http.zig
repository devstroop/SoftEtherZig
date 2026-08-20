//! HTTP Module
//!
//! HTTP client utilities for SoftEther VPN connections.
//! Handles HTTP CONNECT proxy and initial HTTP handshake.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const net = std.net;

const socket = @import("socket.zig");
const TcpSocket = socket.TcpSocket;
const socks = @import("socks.zig");
const tls_mod = @import("tls.zig");
const TlsSocket = tls_mod.TlsSocket;

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
    proxy_type: ProxyType = .http,

    pub const ProxyType = enum {
        http,
        socks4,
        socks5,
    };
};

/// Connect through proxy (HTTP CONNECT, SOCKS4, or SOCKS5).
/// Returns a TcpSocket connected to the target host through the proxy.
pub fn connectViaProxy(
    allocator: Allocator,
    proxy: ProxyConfig,
    target_host: []const u8,
    target_port: u16,
) !TcpSocket {
    return switch (proxy.proxy_type) {
        .http => connectViaHttpConnect(allocator, proxy, target_host, target_port),
        .socks4 => socks.connectViaSocks4(allocator, .{
            .host = proxy.host,
            .port = proxy.port,
            .username = proxy.username,
            .password = proxy.password,
        }, target_host, target_port),
        .socks5 => socks.connectViaSocks5(allocator, .{
            .host = proxy.host,
            .port = proxy.port,
            .username = proxy.username,
            .password = proxy.password,
        }, target_host, target_port),
    };
}

/// Connect through HTTP CONNECT proxy
fn connectViaHttpConnect(
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
    var response = try parseResponse(allocator, tcp.stream);
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
// SoftEther HTTP server envelope (HttpServerRecvEx / HttpServerSend parity)
// ============================================================================

/// Content-Type SoftEther clients send on every VPN POST and expect back on
/// every server response (C: HTTP_CONTENT_TYPE2).
pub const vpn_content_type = "application/octet-stream";
/// POST target for Pack exchanges over the TLS connection (C: HTTP_VPN_TARGET).
/// Only this target is accepted by the envelope: the `connect.cgi` POSTs
/// (signature upload, client hello) are plaintext-HTTP handshakes handled
/// server-side before TLS (C: ServerDownloadSignature), not HttpServerRecvEx.
pub const vpn_target = "/vpnsvc/vpn.cgi";
/// Keep-Alive header value the server echoes (C: HTTP_KEEP_ALIVE).
pub const vpn_keep_alive = "timeout=15; max=19";
/// Hard cap on a Pack body carried in a VPN HTTP exchange (C: HTTP_PACK_MAX_SIZE).
pub const max_pack_body_len: usize = 65536;
/// Cap on the request head (request line + headers) buffered while scanning
/// for the terminating blank line. C caps each line at 4096; capping the whole
/// head keeps a misbehaving client from forcing unbounded buffering.
pub const max_request_head_len: usize = 32 * 1024;

/// A validated SoftEther HTTP POST as received by the server (C: HttpServerRecvEx).
/// `body` is exactly `content_length` bytes at the front of the caller's
/// buffer. The head is validated inside the envelope and then overwritten by
/// the body, so no header state is retained (C frees the HTTP_HEADER after
/// reading the body). `method`/`uri`/`version` are the canonical values that
/// passed validation (static literals, never slices into the body buffer).
pub const HttpRequest = struct {
    method: []const u8 = "POST",
    uri: []const u8,
    version: []const u8 = "HTTP/1.1",
    content_length: usize,
    body: []u8,
};

/// Parse and validate a request head (request line + headers, WITHOUT the
/// terminating `\r\n\r\n`). Mirrors the checks in C's HttpServerRecvEx:
/// POST /vpnsvc/vpn.cgi HTTP/1.1, the VPN content type, and a sane
/// Content-Length. Returns the validated content length.
fn parseRequestHead(head: []const u8) !usize {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return error.InvalidRequest;
    const request_line = head[0..line_end];

    var tokens = std.mem.tokenizeAny(u8, request_line, " ");
    const method = tokens.next() orelse return error.InvalidRequest;
    const uri = tokens.next() orelse return error.InvalidRequest;
    const version = tokens.next() orelse return error.InvalidRequest;
    if (tokens.next() != null) return error.InvalidRequest;

    if (!std.ascii.eqlIgnoreCase(method, "POST")) return error.UnsupportedMethod;
    if (!std.ascii.eqlIgnoreCase(version, "HTTP/1.1")) return error.UnsupportedVersion;
    if (!std.ascii.eqlIgnoreCase(uri, vpn_target)) return error.InvalidUri;

    var content_type_ok = false;
    var content_length: usize = 0;
    var lines = std.mem.splitSequence(u8, head[line_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Content-Type")) {
            content_type_ok = std.ascii.eqlIgnoreCase(value, vpn_content_type);
        } else if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
        }
    }

    if (!content_type_ok) return error.InvalidContentType;
    if (content_length == 0 or content_length > max_pack_body_len) return error.InvalidContentLength;

    return content_length;
}

/// Parse an HTTP/1.1 response status line and extract Content-Length.
/// Used by `readHttpResponse` (C: `HttpClientRecv` pattern).
fn parseResponseHead(head: []const u8) !usize {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return error.InvalidResponse;
    const status_line = head[0..line_end];

    var tokens = std.mem.tokenizeAny(u8, status_line, " ");
    _ = tokens.next() orelse return error.InvalidResponse; // version
    const status = tokens.next() orelse return error.InvalidResponse; // "200"
    _ = tokens.next() orelse return error.InvalidResponse; // "OK"

    if (!std.mem.eql(u8, status, "200")) return error.HttpError;

    var content_length: usize = 0;
    var lines = std.mem.splitSequence(u8, head[line_end + 2 ..], "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
        }
    }

    if (content_length == 0 or content_length > max_pack_body_len) return error.InvalidContentLength;

    return content_length;
}

/// Read and validate one SoftEther HTTP POST from an accepted TLS socket
/// (C: HttpServerRecvEx). The head is scanned byte-by-byte through the
/// socket's read-ahead buffer until the terminating blank line, then exactly
/// Content-Length body bytes are read into `buf[0..content_length]`. Reads are
/// byte-exact (like C's RecvLine/RecvAll), so any bytes beyond the current
/// request — the start of the next keep-alive POST — stay in the socket's
/// read-ahead buffer and are served by the next call. `buf` must be at least
/// `content_length` bytes (size it to `max_pack_body_len`).
pub fn readHttpRequest(sock: *TlsSocket, buf: []u8) !HttpRequest {
    const head_cap = @min(buf.len, max_request_head_len);
    var head_len: usize = 0;
    var head_found = false;
    while (head_len < head_cap) {
        const n = try sock.readBlocking(buf[head_len .. head_len + 1]);
        if (n == 0) return error.EndOfStream;
        head_len += n;
        if (head_len >= 4 and std.mem.eql(u8, buf[head_len - 4 .. head_len], "\r\n\r\n")) {
            head_found = true;
            break;
        }
    }
    if (!head_found) return error.HeaderTooLarge;

    const content_length = try parseRequestHead(buf[0 .. head_len - 4]);
    if (content_length > buf.len) return error.BufferTooSmall;

    const body = buf[0..content_length];
    var got: usize = 0;
    while (got < body.len) {
        const m = try sock.readBlocking(body[got..]);
        if (m == 0) return error.EndOfStream;
        got += m;
    }

    return .{
        .uri = vpn_target,
        .content_length = content_length,
        .body = body,
    };
}

/// Format an RFC 1123 date like C's GetHttpDateStr ("Sat, 20 Dec 2025 ... GMT").
fn httpDateStr(buf: []u8) []const u8 {
    const wday = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    const now_ts = std.time.timestamp();
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(now_ts) };
    const day_secs = epoch.getDaySeconds();
    const epoch_day = epoch.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const hour = day_secs.getHoursIntoDay();
    const minute = day_secs.getMinutesIntoHour();
    const second = day_secs.getSecondsIntoMinute();
    const month_day = year_day.calculateMonthDay();
    const day: u32 = month_day.day_index + 1;
    const month_idx: usize = @intFromEnum(month_day.month) - 1;
    const year = year_day.year;
    const weekday_idx: usize = @intCast(@mod(@as(i64, @intCast(epoch_day.day)) + 3, 7));

    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        wday[weekday_idx], day, months[month_idx], year, hour, minute, second,
    }) catch unreachable;
}

/// Build the response head (status line + headers + blank line) for a body of
/// `body_len` bytes. The client requires Content-Type application/octet-stream
/// and Content-Length, so both are emitted alongside the C keep-alive headers.
fn buildResponseHead(buf: []u8, body_len: usize) []const u8 {
    var date_buf: [64]u8 = undefined;
    return std.fmt.bufPrint(
        buf,
        "HTTP/1.1 200 OK\r\n" ++
            "Date: {s}\r\n" ++
            "Keep-Alive: {s}\r\n" ++
            "Connection: Keep-Alive\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n",
        .{ httpDateStr(&date_buf), vpn_keep_alive, vpn_content_type, body_len },
    ) catch unreachable;
}

/// Write an HTTP/1.1 200 OK response carrying `body` (C: HttpServerSend).
pub fn sendHttpResponse(sock: *TlsSocket, body: []const u8) !void {
    var head_buf: [512]u8 = undefined;
    const head = buildResponseHead(&head_buf, body.len);
    try sock.writeAll(head);
    try sock.writeAll(body);
}

/// Build the request head (POST line + headers + blank line) for a body of
/// `body_len` bytes. Mirrors C `HttpClientSend` (Network.c:22897).
fn buildRequestHead(buf: []u8, body_len: usize, host: []const u8) []const u8 {
    var date_buf: [64]u8 = undefined;
    return std.fmt.bufPrint(
        buf,
        "POST " ++ vpn_target ++ " HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Date: {s}\r\n" ++
            "Keep-Alive: {s}\r\n" ++
            "Connection: Keep-Alive\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n",
        .{ host, httpDateStr(&date_buf), vpn_keep_alive, vpn_content_type, body_len },
    ) catch unreachable;
}

/// Write an HTTP/1.1 POST request carrying `body` (C: `HttpClientSend`).
/// Used by the farm member to send the initial `farm_connect` Pack.
pub fn sendHttpRequest(sock: *TlsSocket, body: []const u8, host: []const u8) !void {
    var head_buf: [512]u8 = undefined;
    const head = buildRequestHead(&head_buf, body.len, host);
    try sock.writeAll(head);
    try sock.writeAll(body);
}

/// Read an HTTP/1.1 response body. Mirrors C `HttpClientRecv` (Network.c:22815).
/// Returns the response body bytes (valid until the next read on this socket).
pub fn readHttpResponse(sock: *TlsSocket, buf: []u8) !HttpResponse {
    const head_cap = @min(buf.len, max_request_head_len);
    var head_len: usize = 0;
    var head_found = false;
    while (head_len < head_cap) {
        const n = try sock.readBlocking(buf[head_len .. head_len + 1]);
        if (n == 0) return error.EndOfStream;
        head_len += n;
        if (head_len >= 4 and std.mem.eql(u8, buf[head_len - 4 .. head_len], "\r\n\r\n")) {
            head_found = true;
            break;
        }
    }
    if (!head_found) return error.HeaderTooLarge;

    const content_length = try parseResponseHead(buf[0 .. head_len - 4]);
    if (content_length > buf.len) return error.BufferTooSmall;

    const body = buf[0..content_length];
    var got: usize = 0;
    while (got < body.len) {
        const m = try sock.readBlocking(body[got..]);
        if (m == 0) return error.EndOfStream;
        got += m;
    }

    return .{
        .content_length = content_length,
        .body = body,
    };
}

pub const HttpResponse = struct {
    content_length: usize,
    body: []u8,
};

// ============================================================================
// Tests
// ============================================================================

test "mayaqua_http.request head parsing" {
    const allocator = testing.allocator;

    // Canonical request: POST /vpnsvc/vpn.cgi, matches C HttpClientSend.
    const req = try std.fmt.allocPrint(
        allocator,
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n" ++
            "Host: vpn\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "Content-Length: {d}\r\n",
        .{17},
    );
    defer allocator.free(req);
    try testing.expectEqual(@as(usize, 17), try parseRequestHead(req));

    // The connect.cgi target (signature upload / client hello) is a pre-TLS
    // handshake handled by the server before the envelope — rejected here,
    // mirroring C's HttpServerRecvEx.
    try testing.expectError(error.InvalidUri, parseRequestHead("POST /vpnsvc/connect.cgi HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n"));

    try testing.expectError(error.UnsupportedMethod, parseRequestHead("GET /vpnsvc/vpn.cgi HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n"));
    try testing.expectError(error.UnsupportedVersion, parseRequestHead("POST /vpnsvc/vpn.cgi HTTP/1.0\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n"));
    try testing.expectError(error.InvalidUri, parseRequestHead("POST /other HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n"));
    try testing.expectError(error.InvalidContentType, parseRequestHead("POST /vpnsvc/vpn.cgi HTTP/1.1\r\nContent-Type: image/jpeg\r\nContent-Length: 4\r\n"));
    try testing.expectError(error.InvalidContentLength, parseRequestHead("POST /vpnsvc/vpn.cgi HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 0\r\n"));
    try testing.expectError(error.InvalidContentLength, parseRequestHead("POST /vpnsvc/vpn.cgi HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 65537\r\n"));
    try testing.expectError(error.InvalidRequest, parseRequestHead("POST /vpnsvc/vpn.cgi\r\nContent-Length: 4\r\n"));
}

test "mayaqua_http.response head build" {
    var buf: [512]u8 = undefined;
    const head = buildResponseHead(&buf, 42);
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Content-Type: application/octet-stream\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length: 42\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Keep-Alive: timeout=15; max=19\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));
}

var test_dial_fd: std.posix.socket_t = -1;

fn testDial(host: [*:0]const u8, port: u16) callconv(.c) c_int {
    _ = host;
    _ = port;
    return test_dial_fd;
}

/// Server side of the roundtrip: TLS accept, then read two pipelined POSTs
/// and echo each body back. The second read exercises the keep-alive path
/// where its bytes were already buffered by the first read.
const ServerEnvelopeCtx = struct {
    allocator: Allocator,
    fd: std.posix.socket_t,
    cert_pem: []const u8,
    key_pem: []const u8,
    err: ?anyerror = null,
};

fn serverEnvelopeThread(ctx: *ServerEnvelopeCtx) void {
    var sock = TlsSocket.accept(ctx.allocator, ctx.fd, .{
        .cert_pem = ctx.cert_pem,
        .key_pem = ctx.key_pem,
        .timeout_ms = 10000,
    }) catch |err| {
        ctx.err = err;
        return;
    };
    defer sock.close();

    var buf: [4096]u8 = undefined;
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        const req = readHttpRequest(&sock, &buf) catch |err| {
            ctx.err = err;
            return;
        };
        sendHttpResponse(&sock, req.body) catch |err| {
            ctx.err = err;
            return;
        };
    }
}

fn buildPost(allocator: Allocator, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n" ++
            "Host: http.test\r\n" ++
            "Keep-Alive: timeout=15; max=19\r\n" ++
            "Connection: Keep-Alive\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n" ++
            "{s}",
        .{ body.len, body },
    );
}

/// Client-side response reader for the test: reads the 200 head byte-by-byte,
/// then exactly Content-Length body bytes (mirrors readHttpRequest).
fn readTestResponse(sock: *TlsSocket, allocator: Allocator) ![]u8 {
    var head_buf: [1024]u8 = undefined;
    var head_len: usize = 0;
    while (head_len < head_buf.len) {
        const n = try sock.readBlocking(head_buf[head_len .. head_len + 1]);
        if (n == 0) return error.EndOfStream;
        head_len += n;
        if (head_len >= 4 and std.mem.eql(u8, head_buf[head_len - 4 .. head_len], "\r\n\r\n")) break;
    }
    const resp_head = head_buf[0 .. head_len - 4];
    try testing.expect(std.mem.startsWith(u8, resp_head, "HTTP/1.1 200 OK"));
    try testing.expect(std.mem.indexOf(u8, resp_head, "Content-Type: application/octet-stream") != null);

    var content_length: usize = 0;
    var lines = std.mem.splitSequence(u8, resp_head, "\r\n");
    while (lines.next()) |line| {
        if (std.ascii.startsWithIgnoreCase(line, "Content-Length:")) {
            const value = std.mem.trim(u8, line["Content-Length:".len..], " \t");
            content_length = try std.fmt.parseInt(usize, value, 10);
        }
    }

    const body = try allocator.alloc(u8, content_length);
    errdefer allocator.free(body);
    var got: usize = 0;
    while (got < body.len) {
        const m = try sock.readBlocking(body[got..]);
        if (m == 0) return error.EndOfStream;
        got += m;
    }
    return body;
}

test "mayaqua_http.server envelope roundtrip over TLS accept" {
    // Requires AF_UNIX socketpair, only guaranteed on Linux.
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = testing.allocator;

    const cert = try tls_mod.generateSelfSignedCert(allocator, "http.test");
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var fds: [2]std.posix.socket_t = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (std.os.linux.E.init(rc) != .SUCCESS) return error.SocketPairFailed;

    // Server side: TLS accept + envelope read/echo on fds[0] from its own
    // thread (the blocking handshake must run parallel to the client connect).
    var server_ctx = ServerEnvelopeCtx{
        .allocator = allocator,
        .fd = fds[0],
        .cert_pem = cert.cert_pem,
        .key_pem = cert.key_pem,
    };
    const server_thread = try std.Thread.spawn(.{}, serverEnvelopeThread, .{&server_ctx});
    var thread_joined = false;
    defer if (!thread_joined) server_thread.join();

    // Client side: TLS connect on fds[1] via the host dial callback, then POST
    // two Pack bodies back-to-back in a single write — exactly like C's
    // keep-alive client (SendAll of head + body, then the next request).
    test_dial_fd = @intCast(fds[1]);
    var client = TlsSocket.connect(allocator, "http-sni.example", 443, .{
        .allow_self_signed = true,
        .timeout_ms = 10000,
        .external_tcp_dial = testDial,
    }) catch |err| {
        std.posix.close(fds[1]);
        return err;
    };
    test_dial_fd = -1;
    defer client.close();

    const request_bodies = [_][]const u8{ "canned pack body 1234", "second keep-alive request" };
    var request = std.ArrayListUnmanaged(u8){};
    defer request.deinit(allocator);
    for (request_bodies) |body| {
        const post = try buildPost(allocator, body);
        defer allocator.free(post);
        try request.appendSlice(allocator, post);
    }
    try client.writeAll(request.items);

    server_thread.join();
    thread_joined = true;
    if (server_ctx.err) |err| return err;

    // Both responses must echo their request body — the second one proves the
    // surplus bytes of the pipelined POST were preserved across the first read.
    for (request_bodies) |expected| {
        const resp_body = try readTestResponse(&client, allocator);
        defer allocator.free(resp_body);
        try testing.expectEqual(expected.len, resp_body.len);
        try testing.expectEqualStrings(expected, resp_body);
    }
}

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
