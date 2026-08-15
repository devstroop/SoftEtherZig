//! SoftEther VPN Protocol Implementation
//!
//! This module implements the SoftEther protocol handshake sequence:
//! 1. Upload Signature (WaterMark) - HTTP POST to /vpnsvc/connect.cgi
//! 2. Download Hello - Receive server challenge
//! 3. Upload Auth - Send authentication credentials
//! 4. Receive Session - Get session parameters
//!
//! The protocol uses HTTP as transport with Pack binary serialization.

const std = @import("std");
const log = std.log.scoped(.cedar_proto);
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;

const pack = @import("pack.zig");
pub const Pack = pack.Pack;
const rpc = @import("rpc.zig");
const auth_mod = @import("auth.zig");

/// Protocol error types
pub const ProtocolError = error{
    ConnectionFailed,
    InvalidSignature,
    InvalidHello,
    AuthenticationFailed,
    SessionFailed,
    InvalidResponse,
    Timeout,
    ServerError,
    UnsupportedVersion,
    OutOfMemory,
    NetworkError,
};

/// OS information for client identification
const OsInfo = struct {
    name: []const u8,
    version: []const u8,
    title: []const u8,
};

fn getOsInfo() OsInfo {
    return switch (builtin.os.tag) {
        .linux => .{ .name = "Linux", .version = "5.0", .title = "Linux" },
        .macos => .{ .name = "macOS", .version = "14.0", .title = "macOS 14" },
        .windows => .{ .name = "Windows", .version = "10.0", .title = "Windows 10" },
        .freebsd => .{ .name = "FreeBSD", .version = "14.0", .title = "FreeBSD 14" },
        .openbsd => .{ .name = "OpenBSD", .version = "7.0", .title = "OpenBSD 7" },
        .netbsd => .{ .name = "NetBSD", .version = "10.0", .title = "NetBSD 10" },
        else => .{ .name = "Unix", .version = "1.0", .title = "Unix" },
    };
}

/// Protocol constants
pub const Protocol = struct {
    /// HTTP endpoint for VPN connection (Pack data)
    pub const vpn_target = "/vpnsvc/vpn.cgi";

    /// HTTP endpoint for signature upload
    pub const vpn_target_signature = "/vpnsvc/connect.cgi";

    /// Content type for signature
    pub const content_type_signature = "image/jpeg";

    /// Content type for Pack data
    pub const content_type_pack = "application/octet-stream";

    /// Maximum random padding for signature
    pub const max_rand_size: usize = 1024;

    /// SHA1 digest length
    pub const sha1_size: usize = 20;

    /// Client identifier (match official SoftEther VPN Client)
    pub const client_str = "SoftEther VPN Client";

    /// Client version (match official client: 4.44)
    pub const client_ver: u32 = 444;

    /// Client build number (match official client)
    pub const client_build: u32 = 9807;

    // ------------------------------------------------------------------
    // Wire protocol constants — SINGLE SOURCE OF TRUTH.
    // Client and server must produce identical values. Consumers in
    // cedar/session and cedar/protocol/tunnel re-export these; the C
    // reference defines the same values in Protocol.c / Network.h / Cedar.h.
    // ------------------------------------------------------------------

    /// Protocol signature sent at connection start (C: "SE Vu", Protocol.c)
    pub const protocol_signature = "SE Vu";

    /// Protocol version (C: 0x00000413, Protocol.c)
    pub const protocol_version: u32 = 0x00000413;

    /// Magic number indicating a keep-alive frame (C: KEEP_ALIVE_MAGIC, Cedar.h:392)
    pub const keep_alive_magic: u32 = 0xFFFFFFFF;

    /// Maximum Ethernet frame size carried in one block (C: MAX_PACKET_SIZE 1514)
    pub const max_packet_size: usize = 1514;

    /// Maximum number of blocks per frame (C: MAX_RECV_BLOCKS 512)
    pub const max_recv_blocks: usize = 512;

    /// HTTP Keep-Alive header value (C: HTTP_KEEP_ALIVE "timeout=15; max=19", Network.h:1000)
    pub const keep_alive_header = "timeout=15; max=19";
};

/// Import WaterMark from dedicated file for visual verification
const watermark = @import("watermark.zig");

/// SoftEther WaterMark signature data (GIF image from WaterMark.c)
/// This is sent as the initial protocol signature
/// Full size: 68,374 bytes (the complete GIF signature file)
pub const WaterMark: []const u8 = &watermark.WaterMark;

/// Hello response from server
pub const HelloResponse = struct {
    random: [Protocol.sha1_size]u8,
    server_ver: u32,
    server_build: u32,
    server_str: []const u8,

    pub fn deinit(self: *HelloResponse, allocator: Allocator) void {
        allocator.free(self.server_str);
    }
};

/// Redirect information for cluster server setups
pub const RedirectInfo = struct {
    ip: u32, // IPv4 address in host byte order
    port: u16,
    ticket: [Protocol.sha1_size]u8,
};

/// Authentication result
pub const AuthResult = struct {
    success: bool,
    error_code: u32,
    error_message: ?[]const u8,
    session_key: ?[Protocol.sha1_size]u8,
    policy: ?[]const u8,
    redirect: ?RedirectInfo, // If set, need to reconnect to this server

    // Server-overridden session parameters (C: Protocol.c:4720-4741)
    // The server may override client-requested values; these are authoritative.
    server_max_connection: u32 = 1,
    server_half_connection: bool = false,
    server_use_compress: bool = false,
    server_use_encrypt: bool = true,
    server_use_fast_rc4: bool = false,
    server_qos: bool = false,
    server_timeout: u32 = 0,
    server_no_routing: bool = false,

    // RC4 fast-encryption keys (from server Welcome, `use_fast_rc4` path)
    rc4_client_to_server_key: ?[16]u8 = null,
    rc4_server_to_client_key: ?[16]u8 = null,

    // UDP acceleration fields (from server response)
    udp_accel_enabled: bool = false,
    udp_accel_port: u16 = 0,
    udp_accel_use_encrypt: bool = true,
    rudp_bulk_version: u32 = 0,
    server_bulk_send_key: ?[16]u8 = null,
    server_bulk_recv_key: ?[16]u8 = null,

    pub fn deinit(self: *AuthResult, allocator: Allocator) void {
        if (self.error_message) |msg| allocator.free(msg);
        if (self.policy) |p| allocator.free(p);
    }
};

/// Protocol fingerprinting configuration.
/// All fields are optional; when null, the protocol uses its built-in defaults.
/// This allows callers to masquerade as different client versions for
/// anti-fingerprinting purposes, avoiding detection by server administrators.
pub const ProtocolFingerprint = struct {
    client_str: ?[]const u8 = null,
    client_ver: ?u32 = null,
    client_build: ?u32 = null,
    os_name: ?[]const u8 = null,
    os_version: ?[]const u8 = null,
    os_title: ?[]const u8 = null,
    vpn_target: ?[]const u8 = null,
    vpn_target_signature: ?[]const u8 = null,
    content_type_signature: ?[]const u8 = null,
    content_type_pack: ?[]const u8 = null,
    max_rand_size: ?usize = null,
    writer_retry_max: ?u32 = null,
    writer_retry_sleep_ms: ?u32 = null,
    /// Custom watermark data. When null, the built-in watermark is used.
    /// Pass an empty slice to skip watermark upload entirely.
    watermark: ?[]const u8 = null,
    /// Hostname sent in auth pack (ClientHostname field).
    /// When null, "zig-client" is used.
    client_hostname: ?[]const u8 = null,
    /// Unique ID sent in auth pack. When null, random bytes are generated.
    unique_id: ?[20]u8 = null,
};

/// Session-level options passed through to the auth pack.
pub const SessionOptions = struct {
    max_connection: u32 = 1,
    half_connection: bool = false,
    qos: bool = true,
    use_encrypt: bool = true,
    use_fast_rc4: bool = false,
    use_compress: bool = false,
    /// Optional protocol fingerprint overrides for anti-fingerprinting.
    /// When null, hardcoded Protocol constants and getOsInfo() are used.
    fingerprint: ?*const ProtocolFingerprint = null,
};

/// Resolve client_str with fingerprint override.
fn fpClientStr(fp: ?*const ProtocolFingerprint) []const u8 {
    if (fp) |f| {
        if (f.client_str) |v| return v;
    }
    return Protocol.client_str;
}

/// Resolve client_ver with fingerprint override.
fn fpClientVer(fp: ?*const ProtocolFingerprint) u32 {
    if (fp) |f| {
        if (f.client_ver) |v| return v;
    }
    return Protocol.client_ver;
}

/// Resolve client_build with fingerprint override.
fn fpClientBuild(fp: ?*const ProtocolFingerprint) u32 {
    if (fp) |f| {
        if (f.client_build) |v| return v;
    }
    return Protocol.client_build;
}

/// Resolve OS info with fingerprint override.
fn fpOsInfo(fp: ?*const ProtocolFingerprint) OsInfo {
    const base = getOsInfo();
    if (fp) |f| {
        return .{
            .name = f.os_name orelse base.name,
            .version = f.os_version orelse base.version,
            .title = f.os_title orelse base.title,
        };
    }
    return base;
}

/// Resolve max_rand_size with fingerprint override.
fn fpMaxRandSize(fp: ?*const ProtocolFingerprint) usize {
    if (fp) |f| {
        if (f.max_rand_size) |v| return v;
    }
    return Protocol.max_rand_size;
}

/// Resolve vpn_target with fingerprint override.
fn fpTarget(fp: ?*const ProtocolFingerprint) []const u8 {
    if (fp) |f| {
        if (f.vpn_target) |v| return v;
    }
    return Protocol.vpn_target;
}

/// Resolve vpn_target_signature with fingerprint override.
fn fpTargetSignature(fp: ?*const ProtocolFingerprint) []const u8 {
    if (fp) |f| {
        if (f.vpn_target_signature) |v| return v;
    }
    return Protocol.vpn_target_signature;
}

/// Resolve content_type_signature with fingerprint override.
fn fpContentTypeSignature(fp: ?*const ProtocolFingerprint) []const u8 {
    if (fp) |f| {
        if (f.content_type_signature) |v| return v;
    }
    return Protocol.content_type_signature;
}

/// Resolve content_type_pack with fingerprint override.
fn fpContentTypePack(fp: ?*const ProtocolFingerprint) []const u8 {
    if (fp) |f| {
        if (f.content_type_pack) |v| return v;
    }
    return Protocol.content_type_pack;
}

/// Resolve client_hostname with fingerprint override.
fn fpClientHostname(fp: ?*const ProtocolFingerprint) []const u8 {
    if (fp) |f| {
        if (f.client_hostname) |v| return v;
    }
    return "zig-client";
}

/// Authentication type enum
pub const AuthType = enum(u32) {
    anonymous = 0,
    password = 1,
    plain_password = 2,
    certificate = 3,
    ticket = 99, // AUTHTYPE_TICKET in C is 99, not 4
    openssh_certificate = 5,
};

/// Writer interface for sending data
pub const Writer = struct {
    context: *anyopaque,
    writeFn: *const fn (*anyopaque, []const u8) anyerror!usize,

    pub fn write(self: Writer, data: []const u8) !usize {
        return self.writeFn(self.context, data);
    }

    pub fn writeAll(self: Writer, data: []const u8) !void {
        var remaining = data;
        var retry_count: u32 = 0;
        while (remaining.len > 0) {
            const written = try self.write(remaining);
            if (written == 0) {
                // TLS returns 0 for WANT_WRITE/WANT_READ — retry with backoff
                retry_count += 1;
                if (retry_count > 100) return error.ConnectionClosed;
                std.Thread.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            retry_count = 0;
            remaining = remaining[written..];
        }
    }
};

/// Reader interface for receiving data
pub const Reader = struct {
    context: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) anyerror!usize,

    pub fn read(self: Reader, buffer: []u8) !usize {
        return self.readFn(self.context, buffer);
    }

    pub fn readAll(self: Reader, buffer: []u8) !usize {
        var total: usize = 0;
        while (total < buffer.len) {
            const bytes_read = try self.read(buffer[total..]);
            if (bytes_read == 0) break;
            total += bytes_read;
        }
        return total;
    }
};

/// Build HTTP header for signature upload
fn buildSignatureHttpHeader(allocator: Allocator, host: []const u8, body_len: usize, fingerprint: ?*const ProtocolFingerprint) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    const writer = list.writer(allocator);
    const target = fpTargetSignature(fingerprint);
    const content_type = fpContentTypeSignature(fingerprint);

    // Signature uses connect.cgi endpoint and simple headers like C code
    try writer.print("POST {s} HTTP/1.1\r\n", .{target});
    try writer.print("Host: {s}\r\n", .{host});
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try writer.writeAll("Connection: Keep-Alive\r\n");
    try writer.print("Content-Length: {d}\r\n", .{body_len});
    try writer.writeAll("\r\n");

    return list.toOwnedSlice(allocator);
}

/// Build HTTP header for Pack data
fn buildPackHttpHeader(allocator: Allocator, host: []const u8, body_len: usize, fingerprint: ?*const ProtocolFingerprint) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    const writer = list.writer(allocator);
    const target = fpTarget(fingerprint);
    const content_type = fpContentTypePack(fingerprint);

    // Generate HTTP Date string like C code: "Sat, 20 Dec 2025 13:31:23 GMT"
    const wday = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    const now_ts = std.time.timestamp();
    const epoch_secs: u64 = @intCast(now_ts);
    const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
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

    // Calculate day of week: (epoch_day + 4) % 7 gives 0=Mon ... 6=Sun (Jan 1, 1970 was Thursday = 3)
    const weekday_idx: usize = @intCast(@mod(@as(i32, @intCast(epoch_day.day)) + 3, 7));

    // Pack data uses full keep-alive headers like C code
    // Order: Date, Host, Keep-Alive, Connection, Content-Type, Content-Length (matches C code)
    try writer.print("POST {s} HTTP/1.1\r\n", .{target});
    try writer.print("Date: {s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT\r\n", .{
        wday[weekday_idx],
        day,
        month_names[month_idx],
        year,
        hour,
        minute,
        second,
    });
    try writer.print("Host: {s}\r\n", .{host});
    try writer.print("Keep-Alive: {s}\r\n", .{Protocol.keep_alive_header});
    try writer.writeAll("Connection: Keep-Alive\r\n");
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try writer.print("Content-Length: {d}\r\n", .{body_len});
    try writer.writeAll("\r\n");

    return list.toOwnedSlice(allocator);
}

/// Send an HTTP POST with binary data (for Pack serialized data)
pub fn sendHttpPost(
    allocator: Allocator,
    writer: Writer,
    host: []const u8,
    body: []const u8,
    fingerprint: ?*const ProtocolFingerprint,
) !void {
    const header = try buildPackHttpHeader(allocator, host, body.len, fingerprint);
    defer allocator.free(header);

    try writer.writeAll(header);
    try writer.writeAll(body);
}

/// Upload the protocol signature (WaterMark)
/// This is the first step in establishing a SoftEther VPN connection
pub fn uploadSignature(
    allocator: Allocator,
    writer: Writer,
    host: []const u8,
    fingerprint: ?*const ProtocolFingerprint,
) !void {
    // Send the full WaterMark GIF signature — servers validate this to confirm
    // the client speaks the SoftEther VPN protocol. "VPNCONNECT" is only accepted
    // by a subset of servers and most production servers reject it.
    const body = if (fingerprint) |fp| blk: {
        if (fp.watermark) |wm| break :blk wm;
        break :blk WaterMark;
    } else WaterMark;
    const body_len = body.len;

    // Build HTTP header
    const header = try buildSignatureHttpHeader(allocator, host, body_len, fingerprint);
    defer allocator.free(header);

    // Send header
    try writer.writeAll(header);

    // Send WaterMark signature
    try writer.writeAll(body);

    std.log.debug("Uploaded protocol signature ({d} bytes)", .{body_len});
}

/// Download Hello from server
/// Returns server version info and random challenge for authentication
pub fn downloadHello(
    allocator: Allocator,
    reader: Reader,
) !HelloResponse {
    // Read HTTP response
    var header_buf: [4096]u8 = undefined;
    var header_len: usize = 0;

    std.log.debug("Starting to read HTTP response headers...", .{});

    // Read until we find end of headers
    while (header_len < header_buf.len - 1) {
        const bytes_read = try reader.read(header_buf[header_len .. header_len + 1]);
        if (bytes_read == 0) {
            std.log.err("Connection closed while reading headers. Got {d} bytes: {s}", .{ header_len, header_buf[0..@min(header_len, 200)] });
            return error.EndOfStream;
        }
        header_len += 1;

        // Check for \r\n\r\n
        if (header_len >= 4) {
            if (mem.eql(u8, header_buf[header_len - 4 .. header_len], "\r\n\r\n")) {
                break;
            }
        }
    }

    std.log.debug("Received headers ({d} bytes): {s}", .{ header_len, header_buf[0..header_len] });

    // Parse HTTP response
    const parsed = try rpc.parseHttpResponse(header_buf[0..header_len]);
    if (parsed.status_code != 200) {
        // Server-side rejection — surface to the caller via the returned
        // error. Logged at warn so the caller can decide whether this is
        // fatal; tests intentionally drive this path.
        std.log.warn("Hello response status: {d}", .{parsed.status_code});
        return ProtocolError.ServerError;
    }

    std.log.debug("Content-Length: {d}", .{parsed.content_length});

    // Read body
    const body = try allocator.alloc(u8, parsed.content_length);
    defer allocator.free(body);

    std.log.debug("Reading body...", .{});
    var total_read: usize = 0;
    while (total_read < parsed.content_length) {
        const bytes_read = try reader.read(body[total_read..]);
        if (bytes_read == 0) {
            std.log.err("EOF after reading {d}/{d} bytes of body", .{ total_read, parsed.content_length });
            return error.EndOfStream;
        }
        total_read += bytes_read;
        std.log.debug("Read {d} bytes, total {d}/{d}", .{ bytes_read, total_read, parsed.content_length });
    }
    std.log.debug("Body read complete: {d} bytes", .{total_read});

    // Parse Pack
    std.log.debug("Parsing Pack from body...", .{});
    var pack_obj = Pack.fromBytes(allocator, body) catch |err| {
        std.log.err("Pack parsing failed: {}", .{err});
        std.log.err("First 64 bytes of body: {x}", .{body[0..@min(64, body.len)]});
        return err;
    };
    defer pack_obj.deinit();
    std.log.debug("Pack parsed successfully", .{});

    // Check for error
    if (pack_obj.getInt("error")) |err_code| {
        if (err_code != 0) {
            // Server-side rejection — surface via returned error.
            std.log.warn("Server returned error: {d}", .{err_code});
            return ProtocolError.ServerError;
        }
    }

    // Extract Hello data
    std.log.debug("Extracting hello data...", .{});
    const random_data = pack_obj.getData("random") orelse {
        std.log.warn("No 'random' field in hello Pack", .{});
        return ProtocolError.InvalidHello;
    };
    if (random_data.len != Protocol.sha1_size) {
        std.log.warn("Invalid random size: {d}, expected {d}", .{ random_data.len, Protocol.sha1_size });
        return ProtocolError.InvalidHello;
    }

    var result = HelloResponse{
        .random = undefined,
        .server_ver = pack_obj.getInt("version") orelse 0,
        .server_build = pack_obj.getInt("build") orelse 0,
        .server_str = try allocator.dupe(u8, pack_obj.getStr("hello") orelse "Unknown"),
    };
    @memcpy(&result.random, random_data);

    std.log.info("Server: {s} v{d}.{d}", .{ result.server_str, result.server_ver, result.server_build });

    return result;
}

/// Build Hello Pack for client
pub fn buildClientHello(allocator: Allocator, fingerprint: ?*const ProtocolFingerprint) ![]u8 {
    var hello_pack = Pack.init(allocator);
    defer hello_pack.deinit();

    try hello_pack.addStr("client_str", fpClientStr(fingerprint));
    try hello_pack.addInt("client_ver", fpClientVer(fingerprint));
    try hello_pack.addInt("client_build", fpClientBuild(fingerprint));

    return hello_pack.toBytes(allocator);
}

/// Add IP address to Pack like C's PackAddIp32 does
/// This adds 4 elements: name@ipv6_bool, name@ipv6_array, name@ipv6_scope_id, name
fn addPackIp32(auth_pack: *Pack, name: []const u8, ip32: u32) !void {
    // Stack buffers for field names
    var ipv6_bool_buf: [64]u8 = undefined;
    var ipv6_array_buf: [64]u8 = undefined;
    var ipv6_scope_buf: [64]u8 = undefined;

    const ipv6_bool_name = std.fmt.bufPrint(&ipv6_bool_buf, "{s}@ipv6_bool", .{name}) catch return error.OutOfMemory;
    const ipv6_array_name = std.fmt.bufPrint(&ipv6_array_buf, "{s}@ipv6_array", .{name}) catch return error.OutOfMemory;
    const ipv6_scope_name = std.fmt.bufPrint(&ipv6_scope_buf, "{s}@ipv6_scope_id", .{name}) catch return error.OutOfMemory;

    // Add the 4 elements (all IPv4, so ipv6_bool = false)
    try auth_pack.addBool(ipv6_bool_name, false); // Not IPv6
    var dummy_ipv6: [16]u8 = .{0} ** 16;
    try auth_pack.addData(ipv6_array_name, &dummy_ipv6); // Empty IPv6 addr
    try auth_pack.addInt(ipv6_scope_name, 0); // No scope ID
    try auth_pack.addInt(name, ip32); // The actual IPv4 address
}

/// UDP acceleration bulk key parameters.
/// Generated by the client and sent in the auth pack.
/// The server will echo back its own keys in the auth response.
pub const UdpBulkKeys = struct {
    /// Client's send key (server uses to decrypt)
    send_key: [16]u8,
    /// Client's recv key (server uses to encrypt)
    recv_key: [16]u8,

    /// Generate random bulk keys.
    pub fn generate() UdpBulkKeys {
        var keys: UdpBulkKeys = undefined;
        std.crypto.random.bytes(&keys.send_key);
        std.crypto.random.bytes(&keys.recv_key);
        return keys;
    }
};

/// Append UDP acceleration fields to an auth pack when udp_accel is enabled.
/// Must be called after rudp_bulk_max_version is already added.
fn addUdpAccelFields(auth_pack_ref: anytype, bulk_keys: ?*const UdpBulkKeys) !void {
    if (bulk_keys) |keys| {
        try auth_pack_ref.addBool("use_udp_acceleration", true);
        try auth_pack_ref.addData("bulk_on_rudp_send_key", &keys.send_key);
        try auth_pack_ref.addData("bulk_on_rudp_recv_key", &keys.recv_key);
    }
}

/// Build Auth Pack with password authentication
pub fn buildPasswordAuth(
    allocator: Allocator,
    username: []const u8,
    password: []const u8,
    hub_name: []const u8,
    server_random: *const [Protocol.sha1_size]u8,
    server_ip: u32,
    server_hostname: []const u8,
    udp_accel: bool,
    bulk_keys: ?*const UdpBulkKeys,
    opts: SessionOptions,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    const fp = opts.fingerprint;

    // Add authentication fields (method must be "login", not "auth")
    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.password));

    // Compute secure password with server random
    const password_hash = auth_mod.hashPassword(password, username);
    const secure_pass = auth_mod.computeSecurePassword(&password_hash, server_random);
    try auth_pack.addData("secure_password", &secure_pass);

    // PackAddClientVersion fields
    try auth_pack.addStr("client_str", fpClientStr(fp));
    try auth_pack.addInt("client_ver", fpClientVer(fp));
    try auth_pack.addInt("client_build", fpClientBuild(fp));

    try auth_pack.addInt("protocol", 0);

    try auth_pack.addStr("hello", fpClientStr(fp));
    try auth_pack.addInt("version", fpClientVer(fp));
    try auth_pack.addInt("build", fpClientBuild(fp));
    try auth_pack.addInt("client_id", 0);

    // Protocol options
    try auth_pack.addInt("max_connection", @intCast(opts.max_connection));
    try auth_pack.addBool("use_encrypt", opts.use_encrypt);
    try auth_pack.addBool("use_fast_rc4", opts.use_fast_rc4);
    try auth_pack.addBool("use_compress", opts.use_compress);
    try auth_pack.addBool("half_connection", opts.half_connection);

    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    try auth_pack.addBool("qos", opts.qos);
    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);
    try auth_pack.addBool("support_udp_recovery", udp_accel);

    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));
    try addUdpAccelFields(&auth_pack, bulk_keys);

    var cedar_unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&cedar_unique_id);

    const os_info = fpOsInfo(fp);
    try auth_pack.addStr("ClientProductName", fpClientStr(fp));
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info.name);
    try auth_pack.addStr("ClientOsVer", os_info.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", fpClientHostname(fp));
    try auth_pack.addStr("ServerHostname", server_hostname);
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &cedar_unique_id);
    try auth_pack.addInt("ClientProductVer", fpClientVer(fp));
    try auth_pack.addInt("ClientProductBuild", fpClientBuild(fp));
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", server_ip);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info.title);

    var pencore_buf: [2048]u8 = undefined;
    const pencore_size = crypto.random.intRangeAtMost(usize, 0, fpMaxRandSize(fp));
    crypto.random.bytes(pencore_buf[0..pencore_size]);
    try auth_pack.addData("pencore", pencore_buf[0..pencore_size]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with PLAIN password authentication (raw, no hashing)
pub fn buildPlainsPasswordAuth(
    allocator: Allocator,
    username: []const u8,
    password: []const u8,
    hub_name: []const u8,
    server_ip: u32,
    server_hostname: []const u8,
    udp_accel: bool,
    bulk_keys: ?*const UdpBulkKeys,
    opts: SessionOptions,
) ![]u8 {
    _ = bulk_keys;
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    const fp = opts.fingerprint;

    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.plain_password));
    try auth_pack.addStr("password", password);

    try auth_pack.addStr("client_str", fpClientStr(fp));
    try auth_pack.addInt("client_ver", fpClientVer(fp));
    try auth_pack.addInt("client_build", fpClientBuild(fp));
    try auth_pack.addInt("protocol", 0);

    try auth_pack.addStr("hello", fpClientStr(fp));
    try auth_pack.addInt("version", fpClientVer(fp));
    try auth_pack.addInt("build", fpClientBuild(fp));
    try auth_pack.addInt("client_id", 0);

    try auth_pack.addInt("max_connection", @intCast(opts.max_connection));
    try auth_pack.addBool("use_encrypt", opts.use_encrypt);
    try auth_pack.addBool("use_fast_rc4", opts.use_fast_rc4);
    try auth_pack.addBool("use_compress", opts.use_compress);
    try auth_pack.addBool("half_connection", opts.half_connection);

    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);
    try auth_pack.addBool("qos", opts.qos);
    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);
    try auth_pack.addBool("support_udp_recovery", false);

    const unique_id: [Protocol.sha1_size]u8 = [1]u8{0} ** Protocol.sha1_size;
    try auth_pack.addData("unique_id", &unique_id);

    if (udp_accel) {
        try auth_pack.addInt("rudp_bulk_max_version", 1);
    } else {
        try auth_pack.addInt("rudp_bulk_max_version", 0);
    }

    const os_info_anon = fpOsInfo(fp);
    try auth_pack.addStr("ClientProductName", fpClientStr(fp));
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info_anon.name);
    try auth_pack.addStr("ClientOsVer", os_info_anon.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", fpClientHostname(fp));
    try auth_pack.addStr("ServerHostname", server_hostname);
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &unique_id);
    try auth_pack.addInt("ClientProductVer", fpClientVer(fp));
    try auth_pack.addInt("ClientProductBuild", fpClientBuild(fp));
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);

    try auth_pack.addBool("ClientIpAddress@ipv6_bool", false);
    try auth_pack.addData("ClientIpAddress@ipv6_array", &[_]u8{0} ** 16);
    try auth_pack.addInt("ClientIpAddress@ipv6_scope_id", 0);
    try auth_pack.addInt("ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &[_]u8{0} ** 16);
    try auth_pack.addInt("ClientPort", 0);

    try auth_pack.addBool("ServerIpAddress@ipv6_bool", false);
    try auth_pack.addData("ServerIpAddress@ipv6_array", &[_]u8{0} ** 16);
    try auth_pack.addInt("ServerIpAddress@ipv6_scope_id", 0);
    try auth_pack.addInt("ServerIpAddress", server_ip);
    try auth_pack.addData("ServerIpAddress6", &[_]u8{0} ** 16);
    try auth_pack.addInt("ServerPort2", 0);

    try auth_pack.addBool("ProxyIpAddress@ipv6_bool", false);
    try auth_pack.addData("ProxyIpAddress@ipv6_array", &[_]u8{0} ** 16);
    try auth_pack.addInt("ProxyIpAddress@ipv6_scope_id", 0);
    try auth_pack.addInt("ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &[_]u8{0} ** 16);
    try auth_pack.addInt("ProxyPort", 0);

    try auth_pack.addInt("V_IsWindows", 0);
    try auth_pack.addInt("V_IsNT", 0);
    try auth_pack.addInt("V_IsServer", 0);
    try auth_pack.addInt("V_IsBeta", 0);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info_anon.title);

    var pencore_buf2: [2048]u8 = undefined;
    const pencore_size2 = crypto.random.intRangeAtMost(usize, 0, fpMaxRandSize(fp));
    crypto.random.bytes(pencore_buf2[0..pencore_size2]);
    try auth_pack.addData("pencore", pencore_buf2[0..pencore_size2]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with pre-hashed password (base64 encoded)
pub fn buildPasswordAuthWithHash(
    allocator: Allocator,
    username: []const u8,
    password_hash_base64: []const u8,
    hub_name: []const u8,
    server_random: *const [Protocol.sha1_size]u8,
    server_ip: u32,
    server_hostname: []const u8,
    udp_accel: bool,
    bulk_keys: ?*const UdpBulkKeys,
    opts: SessionOptions,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    const fp = opts.fingerprint;

    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.password));

    const base64_decoder = std.base64.standard.Decoder;
    var password_hash: [Protocol.sha1_size]u8 = undefined;
    base64_decoder.decode(&password_hash, password_hash_base64) catch {
        std.log.err("Failed to decode base64 password hash", .{});
        return error.InvalidBase64;
    };

    std.log.info("Pre-hashed password (decoded): {x}", .{password_hash});

    const secure_pass = auth_mod.computeSecurePassword(&password_hash, server_random);

    std.log.debug("Server random: {x}", .{server_random.*});
    std.log.debug("Secure password: {x}", .{secure_pass});

    try auth_pack.addData("secure_password", &secure_pass);

    try auth_pack.addStr("client_str", fpClientStr(fp));
    try auth_pack.addInt("client_ver", fpClientVer(fp));
    try auth_pack.addInt("client_build", fpClientBuild(fp));

    try auth_pack.addInt("protocol", 0);

    try auth_pack.addStr("hello", fpClientStr(fp));
    try auth_pack.addInt("version", fpClientVer(fp));
    try auth_pack.addInt("build", fpClientBuild(fp));
    try auth_pack.addInt("client_id", 0);

    try auth_pack.addInt("max_connection", @intCast(opts.max_connection));
    try auth_pack.addBool("use_encrypt", opts.use_encrypt);
    try auth_pack.addBool("use_fast_rc4", opts.use_fast_rc4);
    try auth_pack.addBool("use_compress", opts.use_compress);
    try auth_pack.addBool("half_connection", opts.half_connection);

    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    try auth_pack.addBool("qos", opts.qos);

    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    try auth_pack.addBool("support_udp_recovery", udp_accel);

    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));
    try addUdpAccelFields(&auth_pack, bulk_keys);

    var cedar_unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&cedar_unique_id);

    const os_info2 = fpOsInfo(fp);
    try auth_pack.addStr("ClientProductName", fpClientStr(fp));
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info2.name);
    try auth_pack.addStr("ClientOsVer", os_info2.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", fpClientHostname(fp));
    try auth_pack.addStr("ServerHostname", server_hostname);
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &cedar_unique_id);
    try auth_pack.addInt("ClientProductVer", fpClientVer(fp));
    try auth_pack.addInt("ClientProductBuild", fpClientBuild(fp));
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", server_ip);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info2.title);

    var pencore_buf2: [2048]u8 = undefined;
    const pencore_size2 = crypto.random.intRangeAtMost(usize, 0, fpMaxRandSize(fp));
    crypto.random.bytes(pencore_buf2[0..pencore_size2]);
    try auth_pack.addData("pencore", pencore_buf2[0..pencore_size2]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with anonymous authentication
pub fn buildAnonymousAuth(
    allocator: Allocator,
    hub_name: []const u8,
    server_ip: u32,
    server_hostname: []const u8,
    udp_accel: bool,
    bulk_keys: ?*const UdpBulkKeys,
    opts: SessionOptions,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    const fp = opts.fingerprint;

    _ = server_ip;
    _ = server_hostname;

    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", "anonymous");
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.anonymous));

    try auth_pack.addStr("client_str", fpClientStr(fp));
    try auth_pack.addInt("client_ver", fpClientVer(fp));
    try auth_pack.addInt("client_build", fpClientBuild(fp));

    try auth_pack.addInt("protocol", 0);

    try auth_pack.addStr("hello", fpClientStr(fp));
    try auth_pack.addInt("version", fpClientVer(fp));
    try auth_pack.addInt("build", fpClientBuild(fp));
    try auth_pack.addInt("client_id", 0);

    try auth_pack.addInt("max_connection", @intCast(opts.max_connection));
    try auth_pack.addBool("use_encrypt", opts.use_encrypt);
    try auth_pack.addBool("use_fast_rc4", opts.use_fast_rc4);
    try auth_pack.addBool("use_compress", opts.use_compress);
    try auth_pack.addBool("half_connection", opts.half_connection);

    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    try auth_pack.addBool("qos", opts.qos);

    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    try auth_pack.addBool("support_udp_recovery", udp_accel);

    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));
    try addUdpAccelFields(&auth_pack, bulk_keys);

    var pencore_buf3: [2048]u8 = undefined;
    const pencore_size3 = crypto.random.intRangeAtMost(usize, 0, fpMaxRandSize(fp));
    crypto.random.bytes(pencore_buf3[0..pencore_size3]);
    try auth_pack.addData("pencore", pencore_buf3[0..pencore_size3]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with X.509 certificate authentication.
/// Signs the server random with the client's private key and sends the DER-encoded cert.
pub fn buildCertificateAuth(
    allocator: Allocator,
    cert_pem: []const u8,
    key_pem: []const u8,
    hub_name: []const u8,
    server_random: *const [Protocol.sha1_size]u8,
    server_ip: u32,
    server_hostname: []const u8,
    udp_accel: bool,
    bulk_keys: ?*const UdpBulkKeys,
    opts: SessionOptions,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    const fp = opts.fingerprint;

    const username = auth_mod.extractCertCommonName(allocator, cert_pem) catch "certificate_user";
    defer if (!mem.eql(u8, username, "certificate_user")) allocator.free(username);

    const cert_der = try auth_mod.certPemToDer(allocator, cert_pem);
    defer allocator.free(cert_der);

    const signature = try auth_mod.signWithPrivateKey(allocator, key_pem, server_random);
    defer allocator.free(signature);

    std.log.info("CertAuth: username={s}, cert_der_len={d}, sig_len={d}", .{
        username, cert_der.len, signature.len,
    });

    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.certificate));

    try auth_pack.addData("cert", cert_der);
    try auth_pack.addData("sign", signature);

    try auth_pack.addStr("client_str", fpClientStr(fp));
    try auth_pack.addInt("client_ver", fpClientVer(fp));
    try auth_pack.addInt("client_build", fpClientBuild(fp));

    try auth_pack.addInt("protocol", 0);

    try auth_pack.addInt("max_connection", @intCast(opts.max_connection));
    try auth_pack.addBool("use_encrypt", opts.use_encrypt);
    try auth_pack.addBool("use_fast_rc4", opts.use_fast_rc4);
    try auth_pack.addBool("use_compress", opts.use_compress);
    try auth_pack.addBool("half_connection", opts.half_connection);

    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    try auth_pack.addBool("qos", opts.qos);

    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);
    try auth_pack.addBool("support_udp_recovery", udp_accel);

    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));
    try addUdpAccelFields(&auth_pack, bulk_keys);

    const os_info_cert = fpOsInfo(fp);
    try auth_pack.addStr("ClientProductName", fpClientStr(fp));
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info_cert.name);
    try auth_pack.addStr("ClientOsVer", os_info_cert.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", fpClientHostname(fp));
    try auth_pack.addStr("ServerHostname", server_hostname);
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addInt("ClientProductVer", fpClientVer(fp));
    try auth_pack.addInt("ClientProductBuild", fpClientBuild(fp));
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", server_ip);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info_cert.title);

    var pencore_buf_c: [2048]u8 = undefined;
    const pencore_size_c = crypto.random.intRangeAtMost(usize, 0, fpMaxRandSize(fp));
    crypto.random.bytes(pencore_buf_c[0..pencore_size_c]);
    try auth_pack.addData("pencore", pencore_buf_c[0..pencore_size_c]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with ticket authentication (for cluster redirect)
/// Build ticket-based authentication for cluster redirect.
/// @param server_ip The redirect target's IPv4 address in host byte order.
///                  C client sends this as ServerIpAddress; server uses it to
///                  route data-plane packets to the correct backend node.
/// @param server_hostname The redirect target's hostname for Host header.
pub fn buildTicketAuth(
    allocator: Allocator,
    hub_name: []const u8,
    username: []const u8,
    ticket: *const [Protocol.sha1_size]u8,
    server_ip: u32,
    server_hostname: []const u8,
    udp_accel: bool,
    bulk_keys: ?*const UdpBulkKeys,
    opts: SessionOptions,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    const fp = opts.fingerprint;

    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.ticket));

    try auth_pack.addData("ticket", ticket);

    try auth_pack.addStr("client_str", fpClientStr(fp));
    try auth_pack.addInt("client_ver", fpClientVer(fp));
    try auth_pack.addInt("client_build", fpClientBuild(fp));

    try auth_pack.addInt("protocol", 0);

    try auth_pack.addStr("hello", fpClientStr(fp));
    try auth_pack.addInt("version", fpClientVer(fp));
    try auth_pack.addInt("build", fpClientBuild(fp));
    try auth_pack.addInt("client_id", 0);

    try auth_pack.addInt("max_connection", @intCast(opts.max_connection));
    try auth_pack.addBool("use_encrypt", opts.use_encrypt);
    try auth_pack.addBool("use_fast_rc4", opts.use_fast_rc4);
    try auth_pack.addBool("use_compress", opts.use_compress);
    try auth_pack.addBool("half_connection", opts.half_connection);

    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    try auth_pack.addBool("qos", opts.qos);

    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    try auth_pack.addBool("support_udp_recovery", udp_accel);

    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));
    try addUdpAccelFields(&auth_pack, bulk_keys);

    var cedar_unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&cedar_unique_id);

    const os_info3 = fpOsInfo(fp);
    try auth_pack.addStr("ClientProductName", fpClientStr(fp));
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info3.name);
    try auth_pack.addStr("ClientOsVer", os_info3.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", fpClientHostname(fp));
    try auth_pack.addStr("ServerHostname", server_hostname);
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &cedar_unique_id);
    try auth_pack.addInt("ClientProductVer", fpClientVer(fp));
    try auth_pack.addInt("ClientProductBuild", fpClientBuild(fp));
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", server_ip);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info3.title);

    var pencore_buf: [2048]u8 = undefined;
    const pencore_size = crypto.random.intRangeAtMost(usize, 0, fpMaxRandSize(fp));
    crypto.random.bytes(pencore_buf[0..pencore_size]);
    try auth_pack.addData("pencore", pencore_buf[0..pencore_size]);

    return auth_pack.toBytes(allocator);
}

/// Upload authentication data
pub fn uploadAuth(
    allocator: Allocator,
    writer: Writer,
    reader: Reader,
    host: []const u8,
    auth_pack_data: []const u8,
    fingerprint: ?*const ProtocolFingerprint,
) !AuthResult {
    // Build HTTP header for auth pack
    const header = try buildPackHttpHeader(allocator, host, auth_pack_data.len, fingerprint);
    defer allocator.free(header);

    // Debug: List all elements being sent
    {
        var debug_pack = Pack.fromBytes(allocator, auth_pack_data) catch {
            std.log.info("Failed to parse auth pack for debug", .{});
            return error.InvalidPack;
        };
        defer debug_pack.deinit();

        std.log.debug("=== AUTH PACK ({d} bytes, {d} elements) ===", .{ auth_pack_data.len, debug_pack.elements.items.len });
        for (debug_pack.elements.items) |elem| {
            const type_str = switch (elem.value_type) {
                .int => "int",
                .data => "data",
                .str => "str",
                .unistr => "unistr",
                .int64 => "int64",
            };
            if (elem.values.items.len > 0) {
                switch (elem.values.items[0]) {
                    .int => |v| std.log.debug("  {s} ({s}) = {d}", .{ elem.name, type_str, v }),
                    .str => |v| std.log.debug("  {s} ({s}) = '{s}'", .{ elem.name, type_str, v }),
                    .data => |v| std.log.debug("  {s} ({s}) = [{d} bytes]", .{ elem.name, type_str, v.len }),
                    else => std.log.debug("  {s} ({s})", .{ elem.name, type_str }),
                }
            }
        }
        std.log.debug("=== END ===", .{});
    }

    // Send header and body
    std.log.debug("HTTP Request Header:\n{s}", .{header});

    try writer.writeAll(header);
    try writer.writeAll(auth_pack_data);

    std.log.debug("Uploaded auth data ({d} bytes)", .{auth_pack_data.len});

    // Read response
    var resp_header_buf: [4096]u8 = undefined;
    var resp_header_len: usize = 0;

    while (resp_header_len < resp_header_buf.len - 1) {
        const bytes_read = try reader.read(resp_header_buf[resp_header_len .. resp_header_len + 1]);
        if (bytes_read == 0) return ProtocolError.ConnectionFailed;
        resp_header_len += 1;

        if (resp_header_len >= 4) {
            if (mem.eql(u8, resp_header_buf[resp_header_len - 4 .. resp_header_len], "\r\n\r\n")) {
                break;
            }
        }
    }

    const parsed = try rpc.parseHttpResponse(resp_header_buf[0..resp_header_len]);
    if (parsed.status_code != 200) {
        std.log.err("Auth response status: {d}", .{parsed.status_code});
        return ProtocolError.AuthenticationFailed;
    }

    // Read body
    const body = try allocator.alloc(u8, parsed.content_length);
    defer allocator.free(body);

    const body_read = try reader.readAll(body);
    if (body_read != parsed.content_length) {
        return ProtocolError.InvalidResponse;
    }

    // Parse response
    var resp_pack = try Pack.fromBytes(allocator, body);
    defer resp_pack.deinit();

    // Debug: list all fields in response.
    // Use stack-buffered formatting for ints so we don't leak per-field
    // allocations on every auth response.
    std.log.debug("Auth response fields:", .{});
    for (resp_pack.elements.items) |elem| {
        const elem_type_str = switch (elem.value_type) {
            .int => "int",
            .data => "data",
            .str => "str",
            .unistr => "unistr",
            .int64 => "int64",
        };
        var num_buf: [32]u8 = undefined;
        const first_val: []const u8 = if (elem.values.items.len > 0) blk: {
            const val = elem.values.items[0];
            break :blk switch (elem.value_type) {
                .int => std.fmt.bufPrint(&num_buf, "{d}", .{val.int}) catch "?",
                .int64 => std.fmt.bufPrint(&num_buf, "{d}", .{val.int64}) catch "?",
                .str => val.str,
                else => "(data)",
            };
        } else "(empty)";
        std.log.debug("  {s}: {s} = {s}", .{ elem.name, elem_type_str, first_val });
    }

    // Check for error
    const err_code = resp_pack.getInt("error") orelse 0;
    if (err_code != 0) {
        const err_msg = resp_pack.getStr("error_str");
        // Bad password / wrong hub / etc. — normal protocol outcome,
        // surfaced via AuthResult.success=false. Caller logs at .err.
        std.log.warn("Authentication failed: {d} - {s}", .{ err_code, err_msg orelse "Unknown error" });

        return AuthResult{
            .success = false,
            .error_code = err_code,
            .error_message = if (err_msg) |m| try allocator.dupe(u8, m) else null,
            .session_key = null,
            .policy = null,
            .redirect = null,
        };
    }

    // Check for redirect (cluster server setup)
    const redirect_flag = resp_pack.getInt("Redirect") orelse 0;
    if (redirect_flag != 0) {
        const redirect_ip = resp_pack.getInt("Ip") orelse 0;
        const redirect_port: u16 = @intCast(resp_pack.getInt("Port") orelse 443);

        var ticket: [Protocol.sha1_size]u8 = .{0} ** Protocol.sha1_size;
        if (resp_pack.getData("Ticket")) |ticket_data| {
            std.log.debug("Ticket data length: {d}", .{ticket_data.len});
            if (ticket_data.len == Protocol.sha1_size) {
                @memcpy(&ticket, ticket_data);
            } else if (ticket_data.len > 0) {
                const copy_len = @min(ticket_data.len, Protocol.sha1_size);
                @memcpy(ticket[0..copy_len], ticket_data[0..copy_len]);
            }
        }

        std.log.debug("Ticket bytes: {x}", .{ticket});

        // Convert IP to string for logging (SoftEther uses host byte order)
        const ip_bytes: [4]u8 = @bitCast(redirect_ip);
        std.log.info("Server redirect to: {d}.{d}.{d}.{d}:{d}", .{
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3], redirect_port,
        });

        return AuthResult{
            .success = true,
            .error_code = 0,
            .error_message = null,
            .session_key = null,
            .policy = null,
            .redirect = RedirectInfo{
                .ip = redirect_ip,
                .port = redirect_port,
                .ticket = ticket,
            },
        };
    }

    // Extract session key.
    // SoftEther server uses field name "SessionKey" (PascalCase) in
    // the auth response, NOT "session_key". Older Zig client looked only for
    // lowercase, causing self.auth_session_key to remain null after redirect-
    // ticket auth → "Session established without encryption" + multi-conn
    // additional sockets aborted with "No session key available". Try both,
    // and dump field names if neither is present so we catch future drift.
    var session_key: ?[Protocol.sha1_size]u8 = null;
    const sk_pascal = resp_pack.getData("SessionKey");
    const sk_snake = resp_pack.getData("session_key");
    std.log.debug("session_key probe: SessionKey={?d}B session_key={?d}B", .{
        if (sk_pascal) |d| d.len else null,
        if (sk_snake) |d| d.len else null,
    });
    const session_key_data = sk_pascal orelse sk_snake;
    if (session_key_data) |key_data| {
        if (key_data.len == Protocol.sha1_size) {
            // FIX: previously did `session_key = undefined; @memcpy(&session_key.?, key_data);`
            // which left the optional tag undefined → consumer saw null even though
            // payload bytes were written. Build the array first, then assign whole optional.
            var buf: [Protocol.sha1_size]u8 = undefined;
            @memcpy(&buf, key_data);
            session_key = buf;
            std.log.debug("session_key OK ({d} bytes), opt_set={}", .{ key_data.len, session_key != null });
        } else {
            std.log.err("session_key wrong size: {d} (expected {d})", .{ key_data.len, Protocol.sha1_size });
        }
    } else {
        // One-shot diagnostic: dump all field names so we can see what the
        // server actually sent if we still failed to find it.
        std.log.err("NO session key field found. {d} fields in response:", .{resp_pack.elements.items.len});
        for (resp_pack.elements.items) |elem| {
            std.log.err("  field: '{s}'", .{elem.name});
        }
    }

    // Extract server-overridden session parameters (C: Protocol.c:4720-4741)
    // Defaults match C behavior: if server doesn't send the field, use safe defaults.
    // vpn_client.zig will apply min/max logic with client-requested values.
    const srv_max_conn = resp_pack.getInt("max_connection") orelse 1;
    const srv_half_conn = (resp_pack.getInt("half_connection") orelse 0) != 0;
    const srv_use_compress = (resp_pack.getInt("use_compress") orelse 0) != 0;
    const srv_use_encrypt = (resp_pack.getInt("use_encrypt") orelse 1) != 0;
    // Fast RC4 only takes effect when the session is encrypted, mirroring the
    // C client (Protocol.c:6011-6015): `if (UseEncrypt) UseFastRC4 = ...`.
    const srv_fast_rc4 = (resp_pack.getInt("use_fast_rc4") orelse 0) != 0;
    const srv_use_fast_rc4 = srv_use_encrypt and srv_fast_rc4;
    const srv_qos = (resp_pack.getInt("qos") orelse 0) != 0;
    const srv_timeout = resp_pack.getInt("timeout") orelse 0;
    const srv_no_routing = (resp_pack.getInt("policy:NoRouting") orelse 0) != 0;

    // RC4 key pair from the Welcome packet (C: Protocol.c:6083-6097). Only
    // present when the server enabled fast RC4.
    var rc4_c2s_key: ?[16]u8 = null;
    if (resp_pack.getData("rc4_key_client_to_server")) |key| {
        if (key.len >= 16) {
            var buf: [16]u8 = undefined;
            @memcpy(&buf, key[0..16]);
            rc4_c2s_key = buf;
        }
    }
    var rc4_s2c_key: ?[16]u8 = null;
    if (resp_pack.getData("rc4_key_server_to_client")) |key| {
        if (key.len >= 16) {
            var buf: [16]u8 = undefined;
            @memcpy(&buf, key[0..16]);
            rc4_s2c_key = buf;
        }
    }

    std.log.debug("Server session params: max_conn={d}, half_conn={}, compress={}, encrypt={}, fast_rc4={}, qos={}, timeout={d}, no_routing={}", .{
        srv_max_conn, srv_half_conn, srv_use_compress, srv_use_encrypt, srv_use_fast_rc4, srv_qos, srv_timeout, srv_no_routing,
    });

    // Extract UDP acceleration fields
    const udp_enabled = (resp_pack.getInt("use_udp_acceleration") orelse 0) != 0;
    const udp_port: u16 = @intCast(resp_pack.getInt("udp_acceleration_client_port") orelse 0);
    const udp_enc = (resp_pack.getInt("udp_acceleration_use_encryption") orelse 1) != 0;
    const rudp_ver = @as(u32, @intCast(resp_pack.getInt("rudp_bulk_version") orelse 0));

    var server_send_key: ?[16]u8 = null;
    if (resp_pack.getData("bulk_on_rudp_send_key")) |key| {
        if (key.len >= 16) {
            var buf: [16]u8 = undefined;
            @memcpy(&buf, key[0..16]);
            server_send_key = buf;
        }
    }
    var server_recv_key: ?[16]u8 = null;
    if (resp_pack.getData("bulk_on_rudp_recv_key")) |key| {
        if (key.len >= 16) {
            var buf: [16]u8 = undefined;
            @memcpy(&buf, key[0..16]);
            server_recv_key = buf;
        }
    }

    if (udp_enabled) {
        std.log.info("UDP acceleration: port={d}, enc={}, rudp_ver={d}", .{ udp_port, udp_enc, rudp_ver });
    }

    std.log.info("Authentication successful", .{});

    return AuthResult{
        .success = true,
        .error_code = 0,
        .error_message = null,
        .session_key = session_key,
        .policy = null,
        .redirect = null,
        .server_max_connection = srv_max_conn,
        .server_half_connection = srv_half_conn,
        .server_use_compress = srv_use_compress,
        .server_use_encrypt = srv_use_encrypt,
        .server_use_fast_rc4 = srv_use_fast_rc4,
        .rc4_client_to_server_key = rc4_c2s_key,
        .rc4_server_to_client_key = rc4_s2c_key,
        .server_qos = srv_qos,
        .server_timeout = srv_timeout,
        .server_no_routing = srv_no_routing,
        .udp_accel_enabled = udp_enabled,
        .udp_accel_port = udp_port,
        .udp_accel_use_encrypt = udp_enc,
        .rudp_bulk_version = rudp_ver,
        .server_bulk_send_key = server_send_key,
        .server_bulk_recv_key = server_recv_key,
    };
}

/// Perform complete handshake sequence
pub fn performHandshake(
    allocator: Allocator,
    writer: Writer,
    reader: Reader,
    host: []const u8,
    hub_name: []const u8,
    username: []const u8,
    password: ?[]const u8,
    udp_accel: bool,
) !struct { hello: HelloResponse, auth: AuthResult } {
    // Step 1: Upload signature
    try uploadSignature(allocator, writer, host, null);

    // Step 2: Download Hello
    var hello = try downloadHello(allocator, reader);
    errdefer hello.deinit(allocator);

    // Step 3: Build and upload auth
    const default_opts = SessionOptions{};
    const auth_data = if (password) |pwd|
        try buildPasswordAuth(allocator, username, pwd, hub_name, &hello.random, 0, "", udp_accel, null, default_opts)
    else
        try buildAnonymousAuth(allocator, hub_name, 0, "", udp_accel, null, default_opts);
    defer allocator.free(auth_data);

    var auth = try uploadAuth(allocator, writer, reader, host, auth_data, null);
    errdefer auth.deinit(allocator);

    return .{ .hello = hello, .auth = auth };
}

// ============================================================================
// Additional Connection Protocol
// ============================================================================

/// Result of an additional connection handshake
pub const AdditionalConnectResult = struct {
    success: bool,
    direction: u32, // 0=both, 1=server_to_client, 2=client_to_server
    error_code: u32,
};

/// Build the Pack for an additional TCP connection handshake.
/// Reference: C `PackAdditionalConnect()` in Protocol.c:6891-6906
pub fn buildAdditionalConnectPack(
    allocator: Allocator,
    session_key: *const [Protocol.sha1_size]u8,
) ![]u8 {
    var p = Pack.init(allocator);
    defer p.deinit();

    try p.addStr("method", "additional_connect");
    try p.addData("session_key", session_key);

    return p.toBytes(allocator);
}

/// Send additional connect pack and parse the server response.
/// Reference: C `ClientUploadAuth2()` in Protocol.c:5407-5418
pub fn uploadAdditionalConnect(
    allocator: Allocator,
    writer: Writer,
    reader: Reader,
    host: []const u8,
    session_key: *const [Protocol.sha1_size]u8,
) !AdditionalConnectResult {
    // Build and send the pack
    const pack_data = try buildAdditionalConnectPack(allocator, session_key);
    defer allocator.free(pack_data);

    try sendHttpPost(allocator, writer, host, pack_data, null);

    // Read HTTP response header
    var resp_header_buf: [4096]u8 = undefined;
    var resp_header_len: usize = 0;

    while (resp_header_len < resp_header_buf.len - 1) {
        const bytes_read = try reader.read(resp_header_buf[resp_header_len .. resp_header_len + 1]);
        if (bytes_read == 0) return ProtocolError.ConnectionFailed;
        resp_header_len += 1;

        if (resp_header_len >= 4) {
            if (mem.eql(u8, resp_header_buf[resp_header_len - 4 .. resp_header_len], "\r\n\r\n")) {
                break;
            }
        }
    }

    const parsed = try rpc.parseHttpResponse(resp_header_buf[0..resp_header_len]);
    if (parsed.status_code != 200) {
        std.log.err("Additional connect response status: {d}", .{parsed.status_code});
        return AdditionalConnectResult{ .success = false, .direction = 0, .error_code = 0 };
    }

    // Read body
    const body = try allocator.alloc(u8, parsed.content_length);
    defer allocator.free(body);

    const body_read = try reader.readAll(body);
    if (body_read != parsed.content_length) {
        return ProtocolError.InvalidResponse;
    }

    // Parse response Pack
    var resp_pack = try Pack.fromBytes(allocator, body);
    defer resp_pack.deinit();

    // Check for error
    const err_code = resp_pack.getInt("error") orelse 0;
    if (err_code != 0) {
        std.log.err("Additional connect failed: error={d}", .{err_code});
        return AdditionalConnectResult{ .success = false, .direction = 0, .error_code = err_code };
    }

    // Extract direction (0=both, 1=S2C, 2=C2S)
    const direction = resp_pack.getInt("direction") orelse 0;
    std.log.info("Additional connect accepted: direction={d}", .{direction});

    return AdditionalConnectResult{
        .success = true,
        .direction = direction,
        .error_code = 0,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "WaterMark is correct size" {
    // WaterMark is the GIF image used as protocol signature (1411 bytes)
    // Note: Saitama array (66963 bytes) is separate "bonus" data, not used for auth
    try std.testing.expectEqual(@as(usize, 1411), WaterMark.len);
    // First bytes are GIF89a header
    try std.testing.expectEqual(@as(u8, 0x47), WaterMark[0]); // 'G'
    try std.testing.expectEqual(@as(u8, 0x49), WaterMark[1]); // 'I'
    try std.testing.expectEqual(@as(u8, 0x46), WaterMark[2]); // 'F'
    // Last bytes are GIF trailer
    try std.testing.expectEqual(@as(u8, 0x00), WaterMark[1408]);
    try std.testing.expectEqual(@as(u8, 0x00), WaterMark[1409]);
    try std.testing.expectEqual(@as(u8, 0x3B), WaterMark[1410]); // GIF end marker
}

test "buildClientHello creates valid Pack" {
    const allocator = std.testing.allocator;

    const hello_data = try buildClientHello(allocator, null);
    defer allocator.free(hello_data);

    // Parse it back
    var hello_pack = try Pack.fromBytes(allocator, hello_data);
    defer hello_pack.deinit();

    try std.testing.expectEqualStrings(Protocol.client_str, hello_pack.getStr("client_str").?);
    try std.testing.expectEqual(Protocol.client_ver, hello_pack.getInt("client_ver").?);
}

test "buildPasswordAuth creates valid Pack" {
    const allocator = std.testing.allocator;

    var random: [Protocol.sha1_size]u8 = undefined;
    crypto.random.bytes(&random);

    const auth_data = try buildPasswordAuth(
        allocator,
        "testuser",
        "testpass",
        "VPN",
        &random,
        0,
        "",
        false, // udp_accel
        null,
        .{},
    );
    defer allocator.free(auth_data);

    // Parse it back
    var auth_pack = try Pack.fromBytes(allocator, auth_data);
    defer auth_pack.deinit();

    try std.testing.expectEqualStrings("auth", auth_pack.getStr("method").?);
    try std.testing.expectEqualStrings("VPN", auth_pack.getStr("hubname").?);
    try std.testing.expectEqualStrings("testuser", auth_pack.getStr("username").?);
    try std.testing.expectEqual(@intFromEnum(AuthType.password), auth_pack.getInt("authtype").?);
    try std.testing.expect(auth_pack.getData("secure_password") != null);
}

test "buildAnonymousAuth creates valid Pack" {
    const allocator = std.testing.allocator;

    const auth_data = try buildAnonymousAuth(allocator, "PUBLIC", 0, "", false, null, .{});
    defer allocator.free(auth_data);

    var auth_pack = try Pack.fromBytes(allocator, auth_data);
    defer auth_pack.deinit();

    try std.testing.expectEqualStrings("anonymous", auth_pack.getStr("username").?);
    try std.testing.expectEqual(@intFromEnum(AuthType.anonymous), auth_pack.getInt("authtype").?);
}

test "HTTP header building" {
    const allocator = std.testing.allocator;

    const header = try buildSignatureHttpHeader(allocator, "vpn.example.com", 1234);
    defer allocator.free(header);

    try std.testing.expect(mem.indexOf(u8, header, "POST /vpnsvc/connect.cgi HTTP/1.1") != null);
    try std.testing.expect(mem.indexOf(u8, header, "Host: vpn.example.com") != null);
    try std.testing.expect(mem.indexOf(u8, header, "Content-Type: image/jpeg") != null);
    try std.testing.expect(mem.indexOf(u8, header, "Content-Length: 1234") != null);
}
