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
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = std.crypto;

const pack = @import("pack.zig");
const Pack = pack.Pack;
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

    pub fn deinit(self: *AuthResult, allocator: Allocator) void {
        if (self.error_message) |msg| allocator.free(msg);
        if (self.policy) |p| allocator.free(p);
    }
};

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
        while (remaining.len > 0) {
            const written = try self.write(remaining);
            if (written == 0) return error.ConnectionClosed;
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
fn buildSignatureHttpHeader(allocator: Allocator, host: []const u8, body_len: usize) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    const writer = list.writer(allocator);

    // Signature uses connect.cgi endpoint and simple headers like C code
    try writer.print("POST {s} HTTP/1.1\r\n", .{Protocol.vpn_target_signature});
    try writer.print("Host: {s}\r\n", .{host});
    try writer.print("Content-Type: {s}\r\n", .{Protocol.content_type_signature});
    try writer.writeAll("Connection: Keep-Alive\r\n");
    try writer.print("Content-Length: {d}\r\n", .{body_len});
    try writer.writeAll("\r\n");

    return list.toOwnedSlice(allocator);
}

/// Build HTTP header for Pack data
fn buildPackHttpHeader(allocator: Allocator, host: []const u8, body_len: usize) ![]u8 {
    var list = std.ArrayListUnmanaged(u8){};
    errdefer list.deinit(allocator);

    const writer = list.writer(allocator);

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
    try writer.print("POST {s} HTTP/1.1\r\n", .{Protocol.vpn_target});
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
    try writer.writeAll("Keep-Alive: timeout=15; max=19\r\n");
    try writer.writeAll("Connection: Keep-Alive\r\n");
    try writer.print("Content-Type: {s}\r\n", .{Protocol.content_type_pack});
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
) !void {
    const header = try buildPackHttpHeader(allocator, host, body.len);
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
) !void {
    // Try using VPNCONNECT instead of watermark (some servers accept this)
    const body = "VPNCONNECT";
    const body_len = body.len;

    // Build HTTP header
    const header = try buildSignatureHttpHeader(allocator, host, body_len);
    defer allocator.free(header);

    // Send header
    try writer.writeAll(header);

    // Send VPNCONNECT
    try writer.writeAll(body);

    std.log.debug("Uploaded protocol signature ({d} bytes) - using VPNCONNECT", .{body_len});
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
        std.log.err("Hello response status: {d}", .{parsed.status_code});
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
            std.log.err("Server returned error: {d}", .{err_code});
            return ProtocolError.ServerError;
        }
    }

    // Extract Hello data
    std.log.debug("Extracting hello data...", .{});
    const random_data = pack_obj.getData("random") orelse {
        std.log.err("No 'random' field in hello Pack", .{});
        return ProtocolError.InvalidHello;
    };
    if (random_data.len != Protocol.sha1_size) {
        std.log.err("Invalid random size: {d}, expected {d}", .{ random_data.len, Protocol.sha1_size });
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
pub fn buildClientHello(allocator: Allocator) ![]u8 {
    var hello_pack = Pack.init(allocator);
    defer hello_pack.deinit();

    try hello_pack.addStr("client_str", Protocol.client_str);
    try hello_pack.addInt("client_ver", Protocol.client_ver);
    try hello_pack.addInt("client_build", Protocol.client_build);

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

/// Build Auth Pack with password authentication
pub fn buildPasswordAuth(
    allocator: Allocator,
    username: []const u8,
    password: []const u8,
    hub_name: []const u8,
    server_random: *const [Protocol.sha1_size]u8,
    udp_accel: bool,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    // Add authentication fields (method must be "login", not "auth")
    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.password));

    // Compute secure password
    // First hash the password with SHA-0
    const password_hash = auth_mod.hashPassword(password, username);

    // Debug: Print password hash
    std.log.info("Password hash: {x}", .{password_hash});

    // Then compute secure password with server random
    const secure_pass = auth_mod.computeSecurePassword(&password_hash, server_random);

    // Debug: Print secure password and server random
    std.log.info("Server random: {x}", .{server_random.*});
    std.log.info("Secure password: {x}", .{secure_pass});

    try auth_pack.addData("secure_password", &secure_pass);

    // PackAddClientVersion fields
    try auth_pack.addStr("client_str", Protocol.client_str);
    try auth_pack.addInt("client_ver", Protocol.client_ver);
    try auth_pack.addInt("client_build", Protocol.client_build);

    // Protocol (0 = TCP, 1 = UDP) - C adds this BEFORE hello/version/build
    try auth_pack.addInt("protocol", 0);

    // Version fields (C adds AFTER protocol)
    try auth_pack.addStr("hello", Protocol.client_str);
    try auth_pack.addInt("version", Protocol.client_ver);
    try auth_pack.addInt("build", Protocol.client_build);
    try auth_pack.addInt("client_id", 0); // Cedar client ID

    // Protocol options
    try auth_pack.addInt("max_connection", 1);
    try auth_pack.addBool("use_encrypt", true);
    try auth_pack.addBool("use_compress", false);
    try auth_pack.addBool("half_connection", false);

    // Bridge/monitor mode flags
    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    // QoS flag
    try auth_pack.addBool("qos", true);

    // Bulk transfer support (UDP acceleration)
    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    // UDP recovery support
    try auth_pack.addBool("support_udp_recovery", udp_accel);

    // Unique ID (machine identifier) - GenerateMachineUniqueHash in C
    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    // RUDP bulk max version
    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));

    // Cedar->UniqueId is SEPARATE from unique_id in C
    var cedar_unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&cedar_unique_id);

    // Add NodeInfo fields (required by server)
    const os_info_anon = getOsInfo();
    try auth_pack.addStr("ClientProductName", Protocol.client_str);
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info_anon.name);
    try auth_pack.addStr("ClientOsVer", os_info_anon.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", "zig-client");
    try auth_pack.addStr("ServerHostname", "");
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &cedar_unique_id);
    try auth_pack.addInt("ClientProductVer", Protocol.client_ver);
    try auth_pack.addInt("ClientProductBuild", Protocol.client_build);
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    // Add IP addresses like C's PackAddIp32 (adds 4 elements each)
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", 0);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    // Add WinVer fields (required by server)
    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info_anon.title);

    // Add pencore dummy value (random padding for anti-fingerprinting)
    var pencore_buf: [1000]u8 = undefined;
    const pencore_size = crypto.random.intRangeAtMost(usize, 0, 1000);
    crypto.random.bytes(pencore_buf[0..pencore_size]);
    try auth_pack.addData("pencore", pencore_buf[0..pencore_size]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with pre-hashed password (base64 encoded)
pub fn buildPasswordAuthWithHash(
    allocator: Allocator,
    username: []const u8,
    password_hash_base64: []const u8,
    hub_name: []const u8,
    server_random: *const [Protocol.sha1_size]u8,
    udp_accel: bool,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    // Add authentication fields (method must be "login", not "auth")
    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.password));

    // Decode base64 password hash
    const base64_decoder = std.base64.standard.Decoder;
    var password_hash: [Protocol.sha1_size]u8 = undefined;
    base64_decoder.decode(&password_hash, password_hash_base64) catch {
        std.log.err("Failed to decode base64 password hash", .{});
        return error.InvalidBase64;
    };

    // Debug: Print decoded password hash
    std.log.info("Pre-hashed password (decoded): {x}", .{password_hash});

    // Compute secure password with server random
    const secure_pass = auth_mod.computeSecurePassword(&password_hash, server_random);

    // Debug: Print secure password and server random
    std.log.info("Server random: {x}", .{server_random.*});
    std.log.info("Secure password: {x}", .{secure_pass});

    try auth_pack.addData("secure_password", &secure_pass);

    // PackAddClientVersion fields
    try auth_pack.addStr("client_str", Protocol.client_str);
    try auth_pack.addInt("client_ver", Protocol.client_ver);
    try auth_pack.addInt("client_build", Protocol.client_build);

    // Protocol (0 = TCP, 1 = UDP) - C adds this BEFORE hello/version/build
    try auth_pack.addInt("protocol", 0);

    // Version fields (C adds AFTER protocol)
    try auth_pack.addStr("hello", Protocol.client_str);
    try auth_pack.addInt("version", Protocol.client_ver);
    try auth_pack.addInt("build", Protocol.client_build);
    try auth_pack.addInt("client_id", 0); // Cedar client ID

    // Protocol options
    try auth_pack.addInt("max_connection", 1);
    try auth_pack.addBool("use_encrypt", true);
    try auth_pack.addBool("use_compress", false);
    try auth_pack.addBool("half_connection", false);

    // Bridge/monitor mode flags
    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    // QoS flag
    try auth_pack.addBool("qos", true);

    // Bulk transfer support (UDP acceleration)
    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    // UDP recovery support
    try auth_pack.addBool("support_udp_recovery", udp_accel);

    // Unique ID (machine identifier) - GenerateMachineUniqueHash in C
    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    // RUDP bulk max version
    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));

    // Cedar->UniqueId is SEPARATE from unique_id in C
    var cedar_unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&cedar_unique_id);

    // Add NodeInfo fields (required by server)
    const os_info2 = getOsInfo();
    try auth_pack.addStr("ClientProductName", Protocol.client_str);
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info2.name);
    try auth_pack.addStr("ClientOsVer", os_info2.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", "zig-client");
    try auth_pack.addStr("ServerHostname", "");
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &cedar_unique_id);
    try auth_pack.addInt("ClientProductVer", Protocol.client_ver);
    try auth_pack.addInt("ClientProductBuild", Protocol.client_build);
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    // Add IP addresses like C's PackAddIp32 (adds 4 elements each)
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", 0);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    // Add WinVer fields (required by server)
    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info2.title);

    // Add pencore dummy value (random padding for anti-fingerprinting)
    var pencore_buf2: [1000]u8 = undefined;
    const pencore_size2 = crypto.random.intRangeAtMost(usize, 0, 1000);
    crypto.random.bytes(pencore_buf2[0..pencore_size2]);
    try auth_pack.addData("pencore", pencore_buf2[0..pencore_size2]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with anonymous authentication
pub fn buildAnonymousAuth(
    allocator: Allocator,
    hub_name: []const u8,
    udp_accel: bool,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    // Add authentication fields (method must be "login", not "auth")
    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", "anonymous");
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.anonymous));

    // PackAddClientVersion fields
    try auth_pack.addStr("client_str", Protocol.client_str);
    try auth_pack.addInt("client_ver", Protocol.client_ver);
    try auth_pack.addInt("client_build", Protocol.client_build);

    // Protocol (0 = TCP) - C adds this BEFORE hello/version/build
    try auth_pack.addInt("protocol", 0);

    // Version fields (C adds AFTER protocol)
    try auth_pack.addStr("hello", Protocol.client_str);
    try auth_pack.addInt("version", Protocol.client_ver);
    try auth_pack.addInt("build", Protocol.client_build);
    try auth_pack.addInt("client_id", 0);

    // Protocol options
    try auth_pack.addInt("max_connection", 1);
    try auth_pack.addBool("use_encrypt", true);
    try auth_pack.addBool("use_compress", false);
    try auth_pack.addBool("half_connection", false);

    // Bridge/monitor mode flags
    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    // QoS flag
    try auth_pack.addBool("qos", true);

    // Bulk transfer support (UDP acceleration)
    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    // UDP recovery support
    try auth_pack.addBool("support_udp_recovery", udp_accel);

    // Unique ID
    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    // RUDP bulk max version
    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));

    // Add pencore dummy value (random padding for anti-fingerprinting)
    var pencore_buf3: [1000]u8 = undefined;
    const pencore_size3 = crypto.random.intRangeAtMost(usize, 0, 1000);
    crypto.random.bytes(pencore_buf3[0..pencore_size3]);
    try auth_pack.addData("pencore", pencore_buf3[0..pencore_size3]);

    return auth_pack.toBytes(allocator);
}

/// Build Auth Pack with ticket authentication (for cluster redirect)
pub fn buildTicketAuth(
    allocator: Allocator,
    hub_name: []const u8,
    username: []const u8,
    ticket: *const [Protocol.sha1_size]u8,
    udp_accel: bool,
) ![]u8 {
    var auth_pack = Pack.init(allocator);
    defer auth_pack.deinit();

    // Add authentication fields
    try auth_pack.addStr("method", "login");
    try auth_pack.addStr("hubname", hub_name);
    try auth_pack.addStr("username", username);
    try auth_pack.addInt("authtype", @intFromEnum(AuthType.ticket));

    // Add ticket instead of secure_password
    try auth_pack.addData("ticket", ticket);

    // PackAddClientVersion fields
    try auth_pack.addStr("client_str", Protocol.client_str);
    try auth_pack.addInt("client_ver", Protocol.client_ver);
    try auth_pack.addInt("client_build", Protocol.client_build);

    // Protocol (0 = TCP)
    try auth_pack.addInt("protocol", 0);

    // Version fields
    try auth_pack.addStr("hello", Protocol.client_str);
    try auth_pack.addInt("version", Protocol.client_ver);
    try auth_pack.addInt("build", Protocol.client_build);
    try auth_pack.addInt("client_id", 0);

    // Protocol options
    try auth_pack.addInt("max_connection", 1);
    try auth_pack.addBool("use_encrypt", true);
    try auth_pack.addBool("use_compress", false);
    try auth_pack.addBool("half_connection", false);

    // Bridge/monitor mode flags
    try auth_pack.addBool("require_bridge_routing_mode", false);
    try auth_pack.addBool("require_monitor_mode", false);

    // QoS flag
    try auth_pack.addBool("qos", true);

    // Bulk transfer support (UDP acceleration)
    try auth_pack.addBool("support_bulk_on_rudp", udp_accel);
    try auth_pack.addBool("support_hmac_on_bulk_of_rudp", udp_accel);

    // UDP recovery support
    try auth_pack.addBool("support_udp_recovery", udp_accel);

    // Unique ID
    var unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&unique_id);
    try auth_pack.addData("unique_id", &unique_id);

    // RUDP bulk max version
    try auth_pack.addInt("rudp_bulk_max_version", if (udp_accel) @as(i32, 2) else @as(i32, 0));

    // Cedar->UniqueId
    var cedar_unique_id: [Protocol.sha1_size]u8 = undefined;
    std.crypto.random.bytes(&cedar_unique_id);

    // Add NodeInfo fields
    const os_info3 = getOsInfo();
    try auth_pack.addStr("ClientProductName", Protocol.client_str);
    try auth_pack.addStr("ServerProductName", "");
    try auth_pack.addStr("ClientOsName", os_info3.name);
    try auth_pack.addStr("ClientOsVer", os_info3.version);
    try auth_pack.addStr("ClientOsProductId", "");
    try auth_pack.addStr("ClientHostname", "zig-client");
    try auth_pack.addStr("ServerHostname", "");
    try auth_pack.addStr("ProxyHostname", "");
    try auth_pack.addData("UniqueId", &cedar_unique_id);
    try auth_pack.addInt("ClientProductVer", Protocol.client_ver);
    try auth_pack.addInt("ClientProductBuild", Protocol.client_build);
    try auth_pack.addInt("ServerProductVer", 0);
    try auth_pack.addInt("ServerProductBuild", 0);
    // Add IP addresses like C's PackAddIp32 (adds 4 elements each)
    try addPackIp32(&auth_pack, "ClientIpAddress", 0);
    try auth_pack.addData("ClientIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ClientPort", 0);
    try addPackIp32(&auth_pack, "ServerIpAddress", 0);
    try auth_pack.addData("ServerIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ServerPort2", 0);
    try addPackIp32(&auth_pack, "ProxyIpAddress", 0);
    try auth_pack.addData("ProxyIpAddress6", &([_]u8{0} ** 16));
    try auth_pack.addInt("ProxyPort", 0);

    // Add WinVer fields
    try auth_pack.addBool("V_IsWindows", false);
    try auth_pack.addBool("V_IsNT", false);
    try auth_pack.addBool("V_IsServer", false);
    try auth_pack.addBool("V_IsBeta", false);
    try auth_pack.addInt("V_VerMajor", 14);
    try auth_pack.addInt("V_VerMinor", 0);
    try auth_pack.addInt("V_Build", 0);
    try auth_pack.addInt("V_ServicePack", 0);
    try auth_pack.addStr("V_Title", os_info3.title);

    // Add pencore dummy value
    var pencore_buf: [1000]u8 = undefined;
    const pencore_size = crypto.random.intRangeAtMost(usize, 0, 1000);
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
) !AuthResult {
    // Build HTTP header for auth pack
    const header = try buildPackHttpHeader(allocator, host, auth_pack_data.len);
    defer allocator.free(header);

    // Debug: List all elements being sent
    {
        var debug_pack = Pack.fromBytes(allocator, auth_pack_data) catch {
            std.log.info("Failed to parse auth pack for debug", .{});
            return error.InvalidPack;
        };
        defer debug_pack.deinit();

        std.log.info("=== AUTH PACK ({d} bytes, {d} elements) ===", .{ auth_pack_data.len, debug_pack.elements.items.len });
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
                    .int => |v| std.log.info("  {s} ({s}) = {d}", .{ elem.name, type_str, v }),
                    .str => |v| std.log.info("  {s} ({s}) = '{s}'", .{ elem.name, type_str, v }),
                    .data => |v| std.log.info("  {s} ({s}) = [{d} bytes]", .{ elem.name, type_str, v.len }),
                    else => std.log.info("  {s} ({s})", .{ elem.name, type_str }),
                }
            }
        }
        std.log.info("=== END ===", .{});
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

    // Debug: list all fields in response
    std.log.debug("Auth response fields:", .{});
    for (resp_pack.elements.items) |elem| {
        const elem_type_str = switch (elem.value_type) {
            .int => "int",
            .data => "data",
            .str => "str",
            .unistr => "unistr",
            .int64 => "int64",
        };
        const first_val = if (elem.values.items.len > 0) blk: {
            const val = elem.values.items[0];
            break :blk switch (elem.value_type) {
                .int => std.fmt.allocPrint(allocator, "{d}", .{val.int}) catch "?",
                .int64 => std.fmt.allocPrint(allocator, "{d}", .{val.int64}) catch "?",
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
        std.log.err("Authentication failed: {d} - {s}", .{ err_code, err_msg orelse "Unknown error" });

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
            std.log.info("Ticket data length: {d}", .{ticket_data.len});
            if (ticket_data.len == Protocol.sha1_size) {
                @memcpy(&ticket, ticket_data);
            } else if (ticket_data.len > 0) {
                // Copy what we can
                const copy_len = @min(ticket_data.len, Protocol.sha1_size);
                @memcpy(ticket[0..copy_len], ticket_data[0..copy_len]);
            }
        }

        // Debug: print ticket bytes
        std.log.info("Ticket bytes: {x}", .{ticket});

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

    // Extract session key
    var session_key: ?[Protocol.sha1_size]u8 = null;
    if (resp_pack.getData("session_key")) |key_data| {
        if (key_data.len == Protocol.sha1_size) {
            session_key = undefined;
            @memcpy(&session_key.?, key_data);
        }
    }

    std.log.info("Authentication successful", .{});

    return AuthResult{
        .success = true,
        .error_code = 0,
        .error_message = null,
        .session_key = session_key,
        .policy = null,
        .redirect = null,
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
    try uploadSignature(allocator, writer, host);

    // Step 2: Download Hello
    var hello = try downloadHello(allocator, reader);
    errdefer hello.deinit(allocator);

    // Step 3: Build and upload auth
    const auth_data = if (password) |pwd|
        try buildPasswordAuth(allocator, username, pwd, hub_name, &hello.random, udp_accel)
    else
        try buildAnonymousAuth(allocator, hub_name, udp_accel);
    defer allocator.free(auth_data);

    var auth = try uploadAuth(allocator, writer, reader, host, auth_data);
    errdefer auth.deinit(allocator);

    return .{ .hello = hello, .auth = auth };
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

    const hello_data = try buildClientHello(allocator);
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
        false, // udp_accel
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

    const auth_data = try buildAnonymousAuth(allocator, "PUBLIC", false);
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
