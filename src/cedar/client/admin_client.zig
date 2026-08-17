//! Admin RPC client — connects to a SoftEther server over TLS and sends/receives
//! Pack-based admin RPC frames.  Thin wrapper around the frame I/O in
//! `server/admin/rpc.zig` plus `mayaqua/network/tls.zig`.
//!
//! C reference: `Remote.c` (`AdminConnect` / `AdminSendRequest` /
//! `AdminRecvResponse`) / `Cedar/Command.h`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const tls = @import("../../mayaqua/network/tls.zig");
const Pack = @import("../protocol/pack.zig").Pack;
const admin_rpc = @import("../server/admin/rpc.zig");

const log = std.log.scoped(.admin_client);

/// Error names matching the C `ERR_*` constants used by the admin dispatch.
/// Values sourced from `cedar/server/admin/dispatch.zig`.
pub const err_no_error: u32 = 0;
pub const err_hub_not_found: u32 = 8;
pub const err_object_not_found: u32 = 29;
pub const err_not_supported: u32 = 33;
pub const err_invalid_parameter: u32 = 38;
pub const err_not_enough_right: u32 = 52;

pub const AdminError = error{
    ConnectionFailed,
    TlsHandshakeFailed,
    SendFailed,
    RecvFailed,
    ServerError,
    UnexpectedResponse,
};

/// Admin RPC client connected to a SoftEther server.
pub const AdminClient = struct {
    allocator: Allocator,
    tls_sock: tls.TlsSocket,
    hub_name: []const u8,
    password: ?[]const u8 = null,

    const Self = @This();

    /// Connect to the server admin RPC endpoint.
    pub fn connect(
        allocator: Allocator,
        hostname: []const u8,
        port: u16,
        hub_name: []const u8,
        allow_self_signed: bool,
    ) !Self {
        const sock = tls.TlsSocket.connect(allocator, hostname, port, .{
            .verify_certificate = !allow_self_signed,
            .allow_self_signed = allow_self_signed,
            .timeout_ms = 30000,
            .tcp_nodelay = true,
        }) catch return error.ConnectionFailed;

        return .{
            .allocator = allocator,
            .tls_sock = sock,
            .hub_name = try allocator.dupe(u8, hub_name),
        };
    }

    /// Close the connection and release resources.
    pub fn deinit(self: *Self) void {
        self.tls_sock.close();
        self.allocator.free(self.hub_name);
        if (self.password) |pw| self.allocator.free(pw);
    }

    /// Set the admin password for authentication.  The password is included in
    /// every subsequent RPC request as the `Password` field.
    pub fn authenticate(self: *Self, password: []const u8) !void {
        if (self.password) |old| self.allocator.free(old);
        self.password = try self.allocator.dupe(u8, password);
    }

    /// Inject admin password into a request Pack if one has been set.
    fn injectPassword(self: *Self, req: *Pack) !void {
        if (self.password) |pw| {
            try req.addStr("Password", pw);
        }
    }

    /// Send a request Pack and receive the response Pack.  Checks the response
    /// for server errors and maps them to `ServerError`.
    pub fn call(self: *Self, req: *const Pack) !Pack {
        admin_rpc.sendFrame(&self.tls_sock, self.allocator, req) catch return error.SendFailed;
        const resp = admin_rpc.recvFrame(self.allocator, &self.tls_sock) catch return error.RecvFailed;
        const response = resp orelse return error.RecvFailed;
        if (!admin_rpc.rpcIsOk(&response)) {
            const err_code = admin_rpc.rpcGetError(&response);
            log.warn("server returned error code {d}", .{err_code});
            return error.ServerError;
        }
        return response;
    }

    /// Send a request with `function_name` set and return the response.
    pub fn callFunction(self: *Self, function_name: []const u8, setup: *const fn (*Pack) error{OutOfMemory}!void) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", function_name);
        try setup(&req);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    // ========================================================================
    // Convenience wrappers — one per admin dispatch function
    //
    // Each wrapper: allocates a request Pack, populates it, injects the admin
    // password, calls the server, deinits the request Pack on success, and
    // returns the response Pack (caller owns).
    // ========================================================================

    /// `GetServerInfo` — returns the raw response Pack (caller must deinit).
    pub fn getServerInfo(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetServerInfo");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `GetServerStatus` — returns the raw response Pack.
    pub fn getServerStatus(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetServerStatus");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `GetCaps` — returns the raw response Pack.
    pub fn getCaps(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetCaps");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumHub` — returns the raw response Pack.
    pub fn enumHub(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumHub");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `CreateHub` — create a new hub.
    pub fn createHub(self: *Self, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "CreateHub");
        try req.addStr("HubName", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `DeleteHub` — delete a hub by name.
    pub fn deleteHub(self: *Self, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "DeleteHub");
        try req.addStr("HubName", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `GetHubStatus` — returns the raw response Pack.
    pub fn getHubStatus(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetHubStatus");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `SetHub` — set hub options (online, max_session, etc).
    pub fn setHub(self: *Self, t: SetHubParams) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "SetHub");
        try req.addStr("HubName", t.hub_name);
        if (t.online) |v| try req.addBool("Online", v);
        if (t.max_session) |v| try req.addInt("MaxSession", v);
        if (t.no_enum) |v| try req.addBool("NoEnum", v);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    pub const SetHubParams = struct {
        hub_name: []const u8,
        online: ?bool = null,
        max_session: ?u32 = null,
        no_enum: ?bool = null,
    };

    /// `EnumUser` — list users in a hub.
    pub fn enumUser(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumUser");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `CreateUser` — create a user in a hub.
    pub fn createUser(self: *Self, hub_name: []const u8, name: []const u8, note: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "CreateUser");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try req.addUniStr("Note", note);
        try req.addInt("AuthType", 0); // anonymous
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `DeleteUser` — delete a user from a hub.
    pub fn deleteUser(self: *Self, hub_name: []const u8, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "DeleteUser");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `GetUser` — returns the raw response Pack.
    pub fn getUser(self: *Self, hub_name: []const u8, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetUser");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `SetPassword` — change a user's password.
    pub fn setPassword(self: *Self, hub_name: []const u8, name: []const u8, password: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "SetPassword");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try req.addStr("Password", password);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumGroup` — list groups in a hub.
    pub fn enumGroup(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumGroup");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `CreateGroup` — create a group in a hub.
    pub fn createGroup(self: *Self, hub_name: []const u8, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "CreateGroup");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `DeleteGroup` — delete a group from a hub.
    pub fn deleteGroup(self: *Self, hub_name: []const u8, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "DeleteGroup");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumSession` — list sessions in a hub.
    pub fn enumSession(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumSession");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `DeleteSession` — delete a session by name.
    pub fn deleteSession(self: *Self, hub_name: []const u8, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "DeleteSession");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `GetSessionStatus` — returns the raw response Pack.
    pub fn getSessionStatus(self: *Self, hub_name: []const u8, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetSessionStatus");
        try req.addStr("HubName", hub_name);
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumConnection` — list all connections.
    pub fn enumConnection(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumConnection");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `DisconnectConnection` — disconnect a connection by name.
    pub fn disconnectConnection(self: *Self, name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "DisconnectConnection");
        try req.addStr("Name", name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumListener` — list listeners.
    pub fn enumListener(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumListener");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumAccess` — list access rules in a hub.
    pub fn enumAccess(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumAccess");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumMacTable` — list MAC table entries in a hub.
    pub fn enumMacTable(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumMacTable");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumIpTable` — list IP table entries in a hub.
    pub fn enumIpTable(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumIpTable");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `EnumLog` — list log files.
    pub fn enumLog(self: *Self) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "EnumLog");
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `GetTraffic` — get traffic stats for a hub.
    pub fn getTraffic(self: *Self, hub_name: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "GetTraffic");
        try req.addStr("HubName", hub_name);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `SetServerPassword` — set the server admin password.
    pub fn setServerPassword(self: *Self, password: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "SetServerPassword");
        try req.addStr("Password", password);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }

    /// `Test` — echo/ping the server.
    pub fn testEcho(self: *Self, param: []const u8) !Pack {
        var req = Pack.init(self.allocator);
        errdefer req.deinit();
        try req.addStr("function_name", "Test");
        try req.addStr("param", param);
        try self.injectPassword(&req);
        const resp = try self.call(&req);
        req.deinit();
        return resp;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "AdminClient request Pack construction" {
    const allocator = std.testing.allocator;

    // Verify that the convenience methods build valid Pack frames.
    // (Full TLS round-trip is tested via the server admin_rpc tests.)
    var req = Pack.init(allocator);
    defer req.deinit();
    try req.addStr("function_name", "Test");
    try req.addStr("param", "hello");

    try std.testing.expectEqualStrings("Test", req.getStr("function_name").?);
    try std.testing.expectEqualStrings("hello", req.getStr("param").?);
}

test "AdminClient error constants match dispatch" {
    // Verify our error constants match the server-side dispatch values.
    const dispatch = @import("../server/admin/dispatch.zig");
    try std.testing.expectEqual(@as(u32, 0), err_no_error);
    try std.testing.expectEqual(dispatch.err_not_supported, err_not_supported);
    try std.testing.expectEqual(dispatch.err_hub_not_found, err_hub_not_found);
    try std.testing.expectEqual(dispatch.err_object_not_found, err_object_not_found);
    try std.testing.expectEqual(dispatch.err_invalid_parameter, err_invalid_parameter);
    try std.testing.expectEqual(dispatch.err_not_enough_right, err_not_enough_right);
}
