//! Interactive admin CLI shell — vpncmd-style interface over the native admin
//! RPC client.  Mirrors the `cli/shell.zig` patterns for the client side.
//!
//! C reference: `Cedar/Command.c` (`Command*` functions).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const display = @import("display.zig");
const DisplayContext = display.DisplayContext;
const AdminClient = @import("../cedar/client/admin_client.zig").AdminClient;
const Pack = @import("../cedar/protocol/pack.zig").Pack;
const rpc = @import("../cedar/server/admin/rpc.zig");

// ============================================================================
// Command definitions
// ============================================================================

pub const Command = enum {
    help,
    server_info,
    server_status,
    server_caps,
    hub_list,
    hub_create,
    hub_delete,
    hub_status,
    user_list,
    user_create,
    user_delete,
    user_get,
    group_list,
    group_create,
    group_delete,
    session_list,
    session_delete,
    session_status,
    connection_list,
    connection_disconnect,
    listener_list,
    access_list,
    mac_table,
    ip_table,
    log_list,
    traffic,
    password,
    set_server_password,
    test_echo,
    quit,
    unknown,

    pub fn fromString(s: []const u8) Command {
        const trimmed = std.mem.trim(u8, s, " \t\r\n");
        if (trimmed.len == 0) return .unknown;

        const aliases = [_]struct { []const u8, Command }{
            .{ "help", .help },
            .{ "?", .help },
            .{ "server-info", .server_info },
            .{ "serverinfo", .server_info },
            .{ "server-status", .server_status },
            .{ "serverstatus", .server_status },
            .{ "caps", .server_caps },
            .{ "server-caps", .server_caps },
            .{ "hub-list", .hub_list },
            .{ "hublist", .hub_list },
            .{ "hub-create", .hub_create },
            .{ "hubcreate", .hub_create },
            .{ "hub-delete", .hub_delete },
            .{ "hubdelete", .hub_delete },
            .{ "hub-status", .hub_status },
            .{ "hubstatus", .hub_status },
            .{ "user-list", .user_list },
            .{ "userlist", .user_list },
            .{ "user-create", .user_create },
            .{ "usercreate", .user_create },
            .{ "user-delete", .user_delete },
            .{ "userdelete", .user_delete },
            .{ "user-get", .user_get },
            .{ "userget", .user_get },
            .{ "group-list", .group_list },
            .{ "grouplist", .group_list },
            .{ "group-create", .group_create },
            .{ "groupcreate", .group_create },
            .{ "group-delete", .group_delete },
            .{ "groupdelete", .group_delete },
            .{ "session-list", .session_list },
            .{ "sessionlist", .session_list },
            .{ "session-delete", .session_delete },
            .{ "sessiondelete", .session_delete },
            .{ "session-status", .session_status },
            .{ "sessionstatus", .session_status },
            .{ "connection-list", .connection_list },
            .{ "connectionlist", .connection_list },
            .{ "connection-disconnect", .connection_disconnect },
            .{ "connectiondisconnect", .connection_disconnect },
            .{ "listener-list", .listener_list },
            .{ "listenerlist", .listener_list },
            .{ "access-list", .access_list },
            .{ "accesslist", .access_list },
            .{ "mac-table", .mac_table },
            .{ "mactable", .mac_table },
            .{ "ip-table", .ip_table },
            .{ "iptable", .ip_table },
            .{ "log-list", .log_list },
            .{ "loglist", .log_list },
            .{ "traffic", .traffic },
            .{ "password", .password },
            .{ "set-server-password", .set_server_password },
            .{ "setservpassword", .set_server_password },
            .{ "test", .test_echo },
            .{ "quit", .quit },
            .{ "exit", .quit },
            .{ "q", .quit },
        };

        inline for (aliases) |entry| {
            if (std.ascii.eqlIgnoreCase(trimmed, entry[0])) return entry[1];
        }
        return .unknown;
    }
};

// ============================================================================
// Shell state + REPL
// ============================================================================

pub const Shell = struct {
    allocator: Allocator,
    client: *AdminClient,
    display_ctx: DisplayContext,
    hub_name: []const u8,
    running: bool,

    const Self = @This();

    pub fn init(allocator: Allocator, client: *AdminClient, display_ctx: DisplayContext) Self {
        return .{
            .allocator = allocator,
            .client = client,
            .display_ctx = display_ctx,
            .hub_name = client.hub_name,
            .running = true,
        };
    }

    pub fn run(self: *Self) void {
        self.displayWelcome();
        var buf: [1024]u8 = undefined;

        while (self.running) {
            self.display_ctx.print("vpncmd> ", .{});
            const n = self.readStdin(&buf) catch {
                self.display_ctx.print("\n", .{});
                break;
            };
            if (n == 0) break;
            const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
            if (trimmed.len == 0) continue;

            self.executeCommand(trimmed);
        }
    }

    fn readStdin(self: *Self, buf: []u8) !usize {
        _ = self;
        if (comptime builtin.target.os.tag == .windows) {
            const handle = std.os.windows.kernel32.GetStdHandle(std.os.windows.STD_INPUT_HANDLE) orelse return 0;
            var read: std.os.windows.DWORD = 0;
            const success = std.os.windows.kernel32.ReadFile(handle, buf.ptr, @intCast(buf.len), &read, null);
            if (success == 0) return error.ReadFailed;
            return @intCast(read);
        } else {
            const stdin_file = std.fs.File{ .handle = std.posix.STDIN_FILENO };
            return stdin_file.read(buf);
        }
    }

    fn displayWelcome(self: *Self) void {
        self.display_ctx.printColored(.bold, "SoftEther VPN Server Admin CLI\n", .{});
        self.display_ctx.print("Connected to server. Type 'help' for available commands.\n", .{});
        self.display_ctx.print("Hub: {s}\n\n", .{self.hub_name});
        self.display_ctx.hr();
    }

    fn executeCommand(self: *Self, input: []const u8) void {
        // Split input into command and args
        var parts = std.mem.splitScalar(u8, input, ' ');
        const cmd_str = parts.next() orelse return;
        const rest = parts.rest();
        const args = std.mem.trim(u8, rest, " ");

        const cmd = Command.fromString(cmd_str);
        switch (cmd) {
            .help => self.cmdHelp(),
            .server_info => self.cmdServerInfo(),
            .server_status => self.cmdServerStatus(),
            .server_caps => self.cmdServerCaps(),
            .hub_list => self.cmdHubList(),
            .hub_create => self.cmdHubCreate(args),
            .hub_delete => self.cmdHubDelete(args),
            .hub_status => self.cmdHubStatus(args),
            .user_list => self.cmdUserList(),
            .user_create => self.cmdUserCreate(args),
            .user_delete => self.cmdUserDelete(args),
            .user_get => self.cmdUserGet(args),
            .group_list => self.cmdGroupList(),
            .group_create => self.cmdGroupCreate(args),
            .group_delete => self.cmdGroupDelete(args),
            .session_list => self.cmdSessionList(),
            .session_delete => self.cmdSessionDelete(args),
            .session_status => self.cmdSessionStatus(args),
            .connection_list => self.cmdConnectionList(),
            .connection_disconnect => self.cmdConnectionDisconnect(args),
            .listener_list => self.cmdListenerList(),
            .access_list => self.cmdAccessList(),
            .mac_table => self.cmdMacTable(),
            .ip_table => self.cmdIpTable(),
            .log_list => self.cmdLogList(),
            .traffic => self.cmdTraffic(),
            .password => self.cmdPassword(args),
            .set_server_password => self.cmdSetServerPassword(args),
            .test_echo => self.cmdTest(args),
            .quit => {
                self.running = false;
            },
            .unknown => {
                display.warning(&self.display_ctx, "Unknown command: '{s}'. Type 'help' for available commands.", .{cmd_str});
            },
        }
    }

    // ========================================================================
    // Command implementations
    // ========================================================================

    fn cmdHelp(self: *Self) void {
        self.display_ctx.printColored(.bold, "Available commands:\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Server:\n", .{});
        self.display_ctx.print("  server-info          Show server information\n", .{});
        self.display_ctx.print("  server-status        Show server status\n", .{});
        self.display_ctx.print("  caps                 Show server capabilities\n", .{});
        self.display_ctx.print("  set-server-password <pw>  Set server admin password\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Hubs:\n", .{});
        self.display_ctx.print("  hub-list             List all hubs\n", .{});
        self.display_ctx.print("  hub-create <name>    Create a new hub\n", .{});
        self.display_ctx.print("  hub-delete <name>    Delete a hub\n", .{});
        self.display_ctx.print("  hub-status [name]    Show hub status (default: current hub)\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Users:\n", .{});
        self.display_ctx.print("  user-list            List users in current hub\n", .{});
        self.display_ctx.print("  user-create <name>   Create a user (anonymous auth)\n", .{});
        self.display_ctx.print("  user-delete <name>   Delete a user\n", .{});
        self.display_ctx.print("  user-get <name>      Get user details\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Groups:\n", .{});
        self.display_ctx.print("  group-list           List groups in current hub\n", .{});
        self.display_ctx.print("  group-create <name>  Create a group\n", .{});
        self.display_ctx.print("  group-delete <name>  Delete a group\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Sessions & Connections:\n", .{});
        self.display_ctx.print("  session-list         List sessions in current hub\n", .{});
        self.display_ctx.print("  session-delete <name>  Delete a session\n", .{});
        self.display_ctx.print("  session-status <name>  Get session status\n", .{});
        self.display_ctx.print("  connection-list      List all connections\n", .{});
        self.display_ctx.print("  connection-disconnect <name>  Disconnect a connection\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Tables & Access:\n", .{});
        self.display_ctx.print("  listener-list        List listeners\n", .{});
        self.display_ctx.print("  access-list          List access rules in current hub\n", .{});
        self.display_ctx.print("  mac-table            List MAC table in current hub\n", .{});
        self.display_ctx.print("  ip-table             List IP table in current hub\n", .{});
        self.display_ctx.print("\n", .{});
        self.display_ctx.printColored(.cyan, "Other:\n", .{});
        self.display_ctx.print("  log-list             List log files\n", .{});
        self.display_ctx.print("  traffic              Show traffic stats for current hub\n", .{});
        self.display_ctx.print("  password <user> <pass>  Set user password\n", .{});
        self.display_ctx.print("  test <msg>           Echo test to server\n", .{});
        self.display_ctx.print("  quit / exit          Exit the shell\n", .{});
        self.display_ctx.print("\n", .{});
    }

    fn cmdServerInfo(self: *Self) void {
        var resp = self.client.getServerInfo() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "Server Information\n", .{});
        self.display_ctx.hr();
        self.printStr(&resp, "ServerName", "Server Name");
        self.printStr(&resp, "ServerType", "Server Type");
        self.printBool(&resp, "Online", "Online");
        self.printInt(&resp, "Uptime", "Uptime (sec)");
        self.printStr(&resp, "VerMajor", "Version Major");
        self.printStr(&resp, "VerMinor", "Version Minor");
        self.printStr(&resp, "Build", "Build");
        self.printStr(&resp, "ServerDescription", "Description");
    }

    fn cmdServerStatus(self: *Self) void {
        var resp = self.client.getServerStatus() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "Server Status\n", .{});
        self.display_ctx.hr();
        self.printInt(&resp, "TotalSessions", "Total Sessions");
        self.printInt(&resp, "TotalTcpConnections", "Total TCP Connections");
        self.printInt(&resp, "TotalAssociations", "Total Associations");
        self.printInt(&resp, "TotalBytesReceived", "Bytes Received");
        self.printInt(&resp, "TotalBytesSent", "Bytes Sent");
        self.printInt(&resp, "TotalPacketsReceived", "Packets Received");
        self.printInt(&resp, "TotalPacketsSent", "Packets Sent");
    }

    fn cmdServerCaps(self: *Self) void {
        var resp = self.client.getCaps() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "Server Capabilities\n", .{});
        self.display_ctx.hr();
        const count = resp.getValueCount("CapsName");
        for (0..count) |i| {
            const name = resp.getStrEx("CapsName", i) orelse continue;
            const value = resp.getIntEx("CapsValue", i) orelse 0;
            self.display_ctx.print("  {s}: {d}\n", .{ name, value });
        }
    }

    fn cmdHubList(self: *Self) void {
        var resp = self.client.enumHub() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("HubName");
        self.display_ctx.printColored(.bold, "Hubs ({d})\n", .{count});
        self.display_ctx.hr();
        for (0..count) |i| {
            const name = resp.getStrEx("HubName", i) orelse continue;
            const hub_type = resp.getIntEx("HubType", i) orelse 0;
            self.display_ctx.print("  {s} (type={d})\n", .{ name, hub_type });
        }
    }

    fn cmdHubCreate(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: hub-create <name>", .{});
            return;
        }
        var resp = self.client.createHub(args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Hub '{s}' created.", .{args});
    }

    fn cmdHubDelete(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: hub-delete <name>", .{});
            return;
        }
        var resp = self.client.deleteHub(args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Hub '{s}' deleted.", .{args});
    }

    fn cmdHubStatus(self: *Self, args: []const u8) void {
        const hub = if (args.len > 0) args else self.hub_name;
        var resp = self.client.getHubStatus(hub) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "Hub Status: {s}\n", .{hub});
        self.display_ctx.hr();
        self.printBool(&resp, "Online", "Online");
        self.printInt(&resp, "HubType", "Hub Type");
        self.printInt(&resp, "MaxSession", "Max Sessions");
        self.printInt(&resp, "NumUser", "Users");
        self.printInt(&resp, "NumGroup", "Groups");
        self.printInt(&resp, "NumSession", "Sessions");
        self.printInt(&resp, "NumMacTable", "MAC Table Entries");
        self.printInt(&resp, "NumIpTable", "IP Table Entries");
    }

    fn cmdUserList(self: *Self) void {
        var resp = self.client.enumUser(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("Name");
        self.display_ctx.printColored(.bold, "Users in {s} ({d})\n", .{ self.hub_name, count });
        self.display_ctx.hr();
        for (0..count) |i| {
            const name = resp.getStrEx("Name", i) orelse continue;
            self.display_ctx.print("  {s}\n", .{name});
        }
    }

    fn cmdUserCreate(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: user-create <name>", .{});
            return;
        }
        var resp = self.client.createUser(self.hub_name, args, "") catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "User '{s}' created.", .{args});
    }

    fn cmdUserDelete(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: user-delete <name>", .{});
            return;
        }
        var resp = self.client.deleteUser(self.hub_name, args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "User '{s}' deleted.", .{args});
    }

    fn cmdUserGet(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: user-get <name>", .{});
            return;
        }
        var resp = self.client.getUser(self.hub_name, args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "User: {s}\n", .{args});
        self.display_ctx.hr();
        self.printStr(&resp, "Name", "Name");
        self.printStr(&resp, "RealName", "Real Name");
        self.printStr(&resp, "Note", "Note");
        self.printStr(&resp, "GroupName", "Group");
        self.printInt(&resp, "AuthType", "Auth Type");
        self.printInt(&resp, "NumLogin", "Logins");
        self.printInt(&resp, "CreatedTime", "Created");
        self.printInt(&resp, "UpdatedTime", "Updated");
    }

    fn cmdGroupList(self: *Self) void {
        var resp = self.client.enumGroup(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("Name");
        self.display_ctx.printColored(.bold, "Groups in {s} ({d})\n", .{ self.hub_name, count });
        self.display_ctx.hr();
        for (0..count) |i| {
            const name = resp.getStrEx("Name", i) orelse continue;
            self.display_ctx.print("  {s}\n", .{name});
        }
    }

    fn cmdGroupCreate(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: group-create <name>", .{});
            return;
        }
        var resp = self.client.createGroup(self.hub_name, args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Group '{s}' created.", .{args});
    }

    fn cmdGroupDelete(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: group-delete <name>", .{});
            return;
        }
        var resp = self.client.deleteGroup(self.hub_name, args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Group '{s}' deleted.", .{args});
    }

    fn cmdSessionList(self: *Self) void {
        var resp = self.client.enumSession(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("Name");
        self.display_ctx.printColored(.bold, "Sessions in {s} ({d})\n", .{ self.hub_name, count });
        self.display_ctx.hr();
        for (0..count) |i| {
            const name = resp.getStrEx("Name", i) orelse continue;
            self.display_ctx.print("  {s}\n", .{name});
        }
    }

    fn cmdSessionDelete(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: session-delete <name>", .{});
            return;
        }
        var resp = self.client.deleteSession(self.hub_name, args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Session '{s}' deleted.", .{args});
    }

    fn cmdSessionStatus(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: session-status <name>", .{});
            return;
        }
        var resp = self.client.getSessionStatus(self.hub_name, args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "Session: {s}\n", .{args});
        self.display_ctx.hr();
        self.printStr(&resp, "Name", "Name");
        self.printStr(&resp, "Username", "Username");
        self.printStr(&resp, "RemoteHostname", "Remote Host");
        self.printInt(&resp, "RemotePort", "Remote Port");
        self.printInt(&resp, "BytesReceived", "Bytes Received");
        self.printInt(&resp, "BytesSent", "Bytes Sent");
        self.printInt(&resp, "NumPacketsReceived", "Packets Received");
        self.printInt(&resp, "NumPacketsSent", "Packets Sent");
        self.printInt(&resp, "ConnectedTime", "Connected Time (sec)");
    }

    fn cmdConnectionList(self: *Self) void {
        var resp = self.client.enumConnection() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("Name");
        self.display_ctx.printColored(.bold, "Connections ({d})\n", .{count});
        self.display_ctx.hr();
        for (0..count) |i| {
            const name = resp.getStrEx("Name", i) orelse continue;
            self.display_ctx.print("  {s}\n", .{name});
        }
    }

    fn cmdConnectionDisconnect(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: connection-disconnect <name>", .{});
            return;
        }
        var resp = self.client.disconnectConnection(args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Connection '{s}' disconnected.", .{args});
    }

    fn cmdListenerList(self: *Self) void {
        var resp = self.client.enumListener() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("Port");
        self.display_ctx.printColored(.bold, "Listeners ({d})\n", .{count});
        self.display_ctx.hr();
        for (0..count) |i| {
            const port = resp.getIntEx("Port", i) orelse 0;
            const enabled = resp.getBoolEx("Enabled", i) orelse false;
            self.display_ctx.print("  port={d}  enabled={s}\n", .{ port, if (enabled) "yes" else "no" });
        }
    }

    fn cmdAccessList(self: *Self) void {
        var resp = self.client.enumAccess(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("Id");
        self.display_ctx.printColored(.bold, "Access Rules in {s} ({d})\n", .{ self.hub_name, count });
        self.display_ctx.hr();
        for (0..count) |i| {
            const id = resp.getIntEx("Id", i) orelse 0;
            const active = resp.getBoolEx("Active", i) orelse false;
            const discard = resp.getBoolEx("Discard", i) orelse false;
            const proto = resp.getIntEx("Protocol", i) orelse 0;
            self.display_ctx.print("  id={d}  active={s}  discard={s}  proto={d}\n", .{
                id,
                if (active) "yes" else "no",
                if (discard) "yes" else "no",
                proto,
            });
        }
    }

    fn cmdMacTable(self: *Self) void {
        var resp = self.client.enumMacTable(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("MacAddress");
        self.display_ctx.printColored(.bold, "MAC Table in {s} ({d})\n", .{ self.hub_name, count });
        self.display_ctx.hr();
        for (0..count) |i| {
            const mac = resp.getDataEx("MacAddress", i) orelse continue;
            const session = resp.getStrEx("SessionName", i) orelse "?";
            if (mac.len >= 6) {
                self.display_ctx.print("  {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}  {s}\n", .{
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], session,
                });
            }
        }
    }

    fn cmdIpTable(self: *Self) void {
        var resp = self.client.enumIpTable(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("IpAddress");
        self.display_ctx.printColored(.bold, "IP Table in {s} ({d})\n", .{ self.hub_name, count });
        self.display_ctx.hr();
        for (0..count) |i| {
            const ip = resp.getIntEx("IpAddress", i) orelse 0;
            const session = resp.getStrEx("SessionName", i) orelse "?";
            self.display_ctx.print("  {d}.{d}.{d}.{d}  {s}\n", .{
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF,
                session,
            });
        }
    }

    fn cmdLogList(self: *Self) void {
        var resp = self.client.enumLog() catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const count = resp.getValueCount("FileName");
        self.display_ctx.printColored(.bold, "Log Files ({d})\n", .{count});
        self.display_ctx.hr();
        for (0..count) |i| {
            const name = resp.getStrEx("FileName", i) orelse continue;
            self.display_ctx.print("  {s}\n", .{name});
        }
    }

    fn cmdTraffic(self: *Self) void {
        var resp = self.client.getTraffic(self.hub_name) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        self.display_ctx.printColored(.bold, "Traffic Stats for {s}\n", .{self.hub_name});
        self.display_ctx.hr();
        self.printInt(&resp, "RecvBytes", "Bytes Received");
        self.printInt(&resp, "SendBytes", "Bytes Sent");
        self.printInt(&resp, "RecvPackets", "Packets Received");
        self.printInt(&resp, "SendPackets", "Packets Sent");
    }

    fn cmdPassword(self: *Self, args: []const u8) void {
        var parts = std.mem.splitScalar(u8, args, ' ');
        const user = parts.next() orelse "";
        const pass = parts.rest();
        if (user.len == 0 or pass.len == 0) {
            display.warning(&self.display_ctx, "Usage: password <user> <password>", .{});
            return;
        }
        var resp = self.client.setPassword(self.hub_name, user, pass) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Password set for user '{s}'.", .{user});
    }

    fn cmdSetServerPassword(self: *Self, args: []const u8) void {
        if (args.len == 0) {
            display.warning(&self.display_ctx, "Usage: set-server-password <password>", .{});
            return;
        }
        var resp = self.client.setServerPassword(args) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        display.success(&self.display_ctx, "Server admin password set.", .{});
    }

    fn cmdTest(self: *Self, args: []const u8) void {
        const msg = if (args.len > 0) args else "ping";
        var resp = self.client.testEcho(msg) catch |err| {
            display.failure(&self.display_ctx, "Request failed: {}", .{err});
            return;
        };
        defer resp.deinit();
        if (!rpc.rpcIsOk(&resp)) {
            self.rpcError(&resp);
            return;
        }
        const value = resp.getInt("value") orelse 0;
        display.success(&self.display_ctx, "Server echoed: value={d}", .{value});
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn rpcError(self: *Self, resp: *const Pack) void {
        const code = rpc.rpcGetError(resp);
        display.failure(&self.display_ctx, "Server error: code={d}", .{code});
    }

    fn printStr(self: *Self, resp: *const Pack, key: []const u8, label: []const u8) void {
        const val = resp.getStr(key) orelse "";
        self.display_ctx.print("  {s}: {s}\n", .{ label, val });
    }

    fn printInt(self: *Self, resp: *const Pack, key: []const u8, label: []const u8) void {
        const val = resp.getInt(key) orelse 0;
        self.display_ctx.print("  {s}: {d}\n", .{ label, val });
    }

    fn printBool(self: *Self, resp: *const Pack, key: []const u8, label: []const u8) void {
        const val = resp.getBool(key) orelse false;
        self.display_ctx.print("  {s}: {s}\n", .{ label, if (val) "yes" else "no" });
    }
};
