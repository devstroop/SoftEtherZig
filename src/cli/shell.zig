//! Interactive Shell
//!
//! Phase 8: Interactive command-line shell for VPN management

const std = @import("std");
const Allocator = std.mem.Allocator;
const display = @import("display.zig");

// ============================================================================
// Shell Commands
// ============================================================================

pub const Command = enum {
    help,
    status,
    connect,
    disconnect,
    reconnect,
    stats,
    config,
    set,
    quit,
    clear,
    unknown,

    pub fn fromString(s: []const u8) Command {
        const trimmed = std.mem.trim(u8, s, " \t\n\r");
        if (trimmed.len == 0) return .unknown;

        if (std.mem.eql(u8, trimmed, "help") or std.mem.eql(u8, trimmed, "?")) return .help;
        if (std.mem.eql(u8, trimmed, "status") or std.mem.eql(u8, trimmed, "s")) return .status;
        if (std.mem.eql(u8, trimmed, "connect") or std.mem.eql(u8, trimmed, "c")) return .connect;
        if (std.mem.eql(u8, trimmed, "disconnect") or std.mem.eql(u8, trimmed, "d")) return .disconnect;
        if (std.mem.eql(u8, trimmed, "reconnect") or std.mem.eql(u8, trimmed, "r")) return .reconnect;
        if (std.mem.eql(u8, trimmed, "stats")) return .stats;
        if (std.mem.eql(u8, trimmed, "config")) return .config;
        if (std.mem.startsWith(u8, trimmed, "set ")) return .set;
        if (std.mem.eql(u8, trimmed, "quit") or std.mem.eql(u8, trimmed, "exit") or std.mem.eql(u8, trimmed, "q")) return .quit;
        if (std.mem.eql(u8, trimmed, "clear") or std.mem.eql(u8, trimmed, "cls")) return .clear;

        return .unknown;
    }
};

// ============================================================================
// Command History
// ============================================================================

pub const CommandHistory = struct {
    entries: std.ArrayListUnmanaged([]const u8),
    allocator: Allocator,
    max_entries: usize,
    current_index: usize,

    const Self = @This();

    pub fn init(allocator: Allocator, max_entries: usize) Self {
        return .{
            .entries = .{},
            .allocator = allocator,
            .max_entries = max_entries,
            .current_index = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry);
        }
        self.entries.deinit(self.allocator);
    }

    pub fn add(self: *Self, command: []const u8) !void {
        // Don't add empty or duplicate consecutive commands
        if (command.len == 0) return;
        if (self.entries.items.len > 0) {
            if (std.mem.eql(u8, self.entries.items[self.entries.items.len - 1], command)) {
                return;
            }
        }

        // Remove oldest if at capacity
        if (self.entries.items.len >= self.max_entries) {
            self.allocator.free(self.entries.items[0]);
            _ = self.entries.orderedRemove(0);
        }

        const copy = try self.allocator.dupe(u8, command);
        try self.entries.append(self.allocator, copy);
        self.current_index = self.entries.items.len;
    }

    pub fn getPrevious(self: *Self) ?[]const u8 {
        if (self.entries.items.len == 0) return null;
        if (self.current_index > 0) {
            self.current_index -= 1;
        }
        return self.entries.items[self.current_index];
    }

    pub fn getNext(self: *Self) ?[]const u8 {
        if (self.entries.items.len == 0) return null;
        if (self.current_index < self.entries.items.len - 1) {
            self.current_index += 1;
            return self.entries.items[self.current_index];
        }
        self.current_index = self.entries.items.len;
        return null;
    }

    pub fn reset(self: *Self) void {
        self.current_index = self.entries.items.len;
    }
};

// ============================================================================
// Shell State
// ============================================================================

pub const ShellState = struct {
    connected: bool = false,
    server: ?[]const u8 = null,
    hub: ?[]const u8 = null,
    username: ?[]const u8 = null,
    device_name: ?[]const u8 = null,
    assigned_ip: ?u32 = null,
};

// ============================================================================
// Interactive Shell
// ============================================================================

pub const Shell = struct {
    allocator: Allocator,
    display_ctx: display.DisplayContext,
    history: CommandHistory,
    state: ShellState,
    running: bool,
    prompt: []const u8,

    // Callbacks for VPN operations
    on_connect: ?*const fn () anyerror!void,
    on_disconnect: ?*const fn () anyerror!void,
    on_reconnect: ?*const fn () anyerror!void,
    on_get_status: ?*const fn () ?display.ConnectionStatus,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .display_ctx = display.DisplayContext.init(),
            .history = CommandHistory.init(allocator, 100),
            .state = .{},
            .running = false,
            .prompt = "vpn> ",
            .on_connect = null,
            .on_disconnect = null,
            .on_reconnect = null,
            .on_get_status = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.history.deinit();
    }

    /// Run the interactive shell
    pub fn run(self: *Self) !void {
        self.running = true;

        self.displayWelcome();

        const stdin = std.fs.File.stdin();
        var line_buf: [1024]u8 = undefined;

        while (self.running) {
            // Display prompt
            self.display_ctx.print("{s}", .{self.prompt});

            // Read line using simple file read
            const bytes_read = stdin.read(&line_buf) catch {
                self.running = false;
                break;
            };

            if (bytes_read == 0) {
                self.running = false;
                break;
            }

            // Find newline
            const line = blk: {
                for (line_buf[0..bytes_read], 0..) |c, i| {
                    if (c == '\n') {
                        break :blk line_buf[0..i];
                    }
                }
                break :blk line_buf[0..bytes_read];
            };

            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;

            // Add to history
            self.history.add(trimmed) catch {};

            // Parse and execute command
            self.executeCommand(trimmed);
        }

        self.display_ctx.newline();
        display.info(&self.display_ctx, "Goodbye!", .{});
    }

    fn executeCommand(self: *Self, input: []const u8) void {
        const cmd = Command.fromString(input);

        switch (cmd) {
            .help => self.cmdHelp(),
            .status => self.cmdStatus(),
            .connect => self.cmdConnect(),
            .disconnect => self.cmdDisconnect(),
            .reconnect => self.cmdReconnect(),
            .stats => self.cmdStats(),
            .config => self.cmdConfig(),
            .set => self.cmdSet(input),
            .quit => self.running = false,
            .clear => self.cmdClear(),
            .unknown => self.cmdUnknown(input),
        }
    }

    fn displayWelcome(self: *Self) void {
        self.display_ctx.hrDouble();
        self.display_ctx.printColored(.bold, "SoftEther VPN Client - Interactive Mode\n", .{});
        self.display_ctx.hrDouble();
        self.display_ctx.print("Type 'help' for available commands.\n", .{});
        self.display_ctx.newline();
    }

    fn cmdHelp(self: *Self) void {
        self.display_ctx.newline();
        self.display_ctx.printColored(.bold, "Available Commands:\n", .{});
        self.display_ctx.hr();
        self.display_ctx.print("  help, ?          Show this help message\n", .{});
        self.display_ctx.print("  status, s        Show connection status\n", .{});
        self.display_ctx.print("  connect, c       Connect to VPN server\n", .{});
        self.display_ctx.print("  disconnect, d    Disconnect from VPN\n", .{});
        self.display_ctx.print("  reconnect, r     Reconnect to VPN\n", .{});
        self.display_ctx.print("  stats            Show traffic statistics\n", .{});
        self.display_ctx.print("  config           Show current configuration\n", .{});
        self.display_ctx.print("  set <key>=<val>  Set configuration value\n", .{});
        self.display_ctx.print("  clear, cls       Clear screen\n", .{});
        self.display_ctx.print("  quit, exit, q    Exit the shell\n", .{});
        self.display_ctx.newline();
    }

    fn cmdStatus(self: *Self) void {
        if (self.on_get_status) |get_status| {
            if (get_status()) |status| {
                display.displayConnectionStatus(&self.display_ctx, &status);
                return;
            }
        }

        // Fallback to basic state
        self.display_ctx.newline();
        if (self.state.connected) {
            display.success(&self.display_ctx, "Connected", .{});
            if (self.state.server) |s| self.display_ctx.print("  Server: {s}\n", .{s});
            if (self.state.hub) |h| self.display_ctx.print("  Hub: {s}\n", .{h});
            if (self.state.device_name) |d| self.display_ctx.print("  Device: {s}\n", .{d});
        } else {
            display.info(&self.display_ctx, "Disconnected", .{});
        }
        self.display_ctx.newline();
    }

    fn cmdConnect(self: *Self) void {
        if (self.state.connected) {
            display.warning(&self.display_ctx, "Already connected", .{});
            return;
        }

        if (self.on_connect) |connect_fn| {
            display.info(&self.display_ctx, "Connecting...", .{});
            connect_fn() catch |err| {
                display.failure(&self.display_ctx, "Connection failed: {}", .{err});
                return;
            };
            self.state.connected = true;
            display.success(&self.display_ctx, "Connected", .{});
        } else {
            display.warning(&self.display_ctx, "No connection handler configured", .{});
        }
    }

    fn cmdDisconnect(self: *Self) void {
        if (!self.state.connected) {
            display.warning(&self.display_ctx, "Not connected", .{});
            return;
        }

        if (self.on_disconnect) |disconnect_fn| {
            display.info(&self.display_ctx, "Disconnecting...", .{});
            disconnect_fn() catch |err| {
                display.failure(&self.display_ctx, "Disconnect failed: {}", .{err});
                return;
            };
            self.state.connected = false;
            display.success(&self.display_ctx, "Disconnected", .{});
        } else {
            display.warning(&self.display_ctx, "No disconnect handler configured", .{});
        }
    }

    fn cmdReconnect(self: *Self) void {
        if (self.on_reconnect) |reconnect_fn| {
            display.info(&self.display_ctx, "Reconnecting...", .{});
            reconnect_fn() catch |err| {
                display.failure(&self.display_ctx, "Reconnect failed: {}", .{err});
                return;
            };
            self.state.connected = true;
            display.success(&self.display_ctx, "Reconnected", .{});
        } else {
            display.warning(&self.display_ctx, "No reconnect handler configured", .{});
        }
    }

    fn cmdStats(self: *Self) void {
        if (self.on_get_status) |get_status| {
            if (get_status()) |status| {
                var sent_buf: [32]u8 = undefined;
                var recv_buf: [32]u8 = undefined;
                var dur_buf: [32]u8 = undefined;

                self.display_ctx.newline();
                self.display_ctx.printColored(.bold, "Traffic Statistics\n", .{});
                self.display_ctx.hr();
                self.display_ctx.print("  Sent:       {s} ({d} packets)\n", .{
                    display.formatBytes(status.bytes_sent, &sent_buf),
                    status.packets_sent,
                });
                self.display_ctx.print("  Received:   {s} ({d} packets)\n", .{
                    display.formatBytes(status.bytes_received, &recv_buf),
                    status.packets_received,
                });
                self.display_ctx.print("  Duration:   {s}\n", .{display.formatDuration(status.connected_duration_ms, &dur_buf)});
                self.display_ctx.newline();
                return;
            }
        }
        display.warning(&self.display_ctx, "Statistics not available", .{});
    }

    fn cmdConfig(self: *Self) void {
        self.display_ctx.newline();
        self.display_ctx.printColored(.bold, "Current Configuration\n", .{});
        self.display_ctx.hr();
        if (self.state.server) |s| self.display_ctx.print("  server = {s}\n", .{s});
        if (self.state.hub) |h| self.display_ctx.print("  hub = {s}\n", .{h});
        if (self.state.username) |u| self.display_ctx.print("  username = {s}\n", .{u});
        self.display_ctx.newline();
    }

    fn cmdSet(self: *Self, input: []const u8) void {
        // Parse "set key=value"
        const set_part = input[4..]; // Skip "set "
        const eq_idx = std.mem.indexOf(u8, set_part, "=") orelse {
            display.failure(&self.display_ctx, "Usage: set <key>=<value>", .{});
            return;
        };

        const key = std.mem.trim(u8, set_part[0..eq_idx], " ");
        const value = std.mem.trim(u8, set_part[eq_idx + 1 ..], " ");

        if (key.len == 0 or value.len == 0) {
            display.failure(&self.display_ctx, "Usage: set <key>=<value>", .{});
            return;
        }

        // Handle known keys
        if (std.mem.eql(u8, key, "server")) {
            self.state.server = value;
            display.success(&self.display_ctx, "Set server = {s}", .{value});
        } else if (std.mem.eql(u8, key, "hub")) {
            self.state.hub = value;
            display.success(&self.display_ctx, "Set hub = {s}", .{value});
        } else if (std.mem.eql(u8, key, "username")) {
            self.state.username = value;
            display.success(&self.display_ctx, "Set username = {s}", .{value});
        } else {
            display.warning(&self.display_ctx, "Unknown key: {s}", .{key});
        }
    }

    fn cmdClear(self: *Self) void {
        // ANSI escape to clear screen and move cursor to top
        self.display_ctx.print("\x1b[2J\x1b[H", .{});
    }

    fn cmdUnknown(self: *Self, input: []const u8) void {
        display.warning(&self.display_ctx, "Unknown command: {s}", .{input});
        self.display_ctx.print("Type 'help' for available commands.\n", .{});
    }

    /// Update state from external source
    pub fn updateState(self: *Self, connected: bool, server: ?[]const u8, hub: ?[]const u8) void {
        self.state.connected = connected;
        self.state.server = server;
        self.state.hub = hub;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Command fromString" {
    try std.testing.expectEqual(Command.help, Command.fromString("help"));
    try std.testing.expectEqual(Command.help, Command.fromString("?"));
    try std.testing.expectEqual(Command.status, Command.fromString("status"));
    try std.testing.expectEqual(Command.status, Command.fromString("s"));
    try std.testing.expectEqual(Command.connect, Command.fromString("connect"));
    try std.testing.expectEqual(Command.quit, Command.fromString("quit"));
    try std.testing.expectEqual(Command.quit, Command.fromString("exit"));
    try std.testing.expectEqual(Command.set, Command.fromString("set foo=bar"));
    try std.testing.expectEqual(Command.unknown, Command.fromString("invalid"));
    try std.testing.expectEqual(Command.unknown, Command.fromString(""));
}

test "CommandHistory add and retrieve" {
    var history = CommandHistory.init(std.testing.allocator, 10);
    defer history.deinit();

    try history.add("command1");
    try history.add("command2");
    try history.add("command3");

    try std.testing.expectEqualStrings("command3", history.getPrevious().?);
    try std.testing.expectEqualStrings("command2", history.getPrevious().?);
    try std.testing.expectEqualStrings("command1", history.getPrevious().?);
}

test "CommandHistory no duplicate consecutive" {
    var history = CommandHistory.init(std.testing.allocator, 10);
    defer history.deinit();

    try history.add("same");
    try history.add("same");
    try history.add("same");

    try std.testing.expectEqual(@as(usize, 1), history.entries.items.len);
}

test "CommandHistory max entries" {
    var history = CommandHistory.init(std.testing.allocator, 3);
    defer history.deinit();

    try history.add("cmd1");
    try history.add("cmd2");
    try history.add("cmd3");
    try history.add("cmd4"); // Should evict cmd1

    try std.testing.expectEqual(@as(usize, 3), history.entries.items.len);
    try std.testing.expectEqualStrings("cmd2", history.entries.items[0]);
}

test "CommandHistory getNext" {
    var history = CommandHistory.init(std.testing.allocator, 10);
    defer history.deinit();

    try history.add("cmd1");
    try history.add("cmd2");

    _ = history.getPrevious(); // cmd2
    _ = history.getPrevious(); // cmd1

    try std.testing.expectEqualStrings("cmd2", history.getNext().?);
}

test "Shell init" {
    var shell = Shell.init(std.testing.allocator);
    defer shell.deinit();

    try std.testing.expect(!shell.running);
    try std.testing.expect(!shell.state.connected);
}

test "ShellState defaults" {
    const state = ShellState{};
    try std.testing.expect(!state.connected);
    try std.testing.expect(state.server == null);
}
