//! CLI Display Module
//!
//! Phase 8: Status display, formatting, and progress indicators
//!
//! Compatible with Zig 0.15.2 I/O API

const std = @import("std");
const Allocator = std.mem.Allocator;
const File = std.fs.File;

// ============================================================================
// ANSI Color Codes
// ============================================================================

pub const Color = enum {
    reset,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bold,
    dim,

    pub fn code(self: Color) []const u8 {
        return switch (self) {
            .reset => "\x1b[0m",
            .red => "\x1b[31m",
            .green => "\x1b[32m",
            .yellow => "\x1b[33m",
            .blue => "\x1b[34m",
            .magenta => "\x1b[35m",
            .cyan => "\x1b[36m",
            .white => "\x1b[37m",
            .bold => "\x1b[1m",
            .dim => "\x1b[2m",
        };
    }
};

// ============================================================================
// Status Icons
// ============================================================================

pub const Icon = struct {
    pub const success = "✓";
    pub const failure = "✗";
    pub const warning = "⚠";
    pub const info = "●";
    pub const arrow = "→";
    pub const bullet = "•";
    pub const spinner = [_][]const u8{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
};

// ============================================================================
// Display Context
// ============================================================================

pub const DisplayContext = struct {
    file: ?File,
    use_color: bool,
    use_unicode: bool,
    verbose: bool,
    quiet: bool,

    const Self = @This();

    pub fn init() Self {
        const stdout = std.fs.File.stdout();
        // Check if stdout is a valid TTY
        const use_color = if (stdout.isTty()) stdout.getOrEnableAnsiEscapeSupport() else false;

        return .{
            .file = stdout,
            .use_color = use_color,
            .use_unicode = true,
            .verbose = false,
            .quiet = false,
        };
    }

    pub fn initWithOptions(use_color: bool, use_unicode: bool) Self {
        return .{
            .file = std.fs.File.stdout(),
            .use_color = use_color,
            .use_unicode = use_unicode,
            .verbose = false,
            .quiet = false,
        };
    }

    /// Create a null display that discards all output (for daemon mode)
    pub fn initNull() Self {
        return .{
            .file = null,
            .use_color = false,
            .use_unicode = false,
            .verbose = false,
            .quiet = true,
        };
    }

    fn colorCode(self: *const Self, color: Color) []const u8 {
        if (!self.use_color) return "";
        return color.code();
    }

    /// Write formatted output to stdout
    pub fn print(self: *Self, comptime fmt: []const u8, args: anytype) void {
        const file = self.file orelse return;
        var buf: [4096]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, fmt, args) catch return;
        file.writeAll(str) catch {};
    }

    pub fn printColored(self: *Self, color: Color, comptime fmt: []const u8, args: anytype) void {
        const file = self.file orelse return;
        var buf: [4096]u8 = undefined;
        const color_str = self.colorCode(color);
        const reset_str = self.colorCode(.reset);
        const content = std.fmt.bufPrint(&buf, fmt, args) catch return;

        file.writeAll(color_str) catch {};
        file.writeAll(content) catch {};
        file.writeAll(reset_str) catch {};
    }

    pub fn newline(self: *Self) void {
        const file = self.file orelse return;
        file.writeAll("\n") catch {};
    }

    pub fn hr(self: *Self) void {
        self.print("─────────────────────────────────────────────\n", .{});
    }

    pub fn hrDouble(self: *Self) void {
        self.print("═══════════════════════════════════════════════\n", .{});
    }
};

// ============================================================================
// Message Types
// ============================================================================

pub fn success(ctx: *DisplayContext, comptime fmt: []const u8, args: anytype) void {
    if (ctx.quiet) return;
    ctx.printColored(.green, "[{s}] ", .{Icon.success});
    ctx.print(fmt, args);
    ctx.newline();
}

pub fn failure(ctx: *DisplayContext, comptime fmt: []const u8, args: anytype) void {
    ctx.printColored(.red, "[{s}] ", .{Icon.failure});
    ctx.print(fmt, args);
    ctx.newline();
}

pub fn warning(ctx: *DisplayContext, comptime fmt: []const u8, args: anytype) void {
    if (ctx.quiet) return;
    ctx.printColored(.yellow, "[{s}] ", .{Icon.warning});
    ctx.print(fmt, args);
    ctx.newline();
}

pub fn info(ctx: *DisplayContext, comptime fmt: []const u8, args: anytype) void {
    if (ctx.quiet) return;
    ctx.printColored(.cyan, "[{s}] ", .{Icon.info});
    ctx.print(fmt, args);
    ctx.newline();
}

pub fn debug(ctx: *DisplayContext, comptime fmt: []const u8, args: anytype) void {
    if (!ctx.verbose) return;
    ctx.printColored(.dim, "[DEBUG] ", .{});
    ctx.print(fmt, args);
    ctx.newline();
}

// ============================================================================
// Formatters
// ============================================================================

/// Format bytes as human-readable string
pub fn formatBytes(bytes: u64, buffer: []u8) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var value: f64 = @floatFromInt(bytes);
    var unit_idx: usize = 0;

    while (value >= 1024.0 and unit_idx < units.len - 1) {
        value /= 1024.0;
        unit_idx += 1;
    }

    if (unit_idx == 0) {
        return std.fmt.bufPrint(buffer, "{d} {s}", .{ bytes, units[0] }) catch "";
    } else {
        return std.fmt.bufPrint(buffer, "{d:.2} {s}", .{ value, units[unit_idx] }) catch "";
    }
}

/// Format duration as human-readable string
pub fn formatDuration(ms: u64, buffer: []u8) []const u8 {
    if (ms < 1000) {
        return std.fmt.bufPrint(buffer, "{d}ms", .{ms}) catch "";
    }

    const secs = ms / 1000;
    if (secs < 60) {
        return std.fmt.bufPrint(buffer, "{d}s", .{secs}) catch "";
    }

    const mins = secs / 60;
    const remaining_secs = secs % 60;
    if (mins < 60) {
        return std.fmt.bufPrint(buffer, "{d}m {d}s", .{ mins, remaining_secs }) catch "";
    }

    const hours = mins / 60;
    const remaining_mins = mins % 60;
    return std.fmt.bufPrint(buffer, "{d}h {d}m", .{ hours, remaining_mins }) catch "";
}

/// Format IPv4 address
pub fn formatIpv4(ip: u32, buffer: []u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    }) catch "";
}

/// Format MAC address
pub fn formatMac(mac: [6]u8, buffer: []u8) []const u8 {
    return std.fmt.bufPrint(buffer, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch "";
}

// ============================================================================
// Progress Bar
// ============================================================================

pub const ProgressBar = struct {
    width: usize,
    filled_char: u8,
    empty_char: u8,

    pub fn init() ProgressBar {
        return .{
            .width = 40,
            .filled_char = '=',
            .empty_char = '-',
        };
    }

    pub fn render(self: *const ProgressBar, progress: f64, buffer: []u8) []const u8 {
        const clamped = @min(@max(progress, 0.0), 1.0);
        const filled: usize = @intFromFloat(clamped * @as(f64, @floatFromInt(self.width)));
        const percent: u8 = @intFromFloat(clamped * 100.0);

        var pos: usize = 0;
        buffer[pos] = '[';
        pos += 1;

        for (0..self.width) |i| {
            if (pos >= buffer.len - 10) break;
            buffer[pos] = if (i < filled) self.filled_char else self.empty_char;
            pos += 1;
        }

        buffer[pos] = ']';
        pos += 1;
        buffer[pos] = ' ';
        pos += 1;

        const percent_str = std.fmt.bufPrint(buffer[pos..], "{d}%", .{percent}) catch "";
        pos += percent_str.len;

        return buffer[0..pos];
    }
};

// ============================================================================
// Connection Status Display
// ============================================================================

pub const ConnectionStatus = struct {
    state: []const u8,
    server: []const u8,
    port: u16,
    hub: []const u8,
    device_name: []const u8,
    assigned_ip: ?u32,
    gateway_ip: ?u32,
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    connected_duration_ms: u64,
    reconnect_count: u32,
};

pub fn displayConnectionStatus(ctx: *DisplayContext, status: *const ConnectionStatus) void {
    var ip_buf: [16]u8 = undefined;
    var gw_buf: [16]u8 = undefined;
    var sent_buf: [32]u8 = undefined;
    var recv_buf: [32]u8 = undefined;
    var dur_buf: [32]u8 = undefined;

    ctx.hrDouble();
    ctx.printColored(.bold, "VPN Connection Status\n", .{});
    ctx.hrDouble();
    ctx.newline();

    ctx.print("  State:        ", .{});
    if (std.mem.eql(u8, status.state, "connected")) {
        ctx.printColored(.green, "{s}\n", .{status.state});
    } else if (std.mem.eql(u8, status.state, "disconnected")) {
        ctx.printColored(.red, "{s}\n", .{status.state});
    } else {
        ctx.printColored(.yellow, "{s}\n", .{status.state});
    }

    ctx.print("  Server:       {s}:{d}\n", .{ status.server, status.port });
    ctx.print("  Hub:          {s}\n", .{status.hub});
    ctx.print("  Device:       {s}\n", .{status.device_name});

    if (status.assigned_ip) |ip| {
        ctx.print("  Assigned IP:  {s}\n", .{formatIpv4(ip, &ip_buf)});
    }
    if (status.gateway_ip) |gw| {
        ctx.print("  Gateway:      {s}\n", .{formatIpv4(gw, &gw_buf)});
    }

    ctx.newline();
    ctx.print("  Traffic:\n", .{});
    ctx.print("    Sent:       {s} ({d} packets)\n", .{ formatBytes(status.bytes_sent, &sent_buf), status.packets_sent });
    ctx.print("    Received:   {s} ({d} packets)\n", .{ formatBytes(status.bytes_received, &recv_buf), status.packets_received });
    ctx.print("    Duration:   {s}\n", .{formatDuration(status.connected_duration_ms, &dur_buf)});

    if (status.reconnect_count > 0) {
        ctx.print("    Reconnects: {d}\n", .{status.reconnect_count});
    }

    ctx.newline();
    ctx.hr();
}

// ============================================================================
// Usage Display
// ============================================================================

pub fn displayUsage(ctx: *DisplayContext, version: []const u8) void {
    ctx.printColored(.bold, "SoftEther VPN Client v{s}\n", .{version});
    ctx.newline();

    ctx.printColored(.bold, "USAGE:\n", .{});
    ctx.print("    vpnclient [OPTIONS]\n", .{});
    ctx.print("    vpnclient --gen-hash <USERNAME> <PASSWORD>\n", .{});
    ctx.newline();

    ctx.printColored(.bold, "OPTIONS:\n", .{});
    ctx.print("    -h, --help              Show this help message\n", .{});
    ctx.print("    -v, --version           Show version information\n", .{});
    ctx.print("    -c, --config <FILE>     Load configuration from JSON file\n", .{});
    ctx.print("    -s, --server <HOST>     VPN server hostname (required)\n", .{});
    ctx.print("    -p, --port <PORT>       VPN server port (default: 443)\n", .{});
    ctx.print("    -H, --hub <HUB>         Virtual hub name (required)\n", .{});
    ctx.print("    -u, --user <USERNAME>   Username for authentication\n", .{});
    ctx.print("    -P, --password <PASS>   Password for authentication\n", .{});
    ctx.print("    --password-hash <HASH>  Pre-hashed password (base64)\n", .{});
    ctx.print("    -i, --interactive       Run in interactive shell mode\n", .{});
    ctx.print("    -d, --daemon            Run as daemon (background)\n", .{});
    ctx.print("    --log-level <LEVEL>     Log level: silent, error, warn, info, debug, trace\n", .{});
    ctx.newline();

    ctx.printColored(.bold, "RECONNECTION OPTIONS:\n", .{});
    ctx.print("    --reconnect             Enable automatic reconnection (default)\n", .{});
    ctx.print("    --no-reconnect          Disable automatic reconnection\n", .{});
    ctx.print("    --max-retries <N>       Maximum attempts, 0=infinite (default: 0)\n", .{});
    ctx.print("    --min-backoff <SEC>     Minimum backoff delay (default: 5)\n", .{});
    ctx.print("    --max-backoff <SEC>     Maximum backoff delay (default: 300)\n", .{});
    ctx.newline();

    ctx.printColored(.bold, "EXAMPLES:\n", .{});
    ctx.print("    vpnclient --config config.json\n", .{});
    ctx.print("    vpnclient -s vpn.example.com -H VPN -u user -P pass\n", .{});
    ctx.print("    vpnclient --gen-hash myuser mypassword\n", .{});
    ctx.newline();
}

pub fn displayVersion(ctx: *DisplayContext, version: []const u8) void {
    ctx.print("SoftEther VPN Client v{s}\n", .{version});
    ctx.print("Zig implementation\n", .{});
    ctx.print("Based on SoftEther VPN protocol\n", .{});
}

// ============================================================================
// Spinner
// ============================================================================

pub const Spinner = struct {
    frame: usize,
    message: []const u8,

    pub fn init(message: []const u8) Spinner {
        return .{
            .frame = 0,
            .message = message,
        };
    }

    pub fn tick(self: *Spinner) []const u8 {
        self.frame = (self.frame + 1) % Icon.spinner.len;
        return Icon.spinner[self.frame];
    }

    pub fn render(self: *Spinner, ctx: *DisplayContext) void {
        ctx.print("\r{s} {s}", .{ self.tick(), self.message });
    }

    pub fn finish(self: *Spinner, ctx: *DisplayContext, ok: bool) void {
        _ = self;
        const icon = if (ok) Icon.success else Icon.failure;
        ctx.print("\r{s}  \n", .{icon});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "formatBytes" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("0 B", formatBytes(0, &buf));
    try std.testing.expectEqualStrings("512 B", formatBytes(512, &buf));
    try std.testing.expectEqualStrings("1.00 KB", formatBytes(1024, &buf));
    try std.testing.expectEqualStrings("1.50 MB", formatBytes(1024 * 1024 + 512 * 1024, &buf));
}

test "formatDuration" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("500ms", formatDuration(500, &buf));
    try std.testing.expectEqualStrings("30s", formatDuration(30000, &buf));
    try std.testing.expectEqualStrings("2m 30s", formatDuration(150000, &buf));
    try std.testing.expectEqualStrings("1h 30m", formatDuration(5400000, &buf));
}

test "formatIpv4" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("192.168.1.1", formatIpv4(0xC0A80101, &buf));
    try std.testing.expectEqualStrings("127.0.0.1", formatIpv4(0x7F000001, &buf));
}

test "formatMac" {
    var buf: [18]u8 = undefined;
    const mac = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    try std.testing.expectEqualStrings("AA:BB:CC:DD:EE:FF", formatMac(mac, &buf));
}

test "ProgressBar render" {
    var buf: [64]u8 = undefined;
    const bar = ProgressBar.init();

    const result50 = bar.render(0.5, &buf);
    try std.testing.expect(std.mem.indexOf(u8, result50, "50%") != null);

    const result100 = bar.render(1.0, &buf);
    try std.testing.expect(std.mem.indexOf(u8, result100, "100%") != null);
}

test "Color code" {
    try std.testing.expectEqualStrings("\x1b[32m", Color.green.code());
    try std.testing.expectEqualStrings("\x1b[0m", Color.reset.code());
}

test "Spinner tick" {
    var spinner = Spinner.init("Loading...");
    const frame1 = spinner.tick();
    const frame2 = spinner.tick();
    try std.testing.expect(!std.mem.eql(u8, frame1, frame2));
}

test "DisplayContext init" {
    const ctx = DisplayContext.initWithOptions(false, true);
    try std.testing.expect(!ctx.use_color);
    try std.testing.expect(ctx.use_unicode);
}
