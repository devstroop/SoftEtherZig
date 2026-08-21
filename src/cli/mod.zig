//! CLI Module
//!
//! Command-line interface
//! Provides argument parsing, configuration management, interactive shell,
//! and display utilities.

const std = @import("std");

pub const args = @import("args.zig");
pub const display = @import("display.zig");
pub const config_manager = @import("config_manager.zig");
pub const shell = @import("shell.zig");

// Re-export main types
pub const ArgParser = args.ArgParser;
pub const CliArgs = args.CliArgs;
pub const LogLevel = args.LogLevel;
pub const ParseError = args.ParseError;

pub const DisplayContext = display.DisplayContext;
pub const Color = display.Color;
pub const Icon = display.Icon;
pub const ProgressBar = display.ProgressBar;
pub const ConnectionStatus = display.ConnectionStatus;
pub const Spinner = display.Spinner;

pub const ConfigManager = config_manager.ConfigManager;
pub const ConfigFile = config_manager.ConfigFile;
pub const ReconnectConfig = config_manager.ReconnectConfig;
pub const StaticIpConfig = config_manager.StaticIpConfig;

pub const Shell = shell.Shell;
pub const Command = shell.Command;
pub const CommandHistory = shell.CommandHistory;

// ============================================================================
// Convenience Functions
// ============================================================================

/// Parse command line arguments
pub fn parseArgs(allocator: std.mem.Allocator, argv: []const []const u8) !CliArgs {
    var parser = ArgParser.init(allocator);
    defer parser.deinit();

    // Load environment variables first
    parser.loadFromEnv();

    // Parse CLI args (override env vars)
    return try parser.parse(argv);
}

/// Returns true if the given path is a readable regular file.
fn isFile(path: []const u8) bool {
    const st = std.fs.cwd().statFile(path) catch return false;
    return st.kind == .file;
}

/// Load configuration with priority: CLI > env > vpncmd store (M21 #261)
/// M21 #261: vpnclient no longer auto-loads host `config.json`; profile is owned by
/// `vpncmd` (XDG `vpn_client.config` Cfg binary, no external files). Host file
/// surface is eliminated for vpnclient — flags/env are the only inputs (12-field
/// connect matrix). `vpn_server.config` (Cedar Cfg) remains for vpnserver.
pub fn loadConfig(allocator: std.mem.Allocator, cli_args: *CliArgs) !void {
    _ = allocator;
    _ = cli_args;
    // No-op for vpnclient — deliberately ignore ./config.json and
    // ~/.config/softether-zig/config.json even if present (M21 breaking).
    // Explicit --config is hidden deprecated and also ignored to enforce
    // the 12-field flags/env contract; vpncmd owns the store from M21-2.
    return;
}

/// Display usage information
pub fn showUsage(version: []const u8) void {
    var ctx = DisplayContext.init();
    display.displayUsage(&ctx, version);
}

/// Display version information
pub fn showVersion(version: []const u8) void {
    var ctx = DisplayContext.init();
    display.displayVersion(&ctx, version);
}

/// Run interactive shell
pub fn runInteractiveShell(allocator: std.mem.Allocator) !void {
    var sh = Shell.init(allocator);
    defer sh.deinit();
    try sh.run();
}

// ============================================================================
// Tests
// ============================================================================

test "parseArgs simple" {
    const argv = [_][]const u8{ "vpnclient", "-h" };
    var parsed_args = try parseArgs(std.testing.allocator, &argv);
    defer parsed_args.deinit();

    try std.testing.expect(parsed_args.help);
}

test "parseArgs address" {
    const argv = [_][]const u8{ "vpnclient", "-a", "192.168.1.1", "-H", "VPN" };
    var parsed_args = try parseArgs(std.testing.allocator, &argv);
    defer parsed_args.deinit();

    try std.testing.expectEqualStrings("192.168.1.1", parsed_args.address.?);
    try std.testing.expectEqualStrings("VPN", parsed_args.hub.?);
}

test "parseArgs address and hostname" {
    const argv = [_][]const u8{ "vpnclient", "-a", "1.2.3.4", "--hostname", "vpn.example.com", "-H", "VPN" };
    var parsed_args = try parseArgs(std.testing.allocator, &argv);
    defer parsed_args.deinit();

    try std.testing.expectEqualStrings("1.2.3.4", parsed_args.address.?);
    try std.testing.expectEqualStrings("vpn.example.com", parsed_args.hostname.?);
    try std.testing.expectEqualStrings("VPN", parsed_args.hub.?);
}

test "parseArgs address long form" {
    const argv = [_][]const u8{ "vpnclient", "--address", "10.0.0.1", "--port", "8443" };
    var parsed_args = try parseArgs(std.testing.allocator, &argv);
    defer parsed_args.deinit();

    try std.testing.expectEqualStrings("10.0.0.1", parsed_args.address.?);
    try std.testing.expectEqual(@as(u16, 8443), parsed_args.port);
}

test "module imports" {
    // Verify all modules are accessible
    _ = ArgParser;
    _ = DisplayContext;
    _ = ConfigManager;
    _ = Shell;
}

// Import all submodule tests
test {
    std.testing.refAllDecls(@This());
    _ = args;
    _ = display;
    _ = config_manager;
    _ = shell;
}
