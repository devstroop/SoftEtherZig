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

/// Load configuration with priority: CLI > env > config file
pub fn loadConfig(allocator: std.mem.Allocator, cli_args: *CliArgs) !void {
    // Determine config path
    const config_path = cli_args.config_file orelse blk: {
        if (ConfigManager.defaultConfigExists()) {
            break :blk try ConfigManager.getDefaultPath(allocator);
        }
        break :blk null;
    };

    if (config_path) |path| {
        var mgr = ConfigManager.init(allocator);
        defer mgr.deinit();

        mgr.loadFromFile(path) catch |err| {
            // Config file errors are warnings, not fatal
            var ctx = DisplayContext.init();
            display.warning(&ctx, "Could not load config file: {}", .{err});
            return;
        };

        // Merge with CLI args
        mgr.mergeWithArgs(cli_args);
    }
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

test "parseArgs server" {
    const argv = [_][]const u8{ "vpnclient", "-s", "test.com", "-H", "VPN" };
    var parsed_args = try parseArgs(std.testing.allocator, &argv);
    defer parsed_args.deinit();

    try std.testing.expectEqualStrings("test.com", parsed_args.server.?);
    try std.testing.expectEqualStrings("VPN", parsed_args.hub.?);
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
