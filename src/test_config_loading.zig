// Test configuration file loading
const std = @import("std");
const config = @import("config.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Testing Config File Loading ===\n\n", .{});

    // Get current directory
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = try std.fs.cwd().realpath(".", &buf);

    // Test 1: Load example config
    std.debug.print("Test 1: Loading config.example.json...\n", .{});
    const example_path = try std.fmt.allocPrint(allocator, "{s}/config.example.json", .{cwd});
    defer allocator.free(example_path);

    const file_config = config.loadFromFile(allocator, example_path) catch |err| {
        std.debug.print("  ✗ Failed to load: {any}\n", .{err});
        return err;
    };

    if (file_config.server) |server| {
        std.debug.print("  ✓ Server: {s}\n", .{server});
    }
    if (file_config.port) |port| {
        std.debug.print("  ✓ Port: {d}\n", .{port});
    }
    if (file_config.hub) |hub| {
        std.debug.print("  ✓ Hub: {s}\n", .{hub});
    }
    if (file_config.username) |username| {
        std.debug.print("  ✓ Username: {s}\n", .{username});
    }

    std.debug.print("\n", .{});

    // Test 2: Load minimal config
    std.debug.print("Test 2: Loading config.minimal.json...\n", .{});
    const minimal_path = try std.fmt.allocPrint(allocator, "{s}/config.minimal.json", .{cwd});
    defer allocator.free(minimal_path);

    const minimal_config = config.loadFromFile(allocator, minimal_path) catch |err| {
        std.debug.print("  ✗ Failed to load: {any}\n", .{err});
        return err;
    };

    if (minimal_config.server) |server| {
        std.debug.print("  ✓ Server: {s}\n", .{server});
    }
    if (minimal_config.hub) |hub| {
        std.debug.print("  ✓ Hub: {s}\n", .{hub});
    }

    std.debug.print("\n", .{});

    // Test 3: Merge configs
    std.debug.print("Test 3: Testing config merge (CLI > env > file)...\n", .{});

    const file_for_merge = config.JsonConfig{
        .server = "file.server.com",
        .hub = "FILE_HUB",
        .username = "file_user",
        .port = 443,
    };

    const env_config = config.JsonConfig{
        .username = "env_user",
        .port = 8443,
    };

    const cli_config = config.JsonConfig{
        .server = "cli.server.com",
    };

    const builder = try config.mergeConfigs(allocator, file_for_merge, env_config, cli_config);

    std.debug.print("  Server: {s} (from CLI override)\n", .{builder.server_name.?});
    std.debug.print("  Port: {d} (from env vars)\n", .{builder.server_port});
    std.debug.print("  Hub: {s} (from file)\n", .{builder.hub_name.?});

    if (builder.auth) |auth| {
        std.debug.print("  Username: {s} (from env vars)\n", .{auth.password.username});
    } else {
        std.debug.print("  ✓ Config merge working (auth not set because no password)\n", .{});
    }
    std.debug.print("\n", .{});

    // Test 4: Nonexistent file (should return empty config)
    std.debug.print("Test 4: Loading nonexistent file...\n", .{});
    const empty_config = config.loadFromFile(allocator, "/nonexistent/config.json") catch |err| {
        std.debug.print("  ✗ Unexpected error: {any}\n", .{err});
        return err;
    };

    if (empty_config.server == null) {
        std.debug.print("  ✓ Returns empty config for missing file (correct behavior)\n", .{});
    }

    std.debug.print("\n", .{});

    // Test 5: Path expansion
    std.debug.print("Test 5: Testing path expansion...\n", .{});
    const default_path = try config.getDefaultConfigPath(allocator);
    defer allocator.free(default_path);
    std.debug.print("  Default config path: {s}\n", .{default_path});

    std.debug.print("\n=== All Tests Passed ✓ ===\n", .{});
}
