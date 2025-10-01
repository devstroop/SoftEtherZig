const std = @import("std");
const softether = @import("softether");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // Print library version
    const version = try softether.versionString(allocator);
    defer allocator.free(version);
    try stdout.print("SoftEther VPN Zig Library v{s}\n", .{version});
    try stdout.print("==========================================\n\n", .{});

    // Initialize VPN client
    try stdout.print("Initializing VPN client...\n", .{});
    var client = softether.VpnClient.init(allocator) catch |err| {
        try stdout.print("Failed to initialize client: {}\n", .{err});
        return err;
    };
    defer client.deinit();
    try stdout.print("✓ Client initialized successfully\n\n", .{});

    // Build configuration
    try stdout.print("Building connection configuration...\n", .{});
    const config = softether.ConnectionConfig.builder()
        .setServer("vpn.example.com", 443)
        .setHub("DEFAULT")
        .setAccount("test_user")
        .setAuth(.anonymous)
        .setEncrypt(true)
        .setCompress(true)
        .build() catch |err| {
        try stdout.print("Failed to build configuration: {}\n", .{err});
        return err;
    };
    try stdout.print("✓ Configuration built successfully\n", .{});
    try stdout.print("  Server: {s}:{d}\n", .{ config.server_name, config.server_port });
    try stdout.print("  Hub: {s}\n", .{config.hub_name});
    try stdout.print("  Account: {s}\n\n", .{config.account_name});

    // Check status
    try stdout.print("Checking connection status...\n", .{});
    const status = client.getStatus();
    try stdout.print("✓ Current status: {s}\n\n", .{@tagName(status)});

    // Note: Actual connection not implemented yet (Phase 3)
    try stdout.print("Note: Full connection implementation coming in Phase 3\n", .{});
    try stdout.print("This example demonstrates initialization and configuration only.\n", .{});

    try stdout.print("\n✓ Example completed successfully\n", .{});
}
