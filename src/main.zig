const std = @import("std");

// Re-export all public modules
pub const c = @import("c.zig");
pub const errors = @import("errors.zig");
pub const types = @import("types.zig");
pub const client = @import("client.zig");
pub const config = @import("config.zig");

// Re-export commonly used types
pub const VpnClient = client.VpnClient;
pub const ConnectionConfig = config.ConnectionConfig;
pub const AuthMethod = config.AuthMethod;
pub const VpnError = errors.VpnError;

/// Library version information
pub const version = .{
    .major = 0,
    .minor = 1,
    .patch = 0,
    .suffix = "dev",
};

/// Get the library version as a string
pub fn versionString(allocator: std.mem.Allocator) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "{d}.{d}.{d}-{s}",
        .{ version.major, version.minor, version.patch, version.suffix },
    );
}

test "version string" {
    const allocator = std.testing.allocator;
    const ver = try versionString(allocator);
    defer allocator.free(ver);
    
    try std.testing.expectEqualStrings("0.1.0-dev", ver);
}
