//! Compatibility shim for std.process.getEnvVarOwned removed in Zig 0.16.
//!
//! Uses std.c.getenv (returns a borrowed pointer valid for the process
//! lifetime) and duplicates the value so the caller owns it.

const std = @import("std");

/// Get an environment variable as an owned, null-terminated string.
/// Returns null if the variable is not set.
/// Caller owns the returned memory; free with allocator.free().
pub fn getEnvOwned(allocator: std.mem.Allocator, name: [:0]const u8) !?[:0]u8 {
    const v = std.c.getenv(name) orelse return null;
    const s = std.mem.sliceTo(v, 0);
    return try allocator.dupeZ(u8, s);
}

/// Get an environment variable as an owned `[]u8`.
/// Returns the value, or an error if not set.
pub fn getEnvOwnedSlice(allocator: std.mem.Allocator, name: [:0]const u8) ![]u8 {
    const v = std.c.getenv(name) orelse return error.EnvironmentVariableNotFound;
    const s = std.mem.sliceTo(v, 0);
    return try allocator.dupe(u8, s);
}

/// Check if an environment variable is set to a truthy value.
/// Returns false if the variable is not set or can't be read.
pub fn getEnvBool(allocator: std.mem.Allocator, name: [:0]const u8) bool {
    _ = allocator;
    const v = std.c.getenv(name) orelse return false;
    const s = std.mem.sliceTo(v, 0);
    return std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "true") or std.mem.eql(u8, s, "yes");
}
