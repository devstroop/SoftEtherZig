//! Compatibility shim for std.process.getEnvVarOwned removed in Zig 0.16.
//!
//! Uses std.posix.getenv (returns a borrowed pointer valid for the process
//! lifetime) and duplicates the value so the caller owns it.

const std = @import("std");

/// Get an environment variable as an owned, null-terminated string.
/// Returns null if the variable is not set.
/// Caller owns the returned memory; free with allocator.free().
pub fn getEnvOwned(allocator: std.mem.Allocator, name: [:0]const u8) !?[:0]u8 {
    const v = std.posix.getenv(name) orelse return null;
    return try allocator.dupeZ(u8, v);
}

/// Get an environment variable as an owned `[]u8`.
/// Returns null if the variable is not set.
pub fn getEnvOwnedSlice(allocator: std.mem.Allocator, name: [:0]const u8) !?[]u8 {
    const v = std.posix.getenv(name) orelse return null;
    return try allocator.dupe(u8, v);
}

/// Check if an environment variable is set to a truthy value.
/// Returns false if the variable is not set or can't be read.
pub fn getEnvBool(allocator: std.mem.Allocator, name: [:0]const u8) bool {
    const v = std.posix.getenv(name) orelse return false;
    return std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true") or std.mem.eql(u8, v, "yes");
}
