const std = @import("std");

pub fn main() !void {
    // Test different ways to create empty signal set
    const sigset = std.posix.empty_sigset orelse std.mem.zeroes(std.posix.sigset_t);
    _ = sigset;
}
