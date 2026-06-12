//! Compatibility shim for std.crypto.random.bytes() removed in Zig 0.16.
//!
//! Provides a simple cross-platform random byte generator. Not
//! cryptographically secure — suitable only for collision-resistant IDs
//! like DHCP transaction IDs.

const std = @import("std");

/// Fill `buf` with random bytes derived from a per-call counter and a
/// fixed secret. NOT cryptographically secure.
pub fn bytes(buf: []u8) void {
    var counter: u64 = 0;
    const ptr = &counter;
    _ = .{ptr}; // suppress unused

    // Use a global state initialized once from time + ASLR
    const global = struct {
        var prng: std.Random.DefaultPrng = undefined;
        var initialized: bool = false;
    };

    if (!@atomicLoad(bool, &global.initialized, .acquire)) {
        @branchHint(.unlikely);
        // Seed from monotonic timer if available, else ASLR address
        const seed: u64 = @intFromPtr(&global);
        global.prng = std.Random.DefaultPrng.init(seed);
        @atomicStore(bool, &global.initialized, true, .release);
    }

    var prng = global.prng; // copy the state
    prng.fill(buf);
    global.prng = prng; // write back updated state
}
