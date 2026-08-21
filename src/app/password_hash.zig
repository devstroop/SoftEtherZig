//! Password Hash Generator
//!
//! Generates SoftEther-compatible password hashes.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const crypto = @import("../mayaqua/encrypt/crypto.zig");

/// Generate a SoftEther password hash and print it
pub fn generate(user: []const u8, pass: []const u8) void {
    var ctx = cli.DisplayContext.init();

    // SoftEther password hash: SHA-0(password + UPPERCASE(username))
    // See: SoftEtherVPN/src/Cedar/Account.c HashPassword()
    ctx.print("\n", .{});
    cli.display.info(&ctx, "Password Hash Generator", .{});
    ctx.print("Username: {s}\n", .{user});
    ctx.print("Password: [hidden]\n", .{});

    // Generate hash using SHA-0 (SoftEther compatibility)
    // SoftEther format: SHA0(password + UPPERCASE(username))
    // Use streaming hasher to support arbitrary-length credentials — previous
    // code truncated to 256B each, but server hashes full slices.
    var hasher = crypto.sha0.Sha0.init();
    hasher.update(pass);
    // Stream uppercased username without truncation (chunked for stack safety).
    var upper_buf: [512]u8 = undefined;
    var idx: usize = 0;
    for (user) |c| {
        upper_buf[idx] = std.ascii.toUpper(c);
        idx += 1;
        if (idx == upper_buf.len) {
            hasher.update(upper_buf[0..idx]);
            idx = 0;
        }
    }
    if (idx > 0) hasher.update(upper_buf[0..idx]);
    const hash = hasher.final();

    // Base64 encode (SHA-0 produces 20 bytes)
    const base64 = std.base64.standard;
    var b64_buf: [32]u8 = undefined;
    const encoded = base64.Encoder.encode(&b64_buf, &hash);

    ctx.print("\nPassword Hash (base64):\n", .{});
    ctx.printColored(.green, "{s}\n", .{encoded});
    ctx.print("\nUse with: --password-hash \"{s}\"\n", .{encoded});
}

// ============================================================================
// Tests
// ============================================================================

test "generate does not crash" {
    // Just verify it doesn't panic - actual output goes to stdout
    // In a real test we'd capture stdout, but this at least verifies no crash
    generate("testuser", "testpass");
}
