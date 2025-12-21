//! Password Hash Generator
//!
//! Generates SoftEther-compatible password hashes.

const std = @import("std");

const cli = @import("../cli/mod.zig");
const crypto = @import("../crypto/crypto.zig");

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
    var input_buf: [512]u8 = undefined;
    var username_upper: [256]u8 = undefined;

    const pass_len = @min(pass.len, 256);
    const user_len = @min(user.len, 256);

    // Copy password first
    @memcpy(input_buf[0..pass_len], pass[0..pass_len]);

    // Convert username to uppercase and append
    for (user[0..user_len], 0..) |c, i| {
        username_upper[i] = std.ascii.toUpper(c);
    }
    @memcpy(input_buf[pass_len..][0..user_len], username_upper[0..user_len]);

    const input_len = pass_len + user_len;

    const hash = crypto.sha0.hash(input_buf[0..input_len]);

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
