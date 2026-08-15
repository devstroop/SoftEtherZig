//! First-run server certificate generation (`--gen-cert`).
//!
//! Shared by the `vpnclient` and `vpnserver` executables: writes a self-signed
//! certificate/key pair (`server_cert.pem` + `server_key.pem`, key mode 0600)
//! to the current directory. Mirrors C `SiGenerateDefaultCertEx` (first-run
//! default cert generation for a vpnserver bootstrap).

const std = @import("std");
const builtin = @import("builtin");

const tls = @import("../mayaqua/network/tls.zig");
const cli = @import("../cli/mod.zig");

/// Certificate PEM file name (C: `SERVER_CERT_FILENAME`).
pub const cert_filename = "server_cert.pem";
/// Private key PEM file name (C: `SERVER_KEY_FILENAME`).
pub const key_filename = "server_key.pem";

/// Generate a self-signed cert and write the PEM files to the current
/// directory. `common_name == null` → default CN (host-based). Errors surface
/// on the display context as a failure message.
pub fn generateServerCertFiles(
    allocator: std.mem.Allocator,
    display_ctx: *cli.DisplayContext,
    common_name: ?[]const u8,
) !void {
    const cert = tls.generateSelfSignedCert(allocator, common_name) catch |err| {
        cli.display.failure(display_ctx, "Failed to generate self-signed certificate: {s}", .{@errorName(err)});
        return err;
    };
    defer allocator.free(cert.cert_pem);
    defer allocator.free(cert.key_pem);

    var cert_file = try std.fs.cwd().createFile(cert_filename, .{ .truncate = true });
    defer cert_file.close();
    try cert_file.writeAll(cert.cert_pem);

    var key_file = try std.fs.cwd().createFile(key_filename, .{ .truncate = true, .mode = 0o600 });
    defer key_file.close();
    // Enforce 0600 even if the file pre-exists with wider permissions.
    if (builtin.os.tag != .windows) std.posix.fchmod(key_file.handle, 0o600) catch {};
    try key_file.writeAll(cert.key_pem);

    cli.display.success(display_ctx, "Wrote {s} and {s} to the current directory", .{ cert_filename, key_filename });
}
