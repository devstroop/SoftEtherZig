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

/// Write `data` to `path` atomically: temp file + rename, so a mid-write
/// failure never leaves a half-written file. Without this, a failed key write
/// after a successful cert write would leave a new cert paired with an old key
/// (mismatched identity), which the server bootstrap would happily load.
fn writeFileAtomic(allocator: std.mem.Allocator, path: []const u8, data: []const u8, mode: std.fs.File.Mode) !void {
    const dir = std.fs.cwd();
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    var file = try dir.createFile(tmp_path, .{ .truncate = true, .mode = mode });
    errdefer dir.deleteFile(tmp_path) catch {};
    // Enforce the mode even if the temp file pre-exists with wider perms.
    if (builtin.os.tag != .windows) std.posix.fchmod(file.handle, mode) catch {};
    try file.writeAll(data);
    try file.sync();
    file.close();

    try dir.rename(tmp_path, path);
}

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

    try writeFileAtomic(allocator, cert_filename, cert.cert_pem, 0o644);
    try writeFileAtomic(allocator, key_filename, cert.key_pem, 0o600);

    cli.display.success(display_ctx, "Wrote {s} and {s} to the current directory", .{ cert_filename, key_filename });
}
