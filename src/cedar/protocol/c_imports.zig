//! Shared C imports.
//!
//! Every distinct @cImport block in the library is translated independently,
//! and on aarch64-windows (mingw) translate-c emits an exported
//! `__mingw_current_teb` global (the x18-register TEB pointer from the bundled
//! mingw winnt.h) in every block that reaches winnt.h. Two or more such blocks
//! abort the build with "exported symbol collision". All consumers that may
//! reach winnt.h (OpenSSL headers on Windows, windows.h itself) must therefore
//! share a single import block. zlib.h never reaches winnt.h and stays a
//! separate import in tunnel.zig.

const builtin = @import("builtin");

pub const c = if (builtin.os.tag == .windows)
    @cImport({
        @cInclude("openssl/ssl.h");
        @cInclude("openssl/err.h");
        @cInclude("openssl/x509.h");
        @cInclude("openssl/x509v3.h");
        @cInclude("openssl/pem.h");
        @cInclude("openssl/evp.h");
        @cInclude("openssl/bio.h");
        @cInclude("openssl/md4.h");
        @cInclude("openssl/des.h");
        @cInclude("windows.h");
    })
else
    @cImport({
        @cInclude("openssl/ssl.h");
        @cInclude("openssl/err.h");
        @cInclude("openssl/x509.h");
        @cInclude("openssl/x509v3.h");
        @cInclude("openssl/pem.h");
        @cInclude("openssl/evp.h");
        @cInclude("openssl/bio.h");
        @cInclude("openssl/md4.h");
        @cInclude("openssl/des.h");
    });
