//! X.509 certificate and RSA key management for SoftEther VPN.
//!
//! C reference: `Mayaqua/Encrypt.c` — X509*, K*, NAME*, X_SERIAL* wrappers.
//! This module wraps the OpenSSL X.509/PKEY APIs exposed via `c_imports.zig`
//! and provides Zig-idiomatic types for certificate generation, serialization,
//! inspection, and key management.
//!
//! ## Scope
//!
//! Focused on the subset needed by admin RPC commands:
//! - `RegenerateServerCert`, `SetServerCert`, `GetServerCert` → cert gen + PEM
//! - `GetServerCipher` → cert inspection (subject, issuer, dates, key bits)
//! - `SetServerCipher` → N/A (cipher is a server config, not cert)
//! - `CreateKeyPair` → RSA key gen + PEM
//!
//! Full C reference coverage (CRL, PKCS#12, certificate chain verification,
//! name comparison) is deferred to future milestones.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const c = @import("../../cedar/protocol/c_imports.zig").c;

const log = std.log.scoped(.x509);

// ============================================================================
// Error types
// ============================================================================

pub const X509Error = error{
    OutOfMemory,
    OpenSSLFailed,
    NameTooLong,
    InvalidInput,
};

// ============================================================================
// Types
// ============================================================================

/// Distinguished name fields for certificate subject/issuer.
pub const Name = struct {
    common_name: ?[]const u8 = null,
    organization: ?[]const u8 = null,
    organizational_unit: ?[]const u8 = null,
    country: ?[]const u8 = null,
    state: ?[]const u8 = null,
    locality: ?[]const u8 = null,
};

/// Information extracted from an X.509 certificate.
pub const CertInfo = struct {
    subject_cn: ?[]const u8 = null,
    issuer_cn: ?[]const u8 = null,
    subject_full: ?[]const u8 = null,
    issuer_full: ?[]const u8 = null,
    not_before: i64 = 0,
    not_after: i64 = 0,
    serial: ?[]const u8 = null,
    key_bits: u32 = 0,
    is_self_signed: bool = false,
    is_ca: bool = false,
    key_usage: u32 = 0,
    allocator: Allocator,

    pub fn deinit(self: *CertInfo) void {
        if (self.subject_cn) |s| self.allocator.free(s);
        if (self.issuer_cn) |s| self.allocator.free(s);
        if (self.subject_full) |s| self.allocator.free(s);
        if (self.issuer_full) |s| self.allocator.free(s);
        if (self.serial) |s| self.allocator.free(s);
    }
};

/// RSA key pair (public + private).
pub const KeyPair = struct {
    pub_pem: []u8,
    priv_pem: []u8,

    pub fn deinit(self: *KeyPair, allocator: Allocator) void {
        allocator.free(self.pub_pem);
        allocator.free(self.priv_pem);
    }
};

/// PEM-encoded certificate.
pub const CertPem = struct {
    data: []u8,

    pub fn deinit(self: *CertPem, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

// ============================================================================
// Certificate generation
// ============================================================================

/// Generate a self-signed X.509 v3 certificate with an RSA-2048 key.
///
/// The certificate has:
/// - Basic Constraints: CA:FALSE
/// - Key Usage: digitalSignature, keyEncipherment
/// - Extended Key Usage: serverAuth, clientAuth
/// - Subject Alternative Name: DNS:<cn>
/// - Validity: now → now + days
/// - Signature algorithm: SHA-256
///
/// Returns PEM-encoded certificate and private key.
pub fn generateSelfSigned(
    allocator: Allocator,
    name: Name,
    days: u32,
) !struct { cert: CertPem, key: []u8 } {
    // 1. Generate RSA-2048 keypair.
    const pkey = try generateRsaKey(allocator, 2048);
    defer c.EVP_PKEY_free(pkey);

    // 2. Build certificate (self-signed: issuer_name = null → issuer = subject).
    const x509 = try buildCertificate(allocator, pkey, pkey, name, null, days, false);
    defer c.X509_free(x509);

    // 3. Serialize.
    var cert_pem = try x509ToPem(allocator, x509);
    errdefer cert_pem.deinit(allocator);

    const key_pem = try evpPkeyToPem(allocator, pkey, true);
    errdefer allocator.free(key_pem);

    return .{ .cert = cert_pem, .key = key_pem };
}

/// Generate a root CA certificate (self-signed, CA:TRUE).
pub fn generateRootCA(
    allocator: Allocator,
    name: Name,
    days: u32,
) !struct { cert: CertPem, key: []u8 } {
    const pkey = try generateRsaKey(allocator, 2048);
    defer c.EVP_PKEY_free(pkey);

    const x509 = try buildCertificate(allocator, pkey, pkey, name, null, days, true);
    defer c.X509_free(x509);

    var cert_pem = try x509ToPem(allocator, x509);
    errdefer cert_pem.deinit(allocator);

    const key_pem = try evpPkeyToPem(allocator, pkey, true);
    errdefer allocator.free(key_pem);

    return .{ .cert = cert_pem, .key = key_pem };
}

/// Generate a certificate signed by a CA.
pub fn generateSigned(
    allocator: Allocator,
    ca_cert_pem: []const u8,
    ca_key_pem: []const u8,
    name: Name,
    days: u32,
) !struct { cert: CertPem, key: []u8 } {
    // Parse CA cert and key.
    const ca_x509 = try pemToX509(allocator, ca_cert_pem);
    defer c.X509_free(ca_x509);

    const ca_pkey = try pemToEvpPkey(allocator, ca_key_pem, true);
    defer c.EVP_PKEY_free(ca_pkey);

    // Extract CA's subject name for the issuer field.
    const ca_subject = c.X509_get_subject_name(ca_x509);
    var ca_cn: ?[]const u8 = null;
    var ca_org: ?[]const u8 = null;
    var ca_country: ?[]const u8 = null;
    if (ca_subject != null) {
        ca_cn = getTextByNid(allocator, ca_subject.?, c.NID_commonName);
        ca_org = getTextByNid(allocator, ca_subject.?, c.NID_organizationName);
        ca_country = getTextByNid(allocator, ca_subject.?, c.NID_countryName);
    }
    defer {
        if (ca_cn) |s| allocator.free(s);
        if (ca_org) |s| allocator.free(s);
        if (ca_country) |s| allocator.free(s);
    }

    const issuer = Name{
        .common_name = ca_cn,
        .organization = ca_org,
        .country = ca_country,
    };

    // Generate new keypair for the signed cert.
    const new_pkey = try generateRsaKey(allocator, 2048);
    defer c.EVP_PKEY_free(new_pkey);

    // Build certificate signed by CA with correct issuer.
    const x509 = try buildCertificate(allocator, new_pkey, ca_pkey, name, issuer, days, false);
    defer c.X509_free(x509);

    const cert_pem = try x509ToPem(allocator, x509);
    errdefer cert_pem.deinit(allocator);

    const key_pem = try evpPkeyToPem(allocator, new_pkey, true);
    errdefer allocator.free(key_pem);

    return .{ .cert = cert_pem, .key = key_pem };
}

// ============================================================================
// Certificate inspection
// ============================================================================

/// Extract information from a PEM-encoded certificate.
pub fn inspectCert(allocator: Allocator, cert_pem: []const u8) !CertInfo {
    const x509 = try pemToX509(allocator, cert_pem);
    defer c.X509_free(x509);

    return inspectX509(allocator, x509);
}

/// Extract information from an OpenSSL X509* object.
pub fn inspectX509(allocator: Allocator, x509: *c.X509) !CertInfo {
    var info = CertInfo{ .allocator = allocator };

    // Subject CN.
    const subject_name = c.X509_get_subject_name(x509);
    if (subject_name != null) {
        info.subject_cn = getTextByNid(allocator, subject_name.?, c.NID_commonName);
        info.subject_full = getNameString(allocator, subject_name.?);
    }

    // Issuer CN.
    const issuer_name = c.X509_get_issuer_name(x509);
    if (issuer_name != null) {
        info.issuer_cn = getTextByNid(allocator, issuer_name.?, c.NID_commonName);
        info.issuer_full = getNameString(allocator, issuer_name.?);
    }

    // Self-signed check: subject == issuer.
    if (subject_name != null and issuer_name != null) {
        info.is_self_signed = (c.X509_NAME_cmp(subject_name, issuer_name) == 0);
    }

    // Validity dates.
    const not_before = c.X509_get0_notBefore(x509);
    const not_after = c.X509_get0_notAfter(x509);
    if (not_before != null) {
        info.not_before = asn1TimeToI64(not_before.?);
    }
    if (not_after != null) {
        info.not_after = asn1TimeToI64(not_after.?);
    }

    // Serial number.
    const serial_asn1 = c.X509_get0_serialNumber(x509);
    if (serial_asn1 != null) {
        const serial_int = c.ASN1_INTEGER_get(serial_asn1);
        var buf: [32]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{d}", .{serial_int}) catch {
            log.err("Failed to format serial number", .{});
            return error.OpenSSLFailed;
        };
        info.serial = try allocator.dupe(u8, str);
    }

    // Key bits.
    const pubkey = c.X509_get0_pubkey(x509);
    if (pubkey != null) {
        info.key_bits = @intCast(c.EVP_PKEY_bits(pubkey));
    }

    // CA check: basic constraints.
    const bc_ext = c.X509_get_ext_d2i(x509, c.NID_basic_constraints, null, null);
    if (bc_ext != null) {
        const bc: *c.BASIC_CONSTRAINTS = @ptrCast(bc_ext);
        info.is_ca = (bc.ca != 0);
        c.BASIC_CONSTRAINTS_free(bc);
    }

    // Key usage.
    const ku_ext = c.X509_get_ext_d2i(x509, c.NID_key_usage, null, null);
    if (ku_ext != null) {
        const ku: *c.ASN1_BIT_STRING = @ptrCast(ku_ext);
        if (ku.length > 0) {
            info.key_usage = @intCast(ku.data[0]);
        }
        c.ASN1_BIT_STRING_free(ku);
    }

    return info;
}

// ============================================================================
// Serialization
// ============================================================================

/// Parse a PEM-encoded certificate.
pub fn pemToX509(_: Allocator, pem: []const u8) !*c.X509 {
    const bio = c.BIO_new_mem_buf(@ptrCast(pem.ptr), @intCast(pem.len)) orelse {
        log.err("BIO_new_mem_buf failed", .{});
        return error.OutOfMemory;
    };
    defer _ = c.BIO_free(bio);

    const x509 = c.PEM_read_bio_X509(bio, null, null, null) orelse {
        logOpenSslErrors();
        log.err("PEM_read_bio_X509 failed", .{});
        return error.InvalidInput;
    };
    return x509;
}

/// Serialize an X509* to PEM.
pub fn x509ToPem(allocator: Allocator, x509: *c.X509) !CertPem {
    const bio = c.BIO_new(c.BIO_s_mem()) orelse {
        log.err("BIO_new failed", .{});
        return error.OutOfMemory;
    };
    defer _ = c.BIO_free(bio);

    if (c.PEM_write_bio_X509(bio, x509) != 1) {
        logOpenSslErrors();
        log.err("PEM_write_bio_X509 failed", .{});
        return error.OpenSSLFailed;
    }

    var mem_ptr: [*c]u8 = null;
    const len = c.BIO_get_mem_data(bio, @as([*c][*c]u8, @ptrCast(&mem_ptr)));
    if (len <= 0 or mem_ptr == null) {
        log.err("BIO_get_mem_data returned empty", .{});
        return error.OpenSSLFailed;
    }

    return .{ .data = try allocator.dupe(u8, mem_ptr[0..@intCast(len)]) };
}

/// Parse a PEM-encoded private key. If `is_private` is true, reads as private key;
/// otherwise reads as public key.
pub fn pemToEvpPkey(_: Allocator, pem: []const u8, is_private: bool) !*c.EVP_PKEY {
    const bio = c.BIO_new_mem_buf(@ptrCast(pem.ptr), @intCast(pem.len)) orelse {
        log.err("BIO_new_mem_buf failed", .{});
        return error.OutOfMemory;
    };
    defer _ = c.BIO_free(bio);

    const pkey = if (is_private)
        c.PEM_read_bio_PrivateKey(bio, null, null, null)
    else
        c.PEM_read_bio_PUBKEY(bio, null, null, null);

    if (pkey == null) {
        logOpenSslErrors();
        log.err("PEM_read_bio_{s} failed", .{if (is_private) "PrivateKey" else "PUBKEY"});
        return error.InvalidInput;
    }
    return pkey.?;
}

/// Serialize an EVP_PKEY to PEM.
pub fn evpPkeyToPem(allocator: Allocator, pkey: *c.EVP_PKEY, is_private: bool) ![]u8 {
    const bio = c.BIO_new(c.BIO_s_mem()) orelse {
        log.err("BIO_new failed", .{});
        return error.OutOfMemory;
    };
    defer _ = c.BIO_free(bio);

    const result = if (is_private)
        c.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null)
    else
        c.PEM_write_bio_PUBKEY(bio, pkey);

    if (result != 1) {
        logOpenSslErrors();
        log.err("PEM_write_bio_{s} failed", .{if (is_private) "PrivateKey" else "PUBKEY"});
        return error.OpenSSLFailed;
    }

    var mem_ptr: [*c]u8 = null;
    const len = c.BIO_get_mem_data(bio, @as([*c][*c]u8, @ptrCast(&mem_ptr)));
    if (len <= 0 or mem_ptr == null) {
        log.err("BIO_get_mem_data returned empty", .{});
        return error.OpenSSLFailed;
    }

    return allocator.dupe(u8, mem_ptr[0..@intCast(len)]);
}

// ============================================================================
// Key generation
// ============================================================================

/// Generate an RSA key pair.
pub fn generateRsaKey(_: Allocator, bits: u32) !*c.EVP_PKEY {
    const ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_RSA, null) orelse {
        log.err("EVP_PKEY_CTX_new_id failed", .{});
        return error.OutOfMemory;
    };
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_keygen_init(ctx) != 1) {
        logOpenSslErrors();
        return error.OpenSSLFailed;
    }
    _ = c.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, @intCast(bits));

    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_keygen(ctx, &pkey) != 1 or pkey == null) {
        logOpenSslErrors();
        log.err("EVP_PKEY_keygen failed for {d} bits", .{bits});
        return error.OpenSSLFailed;
    }
    return pkey.?;
}

/// Generate an RSA key pair and return PEM strings.
pub fn generateKeyPair(allocator: Allocator, bits: u32) !KeyPair {
    const pkey = try generateRsaKey(allocator, bits);
    defer c.EVP_PKEY_free(pkey);

    const pub_pem = try evpPkeyToPem(allocator, pkey, false);
    errdefer allocator.free(pub_pem);

    const priv_pem = try evpPkeyToPem(allocator, pkey, true);
    errdefer allocator.free(priv_pem);

    return .{ .pub_pem = pub_pem, .priv_pem = priv_pem };
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Build an X.509 v3 certificate.
fn buildCertificate(
    allocator: Allocator,
    subject_key: *c.EVP_PKEY,
    issuer_key: *c.EVP_PKEY,
    name: Name,
    issuer_name: ?Name,
    days: u32,
    is_ca: bool,
) !*c.X509 {
    const x509 = c.X509_new() orelse {
        log.err("X509_new failed", .{});
        return error.OutOfMemory;
    };

    if (c.X509_set_version(x509, 2) != 1) { // v3
        log.err("X509_set_version failed", .{});
        c.X509_free(x509);
        logOpenSslErrors();
        return error.OpenSSLFailed;
    }

    // Serial number (random positive 63-bit to avoid negative ASN.1 serials).
    var serial_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&serial_bytes);
    serial_bytes[0] &= 0x7f; // Clear high bit → guaranteed positive.
    const serial_asn1 = c.X509_get_serialNumber(x509);
    if (c.ASN1_INTEGER_set(serial_asn1, @bitCast(serial_bytes)) != 1) {
        c.X509_free(x509);
        logOpenSslErrors();
        return error.OpenSSLFailed;
    }

    // Subject name.
    const subject_name = c.X509_get_subject_name(x509) orelse {
        c.X509_free(x509);
        return error.OutOfMemory;
    };
    try populateX509Name(allocator, subject_name, name);

    // Issuer name — use provided issuer_name, or fall back to subject (self-signed).
    const issuer_x509_name = c.X509_get_issuer_name(x509) orelse {
        c.X509_free(x509);
        return error.OutOfMemory;
    };
    if (issuer_name) |ina| {
        try populateX509Name(allocator, issuer_x509_name, ina);
    } else {
        if (c.X509_set_issuer_name(x509, subject_name) != 1) {
            c.X509_free(x509);
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }

    // Validity.
    const now = std.time.timestamp();
    const not_before = c.X509_get_notBefore(x509);
    const not_after = c.X509_get_notAfter(x509);
    _ = c.ASN1_TIME_set(not_before, now);
    _ = c.ASN1_TIME_set(not_after, now + @as(i64, @intCast(days)) * 86400);

    // Public key.
    if (c.X509_set_pubkey(x509, subject_key) != 1) {
        c.X509_free(x509);
        logOpenSslErrors();
        return error.OpenSSLFailed;
    }

    // Extensions.
    if (is_ca) {
        try addBasicConstraintsCa(x509);
        try addKeyUsageCa(x509);
    } else {
        try addBasicConstraintsNonCa(x509);
        try addKeyUsageNonCa(x509);
        try addExtendedKeyUsage(x509);
        try addSubjectAltName(allocator, x509, name.common_name orelse "localhost");
    }

    // Sign.
    if (c.X509_sign(x509, issuer_key, c.EVP_sha256()) == 0) {
        c.X509_free(x509);
        logOpenSslErrors();
        log.err("X509_sign failed", .{});
        return error.OpenSSLFailed;
    }

    return x509;
}

/// Populate an X509_NAME from a Name struct.
fn populateX509Name(allocator: Allocator, x509_name: *c.X509_NAME, name: Name) !void {
    if (name.common_name) |cn| {
        const cn_z = try allocator.dupeZ(u8, cn);
        defer allocator.free(cn_z);
        if (c.X509_NAME_add_entry_by_NID(x509_name, c.NID_commonName, c.MBSTRING_ASC, @ptrCast(cn_z.ptr), -1, -1, 0) != 1) {
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }
    if (name.organization) |org| {
        const org_z = try allocator.dupeZ(u8, org);
        defer allocator.free(org_z);
        if (c.X509_NAME_add_entry_by_NID(x509_name, c.NID_organizationName, c.MBSTRING_ASC, @ptrCast(org_z.ptr), -1, -1, 0) != 1) {
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }
    if (name.organizational_unit) |ou| {
        const ou_z = try allocator.dupeZ(u8, ou);
        defer allocator.free(ou_z);
        if (c.X509_NAME_add_entry_by_NID(x509_name, c.NID_organizationalUnitName, c.MBSTRING_ASC, @ptrCast(ou_z.ptr), -1, -1, 0) != 1) {
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }
    if (name.country) |c_val| {
        const c_z = try allocator.dupeZ(u8, c_val);
        defer allocator.free(c_z);
        if (c.X509_NAME_add_entry_by_NID(x509_name, c.NID_countryName, c.MBSTRING_ASC, @ptrCast(c_z.ptr), -1, -1, 0) != 1) {
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }
    if (name.state) |st| {
        const st_z = try allocator.dupeZ(u8, st);
        defer allocator.free(st_z);
        if (c.X509_NAME_add_entry_by_NID(x509_name, c.NID_stateOrProvinceName, c.MBSTRING_ASC, @ptrCast(st_z.ptr), -1, -1, 0) != 1) {
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }
    if (name.locality) |l| {
        const l_z = try allocator.dupeZ(u8, l);
        defer allocator.free(l_z);
        if (c.X509_NAME_add_entry_by_NID(x509_name, c.NID_localityName, c.MBSTRING_ASC, @ptrCast(l_z.ptr), -1, -1, 0) != 1) {
            logOpenSslErrors();
            return error.OpenSSLFailed;
        }
    }
}

/// Add Basic Constraints CA:TRUE extension.
fn addBasicConstraintsCa(x509: *c.X509) !void {
    const ext = c.X509V3_EXT_conf_nid(null, null, c.NID_basic_constraints, "critical,CA:TRUE") orelse {
        log.err("X509V3_EXT_conf_nid (basic_constraints CA) failed", .{});
        return error.OpenSSLFailed;
    };
    defer c.X509_EXTENSION_free(ext);
    _ = c.X509_add_ext(x509, ext, -1);
}

/// Add Basic Constraints CA:FALSE extension.
fn addBasicConstraintsNonCa(x509: *c.X509) !void {
    const ext = c.X509V3_EXT_conf_nid(null, null, c.NID_basic_constraints, "critical,CA:FALSE") orelse {
        log.err("X509V3_EXT_conf_nid (basic_constraints non-CA) failed", .{});
        return error.OpenSSLFailed;
    };
    defer c.X509_EXTENSION_free(ext);
    _ = c.X509_add_ext(x509, ext, -1);
}

/// Add Key Usage for CA certificates.
fn addKeyUsageCa(x509: *c.X509) !void {
    const ext = c.X509V3_EXT_conf_nid(null, null, c.NID_key_usage, "critical,keyCertSign,cRLSign") orelse {
        log.err("X509V3_EXT_conf_nid (key_usage CA) failed", .{});
        return error.OpenSSLFailed;
    };
    defer c.X509_EXTENSION_free(ext);
    _ = c.X509_add_ext(x509, ext, -1);
}

/// Add Key Usage for non-CA certificates.
fn addKeyUsageNonCa(x509: *c.X509) !void {
    const ext = c.X509V3_EXT_conf_nid(null, null, c.NID_key_usage, "critical,digitalSignature,keyEncipherment") orelse {
        log.err("X509V3_EXT_conf_nid (key_usage non-CA) failed", .{});
        return error.OpenSSLFailed;
    };
    defer c.X509_EXTENSION_free(ext);
    _ = c.X509_add_ext(x509, ext, -1);
}

/// Add Extended Key Usage (serverAuth + clientAuth).
fn addExtendedKeyUsage(x509: *c.X509) !void {
    const ext = c.X509V3_EXT_conf_nid(null, null, c.NID_ext_key_usage, "serverAuth,clientAuth") orelse {
        log.err("X509V3_EXT_conf_nid (ext_key_usage) failed", .{});
        return error.OpenSSLFailed;
    };
    defer c.X509_EXTENSION_free(ext);
    _ = c.X509_add_ext(x509, ext, -1);
}

/// Add Subject Alternative Name extension.
fn addSubjectAltName(allocator: Allocator, x509: *c.X509, dns_name: []const u8) !void {
    var buf: [256]u8 = undefined;
    const san = std.fmt.bufPrint(&buf, "DNS:{s}", .{dns_name}) catch return error.NameTooLong;
    const san_z = try allocator.dupeZ(u8, san);
    defer allocator.free(san_z);

    const ext = c.X509V3_EXT_conf_nid(null, null, c.NID_subject_alt_name, @ptrCast(san_z.ptr)) orelse {
        log.err("X509V3_EXT_conf_nid (subject_alt_name) failed", .{});
        return error.OpenSSLFailed;
    };
    defer c.X509_EXTENSION_free(ext);
    _ = c.X509_add_ext(x509, ext, -1);
}

/// Extract a text field from X509_NAME by NID.
fn getTextByNid(allocator: Allocator, name: *c.X509_NAME, nid: c_int) ?[]const u8 {
    var buf: [256]u8 = undefined;
    const len = c.X509_NAME_get_text_by_NID(name, nid, &buf, @intCast(buf.len));
    if (len <= 0) return null;
    return allocator.dupe(u8, buf[0..@intCast(len)]) catch null;
}

/// Get full name string from X509_NAME (e.g., "CN=foo, O=bar, C=US").
fn getNameString(allocator: Allocator, name: *c.X509_NAME) ?[]const u8 {
    const bio = c.BIO_new(c.BIO_s_mem()) orelse return null;
    defer _ = c.BIO_free(bio);

    _ = c.X509_NAME_print_ex(bio, name, -1, c.XN_FLAG_ONELINE);

    var mem_ptr: ?[*]u8 = null;
    const len = c.BIO_get_mem_data(bio, @ptrCast(&mem_ptr));
    if (len <= 0 or mem_ptr == null) return null;

    return allocator.dupe(u8, mem_ptr.?[0..@intCast(len)]) catch null;
}

/// Convert ASN1_TIME to Unix timestamp (i64) using ASN1_TIME_to_tm + timegm.
fn asn1TimeToI64(asn1_time: *const c.ASN1_TIME) i64 {
    var tm: c.struct_tm = std.mem.zeroes(c.struct_tm);
    if (c.ASN1_TIME_to_tm(asn1_time, &tm) != 1) return 0;
    // timegm interprets struct tm as UTC and returns seconds since epoch.
    var tm_copy = tm;
    return @intCast(c.timegm(&tm_copy));
}

/// Drain the OpenSSL error queue and log errors.
fn logOpenSslErrors() void {
    while (c.ERR_get_error() != 0) {
        // Intentionally drain the error queue. In production, these are
        // logged by OpenSSL itself or by the caller's error path.
    }
}

// ============================================================================
// Tests
// ============================================================================

test "x509.generate self-signed cert" {
    const result = try generateSelfSigned(testing.allocator, .{
        .common_name = "test.softether.vpn",
        .organization = "SoftEther",
        .country = "US",
    }, 365);
    defer result.cert.deinit(testing.allocator);
    defer testing.allocator.free(result.key);

    try testing.expect(result.cert.data.len > 0);
    try testing.expect(result.key.len > 0);
    try testing.expect(std.mem.indexOf(u8, result.cert.data, "BEGIN CERTIFICATE") != null);
    try testing.expect(std.mem.indexOf(u8, result.key, "BEGIN PRIVATE KEY") != null);
}

test "x509.inspect self-signed cert" {
    const gen = try generateSelfSigned(testing.allocator, .{
        .common_name = "inspect.test.vpn",
    }, 365);
    defer gen.cert.deinit(testing.allocator);
    defer testing.allocator.free(gen.key);

    var info = try inspectCert(testing.allocator, gen.cert.data);
    defer info.deinit();

    try testing.expectEqualStrings("inspect.test.vpn", info.subject_cn orelse "");
    try testing.expectEqualStrings("inspect.test.vpn", info.issuer_cn orelse "");
    try testing.expect(info.is_self_signed);
    try testing.expect(!info.is_ca);
    try testing.expectEqual(@as(u32, 2048), info.key_bits);
    try testing.expect(info.not_before != 0);
    try testing.expect(info.not_after > info.not_before);
}

test "x509.generate root CA" {
    const gen = try generateRootCA(testing.allocator, .{
        .common_name = "Test Root CA",
        .organization = "SoftEther Test",
    }, 3650);
    defer gen.cert.deinit(testing.allocator);
    defer testing.allocator.free(gen.key);

    var info = try inspectCert(testing.allocator, gen.cert.data);
    defer info.deinit();

    try testing.expect(info.is_ca);
    try testing.expect(info.is_self_signed);
}

test "x509.generate signed cert from CA" {
    // First generate a CA.
    const ca = try generateRootCA(testing.allocator, .{
        .common_name = "Test CA",
    }, 3650);
    defer ca.cert.deinit(testing.allocator);
    defer testing.allocator.free(ca.key);

    // Then sign a cert with it.
    const signed = try generateSigned(testing.allocator, ca.cert.data, ca.key, .{
        .common_name = "signed.test.vpn",
    }, 365);
    defer signed.cert.deinit(testing.allocator);
    defer testing.allocator.free(signed.key);

    var info = try inspectCert(testing.allocator, signed.cert.data);
    defer info.deinit();

    try testing.expectEqualStrings("signed.test.vpn", info.subject_cn orelse "");
    try testing.expect(!info.is_self_signed);
    try testing.expect(!info.is_ca);
}

test "x509.generate key pair" {
    var kp = try generateKeyPair(testing.allocator, 2048);
    defer kp.deinit(testing.allocator);

    try testing.expect(kp.pub_pem.len > 0);
    try testing.expect(kp.priv_pem.len > 0);
    try testing.expect(std.mem.indexOf(u8, kp.pub_pem, "BEGIN PUBLIC KEY") != null);
    try testing.expect(std.mem.indexOf(u8, kp.priv_pem, "BEGIN PRIVATE KEY") != null);
}

test "x509.round-trip PEM parse and serialize" {
    const gen = try generateSelfSigned(testing.allocator, .{
        .common_name = "roundtrip.test.vpn",
    }, 365);
    defer gen.cert.deinit(testing.allocator);
    defer testing.allocator.free(gen.key);

    // Parse the PEM.
    const x509 = try pemToX509(testing.allocator, gen.cert.data);
    defer c.X509_free(x509);

    // Re-serialize.
    const re = try x509ToPem(testing.allocator, x509);
    defer re.deinit(testing.allocator);

    // Should produce a valid PEM.
    try testing.expect(std.mem.indexOf(u8, re.data, "BEGIN CERTIFICATE") != null);
}

test "x509.inspect with full name fields" {
    const gen = try generateSelfSigned(testing.allocator, .{
        .common_name = "full.test.vpn",
        .organization = "Test Org",
        .organizational_unit = "Test Unit",
        .country = "US",
        .state = "California",
        .locality = "San Francisco",
    }, 365);
    defer gen.cert.deinit(testing.allocator);
    defer testing.allocator.free(gen.key);

    var info = try inspectCert(testing.allocator, gen.cert.data);
    defer info.deinit();

    try testing.expectEqualStrings("full.test.vpn", info.subject_cn orelse "");
    // Full name should contain the CN.
    const full = info.subject_full orelse "";
    try testing.expect(std.mem.indexOf(u8, full, "full.test.vpn") != null);
}

test "x509.key pair PEM round-trip" {
    const kp = try generateKeyPair(testing.allocator, 2048);
    defer kp.deinit(testing.allocator);

    // Parse the private key.
    const pkey = try pemToEvpPkey(testing.allocator, kp.priv_pem, true);
    defer c.EVP_PKEY_free(pkey);

    // Re-serialize.
    const re = try evpPkeyToPem(testing.allocator, pkey, true);
    defer testing.allocator.free(re);

    try testing.expect(std.mem.indexOf(u8, re, "BEGIN PRIVATE KEY") != null);
}
