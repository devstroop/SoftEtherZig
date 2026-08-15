//! Server-side Security Accounts Manager (C: Cedar/Sam.c).
//!
//! Implements the server half of the VPN authentication handshake for M1:
//! user accounts live on a virtual HUB, and the server verifies the client's
//! credentials the same way SoftEther's Sam.c does.
//!
//! C reference (4.44):
//! - `HashPassword` (Account.c:680) — SHA-0(password ‖ UPPER(username))
//! - `SecurePassword` (Sam.c:108) — SHA-0(password_hash ‖ random)
//! - `SamAuthUserByAnonymous` (Sam.c:138)
//! - `SamAuthUserByPassword` (Sam.c:552) — incl. the virtual "Administrator"
//!   account backed by the hub's admin secure password
//! - auth dispatch (Protocol.c:2558-2770) — anonymous is tried FIRST, then the
//!   switch on `authtype`; plain-password is converted to a secure password
//!   before `SamAuthUserByPassword`.
//!
//! ## Digest note
//!
//! The handshake digests are **SHA-0** (`Hash(sha=true)` → `Internal_SHA0` in
//! Encrypt.c), not SHA-1. The Zig client hashes with the same SHA-0 (see
//! `cedar/protocol/auth.zig`), so this module reuses `mayaqua/encrypt/sha0.zig`
//! to stay pure-Zig and dependency-free. The M1 wire target is the Zig client.
//!
//! ## Plain-password field divergence
//!
//! The Zig client sends the plaintext in a pack field named `"password"`
//! (`buildPlainsPasswordAuth`), whereas C 4.44 reads `"plain_password"`. The
//! dispatcher accepts both for robustness (documented client deviation).
//!
//! ## Out of scope (M1)
//! - MS-CHAPv2 (NTLM) — the Zig client never sends the `IPC_PASSWORD_MSCHAPV2_TAG`
//!   prefix; the tag is detected and rejected so the caller can return an
//!   explicit error instead of silently failing.
//! - Ticket / certificate / RADIUS / NT auth, and the in-proc anonymous
//!   MS-CHAPv2 guess dance (IPsec/OpenVPN only).

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

const Sha0 = @import("../../mayaqua/encrypt/sha0.zig").Sha0;
const sha0_digest_length = @import("../../mayaqua/encrypt/sha0.zig").digest_length;

/// Virtual hub administrator account name (C: ADMINISTRATOR_USERNAME).
pub const administrator_username = "administrator";

/// Prefix that marks a plaintext password as an MS-CHAPv2 payload
/// (C: IPC_PASSWORD_MSCHAPV2_TAG in IPsec_IPC.h).
pub const mschap_v2_tag = "xH7DiNlurDhcYV4a:";

/// SHA-0 digest size — 20 bytes, same as SHA-1 (C: SHA1_SIZE).
pub const digest_length = sha0_digest_length;

/// Server-side account authentication types (C: AUTHTYPE_*).
pub const UserAuthType = enum(u8) {
    /// Anyone who knows the username may connect (C: AUTHTYPE_ANONYMOUS).
    anonymous = 0,
    /// The client must prove knowledge of the account password
    /// (C: AUTHTYPE_PASSWORD).
    password = 1,
};

/// A user account on a hub (C: Cedar USER).
pub const User = struct {
    /// Account name (owned by the hub).
    name: []u8,
    auth_type: UserAuthType,
    /// SHA-0 password hash — `hashPassword(password, name)` — set for
    /// `password` accounts (C: AUTHPASSWORD.HashedKey).
    password_hash: ?[digest_length]u8 = null,

    fn deinit(self: *User, allocator: Allocator) void {
        allocator.free(self.name);
    }
};

/// A virtual hub with its user directory (C: Cedar HUB subset).
pub const Hub = struct {
    allocator: Allocator,
    name: []u8,
    users: std.StringHashMapUnmanaged(*User) = .{},
    /// Hub admin secure password: `hashPassword(admin_password, administrator)`.
    /// A fresh hub stores random bytes so an unset admin password never
    /// authenticates (C: Server.c:2574 `Rand(h->SecurePassword, ...)`).
    secure_password: [digest_length]u8 = undefined,

    pub fn init(allocator: Allocator, name: []const u8) !Hub {
        var h: Hub = .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
        };
        std.crypto.random.bytes(&h.secure_password);
        return h;
    }

    pub fn deinit(self: *Hub) void {
        var it = self.users.valueIterator();
        while (it.next()) |u| {
            u.*.deinit(self.allocator);
            self.allocator.destroy(u.*);
        }
        self.users.deinit(self.allocator);
        self.allocator.free(self.name);
    }

    /// Set the hub admin (Administrator) password (C: Admin.c `HashPassword(
    /// h->SecurePassword, ADMINISTRATOR_USERNAME, password)`).
    pub fn setAdminPassword(self: *Hub, password: []const u8) void {
        self.secure_password = hashPassword(password, administrator_username);
    }

    /// Create a user account. `password` may be null for `anonymous` accounts.
    pub fn addUser(
        self: *Hub,
        name: []const u8,
        auth_type: UserAuthType,
        password: ?[]const u8,
    ) !*User {
        if (self.getUser(name) != null) return error.UserExists;

        const u = try self.allocator.create(User);
        errdefer self.allocator.destroy(u);
        u.* = .{
            .name = try self.allocator.dupe(u8, name),
            .auth_type = auth_type,
        };
        errdefer u.deinit(self.allocator);
        if (password) |pw| {
            u.password_hash = hashPassword(pw, name);
        }
        // Key the map with the hub-owned copy so the registry never holds a
        // reference to caller-owned storage (freeing `u.name` releases the
        // key in `deinit`/`removeUser`).
        try self.users.put(self.allocator, u.name, u);
        return u;
    }

    /// Look up a user by name, matching case-insensitively (C: `AcGetUser` →
    /// `SearchUser` with `StrCmpi`; SoftEther account names are not
    /// case-sensitive).
    pub fn getUser(self: *Hub, name: []const u8) ?*User {
        var it = self.users.iterator();
        while (it.next()) |entry| {
            if (eqlIgnoreCase(entry.key_ptr.*, name)) return entry.value_ptr.*;
        }
        return null;
    }

    /// Remove a user account, returning false if it did not exist. Matches
    /// case-insensitively like `getUser`.
    pub fn removeUser(self: *Hub, name: []const u8) bool {
        const u = self.getUser(name) orelse return false;
        // Remove from the map first: it reads the key (u.name) for its
        // equality check before we release it.
        _ = self.users.remove(u.name);
        u.deinit(self.allocator);
        self.allocator.destroy(u);
        return true;
    }
};

/// SoftEther password hash: SHA-0(password ‖ UPPER(username))
/// (C: `HashPassword`, Account.c:680 — note password is written first).
pub fn hashPassword(password: []const u8, username: []const u8) [digest_length]u8 {
    var h = Sha0.init();
    h.update(password);
    for (username) |c| {
        const upper = if (c >= 'a' and c <= 'z') c - 32 else c;
        h.update(&[_]u8{upper});
    }
    return h.final();
}

/// SoftEther secure password: SHA-0(password_hash ‖ random)
/// (C: `SecurePassword`, Sam.c:108).
pub fn securePassword(
    password_hash: *const [digest_length]u8,
    random: *const [digest_length]u8,
) [digest_length]u8 {
    var h = Sha0.init();
    h.update(password_hash);
    h.update(random);
    return h.final();
}

/// C: `SamAuthUserByAnonymous` (Sam.c:138) — a user may connect anonymously
/// iff the account exists and its auth type is `anonymous`.
pub fn authUserByAnonymous(hub: *Hub, username: []const u8) bool {
    const u = hub.getUser(username) orelse return false;
    return u.auth_type == .anonymous;
}

/// ASCII case-insensitive equality (C: `StrCmpi`).
fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const ua = if (ca >= 'a' and ca <= 'z') ca - 32 else ca;
        const ub = if (cb >= 'a' and cb <= 'z') cb - 32 else cb;
        if (ua != ub) return false;
    }
    return true;
}

/// C: `SamAuthUserByPassword` (Sam.c:552) — verifies the client's
/// `secure_password` (SHA-0(password_hash ‖ random)) against the stored hash.
///
/// The virtual `Administrator` account is always checked first against the
/// hub admin secure password, exactly like C. MS-CHAPv2 payloads are rejected.
pub fn authUserByPassword(
    hub: *Hub,
    username: []const u8,
    random: *const [digest_length]u8,
    secure_password: *const [digest_length]u8,
) bool {
    if (eqlIgnoreCase(username, administrator_username)) {
        const check = securePassword(&hub.secure_password, random);
        return mem.eql(u8, &check, secure_password);
    }

    const u = hub.getUser(username) orelse return false;
    if (u.auth_type != .password) return false;
    const stored = u.password_hash orelse return false;
    const check = securePassword(&stored, random);
    return mem.eql(u8, &check, secure_password);
}

/// Convert a plaintext password to a secure password using the challenge,
/// mirroring Protocol.c's PLAIN_PASSWORD branch: `hash_password =
/// HashPassword(username, plain)`, `secure = SecurePassword(hash_password,
/// random)`, then `SamAuthUserByPassword`.
pub fn authUserByPlainPassword(
    hub: *Hub,
    username: []const u8,
    random: *const [digest_length]u8,
    plain_password: []const u8,
) bool {
    if (mem.startsWith(u8, plain_password, mschap_v2_tag)) return false;
    const password_hash = hashPassword(plain_password, username);
    const secure = securePassword(&password_hash, random);
    return authUserByPassword(hub, username, random, &secure);
}

/// `is_empty_password` — whether the received secure password equals the one
/// derived from an empty plaintext password (C: Protocol.c:2700-2709).
pub fn isSecurePasswordOfEmptyPassword(
    username: []const u8,
    random: *const [digest_length]u8,
    secure_password: *const [digest_length]u8,
) bool {
    const password_hash = hashPassword("", username);
    const secure_empty = securePassword(&password_hash, random);
    return mem.eql(u8, &secure_empty, secure_password);
}

/// Result of the pack-based auth dispatch.
pub const AuthResult = struct {
    ok: bool,
    /// The authenticated account, or null for the virtual Administrator.
    user: ?*User = null,
    is_administrator: bool = false,
    is_empty_password: bool = false,
};

/// Dispatch a client login pack, mirroring Protocol.c:2558-2770.
///
/// Anonymous is attempted FIRST regardless of `authtype`; only if that fails
/// is the `authtype` switch consulted. For plain-password auth the plaintext
/// is converted to a secure password before verification.
pub fn authenticate(
    hub: *Hub,
    random: *const [digest_length]u8,
    pack: anytype,
) AuthResult {
    const username = pack.getStr("username") orelse return .{ .ok = false };
    const authtype = pack.getInt("authtype") orelse return .{ .ok = false };

    // Anonymous first (C: Protocol.c:2558).
    if (authUserByAnonymous(hub, username)) {
        return .{
            .ok = true,
            .user = hub.getUser(username),
            .is_empty_password = true,
        };
    }

    var result: AuthResult = .{ .ok = false };
    switch (authtype) {
        0 => {}, // CLIENT_AUTHTYPE_ANONYMOUS — already attempted
        1 => { // CLIENT_AUTHTYPE_PASSWORD
            const secure_password = pack.getData("secure_password") orelse
                return result;
            if (secure_password.len != digest_length) return result;
            const sp: *const [digest_length]u8 = secure_password[0..digest_length];
            result.ok = authUserByPassword(hub, username, random, sp);
            result.user = hub.getUser(username);
            result.is_administrator = eqlIgnoreCase(username, administrator_username);
            if (result.ok) {
                result.is_empty_password =
                    isSecurePasswordOfEmptyPassword(username, random, sp);
            }
        },
        2 => { // CLIENT_AUTHTYPE_PLAIN_PASSWORD
            // Zig client writes "password"; C 4.44 reads "plain_password".
            const plain = pack.getStr("password") orelse
                pack.getStr("plain_password") orelse return result;
            if (mem.startsWith(u8, plain, mschap_v2_tag)) return result;
            result.ok = authUserByPlainPassword(hub, username, random, plain);
            result.user = hub.getUser(username);
            result.is_administrator = eqlIgnoreCase(username, administrator_username);
        },
        else => return result, // ticket/cert unsupported in M1
    }
    return result;
}

// ============================================================================
// Tests
// ============================================================================

const protocol_auth = @import("../protocol/auth.zig");
const Pack = @import("../protocol/pack.zig").Pack;

/// Deterministic 20-byte random used as the auth challenge.
fn fixedRandom() [digest_length]u8 {
    var r: [digest_length]u8 = undefined;
    for (&r, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 256);
    return r;
}

/// Build a login pack the way the client would, using the client's own
/// SHA-0 hashing so the end-to-end path is exercised with real wire values.
fn buildPasswordAuthPack(
    allocator: Allocator,
    username: []const u8,
    password: []const u8,
    random: *const [digest_length]u8,
) ![]u8 {
    var pack = Pack.init(allocator);
    defer pack.deinit();
    try pack.addStr("method", "login");
    try pack.addStr("hubname", "VPN");
    try pack.addStr("username", username);
    try pack.addInt("authtype", @intFromEnum(protocol_auth.AuthType.password));
    const password_hash = protocol_auth.hashPassword(password, username);
    const secure = protocol_auth.computeSecurePassword(&password_hash, random);
    try pack.addData("secure_password", &secure);
    return pack.toBytes(allocator);
}

test "server.auth hub registry owns its keys" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();

    // Caller-mutable buffer — the hub must not retain a reference to it.
    var name_buf: [8]u8 = undefined;
    const name = name_buf[0..5];
    @memcpy(name, "alice");
    _ = try hub.addUser(name, .password, "hunter2");

    // Mutate the caller's buffer after registration.
    @memcpy(name, "EVIL!");

    // Lookups with the original name still resolve to the stored copy.
    try testing.expect(hub.getUser("alice") != null);
    try testing.expect(hub.getUser(name) == null);

    // Removal works via the original name and frees the stored key.
    try testing.expect(hub.removeUser("alice"));
    try testing.expect(hub.getUser("alice") == null);
}

test "server.auth hashPassword matches the Zig client" {
    const pw = "hunter2";
    const user = "Alice";
    const server = hashPassword(pw, user);
    const client = protocol_auth.hashPassword(pw, user);
    try testing.expectEqualSlices(u8, &server, &client);

    // Case-insensitive username (uppercased for hashing).
    const lower = hashPassword(pw, "alice");
    try testing.expectEqualSlices(u8, &server, &lower);

    // Empty password round-trips deterministically.
    const empty = hashPassword("", "Bob");
    try testing.expectEqualSlices(u8, &empty, &hashPassword("", "bob"));
}

test "server.auth securePassword matches the Zig client" {
    const user = "Alice";
    const server_hash = hashPassword("s3cret", user);
    const client_hash = protocol_auth.hashPassword("s3cret", user);
    const challenge = fixedRandom();
    const server = securePassword(&server_hash, &challenge);
    const client = protocol_auth.computeSecurePassword(&client_hash, &challenge);
    try testing.expectEqualSlices(u8, &server, &client);
}

test "server.auth password account authenticates" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();

    _ = try hub.addUser("alice", .password, "hunter2");

    const random = fixedRandom();
    const pw_hash = hashPassword("hunter2", "alice");
    const secure = securePassword(&pw_hash, &random);
    try testing.expect(authUserByPassword(&hub, "alice", &random, &secure));
    try testing.expect(!authUserByPassword(&hub, "alice", &random, &blk: {
        const other = securePassword(&hashPassword("wrong", "alice"), &random);
        break :blk other;
    }));

    // Unknown user and wrong auth type both fail.
    try testing.expect(!authUserByPassword(&hub, "bob", &random, &secure));
    _ = try hub.addUser("anon", .anonymous, null);
    try testing.expect(!authUserByPassword(&hub, "anon", &random, &secure));
}

test "server.auth anonymous account authenticates" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();

    try testing.expect(!authUserByAnonymous(&hub, "ghost"));
    _ = try hub.addUser("guest", .anonymous, null);
    try testing.expect(authUserByAnonymous(&hub, "guest"));
    _ = try hub.addUser("alice", .password, "x");
    try testing.expect(!authUserByAnonymous(&hub, "alice"));
}

test "server.auth administrator authenticates against hub admin password" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();

    hub.setAdminPassword("root");

    const random = fixedRandom();
    const pw_hash = hashPassword("root", administrator_username);
    const secure = securePassword(&pw_hash, &random);
    try testing.expect(authUserByPassword(&hub, "Administrator", &random, &secure));

    const wrong = securePassword(&hashPassword("nope", administrator_username), &random);
    try testing.expect(!authUserByPassword(&hub, "Administrator", &random, &wrong));

    // Case-insensitive administrator lookup (StrCmpi).
    try testing.expect(authUserByPassword(&hub, "administrator", &random, &secure));

    // Unset admin password never authenticates.
    var fresh = try Hub.init(testing.allocator, "VPN2");
    defer fresh.deinit();
    try testing.expect(!authUserByPassword(&fresh, "Administrator", &random, &secure));
}

test "server.auth plain password interop" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();
    _ = try hub.addUser("alice", .password, "hunter2");

    const random = fixedRandom();
    try testing.expect(authUserByPlainPassword(&hub, "alice", &random, "hunter2"));
    try testing.expect(!authUserByPlainPassword(&hub, "alice", &random, "wrong"));
    try testing.expect(!authUserByPlainPassword(&hub, "bob", &random, "hunter2"));
    try testing.expect(!authUserByPlainPassword(&hub, "alice", &random, mschap_v2_tag ++ "junk"));
}

test "server.auth empty password detection" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();
    _ = try hub.addUser("alice", .password, "");

    const random = fixedRandom();
    const pw_hash = hashPassword("", "alice");
    const secure = securePassword(&pw_hash, &random);
    try testing.expect(authUserByPassword(&hub, "alice", &random, &secure));
    try testing.expect(isSecurePasswordOfEmptyPassword("alice", &random, &secure));
    try testing.expect(!isSecurePasswordOfEmptyPassword("alice", &random, &blk: {
        const other = securePassword(&hashPassword("x", "alice"), &random);
        break :blk other;
    }));
}

test "server.auth pack dispatch end-to-end with client hashing" {
    var hub = try Hub.init(testing.allocator, "VPN");
    defer hub.deinit();
    _ = try hub.addUser("alice", .password, "hunter2");
    _ = try hub.addUser("guest", .anonymous, null);
    hub.setAdminPassword("root");

    const random = fixedRandom();

    // Password auth pack built with the client's own SHA-0 hashing.
    {
        const buf = try buildPasswordAuthPack(testing.allocator, "alice", "hunter2", &random);
        defer testing.allocator.free(buf);

        var pack = try Pack.fromBytes(testing.allocator, buf);
        defer pack.deinit();

        const res = authenticate(&hub, &random, &pack);
        try testing.expect(res.ok);
        try testing.expect(res.user != null);
        try testing.expectEqual(UserAuthType.password, res.user.?.auth_type);
        try testing.expect(!res.is_administrator);
        try testing.expect(!res.is_empty_password);
    }

    // Anonymous always wins even when the pack claims password auth.
    {
        const buf = try buildPasswordAuthPack(testing.allocator, "guest", "whatever", &random);
        defer testing.allocator.free(buf);
        var pack = try Pack.fromBytes(testing.allocator, buf);
        defer pack.deinit();

        const res = authenticate(&hub, &random, &pack);
        try testing.expect(res.ok);
        try testing.expectEqual(UserAuthType.anonymous, res.user.?.auth_type);
        try testing.expect(res.is_empty_password);
    }

    // Administrator via admin password.
    {
        const buf = try buildPasswordAuthPack(testing.allocator, "Administrator", "root", &random);
        defer testing.allocator.free(buf);
        var pack = try Pack.fromBytes(testing.allocator, buf);
        defer pack.deinit();

        const res = authenticate(&hub, &random, &pack);
        try testing.expect(res.ok);
        try testing.expect(res.is_administrator);
    }

    // Wrong password rejected.
    {
        const buf = try buildPasswordAuthPack(testing.allocator, "alice", "nope", &random);
        defer testing.allocator.free(buf);
        var pack = try Pack.fromBytes(testing.allocator, buf);
        defer pack.deinit();

        const res = authenticate(&hub, &random, &pack);
        try testing.expect(!res.ok);
    }

    // Unknown username rejected.
    {
        const buf = try buildPasswordAuthPack(testing.allocator, "mallory", "hunter2", &random);
        defer testing.allocator.free(buf);
        var pack = try Pack.fromBytes(testing.allocator, buf);
        defer pack.deinit();

        const res = authenticate(&hub, &random, &pack);
        try testing.expect(!res.ok);
    }

    // Empty password flagged as empty.
    {
        _ = try hub.addUser("nopass", .password, "");
        const buf = try buildPasswordAuthPack(testing.allocator, "nopass", "", &random);
        defer testing.allocator.free(buf);
        var pack = try Pack.fromBytes(testing.allocator, buf);
        defer pack.deinit();

        const res = authenticate(&hub, &random, &pack);
        try testing.expect(res.ok);
        try testing.expect(res.is_empty_password);
    }
}
