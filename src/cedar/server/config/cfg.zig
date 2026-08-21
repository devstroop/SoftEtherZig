//! Cfg — SoftEther text-format configuration tree (C: Mayaqua/Cfg.c, ~2,420 LOC).
//!
//! The on-disk server configuration is a nested tree of named *folders*
//! (`declare <folder> { ... }`) holding typed *items* on single lines:
//!
//! ```text
//! declare ServerConfiguration
//! {
//!  string HostName myserver
//!  uint Port 443
//!  uint64 MaxBytes 123456789
//!  bool DisableNat false
//!  byte CipherKey <base64>
//!
//!  declare VirtualHUB
//!  {
//!      declare DEFAULT
//!      {
//!      }
//!  }
//! }
//! ```
//!
//! ## Wire fidelity (C `Cfg.c`)
//!
//! - Item line: `<type> <name> <value>`, one per line. Types: `string`,
//!   `uint` (decimal u32), `uint64` (decimal u64), `bool` (`true`/`false`),
//!   `byte` (Base64).
//! - Folders: `declare <name>` declares a folder that `{` / `}` delimit (C
//!   only enters a declared folder on the following `{`). Indentation is tabs
//!   (one per depth) in C output; the parser accepts any leading whitespace.
//!   Structure is validated: every `declare` needs its opening `{`, and the
//!   `{` / `}` delimiters must stand alone on their line.
//! - String values are written raw (rest of line) unless they are empty, wrap
//!   in whitespace, or contain `"` or `\` — then they are quoted with `\` and
//!   `"` escaped. The reader unquotes/unescapes exactly that form.
//! - Lines end with `\r\n` in C output (the reader accepts either).
//!
//! ## CFG_RW
//!
//! `saveToFile` mirrors `CfgSave`: the existing file is copied to `<path>~`
//! (backup-on-modify) and the new content is written atomically via a temp
//! file + rename.
//!
//! ## Out of scope
//!
//! - Binary format (`CfgBinary`) is deferred (plan §6.6).
//! - Item comment columns (`CfgWriteLineText`'s `comment` param) are dropped;
//!   comments are not produced by `SiWriteConfiguration` for the core config.
//! - Full C delete/rename/iterate API surface is trimmed to what the server
//!   loader (#86) and admin RPC (#87-#91) need.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;
const base64 = std.base64;

// ============================================================================
// Types
// ============================================================================

/// Item value type (C: `CFG_STRING/INT/INT64/BOOL/BYTE`, `CfgItemType`).
pub const ItemType = enum {
    string,
    uint,
    uint64,
    boolean,
    bytes,

    /// Wire type tag for a given item type (C: `CfgItemTypeToStr`).
    pub fn tag(self: ItemType) []const u8 {
        return switch (self) {
            .string => "string",
            .uint => "uint",
            .uint64 => "uint64",
            .boolean => "bool",
            .bytes => "byte",
        };
    }
};

/// Typed item value. `string` and `bytes` payloads are owned by the item.
pub const Value = union(ItemType) {
    string: []u8,
    uint: u32,
    uint64: u64,
    boolean: bool,
    bytes: []u8,

    fn wireType(self: Value) ItemType {
        return switch (self) {
            .string => .string,
            .uint => .uint,
            .uint64 => .uint64,
            .boolean => .boolean,
            .bytes => .bytes,
        };
    }
};

/// A single typed configuration value. `name` and the owned value payloads
/// are freed by `Folder.deinit`.
pub const Item = struct {
    name: []u8,
    value: Value,
};

/// A named configuration folder (C: `CFG_FOLDER`). Owns its name, child
/// folders and items; freed recursively by `Cfg.deinit`.
pub const Folder = struct {
    allocator: Allocator,
    name: []u8,
    parent: ?*Folder = null,
    folders: std.ArrayListUnmanaged(*Folder) = .{},
    items: std.ArrayListUnmanaged(Item) = .{},

    fn init(allocator: Allocator, name: []const u8) !*Folder {
        const self = try allocator.create(Folder);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .name = try allocator.dupe(u8, name),
        };
        return self;
    }

    pub fn deinit(self: *Folder) void {
        for (self.folders.items) |child| child.deinit();
        self.folders.deinit(self.allocator);
        for (self.items.items) |item| {
            self.allocator.free(item.name);
            switch (item.value) {
                .string => |s| self.allocator.free(s),
                .bytes => |b| self.allocator.free(b),
                else => {},
            }
        }
        self.items.deinit(self.allocator);
        self.allocator.free(self.name);
        self.allocator.destroy(self);
    }

    /// Create and append a child folder with `name`. If a child with that
    /// name already exists it is returned instead (C: `CfgCreateFolder`).
    /// Names must be single tokens without syntax characters (see
    /// `validName`), otherwise the tree would not round-trip through the
    /// text format.
    pub fn addFolder(self: *Folder, name: []const u8) Error!*Folder {
        if (!validName(name)) return Error.SyntaxError;
        if (self.getFolder(name)) |existing| return existing;
        const child = try Folder.init(self.allocator, name);
        errdefer child.deinit();
        child.parent = self;
        try self.folders.append(self.allocator, child);
        return child;
    }

    /// Append an item, replacing any existing item of the same name
    /// (C: `CfgAddItem`).
    pub fn addItem(self: *Folder, name: []const u8, value: Value) Error!void {
        if (!validName(name)) return Error.SyntaxError;
        if (self.getItem(name)) |existing| {
            freeValue(self.allocator, existing.value);
            existing.value = value;
            return;
        }
        try self.items.append(self.allocator, .{
            .name = try self.allocator.dupe(u8, name),
            .value = value,
        });
    }

    /// First child folder named `name`, or null.
    pub fn getFolder(self: *const Folder, name: []const u8) ?*Folder {
        for (self.folders.items) |child| {
            if (mem.eql(u8, child.name, name)) return child;
        }
        return null;
    }

    /// Item named `name`, or null.
    pub fn getItem(self: *const Folder, name: []const u8) ?*Item {
        for (self.items.items) |*item| {
            if (mem.eql(u8, item.name, name)) return item;
        }
        return null;
    }

    /// Walk a `/`-separated path (C: `CfgGetFolder`); empty path returns self.
    pub fn getByPath(self: *const Folder, path: []const u8) ?*Folder {
        if (path.len == 0) return @constCast(self);
        var it = std.mem.splitScalar(u8, path, '/');
        var cur: *const Folder = self;
        while (it.next()) |part| {
            if (part.len == 0) continue;
            const next = cur.getFolder(part) orelse return null;
            cur = next;
        }
        return @constCast(cur);
    }

    /// Look up an item by `/`-separated path with an optional trailing item
    /// name after the last `/` (C: `CfgGetItem` is folder-local; this is the
    /// loader convenience used by #86).
    pub fn getItemByPath(self: *const Folder, path: []const u8) ?*Item {
        const last_slash = std.mem.lastIndexOfScalar(u8, path, '/');
        const folder_part = if (last_slash) |i| path[0..i] else "";
        const item_name = if (last_slash) |i| path[i + 1 ..] else path;
        if (item_name.len == 0) return null;
        const folder = self.getByPath(folder_part) orelse return null;
        return folder.getItem(item_name);
    }

    /// Typed value access with a default (C: `CfgGetStr/Int/Int64/Bool/Byte`).
    pub fn getStr(self: *const Folder, path: []const u8, default: []const u8) []const u8 {
        const item = self.getItemByPath(path) orelse return default;
        return switch (item.value) {
            .string => |s| s,
            else => default,
        };
    }

    pub fn getUint(self: *const Folder, path: []const u8, default: u32) u32 {
        const item = self.getItemByPath(path) orelse return default;
        return switch (item.value) {
            .uint => |v| v,
            else => default,
        };
    }

    pub fn getUint64(self: *const Folder, path: []const u8, default: u64) u64 {
        const item = self.getItemByPath(path) orelse return default;
        return switch (item.value) {
            .uint64 => |v| v,
            .uint => |v| v,
            else => default,
        };
    }

    pub fn getBool(self: *const Folder, path: []const u8, default: bool) bool {
        const item = self.getItemByPath(path) orelse return default;
        return switch (item.value) {
            .boolean => |v| v,
            else => default,
        };
    }

    pub fn getBytes(self: *const Folder, path: []const u8) ?[]const u8 {
        const item = self.getItemByPath(path) orelse return null;
        return switch (item.value) {
            .bytes => |b| b,
            else => null,
        };
    }

    /// Typed setters, replace-or-create (C: `CfgAddStr/Int/...`). The name is
    /// folder-local: unlike the getters, it is NOT a `/`-separated path.
    pub fn setStr(self: *Folder, name: []const u8, value: []const u8) !void {
        if (!validName(name)) return error.SyntaxError;
        try self.addItem(name, .{ .string = try self.allocator.dupe(u8, value) });
    }

    pub fn setUint(self: *Folder, name: []const u8, value: u32) !void {
        try self.addItem(name, .{ .uint = value });
    }

    pub fn setUint64(self: *Folder, name: []const u8, value: u64) !void {
        try self.addItem(name, .{ .uint64 = value });
    }

    pub fn setBool(self: *Folder, name: []const u8, value: bool) !void {
        try self.addItem(name, .{ .boolean = value });
    }

    pub fn setBytes(self: *Folder, name: []const u8, value: []const u8) !void {
        if (!validName(name)) return error.SyntaxError;
        try self.addItem(name, .{ .bytes = try self.allocator.dupe(u8, value) });
    }
};

/// Root of a configuration tree (C: `Cfg` / `CfgCreateRoot`).
pub const Cfg = struct {
    allocator: Allocator,
    root: *Folder,

    pub fn init(allocator: Allocator) !*Cfg {
        const self = try allocator.create(Cfg);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .root = try Folder.init(allocator, ""),
        };
        return self;
    }

    pub fn deinit(self: *Cfg) void {
        self.root.deinit();
        self.allocator.destroy(self);
    }

    pub fn getFolder(self: *const Cfg, path: []const u8) ?*Folder {
        return self.root.getByPath(path);
    }

    /// Serialize the tree to `buf` in the C text format.
    pub fn writeToBuffer(self: *const Cfg, buf: *std.ArrayList(u8)) !void {
        try writeFolderChildren(self.allocator, buf, self.root, 0);
    }

    /// Round-trip helper used by tests and #86: serialize and re-parse.
    pub fn toOwnedText(self: *const Cfg, allocator: Allocator) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(allocator);
        try self.writeToBuffer(&buf);
        return buf.toOwnedSlice(allocator);
    }

    /// CFG_RW: write to `path` in `dir`, backing up the previous file to
    /// `path~` (C: `CfgSave`).
    pub fn saveToFile(self: *const Cfg, dir: std.fs.Dir, path: []const u8) !void {
        try self.saveToFileEx(dir, path, true);
    }

    /// CFG_RW with the backup policy applied by the caller (C
    /// `SaveCfgRwEx` + `CfgRw->DontBackup`): `backup == false` skips the
    /// `<path>~` copy entirely.
    pub fn saveToFileEx(self: *const Cfg, dir: std.fs.Dir, path: []const u8, backup: bool) !void {
        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(self.allocator);
        try self.writeToBuffer(&buf);

        // Backup-on-modify: copy the current file to `<path>~` before
        // replacing it (C: `CfgSave` → `FileCopy(filename, "~")`).
        if (backup) {
            const backup_path = try std.fmt.allocPrint(self.allocator, "{s}~", .{path});
            defer self.allocator.free(backup_path);
            dir.copyFile(path, dir, backup_path, .{}) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
        }

        // Atomic replace: temp file + rename.
        const tmp_path = try std.fmt.allocPrint(self.allocator, "{s}.tmp", .{path});
        defer self.allocator.free(tmp_path);
        {
            const f = try dir.createFile(tmp_path, .{});
            defer f.close();
            try f.writeAll(buf.items);
        }
        try dir.rename(tmp_path, path);
    }

    /// Load and parse a tree from `path` in `dir` (C: `CfgLoad`).
    pub fn loadFromFile(allocator: Allocator, dir: std.fs.Dir, path: []const u8) !*Cfg {
        const text = try dir.readFileAlloc(allocator, path, 16 * 1024 * 1024);
        defer allocator.free(text);
        return parse(allocator, text);
    }
};

// ============================================================================
// Text format
// ============================================================================

/// Parse error union for malformed configuration text.
pub const Error = error{ SyntaxError, OutOfMemory };

/// Parse a configuration tree from `text` (C: `CfgReadText`).
pub fn parse(allocator: Allocator, text: []const u8) Error!*Cfg {
    const cfg = try Cfg.init(allocator);
    errdefer cfg.deinit();

    // Stack of open folders; root is implicitly open.
    var stack = std.ArrayListUnmanaged(*Folder){};
    defer stack.deinit(allocator);
    try stack.append(allocator, cfg.root);

    // A folder declared via `declare X` whose opening `{` we are still
    // waiting for (C only enters a declared folder on the following `{`).
    var pending: ?*Folder = null;

    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 0;
    while (lines.next()) |raw_line| {
        line_no += 1;
        const line = std.mem.trimRight(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        const first = firstToken(line) orelse continue;
        const first_start = @intFromPtr(first.ptr) - @intFromPtr(line.ptr);

        if (mem.eql(u8, first, "declare")) {
            if (pending != null) return syntaxError("missing '{' after previous declare", line_no);
            const rest = std.mem.trimLeft(u8, line[first_start + first.len ..], " \t");
            const name = firstToken(rest) orelse return syntaxError("declare without folder name", line_no);
            const name_start = @intFromPtr(name.ptr) - @intFromPtr(rest.ptr);
            if (std.mem.indexOfNone(u8, rest[name_start + name.len ..], " \t") != null) {
                return syntaxError("extra token after folder name", line_no);
            }
            const current = stack.items[stack.items.len - 1];
            pending = try current.addFolder(name);
            continue;
        }

        if (mem.eql(u8, first, "{")) {
            if (std.mem.indexOfNone(u8, line[first_start + 1 ..], " \t") != null) {
                return syntaxError("unexpected token after '{'", line_no);
            }
            const declared = pending orelse return syntaxError("'{' without a preceding declare", line_no);
            pending = null;
            try stack.append(allocator, declared);
            continue;
        }

        if (mem.eql(u8, first, "}")) {
            if (std.mem.indexOfNone(u8, line[first_start + 1 ..], " \t") != null) {
                return syntaxError("unexpected token after '}'", line_no);
            }
            if (pending != null) return syntaxError("missing '{' after previous declare", line_no);
            if (stack.items.len <= 1) return syntaxError("unmatched '}'", line_no);
            _ = stack.pop();
            continue;
        }

        // Item line: `<type> <name> <value>`.
        if (pending != null) return syntaxError("item before '{' of folder", line_no);
        const current = stack.items[stack.items.len - 1];
        try parseItem(current, line, first, line_no);
    }

    if (stack.items.len != 1 or pending != null) return syntaxError("unclosed folder at end of input", line_no);
    return cfg;
}

fn syntaxError(msg: []const u8, line_no: usize) Error {
    std.log.scoped(.cfg).warn("cfg: {s} (line {d})", .{ msg, line_no });
    return Error.SyntaxError;
}

fn firstToken(line: []const u8) ?[]const u8 {
    const start = std.mem.indexOfNone(u8, line, " \t") orelse return null;
    const after = line[start..];
    const end = std.mem.indexOfAny(u8, after, " \t") orelse after.len;
    return after[0..end];
}

fn parseItem(folder: *Folder, line: []const u8, tag: []const u8, line_no: usize) Error!void {
    const tag_start = @intFromPtr(tag.ptr) - @intFromPtr(line.ptr);
    const rest = std.mem.trimLeft(u8, line[tag_start + tag.len ..], " \t");
    const name = firstToken(rest) orelse return syntaxError("item without name", line_no);
    const value_raw = rest[name.len..];

    if (mem.eql(u8, tag, "string")) {
        // Leading separator whitespace after the name is formatting only;
        // the string value keeps everything else (C: value is rest-of-line).
        const value = std.mem.trimLeft(u8, value_raw, " \t");
        try folder.addItem(name, .{ .string = try unquote(folder.allocator, value) });
    } else {
        const value = std.mem.trim(u8, value_raw, " \t");
        if (mem.eql(u8, tag, "uint")) {
            const v = std.fmt.parseInt(u32, value, 10) catch {
                return syntaxError("bad uint value", line_no);
            };
            try folder.addItem(name, .{ .uint = v });
        } else if (mem.eql(u8, tag, "uint64")) {
            const v = std.fmt.parseInt(u64, value, 10) catch {
                return syntaxError("bad uint64 value", line_no);
            };
            try folder.addItem(name, .{ .uint64 = v });
        } else if (mem.eql(u8, tag, "bool")) {
            const v = parseBool(value) orelse return syntaxError("bad bool value", line_no);
            try folder.addItem(name, .{ .boolean = v });
        } else if (mem.eql(u8, tag, "byte")) {
            try folder.addItem(name, .{ .bytes = try decodeBase64(folder.allocator, value) });
        } else {
            return syntaxError("unknown item type", line_no);
        }
    }
}

fn parseBool(s: []const u8) ?bool {
    if (mem.eql(u8, s, "true")) return true;
    if (mem.eql(u8, s, "false")) return false;
    return null;
}

fn freeValue(allocator: Allocator, value: Value) void {
    switch (value) {
        .string => |s| allocator.free(s),
        .bytes => |b| allocator.free(b),
        else => {},
    }
}

/// Names are emitted verbatim, and the text format tokenizes them on
/// whitespace and treats `{` `}` `"` `\` `/` as syntax. Reject those at
/// mutation time so any tree that can be built can also round-trip.
fn validName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        switch (c) {
            ' ', '\t', '{', '}', '"', '\\', '/' => return false,
            else => {},
        }
    }
    return true;
}

// ============================================================================
// Escaping / encoding
// ============================================================================

/// Whether a string needs the quoted form on the wire (empty, edge
/// whitespace, or a `"` / `\` inside).
fn needsQuoting(s: []const u8) bool {
    if (s.len == 0) return true;
    if (s[0] == ' ' or s[0] == '\t') return true;
    if (s[s.len - 1] == ' ' or s[s.len - 1] == '\t') return true;
    return std.mem.indexOfAny(u8, s, "\"\\") != null;
}

/// Read a string value: if it starts with `"`, unescape to the closing quote;
/// otherwise the value is verbatim (C: `CfgReadItemText` quoted handling).
fn unquote(allocator: Allocator, value: []const u8) ![]u8 {
    if (value.len == 0 or value[0] != '"') return allocator.dupe(u8, value);

    const out = try allocator.alloc(u8, value.len);
    errdefer allocator.free(out);
    var n: usize = 0;
    var i: usize = 1;
    while (i < value.len) : (i += 1) {
        const c = value[i];
        if (c == '\\' and i + 1 < value.len) {
            i += 1;
            out[n] = value[i];
            n += 1;
        } else if (c == '"') {
            // Only whitespace may follow the closing quote; anything else
            // means the value is malformed and would be silently dropped.
            if (std.mem.indexOfNone(u8, value[i + 1 ..], " \t") != null) {
                return Error.SyntaxError;
            }
            return allocator.realloc(out, n);
        } else {
            out[n] = c;
            n += 1;
        }
    }
    return Error.SyntaxError; // unterminated quote
}

fn decodeBase64(allocator: Allocator, s: []const u8) ![]u8 {
    // Strip interior whitespace C's `StrToBin` tolerates.
    const stripped = try allocator.alloc(u8, s.len);
    defer allocator.free(stripped);
    var n: usize = 0;
    for (s) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') {
            stripped[n] = c;
            n += 1;
        }
    }

    const decoder = base64.standard.Decoder;
    const out_len = decoder.calcSizeForSlice(stripped[0..n]) catch return Error.SyntaxError;
    const out = try allocator.alloc(u8, out_len);
    defer allocator.free(out);
    decoder.decode(out, stripped[0..n]) catch {
        return Error.SyntaxError;
    };
    return allocator.dupe(u8, out);
}

// ============================================================================
// Writing
// ============================================================================

fn writeFolderChildren(allocator: Allocator, buf: *std.ArrayList(u8), folder: *const Folder, depth: usize) !void {
    for (folder.items.items) |item| {
        try writeIndent(allocator, buf, depth);
        try buf.appendSlice(allocator, item.value.wireType().tag());
        try buf.append(allocator, ' ');
        try buf.appendSlice(allocator, item.name);
        try buf.append(allocator, ' ');
        try writeValue(allocator, buf, item.value);
        try buf.appendSlice(allocator, "\r\n");
    }
    for (folder.folders.items) |child| {
        try writeIndent(allocator, buf, depth);
        try buf.appendSlice(allocator, "declare ");
        try buf.appendSlice(allocator, child.name);
        try buf.appendSlice(allocator, "\r\n");
        try writeIndent(allocator, buf, depth);
        try buf.appendSlice(allocator, "{\r\n");
        try writeFolderChildren(allocator, buf, child, depth + 1);
        try writeIndent(allocator, buf, depth);
        try buf.appendSlice(allocator, "}\r\n");
    }
}

fn writeIndent(allocator: Allocator, buf: *std.ArrayList(u8), depth: usize) !void {
    try buf.appendNTimes(allocator, '\t', depth);
}

fn writeValue(allocator: Allocator, buf: *std.ArrayList(u8), value: Value) !void {
    switch (value) {
        .string => |s| {
            if (needsQuoting(s)) {
                try buf.append(allocator, '"');
                for (s) |c| {
                    switch (c) {
                        '\\' => try buf.appendSlice(allocator, "\\\\"),
                        '"' => try buf.appendSlice(allocator, "\\\""),
                        else => try buf.append(allocator, c),
                    }
                }
                try buf.append(allocator, '"');
            } else {
                try buf.appendSlice(allocator, s);
            }
        },
        .uint => |v| try buf.writer(allocator).print("{d}", .{v}),
        .uint64 => |v| try buf.writer(allocator).print("{d}", .{v}),
        .boolean => |v| try buf.appendSlice(allocator, if (v) "true" else "false"),
        .bytes => |b| {
            const encoder = base64.standard.Encoder;
            const len = encoder.calcSize(b.len);
            const dest = try allocator.alloc(u8, len);
            defer allocator.free(dest);
            const encoded = encoder.encode(dest, b);
            try buf.appendSlice(allocator, encoded);
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

test "server.cfg parse and lookup" {
    const allocator = testing.allocator;
    const text =
        \\declare ServerConfiguration
        \\{
        \\  string HostName myserver
        \\  uint Port 443
        \\  uint64 MaxBytes 123456789
        \\  bool UseNat true
        \\  byte Key aGVsbG8=
        \\
        \\  declare VirtualHUB
        \\  {
        \\    declare DEFAULT
        \\    {
        \\      bool DisableUserChangePassword true
        \\    }
        \\  }
        \\}
    ;
    const cfg = try parse(allocator, text);
    defer cfg.deinit();

    try testing.expectEqualStrings("myserver", cfg.getFolder("ServerConfiguration").?.getStr("HostName", ""));
    try testing.expectEqual(@as(u32, 443), cfg.getFolder("ServerConfiguration").?.getUint("Port", 0));
    try testing.expectEqual(@as(u64, 123456789), cfg.getFolder("ServerConfiguration").?.getUint64("MaxBytes", 0));
    try testing.expect(cfg.getFolder("ServerConfiguration").?.getBool("UseNat", false));
    const key = cfg.getFolder("ServerConfiguration").?.getBytes("Key");
    try testing.expectEqualStrings("hello", key.?);
    try testing.expect(cfg.getFolder("ServerConfiguration/VirtualHUB/DEFAULT").?.getBool("DisableUserChangePassword", false));
}

test "server.cfg round-trip is byte-stable" {
    const allocator = testing.allocator;
    const text =
        "declare ServerConfiguration\r\n" ++
        "{\r\n" ++
        "\tstring HostName myserver\r\n" ++
        "\tuint Port 443\r\n" ++
        "\tdeclare VirtualHUB\r\n" ++
        "\t{\r\n" ++
        "\t}\r\n" ++
        "}\r\n";
    const cfg = try parse(allocator, text);
    defer cfg.deinit();

    const out = try cfg.toOwnedText(allocator);
    defer allocator.free(out);
    try testing.expectEqualStrings(text, out);
}

test "server.cfg string quoting and escaping" {
    const allocator = testing.allocator;
    const text =
        "declare ServerConfiguration\r\n" ++
        "{\r\n" ++
        "\tstring Raw has spaces inside\r\n" ++
        "\tstring Quoted \"a \\\"quoted\\\" \\\\ path\"\r\n" ++
        "\tstring Empty \"\"\r\n" ++
        "\tstring Edge \" padded \"\r\n" ++
        "}\r\n";
    const cfg = try parse(allocator, text);
    defer cfg.deinit();

    const sc = cfg.getFolder("ServerConfiguration").?;
    try testing.expectEqualStrings("has spaces inside", sc.getStr("Raw", ""));
    try testing.expectEqualStrings("a \"quoted\" \\ path", sc.getStr("Quoted", ""));
    try testing.expectEqualStrings("", sc.getStr("Empty", "?"));
    try testing.expectEqualStrings(" padded ", sc.getStr("Edge", "?"));

    // Writer re-quotes edge cases identically.
    const out = try cfg.toOwnedText(allocator);
    defer allocator.free(out);
    try testing.expectEqualStrings(text, out);
}

test "server.cfg mutate and rewrite" {
    const allocator = testing.allocator;
    const cfg = try Cfg.init(allocator);
    defer cfg.deinit();

    const sc = try cfg.root.addFolder("ServerConfiguration");
    try sc.setStr("HostName", "new host");
    try sc.setUint("Port", 443);
    try sc.setBool("UseNat", false);
    try sc.setBytes("Key", &.{ 1, 2, 3, 4 });
    const hub = try sc.addFolder("VirtualHUB");
    _ = try hub.addFolder("DEFAULT");

    try testing.expectEqualStrings("new host", sc.getStr("HostName", ""));
    try testing.expectEqual(@as(u32, 443), sc.getUint("Port", 0));
    try testing.expect(!sc.getBool("UseNat", true));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, sc.getBytes("Key").?);
    try testing.expect(cfg.getFolder("ServerConfiguration/VirtualHUB/DEFAULT") != null);

    // Replace an existing item (setStr on existing name).
    try sc.setStr("HostName", "renamed");
    try testing.expectEqualStrings("renamed", sc.getStr("HostName", ""));

    const out = try cfg.toOwnedText(allocator);
    defer allocator.free(out);
    try testing.expectEqualStrings(
        "declare ServerConfiguration\r\n" ++
            "{\r\n" ++
            "\tstring HostName renamed\r\n" ++
            "\tuint Port 443\r\n" ++
            "\tbool UseNat false\r\n" ++
            "\tbyte Key AQIDBA==\r\n" ++
            "\tdeclare VirtualHUB\r\n" ++
            "\t{\r\n" ++
            "\t\tdeclare DEFAULT\r\n" ++
            "\t\t{\r\n" ++
            "\t\t}\r\n" ++
            "\t}\r\n" ++
            "}\r\n",
        out,
    );
}

test "server.cfg malformed input rejected" {
    const allocator = testing.allocator;

    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n{\n\tfrobnicate A 1\n}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n{\n\tuint Bad notanumber\n}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n{\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n{\n\tstring A \"unterminated\n}\n"));

    // Structural validation: `declare` needs its `{`, delimiters must stand
    // alone, and a quoted value may not have trailing junk.
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\nstring A v\n}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X {\n}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n{ }\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n{\n\tstring A \"v\" trailing\n}\n"));
    try testing.expectError(Error.SyntaxError, parse(allocator, "declare X\n"));
}

test "server.cfg rejects unsafe folder/item names" {
    const allocator = testing.allocator;
    const cfg = try Cfg.init(allocator);
    defer cfg.deinit();

    try testing.expectError(Error.SyntaxError, cfg.root.addFolder("bad name"));
    try testing.expectError(Error.SyntaxError, cfg.root.addFolder("a/b"));
    try testing.expectError(Error.SyntaxError, cfg.root.addFolder("x{y"));
    var val: [1]u8 = .{'v'};
    try testing.expectError(Error.SyntaxError, cfg.root.addItem("x y", .{ .string = &val }));
    try testing.expectError(Error.SyntaxError, cfg.root.setStr("A/B", "v"));
    try testing.expectError(Error.SyntaxError, cfg.root.setStr("", "v"));
}

test "server.cfg CFG_RW save/load with backup" {
    const allocator = testing.allocator;

    const cfg = try Cfg.init(allocator);
    defer cfg.deinit();
    const sc = try cfg.root.addFolder("ServerConfiguration");
    try sc.setStr("HostName", "first");
    try sc.setUint("Port", 443);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = "cfg_rw_test.config";

    try cfg.saveToFile(tmp.dir, path);

    // Mutate and save again; the previous file must be preserved as `path~`.
    try sc.setStr("HostName", "second");
    try cfg.saveToFile(tmp.dir, path);

    const backup = try tmp.dir.readFileAlloc(allocator, "cfg_rw_test.config~", 1 << 20);
    defer allocator.free(backup);
    try testing.expect(std.mem.indexOf(u8, backup, "first") != null);

    const reloaded = try Cfg.loadFromFile(allocator, tmp.dir, path);
    defer reloaded.deinit();
    try testing.expectEqualStrings("second", reloaded.getFolder("ServerConfiguration").?.getStr("HostName", ""));
}
