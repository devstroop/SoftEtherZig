//! SoftEther Pack Serialization Format
//!
//! The Pack format is SoftEther's binary serialization format used for
//! RPC communication. A Pack contains Elements, each Element has a name,
//! type, and one or more Values.
//!
//! Binary Format:
//! - Pack: [num_elements:u32] [element...]
//! - Element: [name:string] [type:u32] [num_values:u32] [value...]
//! - Value (depending on type):
//!   - INT: [value:u32]
//!   - INT64: [value:u64]
//!   - DATA: [size:u32] [bytes...]
//!   - STR: [len:u32] [utf8_bytes...]
//!   - UNISTR: [utf8_size:u32] [utf8_bytes...]

const std = @import("std");
const log = std.log.scoped(.cedar_pack);
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

/// Maximum sizes (matching SoftEther's limits)
pub const MAX_VALUE_SIZE = 96 * 1024 * 1024;
pub const MAX_VALUE_NUM = 65536;
pub const MAX_ELEMENT_NAME_LEN = 63;
pub const MAX_ELEMENT_NUM = 131072;
pub const MAX_PACK_SIZE = 128 * 1024 * 1024;

/// Value types in Pack format
pub const ValueType = enum(u32) {
    int = 0,
    data = 1,
    str = 2,
    unistr = 3,
    int64 = 4,
};

/// A single value in a Pack element
pub const Value = union(ValueType) {
    int: u32,
    data: []const u8,
    str: []const u8,
    unistr: []const u8, // UTF-8 encoded
    int64: u64,
};

/// An element in a Pack (named collection of values)
pub const Element = struct {
    name: []const u8,
    value_type: ValueType,
    values: std.ArrayListUnmanaged(Value),

    fn deinit(self: *Element, allocator: Allocator) void {
        // Free value data
        for (self.values.items) |v| {
            switch (v) {
                .data => |d| allocator.free(d),
                .str => |s| allocator.free(s),
                .unistr => |u| allocator.free(u),
                else => {},
            }
        }
        self.values.deinit(allocator);
        allocator.free(self.name);
    }
};

/// A Pack is a collection of named Elements
pub const Pack = struct {
    const Self = @This();

    allocator: Allocator,
    elements: std.ArrayListUnmanaged(Element),

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .elements = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.elements.items) |*e| {
            e.deinit(self.allocator);
        }
        self.elements.deinit(self.allocator);
    }

    /// Case-insensitive string comparison (matches C's StrCmpi behavior)
    fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
        }
        return true;
    }

    /// Find an element by name (case-insensitive, matching C behavior)
    fn findElement(self: *Self, name: []const u8) ?*Element {
        for (self.elements.items) |*e| {
            if (eqlIgnoreCase(e.name, name)) {
                return e;
            }
        }
        return null;
    }

    /// Find an element by name (const, case-insensitive)
    fn findElementConst(self: *const Self, name: []const u8) ?*const Element {
        for (self.elements.items) |*e| {
            if (eqlIgnoreCase(e.name, name)) {
                return e;
            }
        }
        return null;
    }

    /// Get or create an element
    fn getOrCreateElement(self: *Self, name: []const u8, value_type: ValueType) !*Element {
        if (self.findElement(name)) |elem| {
            if (elem.value_type != value_type) {
                return error.TypeMismatch;
            }
            return elem;
        }

        // Create new element
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        try self.elements.append(self.allocator, .{
            .name = name_copy,
            .value_type = value_type,
            .values = .{},
        });

        return &self.elements.items[self.elements.items.len - 1];
    }

    /// Get or create an element whose values array is ensured to hold at least
    /// `index + 1` values (C `PackAdd*Ex` pre-sizes the element to `total` and
    /// fills slot `index`; here any missing slots are padded with zero values
    /// so that callers may write indices in any order and rewrite a slot).
    fn getElementEx(self: *Self, name: []const u8, value_type: ValueType, index: usize) !*Element {
        const elem = try self.getOrCreateElement(name, value_type);
        while (elem.values.items.len <= index) {
            try elem.values.append(self.allocator, try zeroValue(self.allocator, value_type));
        }
        return elem;
    }

    /// Add an integer value
    pub fn addInt(self: *Self, name: []const u8, value: u32) !void {
        const elem = try self.getOrCreateElement(name, .int);
        try elem.values.append(self.allocator, .{ .int = value });
    }

    /// Add a 64-bit integer value
    pub fn addInt64(self: *Self, name: []const u8, value: u64) !void {
        const elem = try self.getOrCreateElement(name, .int64);
        try elem.values.append(self.allocator, .{ .int64 = value });
    }

    /// Add a string value (ANSI)
    pub fn addStr(self: *Self, name: []const u8, value: []const u8) !void {
        const elem = try self.getOrCreateElement(name, .str);
        const copy = try self.allocator.dupe(u8, value);
        try elem.values.append(self.allocator, .{ .str = copy });
    }

    /// Add a Unicode string value (UTF-8)
    pub fn addUniStr(self: *Self, name: []const u8, value: []const u8) !void {
        const elem = try self.getOrCreateElement(name, .unistr);
        const copy = try self.allocator.dupe(u8, value);
        try elem.values.append(self.allocator, .{ .unistr = copy });
    }

    /// Add binary data
    pub fn addData(self: *Self, name: []const u8, value: []const u8) !void {
        const elem = try self.getOrCreateElement(name, .data);
        const copy = try self.allocator.dupe(u8, value);
        try elem.values.append(self.allocator, .{ .data = copy });
    }

    /// Add a boolean (stored as int)
    pub fn addBool(self: *Self, name: []const u8, value: bool) !void {
        try self.addInt(name, if (value) 1 else 0);
    }

    /// C `PackAddIntEx` (Pack.c): replace the `index`-th int value of an element.
    pub fn addIntEx(self: *Self, name: []const u8, value: u32, index: usize) !void {
        const elem = try self.getElementEx(name, .int, index);
        elem.values.items[index] = .{ .int = value };
    }

    /// C `PackAddInt64Ex` (Pack.c).
    pub fn addInt64Ex(self: *Self, name: []const u8, value: u64, index: usize) !void {
        const elem = try self.getElementEx(name, .int64, index);
        elem.values.items[index] = .{ .int64 = value };
    }

    /// C `PackAddStrEx` (Pack.c).
    pub fn addStrEx(self: *Self, name: []const u8, value: []const u8, index: usize) !void {
        const elem = try self.getElementEx(name, .str, index);
        const copy = try self.allocator.dupe(u8, value);
        self.allocator.free(elem.values.items[index].str);
        elem.values.items[index] = .{ .str = copy };
    }

    /// C `PackAddUniStrEx` (Pack.c).
    pub fn addUniStrEx(self: *Self, name: []const u8, value: []const u8, index: usize) !void {
        const elem = try self.getElementEx(name, .unistr, index);
        const copy = try self.allocator.dupe(u8, value);
        self.allocator.free(elem.values.items[index].unistr);
        elem.values.items[index] = .{ .unistr = copy };
    }

    /// C `PackAddDataEx` (Pack.c).
    pub fn addDataEx(self: *Self, name: []const u8, value: []const u8, index: usize) !void {
        const elem = try self.getElementEx(name, .data, index);
        const copy = try self.allocator.dupe(u8, value);
        self.allocator.free(elem.values.items[index].data);
        elem.values.items[index] = .{ .data = copy };
    }

    /// C `PackAddBoolEx` (Pack.c): bool stored as int.
    pub fn addBoolEx(self: *Self, name: []const u8, value: bool, index: usize) !void {
        try self.addIntEx(name, if (value) 1 else 0, index);
    }

    /// Get an integer value
    pub fn getInt(self: *const Self, name: []const u8) ?u32 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .int or elem.values.items.len == 0) return null;
        return elem.values.items[0].int;
    }

    /// Get a 64-bit integer value
    pub fn getInt64(self: *const Self, name: []const u8) ?u64 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .int64 or elem.values.items.len == 0) return null;
        return elem.values.items[0].int64;
    }

    /// Get a string value
    pub fn getStr(self: *const Self, name: []const u8) ?[]const u8 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .str or elem.values.items.len == 0) return null;
        return elem.values.items[0].str;
    }

    /// Get a Unicode string value
    pub fn getUniStr(self: *const Self, name: []const u8) ?[]const u8 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .unistr or elem.values.items.len == 0) return null;
        return elem.values.items[0].unistr;
    }

    /// Get binary data
    pub fn getData(self: *const Self, name: []const u8) ?[]const u8 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .data or elem.values.items.len == 0) return null;
        return elem.values.items[0].data;
    }

    /// Get a boolean value
    pub fn getBool(self: *const Self, name: []const u8) ?bool {
        const value = self.getInt(name) orelse return null;
        return value != 0;
    }

    /// Check if element exists
    pub fn contains(self: *const Self, name: []const u8) bool {
        return self.findElementConst(name) != null;
    }

    /// C `PackGetIndexCount` (Pack.c): the number of values on an element.
    pub fn getValueCount(self: *const Self, name: []const u8) usize {
        const elem = self.findElementConst(name) orelse return 0;
        return elem.values.items.len;
    }

    /// C `PackGetIntEx` (Pack.c): the `index`-th int value of an element.
    pub fn getIntEx(self: *const Self, name: []const u8, index: usize) ?u32 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .int) return null;
        if (index >= elem.values.items.len) return null;
        return elem.values.items[index].int;
    }

    /// C `PackGetInt64Ex` (Pack.c).
    pub fn getInt64Ex(self: *const Self, name: []const u8, index: usize) ?u64 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .int64) return null;
        if (index >= elem.values.items.len) return null;
        return elem.values.items[index].int64;
    }

    /// C `PackGetStrEx` (Pack.c).
    pub fn getStrEx(self: *const Self, name: []const u8, index: usize) ?[]const u8 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .str) return null;
        if (index >= elem.values.items.len) return null;
        return elem.values.items[index].str;
    }

    /// C `PackGetUniStrEx` (Pack.c).
    pub fn getUniStrEx(self: *const Self, name: []const u8, index: usize) ?[]const u8 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .unistr) return null;
        if (index >= elem.values.items.len) return null;
        return elem.values.items[index].unistr;
    }

    /// C `PackGetDataEx` (Pack.c).
    pub fn getDataEx(self: *const Self, name: []const u8, index: usize) ?[]const u8 {
        const elem = self.findElementConst(name) orelse return null;
        if (elem.value_type != .data) return null;
        if (index >= elem.values.items.len) return null;
        return elem.values.items[index].data;
    }

    /// C `PackGetBoolEx` (Pack.c): bool stored as int.
    pub fn getBoolEx(self: *const Self, name: []const u8, index: usize) ?bool {
        const v = self.getIntEx(name, index) orelse return null;
        return v != 0;
    }

    /// Serialize the Pack to binary format
    pub fn toBuf(self: *const Self, writer: anytype) !void {
        // Write number of elements
        try writer.writeInt(u32, @intCast(self.elements.items.len), .big);

        // Write each element
        for (self.elements.items) |elem| {
            try writeElement(writer, &elem);
        }
    }

    /// Serialize to a byte buffer
    pub fn toBytes(self: *const Self, allocator: Allocator) ![]u8 {
        var list = std.ArrayListUnmanaged(u8){};
        errdefer list.deinit(allocator);
        try self.toBuf(list.writer(allocator));
        return list.toOwnedSlice(allocator);
    }

    /// Deserialize a Pack from binary format
    pub fn fromBuf(allocator: Allocator, reader: anytype) !Self {
        var pack_obj = Self.init(allocator);
        errdefer pack_obj.deinit();

        // Read number of elements
        const num_elements = try reader.readInt(u32, .big);
        if (num_elements > MAX_ELEMENT_NUM) {
            return error.TooManyElements;
        }

        // Read each element
        for (0..num_elements) |_| {
            try readElement(allocator, reader, &pack_obj);
        }

        return pack_obj;
    }

    /// Deserialize from bytes
    pub fn fromBytes(allocator: Allocator, data: []const u8) !Self {
        var stream = std.io.fixedBufferStream(data);
        return try Self.fromBuf(allocator, stream.reader());
    }
};

// Write a null-terminated string with length prefix
// SoftEther format: length includes null terminator, but we don't write null to stream
fn writeString(writer: anytype, str: []const u8) !void {
    try writer.writeInt(u32, @intCast(str.len + 1), .big); // +1 for null terminator (not written)
    try writer.writeAll(str);
    // Note: null terminator is NOT written to stream, just counted in length
}

/// A zero value of a given type (used to pad index gaps in `getElementEx`).
/// String/data values are heap-allocated empty slices so that `Element.deinit`
/// (which frees every str/data/unistr value) and slot replacement in `add*Ex`
/// can free them safely.
fn zeroValue(allocator: Allocator, value_type: ValueType) !Value {
    return switch (value_type) {
        .int => .{ .int = 0 },
        .int64 => .{ .int64 = 0 },
        .data => .{ .data = try allocator.dupe(u8, "") },
        .str => .{ .str = try allocator.dupe(u8, "") },
        .unistr => .{ .unistr = try allocator.dupe(u8, "") },
    };
}

// Write an element
fn writeElement(writer: anytype, elem: *const Element) !void {
    // Name (length-prefixed string)
    try writeString(writer, elem.name);

    // Type
    try writer.writeInt(u32, @intFromEnum(elem.value_type), .big);

    // Number of values
    try writer.writeInt(u32, @intCast(elem.values.items.len), .big);

    // Write each value
    for (elem.values.items) |v| {
        try writeValue(writer, v, elem.value_type);
    }
}

// Write a value
fn writeValue(writer: anytype, value: Value, value_type: ValueType) !void {
    switch (value_type) {
        .int => {
            try writer.writeInt(u32, value.int, .big);
        },
        .int64 => {
            try writer.writeInt(u64, value.int64, .big);
        },
        .data => {
            try writer.writeInt(u32, @intCast(value.data.len), .big);
            try writer.writeAll(value.data);
        },
        .str => {
            try writer.writeInt(u32, @intCast(value.str.len), .big);
            try writer.writeAll(value.str);
        },
        .unistr => {
            // Unicode strings are stored as UTF-8 with null terminator
            try writer.writeInt(u32, @intCast(value.unistr.len + 1), .big);
            try writer.writeAll(value.unistr);
            try writer.writeByte(0);
        },
    }
}

// Read a string (length-prefixed, null-terminated)
// SoftEther format: length includes null terminator, but only string body is stored
fn readString(allocator: Allocator, reader: anytype) ![]u8 {
    const len = try reader.readInt(u32, .big);
    if (len > MAX_VALUE_SIZE) return error.StringTooLong;
    if (len == 0) return error.InvalidStringLength; // Length 0 is invalid in SoftEther

    // Length includes null terminator, so actual string is len-1 bytes
    const str_len = len - 1;
    if (str_len == 0) return try allocator.dupe(u8, "");

    const data = try allocator.alloc(u8, str_len);
    errdefer allocator.free(data);

    const bytes_read = try reader.readAll(data);
    if (bytes_read != str_len) return error.UnexpectedEof;

    return data;
}

/// Sanitize a name for logging — copies printable bytes into `buf`, replacing
/// control characters (0x00–0x1F, 0x7F) with `?`. Valid multi-byte UTF-8
/// sequences are preserved so internationalized names remain readable. Bytes
/// that look like continuation bytes (0x80–0xBF) without a leading byte or
/// that can't start a valid sequence (>0xC0) are also replaced. Truncates at
/// `buf.len - 1`. A null byte is written at `buf[max]` but is **not** included
/// in the returned slice — the result is NOT a valid C string (`[:0]const u8`).
fn sanitizeName(raw: []const u8, buf: []u8) []const u8 {
    if (buf.len == 0) return "";
    const max = @min(raw.len, buf.len - 1);
    var i: usize = 0;
    var j: usize = 0;
    while (i < max and j < buf.len) {
        const byte = raw[i];
        // Single-byte printable ASCII or whitespace
        if ((byte >= 0x20 and byte <= 0x7e) or byte == 0x09 or byte == 0x0A or byte == 0x0D) {
            buf[j] = byte;
            i += 1;
            j += 1;
        } else if (byte >= 0xC2 and byte <= 0xF4) {
            // Multi-byte UTF-8 leader — count continuation bytes.
            const extra: usize = if (byte < 0xE0) 1 else if (byte < 0xF0) 2 else 3;
            // Check that there are enough input bytes AND enough room in buf
            // for the full sequence + trailing null (j < buf.len check).
            if (i + extra < raw.len and j + extra + 1 < buf.len) {
                var valid = true;
                // Validate continuation bytes AND reject overlongs/surrogates.
                switch (byte) {
                    0xE0 => {
                        if (raw[i + 1] < 0xA0 or raw[i + 1] > 0xBF) valid = false;
                    },
                    0xED => {
                        // Surrogate halves U+D800–U+DFFF
                        if (raw[i + 1] < 0x80 or raw[i + 1] > 0x9F) valid = false;
                    },
                    0xF0 => {
                        if (raw[i + 1] < 0x90 or raw[i + 1] > 0xBF) valid = false;
                    },
                    0xF4 => {
                        if (raw[i + 1] < 0x80 or raw[i + 1] > 0x8F) valid = false;
                    },
                    else => {},
                }
                if (valid) {
                    var k: usize = 1;
                    while (k <= extra) : (k += 1) {
                        if (raw[i + k] < 0x80 or raw[i + k] > 0xBF) {
                            valid = false;
                            break;
                        }
                    }
                }
                if (valid) {
                    const seq_len = extra + 1;
                    @memcpy(buf[j .. j + seq_len], raw[i .. i + seq_len]);
                    i += seq_len;
                    j += seq_len;
                    continue;
                }
            }
            buf[j] = '?';
            i += 1;
            j += 1;
        } else {
            buf[j] = '?';
            i += 1;
            j += 1;
        }
    }
    // j is always < buf.len because every write path checks before writing
    buf[j] = 0;
    return buf[0..j];
}

// Read an element and add to pack
fn readElement(allocator: Allocator, reader: anytype, pack_obj: *Pack) !void {
    // Read name
    const name = try readString(allocator, reader);
    defer allocator.free(name);

    // Log name safely — the wire may contain non-UTF-8/binary names
    var name_buf: [128]u8 = .{0} ** 128;
    const safe_name = sanitizeName(name, &name_buf);

    // Read type
    const type_int = try reader.readInt(u32, .big);
    if (type_int > 4) {
        std.log.debug("Invalid element type {d} for '{s}'", .{ type_int, safe_name });
        return error.InvalidElementType;
    }
    const value_type: ValueType = @enumFromInt(type_int);

    // Read number of values
    const num_values = try reader.readInt(u32, .big);
    if (num_values > MAX_VALUE_NUM) {
        std.log.debug("Element '{s}': type={d}, num_values={d} exceeds MAX_VALUE_NUM", .{ safe_name, type_int, num_values });
        return error.TooManyValues;
    }

    std.log.debug("Element '{s}': type={s}, values={d}", .{ safe_name, @tagName(value_type), num_values });

    // Read each value
    for (0..num_values) |_| {
        switch (value_type) {
            .int => {
                const val = try reader.readInt(u32, .big);
                try pack_obj.addInt(name, val);
            },
            .int64 => {
                const val = try reader.readInt(u64, .big);
                try pack_obj.addInt64(name, val);
            },
            .data => {
                const size = try reader.readInt(u32, .big);
                if (size > MAX_VALUE_SIZE) return error.DataTooLarge;
                const data = try allocator.alloc(u8, size);
                defer allocator.free(data);
                const bytes_read = try reader.readAll(data);
                if (bytes_read != size) return error.UnexpectedEof;
                try pack_obj.addData(name, data);
            },
            .str => {
                const len = try reader.readInt(u32, .big);
                if (len > MAX_VALUE_SIZE) return error.StringTooLong;
                const str = try allocator.alloc(u8, len);
                defer allocator.free(str);
                const bytes_read = try reader.readAll(str);
                if (bytes_read != len) return error.UnexpectedEof;
                try pack_obj.addStr(name, str);
            },
            .unistr => {
                const size = try reader.readInt(u32, .big);
                if (size > MAX_VALUE_SIZE) return error.StringTooLong;
                if (size == 0) {
                    try pack_obj.addUniStr(name, "");
                    continue;
                }
                const data = try allocator.alloc(u8, size);
                defer allocator.free(data);
                const bytes_read = try reader.readAll(data);
                if (bytes_read != size) return error.UnexpectedEof;
                // Remove null terminator
                const actual_len = if (data[size - 1] == 0) size - 1 else size;
                try pack_obj.addUniStr(name, data[0..actual_len]);
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "Pack basic operations" {
    const allocator = testing.allocator;

    var pack_obj = Pack.init(allocator);
    defer pack_obj.deinit();

    try pack_obj.addInt("int_val", 42);
    try pack_obj.addInt64("int64_val", 0x123456789ABCDEF0);
    try pack_obj.addStr("str_val", "Hello");
    try pack_obj.addUniStr("unistr_val", "世界");
    try pack_obj.addData("data_val", &[_]u8{ 1, 2, 3, 4 });
    try pack_obj.addBool("bool_val", true);

    try testing.expectEqual(@as(u32, 42), pack_obj.getInt("int_val").?);
    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), pack_obj.getInt64("int64_val").?);
    try testing.expectEqualStrings("Hello", pack_obj.getStr("str_val").?);
    try testing.expectEqualStrings("世界", pack_obj.getUniStr("unistr_val").?);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, pack_obj.getData("data_val").?);
    try testing.expect(pack_obj.getBool("bool_val").?);
}

test "Pack serialization round-trip" {
    const allocator = testing.allocator;

    var pack1 = Pack.init(allocator);
    defer pack1.deinit();

    try pack1.addInt("version", 1);
    try pack1.addStr("method", "Test");
    try pack1.addInt64("timestamp", 1234567890123);

    // Serialize
    const bytes = try pack1.toBytes(allocator);
    defer allocator.free(bytes);

    // Deserialize
    var pack2 = try Pack.fromBytes(allocator, bytes);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 1), pack2.getInt("version").?);
    try testing.expectEqualStrings("Test", pack2.getStr("method").?);
    try testing.expectEqual(@as(u64, 1234567890123), pack2.getInt64("timestamp").?);
}

test "Pack element not found" {
    const allocator = testing.allocator;

    var pack_obj = Pack.init(allocator);
    defer pack_obj.deinit();

    try testing.expectEqual(@as(?u32, null), pack_obj.getInt("nonexistent"));
    try testing.expectEqual(@as(?[]const u8, null), pack_obj.getStr("nonexistent"));
}

test "Pack indexed accessors (PackGetIntEx/IndexCount)" {
    const allocator = testing.allocator;

    var p = Pack.init(allocator);
    defer p.deinit();

    try p.addInt("Ports", 443);
    try p.addInt("Ports", 992);
    try p.addInt("Ports", 5555);
    try p.addStr("Names", "one");
    try p.addStr("Names", "two");
    try p.addBool("Flags", true);
    try p.addBool("Flags", false);
    try p.addInt64("Times", 1);
    try p.addInt64("Times", 2);
    try p.addUniStr("Notes", "x");
    try p.addData("Blobs", &[_]u8{ 1, 2 });

    try testing.expectEqual(@as(usize, 3), p.getValueCount("Ports"));
    try testing.expectEqual(@as(usize, 0), p.getValueCount("Missing"));
    try testing.expectEqual(@as(u32, 992), p.getIntEx("Ports", 1).?);
    try testing.expectEqual(@as(?u32, null), p.getIntEx("Ports", 3));
    try testing.expectEqualStrings("two", p.getStrEx("Names", 1).?);
    try testing.expectEqual(@as(?bool, false), p.getBoolEx("Flags", 1));
    try testing.expectEqual(@as(u64, 2), p.getInt64Ex("Times", 1).?);
    try testing.expectEqualStrings("x", p.getUniStrEx("Notes", 0).?);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2 }, p.getDataEx("Blobs", 0).?);

    try p.addIntEx("ExInts", 100, 0);
    try p.addIntEx("ExInts", 200, 1);
    try p.addStrEx("ExStrs", "alpha", 0);
    try p.addStrEx("ExStrs", "beta", 1);
    try p.addUniStrEx("ExUni", "gamma", 0);
    try p.addDataEx("ExData", &[_]u8{ 9, 8 }, 0);
    try p.addBoolEx("ExBools", true, 0);
    try p.addBoolEx("ExBools", false, 1);
    try p.addInt64Ex("ExTimes", 5, 0);

    // Out-of-order and slot-rewrite writes must be permitted (C `PackAdd*Ex`
    // pre-sizes the element to `total` and each call fills slot `index`).
    try p.addIntEx("ExOOO", 300, 2);
    try p.addIntEx("ExOOO", 100, 0);
    try p.addStrEx("ExOOOStr", "third", 2);
    try p.addStrEx("ExOOOStr", "first", 0);
    try p.addStrEx("ExOOOStr", "second", 1);
    try p.addStrEx("ExOOOStr", "rewritten", 2);

    try testing.expectEqual(@as(usize, 2), p.getValueCount("ExInts"));
    try testing.expectEqual(@as(u32, 100), p.getIntEx("ExInts", 0).?);
    try testing.expectEqual(@as(u32, 200), p.getIntEx("ExInts", 1).?);
    try testing.expectEqualStrings("beta", p.getStrEx("ExStrs", 1).?);
    try testing.expectEqualStrings("gamma", p.getUniStrEx("ExUni", 0).?);
    try testing.expectEqualSlices(u8, &[_]u8{ 9, 8 }, p.getDataEx("ExData", 0).?);
    try testing.expectEqual(@as(?bool, false), p.getBoolEx("ExBools", 1));
    try testing.expectEqual(@as(u64, 5), p.getInt64Ex("ExTimes", 0).?);

    try testing.expectEqual(@as(usize, 3), p.getValueCount("ExOOO"));
    try testing.expectEqual(@as(u32, 100), p.getIntEx("ExOOO", 0).?);
    try testing.expectEqual(@as(u32, 300), p.getIntEx("ExOOO", 2).?);
    try testing.expectEqualStrings("first", p.getStrEx("ExOOOStr", 0).?);
    try testing.expectEqualStrings("second", p.getStrEx("ExOOOStr", 1).?);
    try testing.expectEqualStrings("rewritten", p.getStrEx("ExOOOStr", 2).?);
}

test "Pack.fromBytes rejects empty input" {
    const data: [0]u8 = .{};
    try testing.expectError(error.EndOfStream, Pack.fromBytes(testing.allocator, &data));
}

test "Pack.fromBytes rejects truncated element count" {
    try testing.expectError(error.EndOfStream, Pack.fromBytes(testing.allocator, &.{ 0x00, 0x01 }));
}

test "Pack.fromBytes rejects oversized element count" {
    const buf = [4]u8{ 0x00, 0x02, 0x01, 0x00 };
    try testing.expectError(error.TooManyElements, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes rejects invalid element type" {
    // Valid element count (1), valid name length (1+1=2 → "X"), type=5 (invalid), num_values=0
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x02, // name_len = 2 (includes phantom null)
        'X', // name body (1 byte)
        0x00, 0x00, 0x00, 0x05, // type = 5 (invalid, max is 4)
        0x00, 0x00, 0x00, 0x00, // num_values = 0
    };
    try testing.expectError(error.InvalidElementType, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes rejects oversized value count" {
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x02, // name_len = 2
        'X', // name body
        0x00, 0x00, 0x00, 0x00, // type = int
        0x00, 0x01, 0x00, 0x01, // num_values = 65537 (exceeds MAX_VALUE_NUM=65536)
        0x00, 0x00, 0x00, 0x2A, // value = 42 (would be read if num_values check passed)
    };
    try testing.expectError(error.TooManyValues, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes rejects truncated name" {
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x0A, // name_len = 10 (claims 9-byte name)
        'a', 'b', // only 2 bytes available
    };
    try testing.expectError(error.UnexpectedEof, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes rejects zero-length name" {
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x00, // name_len = 0 (invalid)
    };
    try testing.expectError(error.InvalidStringLength, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes rejects truncated int value" {
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x02, // name_len = 2
        'X', // name body
        0x00, 0x00, 0x00, 0x00, // type = int
        0x00, 0x00, 0x00, 0x01, // num_values = 1
        // missing int value bytes
    };
    try testing.expectError(error.EndOfStream, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes round-trips all five value types with binary data" {
    var p = Pack.init(testing.allocator);
    defer p.deinit();

    try p.addInt("i", 0xDEAD_BEEF);
    try p.addInt64("i64", 0x0102030405060708);
    try p.addData("d", &[_]u8{ 0x00, 0xFF, 0x80, 0x7F });
    try p.addStr("s", "hello\x00world");
    try p.addUniStr("u", "cafe\u{0301}");

    const bytes = try p.toBytes(testing.allocator);
    defer testing.allocator.free(bytes);

    var p2 = try Pack.fromBytes(testing.allocator, bytes);
    defer p2.deinit();

    try testing.expectEqual(@as(u32, 0xDEAD_BEEF), p2.getInt("i").?);
    try testing.expectEqual(@as(u64, 0x0102030405060708), p2.getInt64("i64").?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0xFF, 0x80, 0x7F }, p2.getData("d").?);
    try testing.expectEqualStrings("hello\x00world", p2.getStr("s").?);
    try testing.expectEqualStrings("cafe\u{0301}", p2.getUniStr("u").?);
}

test "Pack.fromBytes handles empty pack (zero elements)" {
    const buf = [4]u8{ 0x00, 0x00, 0x00, 0x00 };
    var p = try Pack.fromBytes(testing.allocator, &buf);
    defer p.deinit();
    try testing.expectEqual(@as(usize, 0), p.elements.items.len);
}

test "Pack.fromBytes rejects random garbage gracefully" {
    const garbage = [_]u8{ 0xA7, 0x3F, 0x01, 0x9C, 0x55, 0xE0, 0x0B, 0x72, 0xD4, 0x88, 0x1F, 0x63 };
    // Must return an error (not crash or leak memory)
    const result = Pack.fromBytes(testing.allocator, &garbage);
    try testing.expect(result == error.TooManyElements or result == error.EndOfStream or
        result == error.InvalidElementType or result == error.InvalidStringLength);
}

test "Pack.fromBytes rejects string value with oversized length" {
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x02, // name_len = 2
        'X', // name body
        0x00, 0x00, 0x00, 0x02, // type = str
        0x00, 0x00, 0x00, 0x01, // num_values = 1
        0x7F, 0xFF, 0xFF, 0xFF, // len = MAX_VALUE_SIZE+1 (too large)
    };
    try testing.expectError(error.StringTooLong, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes rejects data value with oversized length" {
    const buf = [_]u8{
        0x00, 0x00, 0x00, 0x01, // num_elements = 1
        0x00, 0x00, 0x00, 0x02, // name_len = 2
        'X', // name body
        0x00, 0x00, 0x00, 0x01, // type = data
        0x00, 0x00, 0x00, 0x01, // num_values = 1
        0x7F, 0xFF, 0xFF, 0xFF, // size = MAX_VALUE_SIZE+1 (too large)
    };
    try testing.expectError(error.DataTooLarge, Pack.fromBytes(testing.allocator, &buf));
}

test "Pack.fromBytes mangled valid pack returns error" {
    // Build a valid pack, then flip bits in the middle
    var p = Pack.init(testing.allocator);
    defer p.deinit();
    try p.addInt("key", 42);

    const bytes = try p.toBytes(testing.allocator);
    defer testing.allocator.free(bytes);

    // Flip a byte in the middle of the serialized data
    var mutated = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(mutated);
    mutated[8] ^= 0xFF;

    // May succeed (if mutation is benign) or fail — must not crash
    if (Pack.fromBytes(testing.allocator, mutated)) |mutated_pack| {
        var mp = mutated_pack;
        mp.deinit();
    } else |_| {}
}

test "Pack round-trip preserves binary element name" {
    var p = Pack.init(testing.allocator);
    defer p.deinit();

    // Element names can be arbitrary bytes (the C code uses StrLen, not strlen)
    const name = [_]u8{ 0x00, 0x80, 0xFF, 0x41 };
    // We need to use the addInt API — it takes a []const u8 name
    try p.addInt(&name, 1);

    const bytes = try p.toBytes(testing.allocator);
    defer testing.allocator.free(bytes);

    var p2 = try Pack.fromBytes(testing.allocator, bytes);
    defer p2.deinit();

    try testing.expectEqual(@as(u32, 1), p2.getInt(&name).?);
}

test "Pack.fromBytes handles large valid pack" {
    var p = Pack.init(testing.allocator);
    defer p.deinit();

    // Add 100 elements, each with 10 int values
    for (0..100) |i| {
        const name = try std.fmt.allocPrint(testing.allocator, "field_{d}", .{i});
        defer testing.allocator.free(name);
        for (0..10) |j| {
            try p.addIntEx(name, @intCast(i * 100 + j), j);
        }
    }

    const bytes = try p.toBytes(testing.allocator);
    defer testing.allocator.free(bytes);

    var p2 = try Pack.fromBytes(testing.allocator, bytes);
    defer p2.deinit();

    try testing.expectEqual(@as(usize, 100), p2.elements.items.len);
    for (0..100) |i| {
        const name = try std.fmt.allocPrint(testing.allocator, "field_{d}", .{i});
        defer testing.allocator.free(name);
        try testing.expectEqual(@as(usize, 10), p2.getValueCount(name));
        try testing.expectEqual(@as(u32, @intCast(i * 100 + 5)), p2.getIntEx(name, 5).?);
    }
}
