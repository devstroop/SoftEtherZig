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

// Read an element and add to pack
fn readElement(allocator: Allocator, reader: anytype, pack_obj: *Pack) !void {
    // Read name
    const name = try readString(allocator, reader);
    defer allocator.free(name);

    // Read type
    const type_int = try reader.readInt(u32, .big);
    if (type_int > 4) {
        std.log.err("Invalid element type {d} for '{s}'", .{ type_int, name });
        return error.InvalidElementType;
    }
    const value_type: ValueType = @enumFromInt(type_int);

    // Read number of values
    const num_values = try reader.readInt(u32, .big);
    if (num_values > MAX_VALUE_NUM) {
        std.log.err("Element '{s}': type={d}, num_values={d} exceeds MAX_VALUE_NUM", .{ name, type_int, num_values });
        return error.TooManyValues;
    }

    std.log.debug("Element '{s}': type={s}, values={d}", .{ name, @tagName(value_type), num_values });

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
