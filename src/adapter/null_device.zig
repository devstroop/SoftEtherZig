const std = @import("std");

pub const NullDevice = struct {
    is_open: bool = false,
    name: [8]u8 = .{ 'n', 'u', 'l', 'l', 0, 0, 0, 0 },
    mac: [6]u8 = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 },

    pub fn open(allocator: std.mem.Allocator) !NullDevice {
        _ = allocator;
        return NullDevice{ .is_open = true };
    }

    pub fn isOpen(self: *const NullDevice) bool {
        return self.is_open;
    }

    pub fn close(self: *NullDevice) void {
        self.is_open = false;
    }

    pub fn getName(self: *const NullDevice) ?[]const u8 {
        var len: usize = 0;
        for (self.name) |c| {
            if (c == 0) break;
            len += 1;
        }
        return self.name[0..len];
    }

    pub fn getMac(self: *const NullDevice) ?[6]u8 {
        return self.mac;
    }

    pub fn read(self: *NullDevice, buffer: []u8) !?usize {
        _ = self;
    _ = buffer;
        return null;
    }

    pub fn write(self: *NullDevice, data: []const u8) !usize {
        _ = self;
        return data.len;
    }

    pub fn configure(self: *NullDevice, ip: u32, subnet: u32, gateway: u32) !void {
        _ = self;
        _ = ip;
        _ = subnet;
        _ = gateway;
    }

    pub fn configureTemporary(self: *NullDevice) !void {
        _ = self;
    }

    pub fn getStats(self: *const NullDevice) ?NullStats {
        _ = self;
        return NullStats{};
    }
};

pub const NullStats = struct {
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    packets_read: u64 = 0,
    packets_written: u64 = 0,
};

pub const NullDeviceError = error{
    DeviceNotOpen,
};
