//! Time Utilities Module
//!
//! Pure Zig replacement for time-related functions in Mayaqua/Kernel.c
//! Provides tick counting, timestamps, and time formatting.

const std = @import("std");
const testing = std.testing;

/// Milliseconds since program start (replaces Tick64())
pub fn getTick() u64 {
    const ts = std.time.Instant.now() catch return 0;
    return @intCast(ts.timestamp / std.time.ns_per_ms);
}

/// Current Unix timestamp in seconds
pub fn getUnixTime() i64 {
    return std.time.timestamp();
}

/// Current Unix timestamp in milliseconds
pub fn getUnixTimeMs() i64 {
    const ns = std.time.nanoTimestamp();
    return @intCast(@divFloor(ns, std.time.ns_per_ms));
}

/// Current Unix timestamp in nanoseconds
pub fn getUnixTimeNs() i128 {
    return std.time.nanoTimestamp();
}

/// High-resolution timer for performance measurement
pub const Timer = struct {
    start_time: std.time.Instant,

    pub fn begin() Timer {
        return .{ .start_time = std.time.Instant.now() catch unreachable };
    }

    pub fn read(self: *const Timer) u64 {
        const now = std.time.Instant.now() catch return 0;
        return now.since(self.start_time);
    }

    pub fn readMs(self: *const Timer) u64 {
        return self.read() / std.time.ns_per_ms;
    }

    pub fn readUs(self: *const Timer) u64 {
        return self.read() / std.time.ns_per_us;
    }

    pub fn reset(self: *Timer) void {
        self.start_time = std.time.Instant.now() catch return;
    }
};

/// Stopwatch with lap support
pub const Stopwatch = struct {
    timer: Timer,
    laps: std.ArrayListUnmanaged(u64),
    allocator: std.mem.Allocator,
    is_running: bool,

    pub fn init(allocator: std.mem.Allocator) Stopwatch {
        return .{
            .timer = Timer.begin(),
            .laps = .{},
            .allocator = allocator,
            .is_running = true,
        };
    }

    pub fn deinit(self: *Stopwatch) void {
        self.laps.deinit(self.allocator);
    }

    pub fn lap(self: *Stopwatch) !u64 {
        const elapsed = self.timer.readMs();
        try self.laps.append(self.allocator, elapsed);
        self.timer.reset();
        return elapsed;
    }

    pub fn stop(self: *Stopwatch) u64 {
        self.is_running = false;
        return self.timer.readMs();
    }

    pub fn totalMs(self: *const Stopwatch) u64 {
        var total: u64 = 0;
        for (self.laps.items) |lap_time| {
            total += lap_time;
        }
        if (self.is_running) {
            total += self.timer.readMs();
        }
        return total;
    }
};

// ============================================================================
// Time conversion and formatting
// ============================================================================

/// Broken-down time structure
pub const DateTime = struct {
    year: u16,
    month: u8, // 1-12
    day: u8, // 1-31
    hour: u8, // 0-23
    minute: u8, // 0-59
    second: u8, // 0-59
    millisecond: u16, // 0-999
    day_of_week: u8, // 0=Sunday, 6=Saturday

    /// Create from Unix timestamp (seconds)
    pub fn fromUnixTime(timestamp: i64) DateTime {
        const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(timestamp) };
        const epoch_day = epoch_seconds.getEpochDay();
        const day_seconds = epoch_seconds.getDaySeconds();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        return .{
            .year = year_day.year,
            .month = month_day.month.numeric(),
            .day = month_day.day_index + 1,
            .hour = day_seconds.getHoursIntoDay(),
            .minute = day_seconds.getMinutesIntoHour(),
            .second = day_seconds.getSecondsIntoMinute(),
            .millisecond = 0,
            .day_of_week = @intCast(@mod(epoch_day.day + 4, 7)), // Jan 1, 1970 was Thursday
        };
    }

    /// Create from Unix timestamp (milliseconds)
    pub fn fromUnixTimeMs(timestamp_ms: i64) DateTime {
        var dt = fromUnixTime(@divFloor(timestamp_ms, 1000));
        dt.millisecond = @intCast(@mod(timestamp_ms, 1000));
        return dt;
    }

    /// Get current date/time
    pub fn now() DateTime {
        return fromUnixTime(getUnixTime());
    }

    /// Get current date/time with milliseconds
    pub fn nowMs() DateTime {
        return fromUnixTimeMs(getUnixTimeMs());
    }

    /// Convert to Unix timestamp (seconds)
    pub fn toUnixTime(self: *const DateTime) i64 {
        // Calculate days since Unix epoch
        var days: i64 = 0;

        // Years
        var y: i64 = 1970;
        while (y < self.year) : (y += 1) {
            days += if (isLeapYear(@intCast(y))) 366 else 365;
        }

        // Months
        const days_in_month = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        var m: u8 = 1;
        while (m < self.month) : (m += 1) {
            days += days_in_month[m - 1];
            if (m == 2 and isLeapYear(self.year)) {
                days += 1;
            }
        }

        // Days
        days += self.day - 1;

        // Convert to seconds
        const day_secs: i64 = @as(i64, self.hour) * 3600 + @as(i64, self.minute) * 60 + @as(i64, self.second);
        return days * 86400 + day_secs;
    }

    /// Format as ISO 8601 string
    pub fn formatIso8601(self: *const DateTime, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        });
    }

    /// Format as common date string
    pub fn formatDate(self: *const DateTime, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{d:0>4}/{d:0>2}/{d:0>2}", .{
            self.year,
            self.month,
            self.day,
        });
    }

    /// Format as time string
    pub fn formatTime(self: *const DateTime, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2}", .{
            self.hour,
            self.minute,
            self.second,
        });
    }
};

fn dayOfYear(year: u16, month: u8, day: u8) u16 {
    const days_before_month = [_]u16{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    var result = days_before_month[month - 1] + day - 1;
    if (month > 2 and isLeapYear(year)) {
        result += 1;
    }
    return result;
}

fn isLeapYear(year: u16) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
}

// ============================================================================
// Sleep utilities
// ============================================================================

/// Sleep for specified milliseconds
pub fn sleepMs(ms: u64) void {
    std.Thread.sleep(ms * std.time.ns_per_ms);
}

/// Sleep for specified microseconds
pub fn sleepUs(us: u64) void {
    std.Thread.sleep(us * std.time.ns_per_us);
}

/// Sleep for specified seconds
pub fn sleepSec(sec: u64) void {
    std.Thread.sleep(sec * std.time.ns_per_s);
}

// ============================================================================
// Timeout utilities
// ============================================================================

/// Deadline for timeout operations
pub const Deadline = struct {
    end_time: i64,

    pub fn init(timeout_ms: u64) Deadline {
        return .{
            .end_time = getUnixTimeMs() + @as(i64, @intCast(timeout_ms)),
        };
    }

    pub fn isExpired(self: *const Deadline) bool {
        return getUnixTimeMs() >= self.end_time;
    }

    pub fn remainingMs(self: *const Deadline) u64 {
        const remaining = self.end_time - getUnixTimeMs();
        return if (remaining > 0) @intCast(remaining) else 0;
    }
};

// ============================================================================
// SoftEther-specific time formats
// ============================================================================

/// SoftEther SYSTEMTIME format (Windows-compatible)
/// 64-bit value: YYYYMMDDHHMMSS + milliseconds
pub const SoftEtherTime = struct {
    value: u64,

    pub fn fromDateTime(dt: DateTime) SoftEtherTime {
        const date_part: u64 = @as(u64, dt.year) * 10000000000 +
            @as(u64, dt.month) * 100000000 +
            @as(u64, dt.day) * 1000000 +
            @as(u64, dt.hour) * 10000 +
            @as(u64, dt.minute) * 100 +
            @as(u64, dt.second);
        return .{ .value = date_part * 1000 + dt.millisecond };
    }

    pub fn toDateTime(self: *const SoftEtherTime) DateTime {
        var v = self.value;
        const ms: u16 = @intCast(@mod(v, 1000));
        v /= 1000;
        const sec: u8 = @intCast(@mod(v, 100));
        v /= 100;
        const min: u8 = @intCast(@mod(v, 100));
        v /= 100;
        const hour: u8 = @intCast(@mod(v, 100));
        v /= 100;
        const day: u8 = @intCast(@mod(v, 100));
        v /= 100;
        const month: u8 = @intCast(@mod(v, 100));
        v /= 100;
        const year: u16 = @intCast(v);

        return .{
            .year = year,
            .month = month,
            .day = day,
            .hour = hour,
            .minute = min,
            .second = sec,
            .millisecond = ms,
            .day_of_week = 0, // Would need calculation
        };
    }

    pub fn now() SoftEtherTime {
        return fromDateTime(DateTime.nowMs());
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Timer basic usage" {
    var timer = Timer.begin();
    sleepMs(10);
    const elapsed = timer.readMs();
    try testing.expect(elapsed >= 8); // Allow some slack
    try testing.expect(elapsed < 100);
}

test "DateTime from Unix time" {
    // Jan 1, 2024 00:00:00 UTC
    const dt = DateTime.fromUnixTime(1704067200);
    try testing.expectEqual(@as(u16, 2024), dt.year);
    try testing.expectEqual(@as(u8, 1), dt.month);
    try testing.expectEqual(@as(u8, 1), dt.day);
    try testing.expectEqual(@as(u8, 0), dt.hour);
}

test "DateTime format ISO8601" {
    const dt = DateTime{
        .year = 2024,
        .month = 6,
        .day = 15,
        .hour = 14,
        .minute = 30,
        .second = 45,
        .millisecond = 0,
        .day_of_week = 6,
    };
    var buf: [32]u8 = undefined;
    const formatted = try dt.formatIso8601(&buf);
    try testing.expectEqualStrings("2024-06-15T14:30:45Z", formatted);
}

test "DateTime roundtrip" {
    const original: i64 = 1704067200;
    const dt = DateTime.fromUnixTime(original);
    const converted = dt.toUnixTime();
    try testing.expectEqual(original, converted);
}

test "Deadline" {
    const deadline = Deadline.init(100);
    try testing.expect(!deadline.isExpired());
    try testing.expect(deadline.remainingMs() <= 100);
    try testing.expect(deadline.remainingMs() > 0);
}

test "SoftEtherTime roundtrip" {
    const dt = DateTime{
        .year = 2024,
        .month = 6,
        .day = 15,
        .hour = 14,
        .minute = 30,
        .second = 45,
        .millisecond = 123,
        .day_of_week = 0,
    };
    const st = SoftEtherTime.fromDateTime(dt);
    const back = st.toDateTime();

    try testing.expectEqual(dt.year, back.year);
    try testing.expectEqual(dt.month, back.month);
    try testing.expectEqual(dt.day, back.day);
    try testing.expectEqual(dt.hour, back.hour);
    try testing.expectEqual(dt.minute, back.minute);
    try testing.expectEqual(dt.second, back.second);
    try testing.expectEqual(dt.millisecond, back.millisecond);
}
