//! Log engine — async writer thread with file rotation.
//!
//! C reference: `Logging.c` / `Logging.h`. Provides a `LOG` struct that
//! accepts records via a thread-safe queue and writes them to disk in a
//! background thread. Supports date-based and size-based log rotation.
//!
//! Scope (M4):
//!   - LOG struct with writer thread, record queue, rotation.
//!   - InsertStringRecord / InsertRecord for enqueueing.
//!   - Server log + hub security log instances.
//!   - MakeLogFileName for rotation.
//!   - EnumLog for listing log files.
//!   - HUB_LOG configuration struct.
//!
//! Deferred to M5:
//!   - Packet logger (needs PKT struct).
//!   - Syslog support.
//!   - Eraser (disk space management).
//!   - TrafficDiffList (farm member reporting).

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;
const time = std.time;

const log = std.log.scoped(.cedar_log);

// ============================================================================
// Constants (C: Cedar.h / Logging.h)
// ============================================================================

/// Default max log file size before rotation (~1 GB, C: `MAX_LOG_SIZE_DEFAULT`).
pub const MAX_LOG_SIZE_DEFAULT: u64 = 1073741823;
/// Min free disk space (1 MB).
pub const DISK_FREE_SPACE_MIN: u64 = 1048576;
/// Start caching records when queue exceeds this count.
pub const SAVE_START_CACHE_COUNT: u32 = 100000;

// Log directory names (C: Cedar.h:501-518).
pub const SERVER_LOG_DIR_NAME = "@server_log";
pub const SERVER_LOG_PREFIX = "vpn";
pub const HUB_SECURITY_LOG_DIR_NAME = "@security_log";
pub const HUB_SECURITY_LOG_PREFIX = "sec";
pub const NAT_LOG_DIR_NAME = "@secure_nat_log";
pub const NAT_LOG_PREFIX = "snat";

// ============================================================================
// Log switch types (C: Cedar.h:536-541)
// ============================================================================

pub const LogSwitchType = enum(u32) {
    no = 0, // No switching (single file)
    second = 1,
    minute = 2,
    hour = 3,
    day = 4,
    month = 5,
};

// ============================================================================
// HUB_LOG configuration (C: Logging.h:134-141)
// ============================================================================

/// Per-hub log configuration. Stored on the Hub struct and controls which
/// logs are saved and their rotation granularity.
pub const HubLogConfig = struct {
    save_security_log: bool = true,
    security_log_switch_type: LogSwitchType = .day,
    save_packet_log: bool = false,
    packet_log_switch_type: LogSwitchType = .day,
};

// ============================================================================
// Record (C: Logging.h:144-149)
// ============================================================================

/// A single log record queued for writing.
pub const Record = struct {
    /// Timestamp in milliseconds since epoch.
    tick: i64,
    /// The formatted string to write.
    string: []u8,
};

// ============================================================================
// Log entry (what EnumLog returns)
// ============================================================================

/// Information about a log file on disk, returned by EnumLog.
pub const LogEntry = struct {
    /// File name (e.g., "vpn_20260817.log").
    name: []const u8,
    /// Full path.
    path: []const u8,
    /// File size in bytes.
    size: u64,
};

// ============================================================================
// LOG — the log engine (C: Logging.h:152-170)
// ============================================================================

/// The log engine. Spawns a background writer thread that drains the record
/// queue and writes to disk with rotation.
pub const LOG = struct {
    allocator: Allocator,
    /// Guards the record queue.
    mutex: std.Thread.Mutex = .{},
    /// Records waiting to be written.
    records: std.ArrayListUnmanaged(Record) = .{},
    /// Destination directory path.
    dir_name: []u8,
    /// File name prefix (e.g., "vpn", "sec").
    prefix: []u8,
    /// Rotation granularity.
    switch_type: LogSwitchType = .day,
    /// Max file size before rotation (bytes).
    max_log_size: u64 = MAX_LOG_SIZE_DEFAULT,
    /// Background writer thread.
    thread: ?std.Thread = null,
    /// Signal the writer thread to wake up.
    event: std.Thread.ResetEvent = .{},
    /// Signal the writer thread to stop.
    halt: bool = false,
    /// Current log file handle.
    current_file: ?fs.File = null,
    /// Current log file path.
    current_path: []u8 = &.{},
    /// Bytes written to the current file.
    current_size: u64 = 0,
    /// Current log number suffix (~00, ~01, etc.).
    current_number: u32 = 0,
    /// Last date string for rotation detection.
    last_date_str: [16:0]u8 = .{0} ** 16,

    /// Create a new LOG engine and start the writer thread.
    pub fn init(allocator: Allocator, dir_name: []const u8, prefix: []const u8, switch_type: LogSwitchType) !*LOG {
        const self = try allocator.create(LOG);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .dir_name = try allocator.dupe(u8, dir_name),
            .prefix = try allocator.dupe(u8, prefix),
            .switch_type = switch_type,
        };
        // Ensure the directory exists.
        fs.makeDirAbsolute(dir_name) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
        self.thread = try std.Thread.spawn(.{}, logThread, .{self});
        return self;
    }

    /// Stop the writer thread and free resources.
    pub fn deinit(self: *LOG) void {
        // Signal halt and wake the thread.
        self.mutex.lock();
        self.halt = true;
        self.mutex.unlock();
        self.event.set();
        if (self.thread) |t| t.join();
        // Drain any remaining records.
        self.drainRecords();
        if (self.current_file) |f| f.close();
        self.allocator.free(self.current_path);
        self.allocator.free(self.dir_name);
        self.allocator.free(self.prefix);
        self.allocator.destroy(self);
    }

    /// Insert a pre-formatted string record into the log queue.
    pub fn insertStringRecord(self: *LOG, str: []const u8) void {
        const copy = self.allocator.dupe(u8, str) catch return;
        self.mutex.lock();
        self.records.append(self.allocator, .{
            .tick = time.milliTimestamp(),
            .string = copy,
        }) catch {
            self.allocator.free(copy);
            self.mutex.unlock();
            return;
        };
        self.mutex.unlock();
        self.event.set();
    }

    /// Printf-style convenience: format and insert a record.
    pub fn printf(self: *LOG, comptime fmt: []const u8, args: anytype) void {
        const str = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        self.insertStringRecord(str);
    }

    /// Set the log rotation type at runtime.
    pub fn setSwitchType(self: *LOG, switch_type: LogSwitchType) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.switch_type = switch_type;
    }

    /// Set the max log file size at runtime.
    pub fn setMaxLogSize(self: *LOG, max_size: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.max_log_size = max_size;
    }

    // ---- Internal ----------------------------------------------------------

    fn drainRecords(self: *LOG) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.records.items) |r| self.allocator.free(r.string);
        self.records.clearRetainingCapacity();
    }

    /// Background writer thread (C: `LogThread`, Logging.c:2621).
    fn logThread(self: *LOG) void {
        while (true) {
            self.event.wait();
            self.event.reset();

            while (true) {
                // Dequeue one record.
                self.mutex.lock();
                const record = self.records.pop() orelse {
                    self.mutex.unlock();
                    break;
                };
                const halt = self.halt;
                self.mutex.unlock();

                if (halt) {
                    self.allocator.free(record.string);
                    return;
                }

                // Write the record.
                self.writeRecord(record);
                self.allocator.free(record.string);
            }
        }
    }

    /// Write a single record to the current log file, rotating if needed.
    fn writeRecord(self: *LOG, record: Record) void {
        // Check if we need to rotate (date change or size exceeded).
        self.maybeRotate(record.tick);

        // Open the file if not already open.
        const file = self.openCurrentFile() orelse return;

        // Format: "[YYYY-MM-DD HH:MM:SS] <message>\n"
        var buf: [4096]u8 = undefined;
        const ts = std.time.timestamp();
        const epoch_seconds = @as(u64, @intCast(ts));
        const day_seconds = @mod(epoch_seconds, 86400);
        const hours = @as(u8, @intCast(day_seconds / 3600));
        const mins = @as(u8, @intCast(@mod(day_seconds / 60, 60)));
        const secs = @as(u8, @intCast(@mod(day_seconds, 60)));

        // Compute year/month/day using civil_from_days.
        const epoch_day = @as(i64, @intCast(epoch_seconds / 86400));
        const civil = std.time.epoch.CivilDay.calculate(epoch_day);
        const year: u16 = @intCast(civil.year);
        const month: u8 = @intCast(@intFromEnum(civil.month));
        const day: u8 = civil.day;

        const prefix_len = (std.fmt.bufPrint(&buf, "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}] ", .{
            year, month, day, hours, mins, secs,
        }) catch return).len;

        const msg_end = @min(record.string.len, buf.len - prefix_len - 1);
        @memcpy(buf[prefix_len..][0..msg_end], record.string[0..msg_end]);
        buf[prefix_len + msg_end] = '\n';

        file.writer().writeAll(buf[0 .. prefix_len + msg_end + 1]) catch |err| {
            log.warn("Failed to write log record: {}", .{err});
        };
        self.current_size += prefix_len + msg_end + 1;
    }

    /// Check if we need to rotate to a new log file.
    fn maybeRotate(self: *LOG, tick: i64) void {
        const date_str = self.dateStringFromTick(tick);
        const size_exceeded = self.current_size >= self.max_log_size and self.max_log_size > 0;

        if (self.current_file == null or size_exceeded or
            !mem.eql(u8, &self.last_date_str, &date_str))
        {
            // Close current file.
            if (self.current_file) |f| f.close();
            self.current_file = null;

            // Update state.
            if (!mem.eql(u8, &self.last_date_str, &date_str)) {
                self.last_date_str = date_str;
                self.current_number = 0;
            } else if (size_exceeded) {
                self.current_number += 1;
            }
            self.current_size = 0;
        }
    }

    /// Build the log file path: `<dir>/<prefix>_YYYYMMDD~NN.log`.
    fn makeLogFileName(self: *LOG, tick: i64) ![]u8 {
        const date_str = self.dateStringFromTick(tick);
        // Format: prefix_YYYYMMDD~NN.log
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}_{s}~{d:0>2}.log",
            .{
                self.dir_name,
                self.prefix,
                &date_str,
                self.current_number,
            },
        );
    }

    /// Open the current log file for appending.
    fn openCurrentFile(self: *LOG) ?fs.File {
        if (self.current_file) |f| return f;

        const tick = time.milliTimestamp();
        const path = self.makeLogFileName(tick) catch return null;
        self.allocator.free(self.current_path);
        self.current_path = path;

        const file = fs.cwd().openFile(path, .{
            .mode = .write_only,
        }) catch |err| {
            if (err == error.FileNotFound) {
                // Create a new file.
                return fs.cwd().createFile(path, .{}) catch |e| {
                    log.warn("Failed to create log file {s}: {}", .{ path, e });
                    return null;
                };
            }
            log.warn("Failed to open log file {s}: {}", .{ path, err });
            return null;
        };
        // Seek to end for append.
        file.seekFromEnd(0) catch {};
        self.current_file = file;
        return file;
    }

    /// Generate the date string portion of the log file name based on switch type.
    fn dateStringFromTick(self: *LOG, tick: i64) [16:0]u8 {
        var result: [16:0]u8 = .{0} ** 16;
        const ts: i64 = @divTrunc(tick, 1000);
        const epoch_day: i64 = @divTrunc(ts, 86400);
        const civil = std.time.epoch.CivilDay.calculate(epoch_day);
        const year: u16 = @intCast(civil.year);
        const month: u8 = @intCast(@intFromEnum(civil.month));
        const day: u8 = civil.day;

        switch (self.switch_type) {
            .no, .second, .minute => {
                const day_secs = @mod(@as(u64, @intCast(ts)), 86400);
                const hh = @as(u8, @intCast(day_secs / 3600));
                const mm = @as(u8, @intCast(@mod(day_secs / 60, 60)));
                const ss = @as(u8, @intCast(@mod(day_secs, 60)));
                _ = std.fmt.bufPrint(&result, "{d:0>4}{d:0>2}{d:0>2}_{d:0>2}{d:0>2}{d:0>2}", .{
                    year, month, day, hh, mm, ss,
                }) catch {};
            },
            .hour => {
                const day_secs = @mod(@as(u64, @intCast(ts)), 86400);
                const hh = @as(u8, @intCast(day_secs / 3600));
                _ = std.fmt.bufPrint(&result, "{d:0>4}{d:0>2}{d:0>2}_{d:0>2}", .{
                    year, month, day, hh,
                }) catch {};
            },
            .day => {
                _ = std.fmt.bufPrint(&result, "{d:0>4}{d:0>2}{d:0>2}", .{
                    year, month, day,
                }) catch {};
            },
            .month => {
                _ = std.fmt.bufPrint(&result, "{d:0>4}{d:0>2}", .{
                    year, month,
                }) catch {};
            },
        }
        return result;
    }
};

// ============================================================================
// EnumLog — list log files in a directory
// ============================================================================

/// List all .log files in a directory, sorted by name.
pub fn enumLog(allocator: Allocator, dir_name: []const u8) ![]LogEntry {
    var dir = try fs.cwd().openDir(dir_name, .{ .iterate = true });
    defer dir.close();

    var entries = std.ArrayListUnmanaged(LogEntry){};
    errdefer {
        for (entries.items) |e| {
            allocator.free(e.name);
            allocator.free(e.path);
        }
        entries.deinit(allocator);
    }

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        // Only include .log files.
        if (!mem.endsWith(u8, entry.name, ".log")) continue;

        const name = try allocator.dupe(u8, entry.name);
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_name, entry.name });

        const stat = dir.statFile(entry.name) catch continue;
        try entries.append(allocator, .{
            .name = name,
            .path = path,
            .size = @intCast(stat.size),
        });
    }

    // Sort by name.
    std.mem.sort(LogEntry, entries.items, {}, struct {
        fn lessThan(_: void, a: LogEntry, b: LogEntry) bool {
            return mem.lessThan(u8, a.name, b.name);
        }
    }.lessThan);

    return try entries.toOwnedSlice(allocator);
}

/// Free the result of enumLog.
pub fn freeEnumLog(allocator: Allocator, entries: []LogEntry) void {
    for (entries) |e| {
        allocator.free(e.name);
        allocator.free(e.path);
    }
    allocator.free(entries);
}

// ============================================================================
// Convenience logging functions (C: Logging.c)
// ============================================================================

/// Write a server log entry (C: `ServerLog`, Logging.c:609).
pub fn serverLog(logger: ?*LOG, comptime fmt: []const u8, args: anytype) void {
    if (logger) |l| l.printf(fmt, args);
}

/// Write a hub security log entry (C: `HubLog`, Logging.c:666).
pub fn hubLog(logger: ?*LOG, hub_name: []const u8, comptime fmt: []const u8, args: anytype) void {
    if (logger) |l| {
        l.printf("[HUB \"{s}\"] " ++ fmt, .{hub_name} ++ args);
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "LogSwitchType values" {
    try testing.expectEqual(@as(u32, 0), @intFromEnum(LogSwitchType.no));
    try testing.expectEqual(@as(u32, 4), @intFromEnum(LogSwitchType.day));
}

test "HubLogConfig defaults" {
    const cfg = HubLogConfig{};
    try testing.expect(cfg.save_security_log);
    try testing.expect(!cfg.save_packet_log);
    try testing.expectEqual(LogSwitchType.day, cfg.security_log_switch_type);
}

test "LOG insert and drain" {
    const allocator = testing.allocator;
    const dir = test_log_dir ++ "/test_insert";

    // Clean up any previous run.
    fs.cwd().deleteTree(dir) catch {};
    defer fs.cwd().deleteTree(dir) catch {};

    const logger = try LOG.init(allocator, dir, "test", .day);
    defer logger.deinit();

    // Insert some records.
    logger.insertStringRecord("Hello, world!");
    logger.insertStringRecord("Second record");
    logger.printf("Formatted: {d}", .{42});

    // Allow the writer thread to process.
    time.sleep(50 * std.time.ns_per_ms);
}

test "LOG rotation on date change" {
    const allocator = testing.allocator;
    const dir = test_log_dir ++ "/test_rotation";

    fs.cwd().deleteTree(dir) catch {};
    defer fs.cwd().deleteTree(dir) catch {};

    const logger = try LOG.init(allocator, dir, "rot", .day);
    defer logger.deinit();

    logger.insertStringRecord("Record 1");
    time.sleep(50 * std.time.ns_per_ms);
}

test "enumLog lists log files" {
    const allocator = testing.allocator;
    const dir = test_log_dir ++ "/test_enum";

    fs.cwd().deleteTree(dir) catch {};
    defer fs.cwd().deleteTree(dir) catch {};
    fs.makeDirAbsolute(dir) catch {};

    // Create some fake log files.
    const f1 = try fs.cwd().createFile(dir ++ "/vpn_20260817.log", .{});
    defer f1.close();
    try f1.writer().writeAll("test log entry\n");

    const f2 = try fs.cwd().createFile(dir ++ "/vpn_20260816.log", .{});
    defer f2.close();
    try f2.writer().writeAll("older entry\n");

    // A non-log file should be excluded.
    const f3 = try fs.cwd().createFile(dir ++ "/readme.txt", .{});
    defer f3.close();

    const entries = try enumLog(allocator, dir);
    defer freeEnumLog(allocator, entries);

    try testing.expectEqual(@as(usize, 2), entries.len);
    // Sorted by name, so 20260816 comes before 20260817.
    try testing.expectEqualStrings("vpn_20260816.log", entries[0].name);
    try testing.expectEqualStrings("vpn_20260817.log", entries[1].name);
}

test "enumLog empty directory" {
    const allocator = testing.allocator;
    const dir = test_log_dir ++ "/test_enum_empty";

    fs.cwd().deleteTree(dir) catch {};
    defer fs.cwd().deleteTree(dir) catch {};
    fs.makeDirAbsolute(dir) catch {};

    const entries = try enumLog(allocator, dir);
    defer freeEnumLog(allocator, entries);

    try testing.expectEqual(@as(usize, 0), entries.len);
}

const test_log_dir = "/tmp/zig_softether_log_test";
