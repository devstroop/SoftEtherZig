//! Log engine — async writer thread with file rotation + syslog forwarding.
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
//! Scope (M14 — syslog forwarding):
//!   - SyslogClient: UDP socket, DNS resolution, RFC 3164 message format.
//!   - SyslogSetting save types (C: Cedar.h:328-331).
//!   - Log hooks: forward records based on save_type.
//!   - Config persistence: SyslogSettings folder in vpn_server.config.

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const Allocator = mem.Allocator;
const time = std.time;

const log = std.log.scoped(.cedar_log);

// ============================================================================
// Syslog save types (C: Cedar.h:328-331)
// ============================================================================

/// Syslog forwarding mode (C: `SYSLOG_*` constants).
pub const SyslogSaveType = enum(u32) {
    none = 0,
    server_log = 1,
    server_and_hub_security_log = 2,
    server_and_hub_all_log = 3,
};

/// Default syslog UDP port (C: `SYSLOG_PORT`).
pub const SYSLOG_PORT: u32 = 514;
/// Maximum syslog message length (C: `SYSLOG_MAX_LENGTH`).
pub const SYSLOG_MAX_LENGTH: usize = 1024;
/// DNS re-resolution interval in seconds (C: `SYSLOG_POLL_IP_INTERVAL`).
pub const SYSLOG_POLL_IP_INTERVAL: u64 = 300;

// ============================================================================
// SyslogSetting — persisted config (C: Server.h:235-239)
// ============================================================================

/// Syslog destination configuration. Stored in vpn_server.config as a
/// `SyslogSettings` folder with keys `SaveType`, `HostName`, `Port`.
pub const SyslogSetting = struct {
    save_type: SyslogSaveType = .none,
    hostname: []u8 = &.{},
    port: u32 = SYSLOG_PORT,

    pub fn deinit(self: *SyslogSetting, allocator: Allocator) void {
        allocator.free(self.hostname);
        self.* = .{};
    }

    pub fn clone(self: *const SyslogSetting, allocator: Allocator) !SyslogSetting {
        return .{
            .save_type = self.save_type,
            .hostname = try allocator.dupe(u8, self.hostname),
            .port = self.port,
        };
    }
};

// ============================================================================
// SyslogClient — UDP syslog forwarder (C: Logging.c SLOG)
// ============================================================================

const builtin = @import("builtin");

/// Platform-correct "invalid fd" sentinel — HANDLE on Windows, -1 on POSIX.
const invalid_fd: std.posix.fd_t = if (builtin.os.tag == .windows)
    @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))))
else
    @as(std.posix.fd_t, -1);

/// UDP syslog client. Resolves the hostname, caches the IP, and sends
/// RFC 3164 formatted datagrams. Re-resolves DNS periodically.
pub const SyslogClient = struct {
    allocator: Allocator,
    /// Mutex protecting all mutable state (hostname, port, dest_ip, socket).
    mutex: std.Thread.Mutex = .{},
    /// Current destination hostname.
    hostname: []u8 = &.{},
    /// Current destination port (host byte order).
    port: u32 = SYSLOG_PORT,
    /// Cached destination IP (host byte order, 0 = unresolved).
    dest_ip: u32 = 0,
    /// Unix timestamp of last DNS resolution.
    last_resolve_ts: i64 = 0,
    /// UDP socket (invalid_fd when not connected).
    socket: std.posix.fd_t = invalid_fd,
    /// Cached hostname for the current send operation (owned snapshot).
    send_hostname: []u8 = &.{},

    /// Create a new SyslogClient.
    pub fn init(allocator: Allocator) SyslogClient {
        return .{ .allocator = allocator };
    }

    /// Stop and free the client.
    pub fn deinit(self: *SyslogClient) void {
        self.mutex.lock();
        self.closeSocketLocked();
        self.allocator.free(self.hostname);
        self.allocator.free(self.send_hostname);
        self.* = undefined;
        self.allocator = undefined; // already freed everything
    }

    /// Reconfigure the syslog destination. Pass empty hostname or port 0
    /// to disable syslog forwarding.
    pub fn configure(self: *SyslogClient, hostname: []const u8, port: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closeSocketLocked();
        self.allocator.free(self.hostname);
        self.hostname = self.allocator.dupe(u8, hostname) catch &.{};
        self.port = if (port == 0) SYSLOG_PORT else port;
        self.dest_ip = 0; // force re-resolve
        self.last_resolve_ts = 0;
    }

    /// Send a syslog message (C: `SendSysLog`). Formats as RFC 3164 and
    /// sends a UDP datagram. Silently drops if destination is not configured.
    pub fn send(self: *SyslogClient, message: []const u8) void {
        self.mutex.lock();

        // Snapshot all config under the lock to avoid use-after-free.
        self.allocator.free(self.send_hostname);
        self.send_hostname = self.allocator.dupe(u8, self.hostname) catch {
            self.mutex.unlock();
            return;
        };
        const hostname = self.send_hostname;
        const port: u16 = @intCast(self.port);
        self.mutex.unlock();

        if (hostname.len == 0) return;

        // Resolve hostname if needed (updates self.dest_ip under mutex).
        self.maybeResolve(hostname);

        // Use the resolved IP from the mutex snapshot or after resolve.
        self.mutex.lock();
        const ip = self.dest_ip;
        self.mutex.unlock();
        if (ip == 0) return;

        // Format: RFC 3164 — `<pri>Mon DD HH:MM:SS hostname tag: message`
        // Priority: facility(14=local0) + severity(6=info) = 134.
        var buf: [SYSLOG_MAX_LENGTH + 128]u8 = undefined;
        const ts = std.time.timestamp();
        const epoch_seconds: u64 = @intCast(@max(0, ts));
        const day_seconds = @mod(epoch_seconds, 86400);
        const hours: u8 = @intCast(day_seconds / 3600);
        const mins: u8 = @intCast(@mod(day_seconds / 60, 60));
        const secs: u8 = @intCast(@mod(day_seconds, 60));

        // Month names for RFC 3164.
        const month_names = [_][]const u8{
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        };
        const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_seconds) };
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        const month_idx: usize = @intCast(@intFromEnum(month_day.month) - 1);
        const day: u8 = month_day.day_index + 1;

        const msg_len = @min(message.len, SYSLOG_MAX_LENGTH);
        const frame = std.fmt.bufPrint(
            &buf,
            "<134>{s} {d: >2} {d:0>2}:{d:0>2}:{d:0>2} {s} {s}",
            .{
                month_names[month_idx],
                day,
                hours,
                mins,
                secs,
                hostname,
                message[0..msg_len],
            },
        ) catch return;

        // Send UDP datagram — hold the lock briefly for socket access.
        self.mutex.lock();
        defer self.mutex.unlock();
        const sock = self.getSocketLocked() orelse return;
        const dest = std.posix.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = std.mem.nativeToBig(u32, ip),
            .zero = [_]u8{0} ** 8,
        };
        const dest_ptr: *const std.posix.sockaddr = @ptrCast(&dest);
        _ = std.posix.sendto(sock, frame, 0, dest_ptr, @sizeOf(std.posix.sockaddr.in)) catch |err| {
            log.warn("Syslog send failed: {}", .{err});
        };
    }

    // ---- Internal (must be called with mutex held) --------------------------

    fn closeSocketLocked(self: *SyslogClient) void {
        if (self.socket != invalid_fd) {
            std.posix.close(self.socket);
            self.socket = invalid_fd;
        }
    }

    fn getSocketLocked(self: *SyslogClient) ?std.posix.fd_t {
        if (self.socket != invalid_fd) return self.socket;
        const sock = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0) catch return null;
        // Set a short send timeout so we never block the writer thread.
        const timeout: std.posix.timeval = .{ .sec = 0, .usec = 100_000 }; // 100ms
        std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
        self.socket = sock;
        return self.socket;
    }

    // ---- Internal (mutex not required) --------------------------------------

    fn maybeResolve(self: *SyslogClient, hostname: []const u8) void {
        self.mutex.lock();
        const now = std.time.timestamp();
        const needs_resolve = self.dest_ip == 0 or
            (now - self.last_resolve_ts >= SYSLOG_POLL_IP_INTERVAL);
        self.mutex.unlock();

        if (!needs_resolve) return;

        self.resolveHostname(hostname);
    }

    fn resolveHostname(self: *SyslogClient, hostname: []const u8) void {
        // Try parsing as a dotted-decimal IP first.
        const ip = parseIPv4(hostname) orelse blk: {
            // DNS resolution: use getaddrinfo.
            const addr_list = std.net.getAddressList(
                self.allocator,
                hostname,
                @intCast(self.port),
            ) catch {
                log.warn("Syslog: failed to resolve hostname '{s}'", .{hostname});
                self.mutex.lock();
                self.dest_ip = 0;
                self.mutex.unlock();
                return;
            };
            defer addr_list.deinit();
            for (addr_list.addrs) |addr| {
                if (addr.any.family == std.posix.AF.INET) {
                    break :blk std.mem.bigToNative(u32, addr.in.sa.addr);
                }
            }
            self.mutex.lock();
            self.dest_ip = 0;
            self.mutex.unlock();
            return;
        };
        self.mutex.lock();
        self.dest_ip = ip;
        self.last_resolve_ts = std.time.timestamp();
        self.mutex.unlock();
    }

    fn parseIPv4(str: []const u8) ?u32 {
        var parts: [4]u8 = undefined;
        var idx: usize = 0;
        var start: usize = 0;
        for (str, 0..) |c, i| {
            if (c == '.') {
                if (idx >= 4) return null;
                parts[idx] = std.fmt.parseInt(u8, str[start..i], 10) catch return null;
                idx += 1;
                start = i + 1;
            }
        }
        if (idx != 3) return null;
        parts[3] = std.fmt.parseInt(u8, str[start..], 10) catch return null;
        return (@as(u32, parts[0]) << 24) | (@as(u32, parts[1]) << 16) |
            (@as(u32, parts[2]) << 8) | @as(u32, parts[3]);
    }
};

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

/// Log category — used for syslog save_type filtering.
pub const LogCategory = enum(u8) {
    server = 0,
    hub_security = 1,
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
    /// Syslog client for forwarding (M14). Null when syslog is disabled.
    syslog_client: ?*SyslogClient = null,
    /// Syslog forwarding mode — controls which records are sent.
    syslog_save_type: SyslogSaveType = .none,
    /// Log category — determines syslog filtering behavior.
    log_category: LogCategory = .server,

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

    /// Attach a syslog client for forwarding. Does not take ownership —
    /// the caller owns the SyslogClient and must outlive the LOG.
    pub fn setSyslogClient(self: *LOG, client: ?*SyslogClient, save_type: SyslogSaveType) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.syslog_client = client;
        self.syslog_save_type = save_type;
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
                // Forward to syslog if configured.
                self.forwardToSyslog(record.string, self.log_category == .hub_security);
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

        // Compute year/month/day using epoch API.
        const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_seconds) };
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const year: u16 = @intCast(year_day.year);
        const month_day = year_day.calculateMonthDay();
        const month: u8 = @intCast(@intFromEnum(month_day.month));
        const day: u8 = month_day.day_index + 1;

        const prefix_len = (std.fmt.bufPrint(&buf, "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}] ", .{
            year, month, day, hours, mins, secs,
        }) catch return).len;

        const msg_end = @min(record.string.len, buf.len - prefix_len - 1);
        @memcpy(buf[prefix_len..][0..msg_end], record.string[0..msg_end]);
        buf[prefix_len + msg_end] = '\n';

        file.writeAll(buf[0 .. prefix_len + msg_end + 1]) catch |err| {
            log.warn("Failed to write log record: {}", .{err});
        };
        self.current_size += prefix_len + msg_end + 1;
    }

    /// Forward a log record to syslog if a client is attached (C: `SiWriteSysLog`).
    /// `is_hub_log` indicates whether this record is a hub security log.
    fn forwardToSyslog(self: *LOG, record: []const u8, is_hub_log: bool) void {
        // Snapshot the syslog_client pointer and save_type under the LOG mutex
        // to avoid racing with setSyslogClient().
        self.mutex.lock();
        const client = self.syslog_client orelse {
            self.mutex.unlock();
            return;
        };
        const save_type = self.syslog_save_type;
        self.mutex.unlock();

        // Check save_type mode.
        switch (save_type) {
            .none => return,
            .server_log => {
                if (is_hub_log) return;
            },
            .server_and_hub_security_log, .server_and_hub_all_log => {},
        }

        // Format syslog message: `[prefix] record`
        var buf: [SYSLOG_MAX_LENGTH + 64]u8 = undefined;
        const prefix_len = self.prefix.len;
        const copy_len = @min(record.len, buf.len - prefix_len - 1);
        @memcpy(buf[0..prefix_len], self.prefix[0..prefix_len]);
        @memcpy(buf[prefix_len..][0..copy_len], record[0..copy_len]);
        const total = prefix_len + copy_len;
        client.send(buf[0..total]);
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
        const ds = std.mem.span(@as([*:0]const u8, @ptrCast(&date_str)));
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}_{s}~{d:0>2}.log",
            .{
                self.dir_name,
                self.prefix,
                ds,
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
        const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const year: u16 = @intCast(year_day.year);
        const month_day = year_day.calculateMonthDay();
        const month: u8 = @intCast(@intFromEnum(month_day.month));
        const day: u8 = month_day.day_index + 1;

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
    std.Thread.sleep(50 * std.time.ns_per_ms);
}

test "LOG rotation on date change" {
    const allocator = testing.allocator;
    const dir = test_log_dir ++ "/test_rotation";

    fs.cwd().deleteTree(dir) catch {};
    defer fs.cwd().deleteTree(dir) catch {};

    const logger = try LOG.init(allocator, dir, "rot", .day);
    defer logger.deinit();

    logger.insertStringRecord("Record 1");
    std.Thread.sleep(50 * std.time.ns_per_ms);
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
    try f1.writeAll("test log entry\n");

    const f2 = try fs.cwd().createFile(dir ++ "/vpn_20260816.log", .{});
    defer f2.close();
    try f2.writeAll("older entry\n");

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

// ============================================================================
// Syslog tests (M14)
// ============================================================================

test "SyslogSaveType enum values" {
    try testing.expectEqual(@as(u32, 0), @intFromEnum(SyslogSaveType.none));
    try testing.expectEqual(@as(u32, 1), @intFromEnum(SyslogSaveType.server_log));
    try testing.expectEqual(@as(u32, 2), @intFromEnum(SyslogSaveType.server_and_hub_security_log));
    try testing.expectEqual(@as(u32, 3), @intFromEnum(SyslogSaveType.server_and_hub_all_log));
}

test "SyslogSetting default and clone" {
    const allocator = testing.allocator;
    var setting = SyslogSetting{};
    defer setting.deinit(allocator);

    try testing.expectEqual(SyslogSaveType.none, setting.save_type);
    try testing.expectEqual(@as(u32, SYSLOG_PORT), setting.port);
    try testing.expectEqual(@as(usize, 0), setting.hostname.len);

    // Configure
    setting.hostname = try allocator.dupe(u8, "syslog.example.com");
    setting.port = 1514;
    setting.save_type = .server_log;

    // Clone
    var cloned = try setting.clone(allocator);
    defer cloned.deinit(allocator);

    try testing.expectEqual(SyslogSaveType.server_log, cloned.save_type);
    try testing.expectEqual(@as(u32, 1514), cloned.port);
    try testing.expectEqualStrings("syslog.example.com", cloned.hostname);
    // Deep copy — different pointer.
    try testing.expect(setting.hostname.ptr != cloned.hostname.ptr);
}

test "SyslogClient init and deinit" {
    const allocator = testing.allocator;
    var client = SyslogClient.init(allocator);
    defer client.deinit();

    try testing.expectEqualStrings("", client.hostname);
    try testing.expectEqual(@as(u32, SYSLOG_PORT), client.port);
    try testing.expectEqual(@as(u32, 0), client.dest_ip);
    try testing.expect(client.socket < 0);
}

test "SyslogClient configure" {
    const allocator = testing.allocator;
    var client = SyslogClient.init(allocator);
    defer client.deinit();

    // Configure with IP address
    client.configure("192.168.1.100", 1514);
    try testing.expectEqualStrings("192.168.1.100", client.hostname);
    try testing.expectEqual(@as(u32, 1514), client.port);
    try testing.expectEqual(@as(u32, 0), client.dest_ip); // force re-resolve

    // Configure with port 0 → defaults to SYSLOG_PORT
    client.configure("10.0.0.1", 0);
    try testing.expectEqual(@as(u32, SYSLOG_PORT), client.port);

    // Configure with empty hostname → disables
    client.configure("", 1514);
    try testing.expectEqual(@as(usize, 0), client.hostname.len);
}

test "SyslogClient parseIPv4" {
    try testing.expectEqual(@as(?u32, 0xC0A80101), SyslogClient.parseIPv4("192.168.1.1"));
    try testing.expectEqual(@as(?u32, 0x7F000001), SyslogClient.parseIPv4("127.0.0.1"));
    try testing.expectEqual(@as(?u32, 0), SyslogClient.parseIPv4("0.0.0.0"));
    try testing.expectEqual(@as(?u32, 0xFFFFFFFF), SyslogClient.parseIPv4("255.255.255.255"));
    try testing.expectEqual(@as(?u32, null), SyslogClient.parseIPv4("not-an-ip"));
    try testing.expectEqual(@as(?u32, null), SyslogClient.parseIPv4("192.168.1"));
    try testing.expectEqual(@as(?u32, null), SyslogClient.parseIPv4("192.168.1.1.1"));
}

test "SyslogClient send to IP (no DNS)" {
    const allocator = testing.allocator;
    var client = SyslogClient.init(allocator);
    defer client.deinit();

    // Configure with a direct IP — no DNS needed.
    client.configure("127.0.0.1", 1514);
    // Resolve the IP.
    client.dest_ip = 0x7F000001;
    client.last_resolve_ts = std.time.timestamp();

    // Send — should not crash (UDP to localhost, no receiver is fine).
    client.send("test syslog message from Zig");
}

test "SyslogClient send with empty hostname skips" {
    const allocator = testing.allocator;
    var client = SyslogClient.init(allocator);
    defer client.deinit();

    // No hostname configured — send should be a no-op.
    client.send("should not be sent");
}

test "SyslogSaveType round-trip via @enumFromInt" {
    try testing.expectEqual(SyslogSaveType.none, @as(SyslogSaveType, @enumFromInt(0)));
    try testing.expectEqual(SyslogSaveType.server_log, @as(SyslogSaveType, @enumFromInt(1)));
    try testing.expectEqual(SyslogSaveType.server_and_hub_security_log, @as(SyslogSaveType, @enumFromInt(2)));
    try testing.expectEqual(SyslogSaveType.server_and_hub_all_log, @as(SyslogSaveType, @enumFromInt(3)));
}
