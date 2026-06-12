//! Compatibility shim for std.Thread synchronization primitives
//! (removed in Zig 0.16).
//! On POSIX: wraps pthread types. On Windows: wraps OS primitives.
const std = @import("std");
const builtin = @import("builtin");

pub const Mutex = if (builtin.os.tag == .windows)
    std.os.windows.SRWLOCK
else
    extern struct {
        handle: std.c.pthread_mutex_t = .{},
        pub fn lock(self: *@This()) void {
            _ = std.c.pthread_mutex_lock(&self.handle);
        }
        pub fn unlock(self: *@This()) void {
            _ = std.c.pthread_mutex_unlock(&self.handle);
        }
    };

pub const Condition = if (builtin.os.tag == .windows)
    std.os.windows.CONDITION_VARIABLE
else
    extern struct {
        handle: std.c.pthread_cond_t = .{},
        pub fn signal(self: *@This()) void {
            _ = std.c.pthread_cond_signal(&self.handle);
        }
        pub fn broadcast(self: *@This()) void {
            _ = std.c.pthread_cond_broadcast(&self.handle);
        }
        pub fn wait(self: *@This(), mutex: *Mutex) void {
            _ = std.c.pthread_cond_wait(&self.handle, &mutex.handle);
        }
        pub fn timedWait(self: *@This(), mutex: *Mutex, timeout_ns: u64) bool {
            var ts: std.c.timespec = undefined;
            // pthread_cond_timedwait uses absolute time
            _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
            ts.sec += @intCast(@divFloor(timeout_ns, std.time.ns_per_s));
            ts.nsec += @intCast(@mod(timeout_ns, std.time.ns_per_s));
            if (ts.nsec >= std.time.ns_per_s) {
                ts.sec += 1;
                ts.nsec -= std.time.ns_per_s;
            }
            return std.c.pthread_cond_timedwait(&self.handle, &mutex.handle, &ts) != std.c.ETIMEDOUT;
        }
    };
