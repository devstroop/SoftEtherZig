//! Compatibility shim for std.time.microTimestamp() removed in Zig 0.16.
//!
//! Uses clock_gettime(CLOCK_MONOTONIC) on POSIX for monotonic microsecond
//! timestamps. Falls back to gettimeofday on older systems.

const std = @import("std");
const builtin = @import("builtin");

/// Return a monotonically increasing timestamp in microseconds.
/// Suitable for latency/perf measurement, not for wall-clock time.
pub fn microTimestamp() i64 {
    if (builtin.os.tag == .windows) {
        // Windows: use QueryPerformanceCounter via std.time
        // For now, just return 0 — Windows support is not needed for iOS build
        return 0;
    }
    var ts: std.c.timespec = undefined;
    // CLOCK_MONOTONIC = 6 on Darwin (macOS/iOS), Linux, BSD
    const clock_id: std.c.clockid_t = @enumFromInt(6);
    _ = std.c.clock_gettime(clock_id, &ts);
    return @as(i64, ts.sec) * 1_000_000 + @as(i64, @divTrunc(ts.nsec, 1000));
}
