//! SoftEther VPN - Pure Zig Foundation Library
//!
//! This module provides Zig replacements for Mayaqua C utilities.
//! Phase 1 of the C-to-Zig migration.

pub const memory = @import("memory.zig");
pub const strings = @import("strings.zig");
pub const time = @import("time.zig");
pub const threads = @import("threads.zig");
pub const unicode = @import("unicode.zig");

// Re-export commonly used types
pub const Buffer = memory.Buffer;
pub const BufferReader = memory.BufferReader;
pub const TrackingAllocator = memory.TrackingAllocator;

pub const Timer = time.Timer;
pub const DateTime = time.DateTime;
pub const Deadline = time.Deadline;

pub const Mutex = threads.Mutex;
pub const Event = threads.Event;
pub const AtomicCounter = threads.AtomicCounter;
pub const AtomicFlag = threads.AtomicFlag;
pub const ThreadSafeQueue = threads.ThreadSafeQueue;
pub const ThreadPool = threads.ThreadPool;

// Tests
test {
    @import("std").testing.refAllDecls(@This());
}
