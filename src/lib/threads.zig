//! Threading Utilities Module
//!
//! Pure Zig replacement for threading functions in Mayaqua/Kernel.c
//! Provides thread management, synchronization primitives, and concurrent data structures.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

// ============================================================================
// Thread wrapper
// ============================================================================

/// Thread handle with cleanup tracking
pub fn Thread(comptime Context: type, comptime func: fn (Context) void) type {
    return struct {
        const Self = @This();

        handle: std.Thread,
        context: Context,

        pub fn spawn(context: Context) !Self {
            const handle = try std.Thread.spawn(.{}, wrapper, .{context});
            return .{
                .handle = handle,
                .context = context,
            };
        }

        fn wrapper(ctx: Context) void {
            func(ctx);
        }

        pub fn join(self: *Self) void {
            self.handle.join();
        }

        pub fn detach(self: *Self) void {
            self.handle.detach();
        }
    };
}

/// Simple thread spawn without context type
pub fn spawnThread(comptime func: fn () void) !std.Thread {
    return std.Thread.spawn(.{}, func, .{});
}

// ============================================================================
// Mutex (replaces LOCK)
// ============================================================================

pub const Mutex = std.Thread.Mutex;

/// RAII mutex lock guard
pub fn MutexGuard(comptime T: type) type {
    return struct {
        const Self = @This();

        mutex: *Mutex,
        value: *T,

        pub fn lock(mutex: *Mutex, value: *T) Self {
            mutex.lock();
            return .{ .mutex = mutex, .value = value };
        }

        pub fn unlock(self: *Self) void {
            self.mutex.unlock();
        }

        pub fn get(self: *Self) *T {
            return self.value;
        }
    };
}

// ============================================================================
// Condition Variable (replaces EVENT)
// ============================================================================

pub const Condition = std.Thread.Condition;

/// Event - a simple signal/wait primitive (like Windows EVENT)
pub const Event = struct {
    cond: Condition,
    mutex: Mutex,
    signaled: bool,
    auto_reset: bool,

    pub fn init(auto_reset: bool) Event {
        return .{
            .cond = .{},
            .mutex = .{},
            .signaled = false,
            .auto_reset = auto_reset,
        };
    }

    /// Signal the event (wake one or all waiters)
    pub fn set(self: *Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.signaled = true;
        if (self.auto_reset) {
            self.cond.signal();
        } else {
            self.cond.broadcast();
        }
    }

    /// Reset the event (for manual-reset events)
    pub fn reset(self: *Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.signaled = false;
    }

    /// Wait for the event to be signaled
    pub fn wait(self: *Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (!self.signaled) {
            self.cond.wait(&self.mutex);
        }
        if (self.auto_reset) {
            self.signaled = false;
        }
    }

    /// Wait with timeout (returns true if signaled, false if timeout)
    pub fn timedWait(self: *Event, timeout_ns: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.signaled) {
            if (self.auto_reset) self.signaled = false;
            return true;
        }

        const result = self.cond.timedWait(&self.mutex, timeout_ns);
        if (result == .timed_out) {
            return false;
        }

        if (self.signaled) {
            if (self.auto_reset) self.signaled = false;
            return true;
        }
        return false;
    }
};

// ============================================================================
// Read-Write Lock (replaces RWLOCK)
// ============================================================================

pub const RwLock = std.Thread.RwLock;

// ============================================================================
// Semaphore
// ============================================================================

pub const Semaphore = std.Thread.Semaphore;

// ============================================================================
// Atomic operations
// ============================================================================

pub fn Atomic(comptime T: type) type {
    return std.atomic.Value(T);
}

/// Atomic counter
pub const AtomicCounter = struct {
    value: Atomic(i64),

    pub fn init(initial: i64) AtomicCounter {
        return .{ .value = Atomic(i64).init(initial) };
    }

    pub fn get(self: *const AtomicCounter) i64 {
        return self.value.load(.acquire);
    }

    pub fn set(self: *AtomicCounter, val: i64) void {
        self.value.store(val, .release);
    }

    pub fn increment(self: *AtomicCounter) i64 {
        return self.value.fetchAdd(1, .acq_rel) + 1;
    }

    pub fn decrement(self: *AtomicCounter) i64 {
        return self.value.fetchSub(1, .acq_rel) - 1;
    }

    pub fn add(self: *AtomicCounter, delta: i64) i64 {
        return self.value.fetchAdd(delta, .acq_rel) + delta;
    }
};

/// Atomic boolean flag
pub const AtomicFlag = struct {
    value: Atomic(bool),

    pub fn init(initial: bool) AtomicFlag {
        return .{ .value = Atomic(bool).init(initial) };
    }

    pub fn get(self: *const AtomicFlag) bool {
        return self.value.load(.acquire);
    }

    pub fn set(self: *AtomicFlag, val: bool) void {
        self.value.store(val, .release);
    }

    pub fn swap(self: *AtomicFlag, val: bool) bool {
        return self.value.swap(val, .acq_rel);
    }
};

// ============================================================================
// Thread-safe queue (for packet queuing)
// ============================================================================

pub fn ThreadSafeQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        items: std.ArrayListUnmanaged(T),
        allocator: Allocator,
        mutex: Mutex,
        not_empty: Condition,
        closed: bool,

        pub fn init(allocator: Allocator) Self {
            return .{
                .items = .{},
                .allocator = allocator,
                .mutex = .{},
                .not_empty = .{},
                .closed = false,
            };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.allocator);
        }

        /// Push item to queue
        pub fn push(self: *Self, item: T) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.closed) return error.QueueClosed;

            try self.items.append(self.allocator, item);
            self.not_empty.signal();
        }

        /// Pop item from queue (blocking)
        pub fn pop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (self.items.items.len == 0 and !self.closed) {
                self.not_empty.wait(&self.mutex);
            }

            if (self.items.items.len == 0) return null;

            return self.items.orderedRemove(0);
        }

        /// Try to pop without blocking
        pub fn tryPop(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.items.items.len == 0) return null;
            return self.items.orderedRemove(0);
        }

        /// Pop with timeout (returns null on timeout or close)
        pub fn timedPop(self: *Self, timeout_ns: u64) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.items.items.len == 0 and !self.closed) {
                const result = self.not_empty.timedWait(&self.mutex, timeout_ns);
                if (result == .timed_out) return null;
            }

            if (self.items.items.len == 0) return null;
            return self.items.orderedRemove(0);
        }

        /// Get current queue length
        pub fn len(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.items.items.len;
        }

        /// Close the queue (wake all waiters)
        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.closed = true;
            self.not_empty.broadcast();
        }
    };
}

// ============================================================================
// Thread pool (for async operations)
// ============================================================================

pub const ThreadPool = struct {
    const Self = @This();
    const Task = struct {
        func: *const fn (*anyopaque) void,
        context: *anyopaque,
    };

    workers: []std.Thread,
    tasks: ThreadSafeQueue(Task),
    running: AtomicFlag,
    allocator: Allocator,

    pub fn init(allocator: Allocator, num_threads: usize) !Self {
        var self = Self{
            .workers = try allocator.alloc(std.Thread, num_threads),
            .tasks = ThreadSafeQueue(Task).init(allocator),
            .running = AtomicFlag.init(true),
            .allocator = allocator,
        };

        for (self.workers, 0..) |*worker, i| {
            worker.* = std.Thread.spawn(.{}, workerLoop, .{&self}) catch |err| {
                // Clean up already spawned threads
                for (self.workers[0..i]) |*w| {
                    w.join();
                }
                allocator.free(self.workers);
                self.tasks.deinit();
                return err;
            };
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.running.set(false);
        self.tasks.close();

        for (self.workers) |*worker| {
            worker.join();
        }

        self.allocator.free(self.workers);
        self.tasks.deinit();
    }

    pub fn submit(self: *Self, comptime func: fn (*anyopaque) void, context: *anyopaque) !void {
        try self.tasks.push(.{
            .func = func,
            .context = context,
        });
    }

    fn workerLoop(self: *Self) void {
        while (self.running.get()) {
            if (self.tasks.timedPop(100 * std.time.ns_per_ms)) |task| {
                task.func(task.context);
            }
        }

        // Drain remaining tasks
        while (self.tasks.tryPop()) |task| {
            task.func(task.context);
        }
    }
};

// ============================================================================
// Once (one-time initialization)
// ============================================================================

pub fn Once(comptime func: fn () void) type {
    return struct {
        done: AtomicFlag = AtomicFlag.init(false),
        mutex: Mutex = .{},

        pub fn call(self: *@This()) void {
            if (self.done.get()) return;

            self.mutex.lock();
            defer self.mutex.unlock();

            if (!self.done.get()) {
                func();
                self.done.set(true);
            }
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "AtomicCounter" {
    var counter = AtomicCounter.init(0);

    try testing.expectEqual(@as(i64, 1), counter.increment());
    try testing.expectEqual(@as(i64, 2), counter.increment());
    try testing.expectEqual(@as(i64, 1), counter.decrement());
    try testing.expectEqual(@as(i64, 1), counter.get());
}

test "Event auto-reset" {
    var event = Event.init(true);

    // Signal should wake waiter
    event.set();
    event.wait(); // Should return immediately
    // Auto-reset means it's now unsignaled
}

test "ThreadSafeQueue basic" {
    var queue = ThreadSafeQueue(u32).init(testing.allocator);
    defer queue.deinit();

    try queue.push(1);
    try queue.push(2);
    try queue.push(3);

    try testing.expectEqual(@as(usize, 3), queue.len());
    try testing.expectEqual(@as(?u32, 1), queue.tryPop());
    try testing.expectEqual(@as(?u32, 2), queue.tryPop());
    try testing.expectEqual(@as(?u32, 3), queue.tryPop());
    try testing.expectEqual(@as(?u32, null), queue.tryPop());
}

test "ThreadSafeQueue close" {
    var queue = ThreadSafeQueue(u32).init(testing.allocator);
    defer queue.deinit();

    try queue.push(1);
    queue.close();

    // Can still pop existing items
    try testing.expectEqual(@as(?u32, 1), queue.tryPop());

    // Cannot push after close
    try testing.expectError(error.QueueClosed, queue.push(2));
}

var test_once_counter: u32 = 0;

fn testOnceFunc() void {
    test_once_counter += 1;
}

test "Once" {
    var once = Once(testOnceFunc){};
    test_once_counter = 0;

    once.call();
    once.call();
    once.call();

    try testing.expectEqual(@as(u32, 1), test_once_counter);
}
