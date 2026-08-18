//! Pre-spawned thread pool for connection handling.
//!
//! Replaces the thread-per-connection model with a fixed-size pool of
//! worker threads consuming jobs from a mutex+condvar queue. This avoids
//! the overhead of spawning/detaching an OS thread for every accepted
//! connection.
//!
//! C equivalent: the C codebase uses `NewThread` per-connection but
//! modern deployments benefit from a pool to cap kernel thread usage.

const std = @import("std");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.cedar_server);

// ============================================================================
// Constants
// ============================================================================

/// Default number of worker threads. On a multi-core server, this allows
/// parallel TLS handshakes while capping kernel thread overhead.
pub const DEFAULT_WORKER_COUNT: u32 = 8;

/// Max queued jobs before the pool starts dropping (back-pressure).
/// Prevents unbounded memory growth under DoS.
pub const MAX_QUEUED_JOBS: u32 = 4096;

// ============================================================================
// Job
// ============================================================================

/// A unit of work to be executed by a worker thread.
pub const Job = struct {
    /// The function to execute.
    callback: *const fn (ctx: *anyopaque) void,
    /// Opaque context pointer (typically the ConnJob or equivalent).
    ctx: *anyopaque,
};

// ============================================================================
// Queue (mutex + condvar)
// ============================================================================

const Queue = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    buf: [MAX_QUEUED_JOBS]Job = undefined,
    head: u32 = 0,
    tail: u32 = 0,
    count: u32 = 0,
    shutdown: bool = false,

    fn push(self: *Queue, job: Job) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count >= MAX_QUEUED_JOBS) return false;
        self.buf[self.tail % MAX_QUEUED_JOBS] = job;
        self.tail +|= 1;
        self.count +|= 1;
        self.cond.signal();
        return true;
    }

    fn pop(self: *Queue) ?Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.count == 0) {
            if (self.shutdown) return null;
            self.cond.wait(&self.mutex);
        }
        const job = self.buf[self.head % MAX_QUEUED_JOBS];
        self.head +|= 1;
        self.count -|= 1;
        return job;
    }

    fn wakeAll(self: *Queue) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.shutdown = true;
        self.cond.broadcast();
    }
};

// ============================================================================
// ThreadPool
// ============================================================================

pub const ThreadPool = struct {
    allocator: Allocator,
    queue: *Queue,
    threads: []std.Thread,

    /// Create and start a thread pool with `worker_count` threads.
    /// Each thread runs `workerFn` consuming jobs from the shared queue.
    pub fn start(allocator: Allocator, worker_count: u32) !ThreadPool {
        const queue = try allocator.create(Queue);
        errdefer allocator.destroy(queue);
        queue.* = .{};

        const threads = try allocator.alloc(std.Thread, worker_count);
        errdefer allocator.free(threads);

        var spawned: u32 = 0;
        errdefer {
            queue.wakeAll();
            for (threads[0..spawned]) |t| t.join();
        }

        for (0..worker_count) |i| {
            threads[i] = try std.Thread.spawn(.{}, workerFn, .{queue});
            spawned += 1;
        }

        log.info("thread pool started: {d} workers", .{worker_count});
        return .{
            .allocator = allocator,
            .queue = queue,
            .threads = threads,
        };
    }

    /// Submit a job to the pool. Returns false if the queue is full.
    pub fn submit(self: *ThreadPool, job: Job) bool {
        return self.queue.push(job);
    }

    /// Signal all workers to drain remaining jobs and stop, then join them.
    pub fn shutdown(self: *ThreadPool) void {
        self.queue.wakeAll();
        for (self.threads) |t| t.join();
        log.info("thread pool stopped", .{});
    }

    /// Free resources (call after shutdown).
    pub fn deinit(self: *ThreadPool) void {
        self.allocator.free(self.threads);
        self.allocator.destroy(self.queue);
    }
};

fn workerFn(queue: *Queue) void {
    while (queue.pop()) |job| {
        job.callback(job.ctx);
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "thread pool submit and execute" {
    const Counter = struct {
        var count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
        fn incr(_: *anyopaque) void {
            _ = count.fetchAdd(1, .release);
        }
    };

    var pool = try ThreadPool.start(testing.allocator, 2);
    defer pool.deinit();

    for (0..10) |_| {
        _ = pool.submit(.{ .callback = Counter.incr, .ctx = undefined });
    }

    pool.shutdown();

    // Give a moment for all jobs to complete.
    std.Thread.sleep(50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 10), Counter.count.load(.acquire));
    Counter.count.store(0, .release);
}
