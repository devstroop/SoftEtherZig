//! DNS Cache with TTL Awareness
//!
//! Provides a thread-safe DNS resolution cache that stores resolved addresses
//! with configurable TTL to avoid repeated OS-level DNS lookups during
//! reconnection cycles.

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const testing = std.testing;

const log = std.log.scoped(.dns_cache);

/// Default TTL for cached entries (seconds)
const DEFAULT_TTL_SECS: i64 = 300; // 5 minutes

/// Maximum number of cached hostnames
const MAX_CACHE_ENTRIES: usize = 64;

/// A cached DNS resolution result
pub const CacheEntry = struct {
    addresses: []net.Address,
    /// Timestamp (seconds since epoch) when this entry expires
    expires_at: i64,
    /// How many times this entry has been used
    hit_count: u64 = 0,

    fn isExpired(self: *const CacheEntry, now: i64) bool {
        return now >= self.expires_at;
    }
};

/// Thread-safe DNS cache with TTL-based expiration
pub const DnsCache = struct {
    entries: std.StringHashMap(CacheEntry),
    allocator: Allocator,
    mutex: Mutex = .{},
    ttl_secs: i64,
    stats: Stats = .{},

    pub const Stats = struct {
        hits: u64 = 0,
        misses: u64 = 0,
        evictions: u64 = 0,
    };

    pub fn init(allocator: Allocator, ttl_secs: ?i64) DnsCache {
        return .{
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .allocator = allocator,
            .ttl_secs = ttl_secs orelse DEFAULT_TTL_SECS,
        };
    }

    pub fn deinit(self: *DnsCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.addresses);
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    /// Look up a hostname in the cache. Returns cached addresses if valid.
    pub fn get(self: *DnsCache, hostname: []const u8) ?[]const net.Address {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();

        if (self.entries.getPtr(hostname)) |entry| {
            if (entry.isExpired(now)) {
                log.debug("Cache expired for {s}", .{hostname});
                self.removeEntryLocked(hostname);
                self.stats.misses += 1;
                return null;
            }
            entry.hit_count += 1;
            self.stats.hits += 1;
            log.debug("Cache hit for {s} ({d} addrs, hit #{d})", .{
                hostname, entry.addresses.len, entry.hit_count,
            });
            return entry.addresses;
        }

        self.stats.misses += 1;
        return null;
    }

    /// Store resolved addresses for a hostname with TTL.
    pub fn put(self: *DnsCache, hostname: []const u8, addresses: []const net.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();

        // Evict expired entries if at capacity
        if (self.entries.count() >= MAX_CACHE_ENTRIES) {
            self.evictExpiredLocked(now);
        }

        // If still at capacity, evict the oldest entry
        if (self.entries.count() >= MAX_CACHE_ENTRIES) {
            self.evictOldestLocked();
        }

        // Remove existing entry for this hostname
        if (self.entries.contains(hostname)) {
            self.removeEntryLocked(hostname);
        }

        // Copy the hostname and addresses into owned memory
        const owned_hostname = try self.allocator.dupe(u8, hostname);
        errdefer self.allocator.free(owned_hostname);

        const owned_addrs = try self.allocator.dupe(net.Address, addresses);
        errdefer self.allocator.free(owned_addrs);

        try self.entries.put(owned_hostname, .{
            .addresses = owned_addrs,
            .expires_at = now + self.ttl_secs,
        });

        log.debug("Cached {d} addrs for {s} (TTL {d}s)", .{
            addresses.len, hostname, self.ttl_secs,
        });
    }

    /// Invalidate a specific hostname entry.
    pub fn invalidate(self: *DnsCache, hostname: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.removeEntryLocked(hostname);
    }

    /// Clear all cached entries.
    pub fn clear(self: *DnsCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.addresses);
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.clearAndFree();
    }

    /// Resolve a hostname, using the cache if available.
    /// Falls back to OS-level DNS resolution on cache miss.
    pub fn resolveWithCache(self: *DnsCache, hostname: []const u8, port: u16) ![]const net.Address {
        // Check cache first
        if (self.get(hostname)) |cached| {
            return cached;
        }

        // Cache miss — do real DNS resolution
        const addr_list = try net.getAddressList(self.allocator, hostname, port);
        defer addr_list.deinit();

        if (addr_list.addrs.len == 0) {
            return error.UnknownHostName;
        }

        // Store in cache
        try self.put(hostname, addr_list.addrs);

        // Return the cached copy (which we just inserted)
        return self.get(hostname) orelse error.UnknownHostName;
    }

    // -- Internal helpers (caller must hold mutex) --

    fn removeEntryLocked(self: *DnsCache, hostname: []const u8) void {
        if (self.entries.fetchRemove(hostname)) |kv| {
            self.allocator.free(kv.value.addresses);
            self.allocator.free(kv.key);
        }
    }

    fn evictExpiredLocked(self: *DnsCache, now: i64) void {
        var to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired(now)) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                self.allocator.free(kv.value.addresses);
                self.allocator.free(kv.key);
                self.stats.evictions += 1;
            }
        }
    }

    fn evictOldestLocked(self: *DnsCache) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_expires: i64 = std.math.maxInt(i64);

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at < oldest_expires) {
                oldest_expires = entry.value_ptr.expires_at;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.entries.fetchRemove(key)) |kv| {
                self.allocator.free(kv.value.addresses);
                self.allocator.free(kv.key);
                self.stats.evictions += 1;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DnsCache init and deinit" {
    var cache = DnsCache.init(testing.allocator, 60);
    defer cache.deinit();

    try testing.expectEqual(@as(i64, 60), cache.ttl_secs);
    try testing.expectEqual(@as(u64, 0), cache.stats.hits);
    try testing.expectEqual(@as(u64, 0), cache.stats.misses);
}

test "DnsCache get returns null for missing" {
    var cache = DnsCache.init(testing.allocator, 60);
    defer cache.deinit();

    const result = cache.get("nonexistent.example.com");
    try testing.expect(result == null);
    try testing.expectEqual(@as(u64, 1), cache.stats.misses);
}

test "DnsCache put and get round-trip" {
    var cache = DnsCache.init(testing.allocator, 300);
    defer cache.deinit();

    const addr = try net.Address.parseIp4("1.2.3.4", 443);
    const addrs = [_]net.Address{addr};
    try cache.put("example.com", &addrs);

    const cached = cache.get("example.com");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(usize, 1), cached.?.len);
    try testing.expectEqual(@as(u16, 443), cached.?[0].getPort());
    try testing.expectEqual(@as(u64, 1), cache.stats.hits);
}

test "DnsCache invalidate removes entry" {
    var cache = DnsCache.init(testing.allocator, 300);
    defer cache.deinit();

    const addr = try net.Address.parseIp4("10.0.0.1", 80);
    const addrs = [_]net.Address{addr};
    try cache.put("test.local", &addrs);

    try testing.expect(cache.get("test.local") != null);
    cache.invalidate("test.local");
    try testing.expect(cache.get("test.local") == null);
}

test "DnsCache clear removes all entries" {
    var cache = DnsCache.init(testing.allocator, 300);
    defer cache.deinit();

    const addr1 = try net.Address.parseIp4("1.1.1.1", 53);
    const addr2 = try net.Address.parseIp4("8.8.8.8", 53);
    try cache.put("dns1.example.com", &[_]net.Address{addr1});
    try cache.put("dns2.example.com", &[_]net.Address{addr2});

    cache.clear();
    try testing.expect(cache.get("dns1.example.com") == null);
    try testing.expect(cache.get("dns2.example.com") == null);
}

test "DnsCache multiple addresses per hostname" {
    var cache = DnsCache.init(testing.allocator, 300);
    defer cache.deinit();

    const addr1 = try net.Address.parseIp4("10.0.0.1", 443);
    const addr2 = try net.Address.parseIp4("10.0.0.2", 443);
    const addrs = [_]net.Address{ addr1, addr2 };
    try cache.put("multi.example.com", &addrs);

    const cached = cache.get("multi.example.com");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(usize, 2), cached.?.len);
}

test "DnsCache replaces existing entry" {
    var cache = DnsCache.init(testing.allocator, 300);
    defer cache.deinit();

    const addr1 = try net.Address.parseIp4("1.1.1.1", 443);
    try cache.put("replace.example.com", &[_]net.Address{addr1});

    const addr2 = try net.Address.parseIp4("2.2.2.2", 443);
    try cache.put("replace.example.com", &[_]net.Address{addr2});

    const cached = cache.get("replace.example.com");
    try testing.expect(cached != null);
    try testing.expectEqual(@as(usize, 1), cached.?.len);
}

test "DnsCache stats tracking" {
    var cache = DnsCache.init(testing.allocator, 300);
    defer cache.deinit();

    _ = cache.get("miss1.com");
    _ = cache.get("miss2.com");

    const addr = try net.Address.parseIp4("1.2.3.4", 80);
    try cache.put("hit.com", &[_]net.Address{addr});
    _ = cache.get("hit.com");
    _ = cache.get("hit.com");

    try testing.expectEqual(@as(u64, 2), cache.stats.hits);
    try testing.expectEqual(@as(u64, 2), cache.stats.misses);
}
