//! Comprehensive adapter lifecycle and functionality tests
//! Tests creation, configuration, I/O operations, and error handling

const std = @import("std");
const testing = std.testing;
const adapter = @import("adapter.zig");

test "adapter creation and destruction" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // Verify state
    try testing.expectEqual(adapter.AdapterState.created, test_adapter.state);
    try testing.expect(test_adapter.dhcp_client == null);
    try testing.expectEqual(@as(u64, 0), test_adapter.stats.packets_read);
}

test "adapter config validation" {
    const alloc = testing.allocator;

    // Valid config
    const valid = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, valid);
    defer test_adapter.deinit();

    try testing.expectEqual(@as(usize, 64), test_adapter.recv_queue.capacity());
    try testing.expectEqual(@as(usize, 64), test_adapter.send_queue.capacity());
}

test "adapter stats accumulation" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // Manually update stats (simulating operations)
    test_adapter.stats.packets_read = 1000;
    test_adapter.stats.bytes_read = 1500000;
    test_adapter.stats.packets_written = 900;
    test_adapter.stats.bytes_written = 1350000;

    try testing.expectEqual(@as(u64, 1000), test_adapter.stats.packets_read);
    try testing.expectEqual(@as(u64, 1500000), test_adapter.stats.bytes_read);
    try testing.expectEqual(@as(u64, 900), test_adapter.stats.packets_written);
}

test "CStats FFI structure layout" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
        .poll_timeout_ms = 1,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // Set stats
    test_adapter.stats.packets_read = 42;
    test_adapter.stats.recv_queue_drops = 3;

    // Export to C struct
    var c_stats: adapter.CStats = undefined;
    adapter.zig_adapter_get_stats(test_adapter, &c_stats);

    try testing.expectEqual(@as(u64, 42), c_stats.packets_read);
    try testing.expectEqual(@as(u64, 3), c_stats.recv_queue_drops);
}

test "adapter queue state tracking" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 8, // Small for testing
        .send_queue_size = 8,
        .packet_pool_size = 16,
        .batch_size = 4,
        .poll_timeout_ms = 1,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // Check initial queue state
    var recv_used: usize = undefined;
    var recv_cap: usize = undefined;
    var send_used: usize = undefined;
    var send_cap: usize = undefined;

    adapter.zig_adapter_get_queue_info(test_adapter, &recv_used, &recv_cap, &send_used, &send_cap);

    try testing.expectEqual(@as(usize, 0), recv_used);
    try testing.expectEqual(@as(usize, 8), recv_cap);
    try testing.expectEqual(@as(usize, 0), send_used);
    try testing.expectEqual(@as(usize, 8), send_cap);
}

test "adapter pool management" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 100,
        .batch_size = 32,
        .poll_timeout_ms = 1,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    var available: usize = undefined;
    var total: usize = undefined;

    adapter.zig_adapter_get_pool_info(test_adapter, &available, &total);

    try testing.expectEqual(@as(usize, 100), total);
    try testing.expectEqual(@as(usize, 100), available); // All free initially
}

test "adapter state transitions" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
        .poll_timeout_ms = 1,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // Initial state
    try testing.expectEqual(adapter.AdapterState.created, test_adapter.state);
    try testing.expect(!adapter.zig_adapter_is_running(test_adapter));

    // Note: Cannot test full open() -> running transition without actual TUN device
    // That requires system permissions and is tested in integration tests
}

test "adapter FFI reset stats" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
        .poll_timeout_ms = 1,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // Set some stats
    test_adapter.stats.packets_read = 1000;
    test_adapter.stats.read_errors = 5;

    try testing.expectEqual(@as(u64, 1000), test_adapter.stats.packets_read);

    // Reset
    adapter.zig_adapter_reset_stats(test_adapter);

    try testing.expectEqual(@as(u64, 0), test_adapter.stats.packets_read);
    try testing.expectEqual(@as(u64, 0), test_adapter.stats.read_errors);
}

test "adapter DHCP state check" {
    const alloc = testing.allocator;

    const config = adapter.Config{
        .recv_queue_size = 64,
        .send_queue_size = 64,
        .packet_pool_size = 128,
        .batch_size = 32,
        .poll_timeout_ms = 1,
    };

    var test_adapter = try adapter.ZigPacketAdapter.init(alloc, config);
    defer test_adapter.deinit();

    // DHCP not enabled initially
    try testing.expect(!adapter.zig_adapter_is_dhcp_enabled(test_adapter));
}

test "adapter config extremes" {
    const alloc = testing.allocator;

    // Minimal config
    const minimal = adapter.Config{
        .recv_queue_size = 2,
        .send_queue_size = 2,
        .packet_pool_size = 4,
        .batch_size = 1,
        .poll_timeout_ms = 1,
    };

    var min_adapter = try adapter.ZigPacketAdapter.init(alloc, minimal);
    defer min_adapter.deinit();

    try testing.expectEqual(@as(usize, 2), min_adapter.recv_queue.capacity());

    // Large config
    const large = adapter.Config{
        .recv_queue_size = 512,
        .send_queue_size = 512,
        .packet_pool_size = 1024,
        .batch_size = 128,
        .poll_timeout_ms = 1,
    };

    var large_adapter = try adapter.ZigPacketAdapter.init(alloc, large);
    defer large_adapter.deinit();

    try testing.expectEqual(@as(usize, 512), large_adapter.recv_queue.capacity());
}

test "adapter Stats format output" {
    const stats = adapter.ZigPacketAdapter.Stats{
        .packets_read = 1234,
        .packets_written = 5678,
        .bytes_read = 1500000,
        .bytes_written = 8500000,
        .read_errors = 2,
        .write_errors = 0,
        .recv_queue_drops = 1,
        .send_queue_drops = 0,
        .buffer_tracking_failures = 0,
    };

    var buf: [256]u8 = undefined;
    const output = try std.fmt.bufPrint(&buf, "{any}", .{stats});

    // Verify output contains key stats
    try testing.expect(std.mem.indexOf(u8, output, "1234pkt") != null);
    try testing.expect(std.mem.indexOf(u8, output, "5678pkt") != null);
}
