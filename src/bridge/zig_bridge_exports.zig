// Zig Bridge Exports - Makes Zig adapter available to C code
// This file is compiled as part of the Zig static library

// The export functions are defined in adapter.zig:
// - zig_adapter_create
// - zig_adapter_destroy
// - zig_adapter_open
// - zig_adapter_start
// - zig_adapter_stop
// - zig_adapter_get_packet
// - zig_adapter_put_packet
// - zig_adapter_print_stats

// Import to ensure they're included in the build
const adapter = @import("../packet/adapter.zig");

comptime {
    // Force inclusion of all export functions
    _ = adapter;
}
