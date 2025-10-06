// Zig Bridge Module - Export for C integration
// Simply re-export the packet adapter which has all the export functions

pub const adapter = @import("../packet/adapter.zig");

// Re-export for convenience
pub const ZigPacketAdapter = adapter.ZigPacketAdapter;
pub const Config = adapter.Config;
