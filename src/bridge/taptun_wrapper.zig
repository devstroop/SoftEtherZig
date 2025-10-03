// C-compatible wrapper for ZigTapTun library
// Allows packet_adapter_macos.c to use Zig L2↔L3 translation

const std = @import("std");
const taptun = @import("taptun");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

/// Opaque handle to L2L3Translator for C code
pub const TranslatorHandle = ?*anyopaque;

/// C-compatible translator options
pub const CTranslatorOptions = extern struct {
    our_mac: [6]u8,
    learn_ip: bool,
    learn_gateway_mac: bool,
    handle_arp: bool,
    verbose: bool,
};

/// Create a new L2↔L3 translator
export fn taptun_translator_create(options: *const CTranslatorOptions) callconv(.c) TranslatorHandle {
    const translator = allocator.create(taptun.L2L3Translator) catch return null;

    translator.* = taptun.L2L3Translator.init(allocator, .{
        .our_mac = options.our_mac,
        .learn_ip = options.learn_ip,
        .learn_gateway_mac = options.learn_gateway_mac,
        .handle_arp = options.handle_arp,
        .verbose = options.verbose,
    }) catch {
        allocator.destroy(translator);
        return null;
    };

    return @ptrCast(translator);
}

/// Destroy translator
export fn taptun_translator_destroy(handle: TranslatorHandle) callconv(.c) void {
    if (handle) |h| {
        const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(h));
        translator.deinit();
        allocator.destroy(translator);
    }
}

/// Convert IP packet (L3) to Ethernet frame (L2)
/// Returns size of ethernet frame written to out_buffer, or 0 on error
/// out_buffer must be at least ip_size + 14 bytes
export fn taptun_ip_to_ethernet(
    handle: TranslatorHandle,
    ip_packet: [*c]const u8,
    ip_size: usize,
    out_buffer: [*c]u8,
    out_buffer_size: usize,
) callconv(.c) usize {
    if (handle == null) return 0;
    if (ip_packet == null or out_buffer == null) return 0;
    if (out_buffer_size < ip_size + 14) return 0; // Not enough space

    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));

    const ip_slice = ip_packet[0..ip_size];
    const eth_frame = translator.ipToEthernet(ip_slice) catch return 0;
    defer allocator.free(eth_frame);

    if (eth_frame.len > out_buffer_size) return 0; // Frame too large

    @memcpy(out_buffer[0..eth_frame.len], eth_frame);
    return eth_frame.len;
}

/// Convert Ethernet frame (L2) to IP packet (L3)
/// Returns size of IP packet written to out_buffer, or 0 if no IP packet (e.g., ARP handled)
/// Returns -1 on error
/// out_buffer must be at least eth_size bytes
export fn taptun_ethernet_to_ip(
    handle: TranslatorHandle,
    eth_frame: [*c]const u8,
    eth_size: usize,
    out_buffer: [*c]u8,
    out_buffer_size: usize,
) callconv(.c) isize {
    if (handle == null) return -1;
    if (eth_frame == null or out_buffer == null) return -1;

    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));

    const eth_slice = eth_frame[0..eth_size];
    const maybe_ip = translator.ethernetToIp(eth_slice) catch return -1;

    if (maybe_ip) |ip_packet| {
        defer allocator.free(ip_packet);

        if (ip_packet.len > out_buffer_size) return -1; // Packet too large

        @memcpy(out_buffer[0..ip_packet.len], ip_packet);
        return @intCast(ip_packet.len);
    } else {
        // Packet was handled internally (e.g., ARP)
        return 0;
    }
}

/// Get learned IP address (0 if not learned yet)
export fn taptun_get_our_ip(handle: TranslatorHandle) callconv(.c) u32 {
    if (handle == null) return 0;
    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));
    return translator.our_ip orelse 0;
}

/// Alias for taptun_get_our_ip (for consistency with C bridge API)
export fn taptun_get_learned_ip(handle: TranslatorHandle) callconv(.c) u32 {
    return taptun_get_our_ip(handle);
}

/// Get learned gateway MAC address (returns false if not learned yet)
export fn taptun_get_gateway_mac(handle: TranslatorHandle, out_mac: [*c]u8) callconv(.c) bool {
    if (handle == null or out_mac == null) return false;
    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));

    if (translator.gateway_mac) |mac| {
        @memcpy(out_mac[0..6], &mac);
        return true;
    }
    return false;
}

/// Check if translator has a pending ARP reply
export fn taptun_has_pending_arp(handle: TranslatorHandle) callconv(.c) bool {
    if (handle == null) return false;
    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));
    return translator.hasPendingArpReply();
}

/// Get pending ARP reply (returns size, or 0 if no pending reply)
/// Caller must call this in a loop until it returns 0
export fn taptun_get_pending_arp(
    handle: TranslatorHandle,
    out_buffer: [*c]u8,
    out_buffer_size: usize,
) callconv(.c) isize {
    if (handle == null or out_buffer == null) return 0;
    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));

    const maybe_reply = translator.popArpReply();
    if (maybe_reply) |reply| {
        defer allocator.free(reply); // Free after copying

        if (reply.len > out_buffer_size) return -1; // Buffer too small

        @memcpy(out_buffer[0..reply.len], reply);
        return @intCast(reply.len);
    }

    return 0; // No pending replies
}

/// Get statistics
pub const CTranslatorStats = extern struct {
    packets_l2_to_l3: u64,
    packets_l3_to_l2: u64,
    arp_requests_handled: u64,
    arp_replies_learned: u64,
};

export fn taptun_get_stats(handle: TranslatorHandle, stats: *CTranslatorStats) callconv(.c) void {
    if (handle == null) return;
    const translator: *taptun.L2L3Translator = @ptrCast(@alignCast(handle.?));

    stats.packets_l2_to_l3 = translator.packets_translated_l2_to_l3;
    stats.packets_l3_to_l2 = translator.packets_translated_l3_to_l2;
    stats.arp_requests_handled = translator.arp_requests_handled;
    stats.arp_replies_learned = translator.arp_replies_learned;
}
