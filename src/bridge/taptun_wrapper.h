// C header for ZigTapTun wrapper
// Allows C code to use Zig L2↔L3 translation

#ifndef TAPTUN_WRAPPER_H
#define TAPTUN_WRAPPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to translator (only if not already declared)
#ifndef TRANSLATOR_HANDLE_DEFINED
#define TRANSLATOR_HANDLE_DEFINED
typedef void* TranslatorHandle;
#endif

// Translator options
typedef struct {
    uint8_t our_mac[6];
    bool learn_ip;
    bool learn_gateway_mac;
    bool handle_arp;
    bool verbose;
} CTranslatorOptions;

// Statistics
typedef struct {
    uint64_t packets_l2_to_l3;
    uint64_t packets_l3_to_l2;
    uint64_t arp_requests_handled;
    uint64_t arp_replies_learned;
} CTranslatorStats;

// Create/destroy translator
TranslatorHandle taptun_translator_create(const CTranslatorOptions* options);
void taptun_translator_destroy(TranslatorHandle handle);

// Convert IP (L3) to Ethernet (L2)
// Returns size of ethernet frame, or 0 on error
size_t taptun_ip_to_ethernet(
    TranslatorHandle handle,
    const uint8_t* ip_packet,
    size_t ip_size,
    uint8_t* out_buffer,
    size_t out_buffer_size
);

// Convert Ethernet (L2) to IP (L3)
// Returns size of IP packet, 0 if handled internally (ARP), or -1 on error
ssize_t taptun_ethernet_to_ip(
    TranslatorHandle handle,
    const uint8_t* eth_frame,
    size_t eth_size,
    uint8_t* out_buffer,
    size_t out_buffer_size
);

// Get learned IP address (0 if not learned)
uint32_t taptun_get_our_ip(TranslatorHandle handle);

// Get learned gateway MAC (returns false if not learned)
bool taptun_get_gateway_mac(TranslatorHandle handle, uint8_t* out_mac);

// Check if ARP reply is pending
bool taptun_has_pending_arp(TranslatorHandle handle);

// Get pending ARP reply (returns size, or 0 if none)
size_t taptun_get_pending_arp(
    TranslatorHandle handle,
    uint8_t* out_buffer,
    size_t out_buffer_size
);

// Get statistics
void taptun_get_stats(TranslatorHandle handle, CTranslatorStats* stats);

#ifdef __cplusplus
}
#endif

#endif // TAPTUN_WRAPPER_H
