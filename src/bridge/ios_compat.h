/*
 * iOS Compatibility Header
 * 
 * This header provides compatibility definitions for iOS builds
 * where certain headers/functions are not available.
 * 
 * Include this BEFORE including SoftEther headers when building for iOS.
 */

#ifndef IOS_COMPAT_H
#define IOS_COMPAT_H

#ifdef UNIX_IOS

// iOS doesn't have net/if_arp.h, but we can define the minimal ARP structures we need
// Most of these are not actually used in client-only VPN mode

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1  // Ethernet hardware type
#endif

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1  // ARP request
#endif

#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2  // ARP reply
#endif

// Minimal arphdr structure (not actually used on iOS)
struct arphdr {
    unsigned short ar_hrd;   // Hardware type
    unsigned short ar_pro;   // Protocol type
    unsigned char ar_hln;    // Hardware address length
    unsigned char ar_pln;    // Protocol address length
    unsigned short ar_op;    // Operation
};

// iOS doesn't have readline/history, stub them out
// These are only used in CLI/console mode which we don't use on iOS
#define readline(x) NULL
#define add_history(x) do {} while(0)
#define using_history() do {} while(0)

// For any ARP-related functions that might be referenced
// They won't actually be called in iOS client mode
static inline void ios_compat_init(void) {
    // Placeholder for any iOS-specific initialization
}

#endif // UNIX_IOS

#endif // IOS_COMPAT_H
