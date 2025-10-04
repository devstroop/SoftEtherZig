/*
 * iOS net/if_arp.h stub
 * 
 * iOS doesn't have net/if_arp.h, so we provide minimal definitions here.
 * Place this in a directory that comes before system includes.
 */

#ifndef _NET_IF_ARP_H_
#define _NET_IF_ARP_H_

// ARP hardware types
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

// ARP protocol opcodes
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif

#ifndef ARPOP_REPLY  
#define ARPOP_REPLY 2
#endif

// Minimal ARP header structure
struct arphdr {
    unsigned short ar_hrd;   // Hardware type
    unsigned short ar_pro;   // Protocol type
    unsigned char ar_hln;    // Hardware address length
    unsigned char ar_pln;    // Protocol address length
    unsigned short ar_op;    // Operation
};

#endif /* _NET_IF_ARP_H_ */
