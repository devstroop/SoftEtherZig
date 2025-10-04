/*
 * iOS sys/kern_control.h stub
 * 
 * iOS has these headers but they're for kernel extensions.
 * For client VPN, we don't need them.
 */

#ifndef _SYS_KERN_CONTROL_H_
#define _SYS_KERN_CONTROL_H_

// Minimal definitions - not actually used in iOS client mode
#define CTLIOCGINFO 0xc0644e03

struct ctl_info {
    unsigned int ctl_id;
    char ctl_name[96];
};

struct sockaddr_ctl {
    unsigned char sc_len;
    unsigned char sc_family;
    unsigned short ss_sysaddr;
    unsigned int sc_id;
    unsigned int sc_unit;
    unsigned int sc_reserved[5];
};

#endif /* _SYS_KERN_CONTROL_H_ */
