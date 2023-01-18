/*
 * BigBro @2023
 */

#ifndef __LPM_STRUCTS_H
#define __LPM_STRUCTS_H

#include <linux/ipv6.h>     /* for struct in6_addr */

struct lpm_key {
    __u32 prefixlen;
    __u32 app_id_lo;
    __u32 app_id_hi;
    union {
        struct in6_addr in6_saddr;
        __u32 saddr[4];
        __u8 addr[16];
    } addr;
} __attribute__((packed));

#endif