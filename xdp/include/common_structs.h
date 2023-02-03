/*
 * BigBro 2023
 */

#ifndef __COMMON_STRUCTS_H
#define __COMMON_STRUCTS_H

#include <linux/if_ether.h>	/* for ETH_ALEN */
#include <linux/ipv6.h>     /* for struct in6_addr */

#define SESSION_NAT_INNER_MAP_NAME			"session_nat_table_inner"
#define MAX_SUPPORTED_CPUS 					128
#define SESS_NAT_TABLE_PERCPU_CAPACITY		1024

#if 0
typedef struct flow_key {
	__be32 src;
	__be32 dst;
	__be16 sport;
	__be16 dport;
	__u8 proto;
} flow_key_t;

typedef struct flow_value {
	__be32 src;
	__be32 dst;
	__be16 sport;
	__be16 dport;
	struct bpf_timer timer;
} flow_value_t;
#endif

typedef struct flow_key {
    union {
        __be32 src;
        __be32 srcv6[4];
    };
    union {
        __be32 dst;
        __be32 dstv6[4];
    };
    union {
        __be32 ports;
        __be16 port16[2];
        struct {
            __be16 id;
            __u16 zeroed;
        };
    };
    __u8 proto;
} flow_key_t;

typedef struct flow_value {
    struct flow_key key;
    __u32 flags;
    union {
        union {
            __be32 ports;
            __be16 port16[2];
        };
        __be16 ip_id;
    };
    union {
        __u32 seq;
        __u32 seq_client;
    };
    union {
        __u32 ack;
        __u32 seq_server;
    };
    union {
        __u8 cpu_id_for_session;
        __u8 cpu_id_for_nat;
    };
    __u8 state;
    __u8 reserved[2];
#ifdef USE_BPF_TIMER
    struct bpf_timer timer;
#endif
    __u32 expires;
} flow_value_t;

#endif
