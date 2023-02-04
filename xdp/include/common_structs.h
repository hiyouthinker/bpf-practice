/*
 * BigBro 2023
 */

#ifndef __COMMON_STRUCTS_H
#define __COMMON_STRUCTS_H

#include <linux/if_ether.h> /* for ETH_ALEN */
#include <linux/ipv6.h>     /* for struct in6_addr */

#define SESSION_NAT_INNER_MAP_NAME     "session_nat_table_inner"
#define MAX_SUPPORTED_CPUS             128
#define SESS_NAT_TABLE_PERCPU_CAPACITY 1024

enum {
	STAT_PKT_ALL,
	STAT_PKT_ETH,
	STAT_PKT_VLAN,
	STAT_PKT_IPV4,
	STAT_PKT_IPV6,
	STAT_PKT_TCP,
	STAT_PKT_TCP_SYN,
	STAT_PKT_UDP,
	__STAT_MAX,
};

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

struct packet_description {
    struct flow_key flow;

    __u16 vlanid;
    __be16 ip_id;
    __u8 ttl;
    __u8 tcp_flags;

    void *next_hdr;
};

#endif
