/*
 * BigBro @2021 - 2023
 */

#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/if_ether.h>	/* for ETH_ALEN */
#include <linux/ipv6.h>     /* for struct in6_addr */

#define SESSION_NAT_INNER_MAP_NAME			"session_nat_table_inner"

#define __XDP_ACTION_MAX 					(XDP_REDIRECT + 1)
#define MAX_SUPPORTED_CPUS 					128
#define SNAT_IP_POOL_CAPACITY 				4
#define SESS_NAT_TABLE_PERCPU_CAPACITY		1024
#define VIP_VPORT_POLICY_CAPACITY 			128
#define BIP_CAPACITY 						8
#define I40E_RSS_HASH_KEY_LEN				52
#define I40E_INDIR_TABLE_LEN				512
#define I40E_RX_RINGS_NUM					24
#define IXGBE_RSS_HASH_KEY_LEN				40
#define IXGBE_INDIR_TABLE_LEN				128
#define IXGBE_RX_RINGS_NUM					16

#define RSS_HASH_KEY_LEN					IXGBE_RSS_HASH_KEY_LEN
#define INDIR_TABLE_LEN						IXGBE_INDIR_TABLE_LEN
#define RX_RINGS_NUM						IXGBE_RX_RINGS_NUM

struct flow_key {
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
	};
	__u8 proto;
};

struct fullnat_info {
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
};

struct flow_value {
	struct fullnat_info fnat;
	__u64 last_time;
};

struct vip_vport_policy_key_s {
	__be32 vip;
	__be16 vport;
};

struct vip_vport_policy_value_s {
	__be32 bip[BIP_CAPACITY];
	__u32 bip_num;
	__be16 bport;
};

struct rss_hash_key_s {
	__u8 hash_key[RSS_HASH_KEY_LEN];
};

struct smac_dmac_s {
	__u8 mac[ETH_ALEN];
};

struct pkt_stats {
	__u64 rx_packets;
	__u64 rx_bytes;
};

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

enum {
	STATS_GLOBAL_PKT_ALL,
	STATS_GLOBAL_PKT_ETH_HEADER_INVALID,
	STATS_GLOBAL_PKT_VLAN,
	STATS_GLOBAL_PKT_VLAN_FROM_CLIENT,
	STATS_GLOBAL_PKT_VLAN_FROM_SERVER,
	STATS_GLOBAL_PKT_OTHER_VLAN,
	STATS_GLOBAL_PKT_L3_UNKNOWN,
	STATS_GLOBAL_PKT_ARP,
	STATS_GLOBAL_PKT_IPv4_UNKNOWN,
	STATS_GLOBAL_PKT_IPv4_HEADER_INVALID,
	STATS_GLOBAL_PKT_ICMPv4_ECHO,
	STATS_GLOBAL_PKT_ICMPv4_ECHOREPLY,
	STATS_GLOBAL_PKT_ICMPv4_OTHER,
	STATS_GLOBAL_PKT_TCPv4,
	STATS_GLOBAL_PKT_UDPv4,
	STATS_GLOBAL_PKT_IPv6_UNKNOWN,
	STATS_GLOBAL_PKT_IPv6_HEADER_INVALID,
	STATS_GLOBAL_PKT_ICMPv6_ECHO,
	STATS_GLOBAL_PKT_ICMPv6_ECHOREPLY,
	STATS_GLOBAL_PKT_ICMPv6_OTHER,
	STATS_GLOBAL_PKT_TCPv6,
	STATS_GLOBAL_PKT_UDPv6,
	__STATS_GLOBAL_PKT_MAX
};

enum {
	STATS_GLOBAL_VALIDITY_NONE_TAG,
	STATS_GLOBAL_VALIDITY_UNKNOWN_TAG,
	STATS_GLOBAL_VALIDITY_ETHERNET_HEADER_MALFORM,
	STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM,
	STATS_GLOBAL_VALIDITY_UDP_HEADER_MALFORM,
	STATS_GLOBAL_VALIDITY_IPv6_HEADER_MALFORM,
	__STATS_GLOBAL_VALIDITY_MAX
};

enum {
	STATS_GLOBAL_EVENT_SESS_MAP_DOES_NOT_EXIST,
	STATS_GLOBAL_EVENT_SNAT_IP_DOES_NOT_EXIST,
	STATS_GLOBAL_EVENT_SESSION_FIRST_SEEN,
	STATS_GLOBAL_EVENT_SESSION_HIT,
	STATS_GLOBAL_EVENT_NAT_HIT,
	STATS_GLOBAL_EVENT_NAT_DOES_NOT_EXIST,
	STATS_GLOBAL_EVENT_POLICY_DOES_NOT_EXIST,
	STATS_GLOBAL_EVENT_BIP_DOES_NOT_EXIST,
	STATS_GLOBAL_EVENT_SMAC_DOES_NOT_EXIST,
	STATS_GLOBAL_EVENT_DMAC_DOES_NOT_EXIST,
	__STATS_GLOBAL_EVENT_MAX
};

#endif