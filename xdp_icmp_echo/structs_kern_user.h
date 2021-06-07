/*
 * BigBro/2021
 */

#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

struct pkt_stats {
	__u64 rx_packets;
	__u64 rx_bytes;
};

enum {
	STATS_GLOBAL_PKT_XDP_PASS,
	STATS_GLOBAL_PKT_XDP_TX,
	STATS_GLOBAL_PKT_VLAN,
	STATS_GLOBAL_PKT_L3_UNKNOWN,
	STATS_GLOBAL_PKT_ARP,
	STATS_GLOBAL_PKT_IPv4_UNKNOWN,
	STATS_GLOBAL_PKT_IPv6_UNKNOWN,
	STATS_GLOBAL_PKT_IPv6_NOT_SUPPORT,
	STATS_GLOBAL_PKT_ICMPv4_ECHO,
	STATS_GLOBAL_PKT_ICMPv4_NON_ECHO,
	STATS_GLOBAL_PKT_TCPv4,
	STATS_GLOBAL_PKT_UDPv4,
	STATS_GLOBAL_PKT_ICMPv6_ECHO,
	STATS_GLOBAL_PKT_ICMPv6_NON_ECHO,
	STATS_GLOBAL_PKT_TCPv6,
	STATS_GLOBAL_PKT_UDPv6,
	__STATS_GLOBAL_MAX
};

#endif
