/*
 * (reference xdp_tutorial)
 * BigBro/2021
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "maps_kern.h"

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

static __always_inline
int get_pkt_type(struct hdr_cursor *nh, void *data_end, int eth_type)
{
	int ip_type;
	int icmp_type;
	int type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct icmphdr_common *icmphdr;

	if (eth_type == bpf_htons(ETH_P_ARP)) {
		type = STATS_GLOBAL_PKT_ARP;
		goto out;
	}
	else if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(nh, data_end, &iphdr);
		switch (ip_type) {
		case IPPROTO_ICMP:
			break;
		case IPPROTO_TCP:
			type = STATS_GLOBAL_PKT_TCPv4;
			break;
		case IPPROTO_UDP:
			type = STATS_GLOBAL_PKT_UDPv4;
			break;
		default:
			type = STATS_GLOBAL_PKT_IPv4_UNKNOWN;
			break;
		}
		if (ip_type != IPPROTO_ICMP) {
			goto out;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(nh, data_end, &ipv6hdr);
		switch (ip_type) {
		case IPPROTO_ICMP:
			break;
		case IPPROTO_TCP:
			type = STATS_GLOBAL_PKT_TCPv6;
			break;
		case IPPROTO_UDP:
			type = STATS_GLOBAL_PKT_UDPv6;
			break;
		default:
			type = STATS_GLOBAL_PKT_IPv6_UNKNOWN;
			break;
		}
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		type = STATS_GLOBAL_PKT_L3_UNKNOWN;
		goto out;
	}

	icmp_type = parse_icmphdr_common(nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		switch (icmp_type) {
		case ICMP_ECHO:
			type = STATS_GLOBAL_PKT_ICMPv4_ECHO;
			break;
		default:
			type = STATS_GLOBAL_PKT_ICMPv4_NON_ECHO;
			goto out;
		}
	}
	else {
		switch (icmp_type) {
		case ICMPV6_ECHO_REQUEST:
			type = STATS_GLOBAL_PKT_ICMPv6_ECHO;
			break;
		default:
			type = STATS_GLOBAL_PKT_ICMPv6_NON_ECHO;
			goto out;
		}
	}
out:
	return type;
}

static __always_inline
__u32 __xdp_stats(struct xdp_md *ctx, __u32 key)
{
	struct pkt_stats *rec;

	if (key >= __STATS_GLOBAL_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return -1;

	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, (ctx->data_end - ctx->data));

	return 0;
}

/*
 * from xdp_tutorial/packet-solutions/xdp_prog_kern_03.c
 */
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old)
{
#ifdef SUPPORT_BPF_CSUM
	__u32 csum, size = sizeof(struct icmphdr_common);
	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
#else
	__u32 csum = 0;
#endif
	return csum_fold_helper(csum);
}

SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
#ifdef SUPPORT_IPv6
	struct ipv6hdr *ipv6hdr;
#endif
	__u16 echo_reply = ICMP_ECHOREPLY, old_csum;
	struct icmphdr_common *icmphdr;
	struct icmphdr_common icmphdr_old;
	__u32 action = XDP_PASS;
	__u32 key;
	struct collect_vlans vlans;

	__builtin_memset(&vlans, 0, sizeof(vlans));

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr_and_tag(&nh, data_end, &eth, &vlans);

	if (vlans.id[0] != 0) {
		key = STATS_GLOBAL_PKT_VLAN;
		__xdp_stats(ctx, key);
	}

	key = get_pkt_type(&nh, data_end, eth_type);

	if (eth_type == bpf_htons(ETH_P_ARP)) {
		goto out;
	}
	else if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP) {
			goto out;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
#ifdef SUPPORT_IPv6
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
#else
		goto out;
#endif
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		switch (icmp_type) {
		case ICMP_ECHO:
			swap_src_dst_ipv4(iphdr);
			echo_reply = ICMP_ECHOREPLY;
			break;
		default:
			goto out;
		}
	}
	else {
#ifdef SUPPORT_IPv6
		switch (icmp_type) {
		case ICMPV6_ECHO_REQUEST:
			swap_src_dst_ipv6(ipv6hdr);
			echo_reply = ICMPV6_ECHO_REPLY;
			break;
		default:
			goto out;
		}
#else
		/* Can't reach here, Trust Me */
#endif
	}

	swap_src_dst_mac(eth);

	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	action = XDP_TX;
out:
	__xdp_stats(ctx, key);
	return action;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
