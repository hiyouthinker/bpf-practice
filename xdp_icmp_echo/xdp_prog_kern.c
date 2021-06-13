/*
 * BigBro/2021
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "maps_kern.h"

/*
 * verifier complains:
 *		math between pkt pointer and register with unbounded min value is not allowed
 */
#define KENREL_VERIFIER_SHUTUP_UNBOUNDED_MIN_VALUE
/*
 * unreachable insn 277
 */
#define KERNEL_VERIFIER_SHUTUP_UNREACHABLE_INSN

#define SUPPORT_UDP_CHECKSUM

#define TAG_FROM_CLIENT		705
#define TAG_FROM_SERVER		708
#define TAG_TO_NEXTHOP		708

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
	void *pos = nh->pos;

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
		case ICMP_ECHOREPLY:
			type = STATS_GLOBAL_PKT_ICMPv4_ECHOREPLY;
			break;
		default:
			type = STATS_GLOBAL_PKT_ICMPv4_OTHER;
			goto out;
		}
	}
	else {
		switch (icmp_type) {
		case ICMPV6_ECHO_REQUEST:
			type = STATS_GLOBAL_PKT_ICMPv6_ECHO;
			break;
		case ICMPV6_ECHO_REPLY:
			type = STATS_GLOBAL_PKT_ICMPv6_ECHOREPLY;
		default:
			type = STATS_GLOBAL_PKT_ICMPv6_OTHER;
			goto out;
		}
	}
out:
	nh->pos = pos;
	return type;
}

static __always_inline
__u32 xdp_stats_action(struct xdp_md *ctx, __u32 key)
{
	__u32 *rec;

	if (key >= __XDP_ACTION_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&stats_action, &key);
	if (!rec)
		return -1;

	*rec += 1;
	return 0;
}

static __always_inline
__u32 xdp_stats_pkt(struct xdp_md *ctx, __u32 key)
{
	struct pkt_stats *rec;

	if (key >= __STATS_GLOBAL_PKT_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&stats_pkt, &key);
	if (!rec)
		return -1;

	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, (ctx->data_end - ctx->data));

	return 0;
}

static __always_inline
__u32 xdp_stats_validity(struct xdp_md *ctx, __u32 key)
{
	struct pkt_stats *rec;

	if (key >= __STATS_GLOBAL_PKT_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&stats_validity, &key);
	if (!rec)
		return -1;

	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, (ctx->data_end - ctx->data));

	return 0;
}

static __always_inline
__u32 xdp_stats_events(struct xdp_md *ctx, __u32 key)
{
	__u32 *value;

	if (key >= __STATS_GLOBAL_PKT_MAX)
		return -1;

	value = bpf_map_lookup_elem(&stats_events, &key);
	if (!value)
		return -1;

	lock_xadd(value, 1);
	return 0;
}

/**
 * Calculate sum of 16-bit words from `data` of `size` bytes,
 * Size is assumed to be even, from 0 to MAX_CSUM_BYTES.
 */
#define MAX_CSUM_WORDS 32
#define MAX_CSUM_BYTES (MAX_CSUM_WORDS * 2)

static __always_inline __u32
sum16(const void* data, __u32 size, const void* data_end)
{
    __u32 s = 0, i;
#pragma unroll
    for (i = 0; i < MAX_CSUM_WORDS; i++) {
        if (2*i >= size) {
            return s; /* normal exit */
        }
        if (data + 2*i + 1 + 1 > data_end) {
            return 0; /* should be unreachable */
        }
        s += ((const __u16*)data)[i];
    }
    return s;
}

/**
 * Carry upper bits and compute one's complement for a checksum.
 */
static __always_inline __u16
carry(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16); // loop
    return ~csum;
}

/*
 * from xdp_tutorial/packet-solutions/xdp_prog_kern_03.c
 */
#ifdef SUPPORT_BPF_CSUM
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
	__u32 csum, size = sizeof(struct icmphdr_common);
	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);

	return csum_fold_helper(csum);
}
#endif

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline void connection_table_lookup(            void *inner_map
				, struct flow_key *key, struct flow_value **value)
{
	if (!value)
		return;
	*value = bpf_map_lookup_elem(inner_map, key);
	if (!*value)
		return;
	(*value)->last_time = bpf_ktime_get_ns();
}

SEC("xdp_udp_fullnat_forward")
int xdp_udp_fullnat_forward_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct collect_vlans vlans;
	struct vlan_hdr *vlh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct udphdr *uhdr;
	int eth_type;
	__u32 action = XDP_PASS;
	__u32 pkt_type_key, pkt_validity_key;
	char smac[ETH_ALEN] = {0x9c, 0x69, 0xb4, 0x60, 0x35, 0x61};
	char dmac[ETH_ALEN] = {0x68, 0x91, 0xd0, 0x61, 0x94, 0xca};
	__be32 snat_key, *snat_value;
	int l4proto;
	__u32 cpu_num;
	void *session_nat_table_inner;
	struct flow_key sess_key;
	struct flow_value *sess_value = NULL, sess_value_from_client, sess_value_from_server;

	xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_ALL);

	__builtin_memset(&vlans, 0, sizeof(vlans));

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (vlans.id[0] != 0) {
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_VLAN);
	}

	pkt_type_key = get_pkt_type(&nh, data_end, eth_type);

	switch (vlans.id[0]) {
	case 0:
		pkt_validity_key = STATS_GLOBAL_VALIDITY_NONE_TAG;
		goto error;
	case TAG_FROM_CLIENT:
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_VLAN_FROM_CLIENT);
		break;
	case TAG_FROM_SERVER:
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_VLAN_FROM_SERVER);
		break;
	default:
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_OTHER_VLAN);
		pkt_validity_key = STATS_GLOBAL_VALIDITY_UNKNOWN_TAG;
		goto error;
	}

	if (!eth || ((eth + 1) > data_end)) {
		pkt_validity_key = STATS_GLOBAL_VALIDITY_ETHERNET_HEADER_MALFORM;
		goto error;
	}

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto done;
	}

	l4proto = parse_iphdr(&nh, data_end, &iphdr);
	if (l4proto == -1) {
		pkt_validity_key = STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM;
		goto error;
	} else if (l4proto == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &uhdr) < 0) {
			pkt_validity_key = STATS_GLOBAL_VALIDITY_UDP_HEADER_MALFORM;
			goto error;
		}
#ifdef SUPPORT_UDP_CHECKSUM
		uhdr->check = 0;
#else
		uhdr->check = 0;
#endif
	} else {
		/* support UDP only */
		goto done;
	}

	cpu_num = bpf_get_smp_processor_id();
	session_nat_table_inner = bpf_map_lookup_elem(&session_nat_table_outer, &cpu_num);
	if (!session_nat_table_inner) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SESS_MAP_DOES_NOT_EXIST);
		goto done;
	}

	__builtin_memset(&sess_key, 0, sizeof(sess_key));
	sess_key.src = iphdr->saddr;
	sess_key.dst = iphdr->daddr;
	sess_key.proto = iphdr->protocol;
	sess_key.port16[0] = uhdr->source;
	sess_key.port16[1] = uhdr->dest;

	connection_table_lookup(session_nat_table_inner, &sess_key, &sess_value);
	if (sess_value) {
		snat_value = &sess_value->fnat.src;
		if (vlans.id[0] == TAG_FROM_CLIENT) {
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SESSION_HIT);
		} else {
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_NAT_HIT);
		}
		goto modify_ip;
	} else {
		if (vlans.id[0] == TAG_FROM_SERVER) {
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_NAT_DOES_NOT_EXIST);
			goto done;
		} else {
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SESSION_FIRST_SEEN);
			sess_value = &sess_value_from_client;
		}
	}

	snat_key = cpu_num % SNAT_IP_POOL_CAPACITY;
	snat_value = bpf_map_lookup_elem(&snat_ip_pool, &snat_key);
	if (!snat_value) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SNAT_IP_DOES_NOT_EXIST);
		goto done;
	}
	/*
	 * A:a -> B:b	->	C:c -> D:d
	 * 		client -> server: C:c -> D:d
	 */
	__builtin_memset(&sess_value_from_client, 0, sizeof(sess_value_from_client));
	sess_value_from_client.fnat.src = *snat_value;
	sess_value_from_client.fnat.dst = iphdr->daddr;
	sess_value_from_client.fnat.port16[0] = uhdr->source;
	sess_value_from_client.fnat.port16[1] = uhdr->dest;
	bpf_map_update_elem(session_nat_table_inner, &sess_key, &sess_value_from_client, 0);

	/*
	 * D:d -> C:c	->	B:b	->	A:a
	 * 		server -> client: D:d -> C:c
	 */
	sess_key.src = sess_value_from_client.fnat.dst;
	sess_key.dst = sess_value_from_client.fnat.src;
	sess_key.port16[0] = sess_value_from_client.fnat.port16[1];
	sess_key.port16[1] = sess_value_from_client.fnat.port16[0];

	/*
	 * D:d -> C:c	->	B:b	->	A:a
	 * 		server -> client: B:b	->	A:a
	 */
	__builtin_memset(&sess_value_from_server, 0, sizeof(sess_value_from_server));
	sess_value_from_server.fnat.src = iphdr->daddr;
	sess_value_from_server.fnat.dst = iphdr->saddr;
	sess_value_from_server.fnat.port16[0] = uhdr->dest;
	sess_value_from_server.fnat.port16[1] = uhdr->source;
	sess_value_from_server.last_time = bpf_ktime_get_ns();
	if (bpf_map_update_elem(session_nat_table_inner, &sess_key, &sess_value_from_server, 0) < 0) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_NAT_DOES_NOT_EXIST);
		goto done;
	}
modify_ip:
	iphdr->saddr = sess_value->fnat.src;
	iphdr->daddr = sess_value->fnat.dst;
    /* Update IP checksum */
	iphdr->check = 0;
#ifdef KERNEL_VERIFIER_SHUTUP_UNREACHABLE_INSN
	iphdr->check = carry(sum16(iphdr, sizeof(*iphdr), data_end));
#else
	iphdr->check = carry(sum16(iphdr, iphdr->ihl * 4, data_end));
#endif
	ip_decrease_ttl(iphdr);

	/* Build Ethernet Header */
	vlh = (struct vlan_hdr *)(eth + 1);
	vlh->h_vlan_TCI = bpf_htons(TAG_TO_NEXTHOP | (vlh->h_vlan_TCI & ~VLAN_VID_MASK));
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);

	action = XDP_TX;
done:
	xdp_stats_pkt(ctx, pkt_type_key);
	xdp_stats_action(ctx, action);
	return action;
error:
	xdp_stats_validity(ctx, pkt_validity_key);
	goto done;
}

SEC("xdp_ip_forward")
int xdp_ip_forward_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	int eth_type;
	__u32 action = XDP_PASS;
	__u32 key1, key2;
	struct collect_vlans vlans;
	struct vlan_hdr *vlh;
	char smac[ETH_ALEN] = {0x9c, 0x69, 0xb4, 0x60, 0x35, 0x61};
	char dmac[ETH_ALEN] = {0x68, 0x91, 0xd0, 0x61, 0x94, 0xca};
	__be32 snat_ip = bpf_htonl(0xAC320249);
	__be32 dnat_ip = bpf_htonl(0xAC320148);
	int l4proto;

	xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_ALL);

	__builtin_memset(&vlans, 0, sizeof(vlans));

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (vlans.id[0] != 0) {
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_VLAN);
	}

	key1 = get_pkt_type(&nh, data_end, eth_type);

	switch (vlans.id[0]) {
	case 0:
		key2 = STATS_GLOBAL_VALIDITY_NONE_TAG;
		goto error;
	case TAG_FROM_CLIENT:
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_VLAN_FROM_CLIENT);
		break;
	case TAG_FROM_SERVER:
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_VLAN_FROM_SERVER);
		break;
	default:
		xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_OTHER_VLAN);
		key2 = STATS_GLOBAL_VALIDITY_UNKNOWN_TAG;
		goto error;
	}

	if (!eth || ((eth + 1) > data_end)) {
		key2 = STATS_GLOBAL_VALIDITY_ETHERNET_HEADER_MALFORM;
		goto error;
	}

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto done;
	}

	l4proto = parse_iphdr(&nh, data_end, &iphdr);
	if (l4proto == -1) {
		key2 = STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM;
		goto error;
	} else if (l4proto == IPPROTO_UDP) {
		struct udphdr *uhdr;
		if (parse_udphdr(&nh, data_end, &uhdr) < 0) {
			key2 = STATS_GLOBAL_VALIDITY_UDP_HEADER_MALFORM;
			goto error;
		}
#ifdef SUPPORT_UDP_CHECKSUM
		uhdr->check = 0;
#else
		uhdr->check = 0;
#endif
	}

	/* Build Ethernet Header */
	vlh = (struct vlan_hdr *)(eth + 1);
	vlh->h_vlan_TCI = bpf_htons(TAG_TO_NEXTHOP | (vlh->h_vlan_TCI & ~VLAN_VID_MASK));
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);

	if (vlans.id[0] == TAG_FROM_CLIENT)
		/* SNAT */
		iphdr->saddr = snat_ip;
	else
		iphdr->daddr = dnat_ip;

    /* Update IP checksum */
	iphdr->check = 0;
#ifdef KERNEL_VERIFIER_SHUTUP_UNREACHABLE_INSN
	iphdr->check = carry(sum16(iphdr, sizeof(*iphdr), data_end));
#else
	iphdr->check = carry(sum16(iphdr, iphdr->ihl * 4, data_end));
#endif
	ip_decrease_ttl(iphdr);
	action = XDP_TX;
done:
	xdp_stats_pkt(ctx, key1);
	xdp_stats_action(ctx, action);
	return action;
error:
	xdp_stats_validity(ctx, key2);
	goto done;
}

SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type, ip_type, icmp_type;
	struct iphdr *iphdr;
#ifdef SUPPORT_IPv6
	struct ipv6hdr *ipv6hdr;
#endif
	struct icmphdr_common *icmphdr;
#ifdef SUPPORT_BPF_CSUM
	__u16 old_csum;
	struct icmphdr_common icmphdr_old;
#endif
	__u16 echo_reply = ICMP_ECHOREPLY;
	__u16 ip_tot_len;
	__u32 action = XDP_PASS;
	__u32 key;
	struct collect_vlans vlans;

	__builtin_memset(&vlans, 0, sizeof(vlans));

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);

	if (vlans.id[0] != 0) {
		key = STATS_GLOBAL_PKT_VLAN;
		xdp_stats_pkt(ctx, key);
	}

	key = get_pkt_type(&nh, data_end, eth_type);

	if (eth_type == bpf_htons(ETH_P_ARP)) {
		goto out;
	}
	else if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type == -1) {
			xdp_stats_validity(ctx, STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM);
			goto out;
		}
		ip_tot_len = bpf_ntohs(iphdr->tot_len);
		if (ip_tot_len < iphdr->ihl * 4) {
			xdp_stats_validity(ctx, STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM);
			goto out;
		}
#ifdef KENREL_VERIFIER_SHUTUP_UNBOUNDED_MIN_VALUE
		if (ip_tot_len & 0x8000) {
			xdp_stats_validity(ctx, STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM);
			goto out;
		}
		ip_tot_len &= 0x7FFF;
#endif
		if (((char *)iphdr + ip_tot_len) > data_end) {
			xdp_stats_validity(ctx, STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM);
			goto out;
		}
		if (ip_type != IPPROTO_ICMP) {
			goto out;
		}
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
#ifdef SUPPORT_IPv6
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type == -1) {
			xdp_stats_validity(ctx, STATS_GLOBAL_VALIDITY_IPv6_HEADER_MALFORM);
			goto out;
		}
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
#endif
	}

	swap_src_dst_mac(eth);

#ifdef SUPPORT_BPF_CSUM
	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);
#else
	icmphdr->type = echo_reply;
	icmphdr->cksum = 0;
	icmphdr->cksum = carry(sum16(icmphdr, ip_tot_len - iphdr->ihl * 4, data_end));
#endif

	action = XDP_TX;
out:
	xdp_stats_pkt(ctx, key);
	xdp_stats_action(ctx, action);
	return action;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
