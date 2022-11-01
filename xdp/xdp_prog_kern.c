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

#define SUPPORT_UDP_CHECKSUM
#define USE_GLOBAL_MAP_INSTEAD_OF_PERCPU
//#define USE_BUILTIN_CTZ

#define THASH_IPV4_L4_LEN	 ((sizeof(struct rss_ipv4_tuple)) / 4)

#define TAG_FROM_CLIENT		805		//	705
#define TAG_FROM_SERVER		808		//	708
#define TAG_TO_NEXTHOP		808		//	708

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

#ifndef USE_GLOBAL_MAP_INSTEAD_OF_PERCPU
#ifdef USE_BUILTIN_CTZ
#define bsf32(v)	__builtin_ctz(v)
#else
static __always_inline __u32 bsf32(__u32 v)
{
	__u32 c = 0;

#pragma unroll
	for (; (v & 0x01); v >>= 1) {
		c++;
	}
	return c;
}
#endif
#endif

/* saddr/daddr and ports have to be CPU byte order */
struct rss_ipv4_tuple {
	__u32 saddr;
	__u32 daddr;
	union {
		struct {
			__u16 dport;
			__u16 sport;
		};
		__u32 ports;
	};
};

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
		case IPPROTO_ICMPV6:
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

	if (key >= __STATS_GLOBAL_VALIDITY_MAX)
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

	if (key >= __STATS_GLOBAL_EVENT_MAX)
		return -1;

	value = bpf_map_lookup_elem(&stats_events, &key);
	if (!value)
		return -1;

	lock_xadd(value, 1);
	return 0;
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

static inline __wsum csum_add(__wsum csum, __wsum addend)
{
	__u32 res = (__u32)csum;
	res += (__u32)addend;
	return (__wsum)(res + (res < (__u32)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static __always_inline __sum16 csum_fold(__wsum csum)
{
	__u32 sum = (__u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

static __always_inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__wsum tmp = csum_sub(~(__wsum)(*sum), (__wsum)from);

	*sum = csum_fold(csum_add(tmp, (__wsum)to));
}

static __always_inline void udp_checksum(struct iphdr *iph, struct udphdr *udph, struct fullnat_info *fnat)
{
	if (iph->saddr != fnat->src)
		csum_replace4(&udph->check, iph->saddr, fnat->src);
	if (iph->daddr != fnat->dst)
		csum_replace4(&udph->check, iph->daddr, fnat->dst);

	if (udph->source != fnat->port16[0])
		csum_replace4(&udph->check, (__be32)udph->source, (__be32)fnat->port16[0]);
	if (udph->dest != fnat->port16[1])
		csum_replace4(&udph->check, (__be32)udph->dest, (__be32)fnat->port16[1]);
}

static __always_inline void ip_checksum(struct iphdr *iph, struct fullnat_info *fnat)
{
	if (iph->saddr != fnat->src)
		csum_replace4(&iph->check, iph->saddr, fnat->src);
	if (iph->daddr != fnat->dst)
		csum_replace4(&iph->check, iph->daddr, fnat->dst);
}

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline void connection_table_lookup(void *inner_map,
				struct flow_key *key, struct flow_value **value)
{
	if (!value)
		return;
	*value = bpf_map_lookup_elem(inner_map, key);
	if (!*value)
		return;
	(*value)->last_time = bpf_ktime_get_ns();
}

#ifndef USE_GLOBAL_MAP_INSTEAD_OF_PERCPU
/* from rte_thash.h */
static __always_inline __u32
softrss_be(__u32 *input_tuple, __u32 input_len, const __u8 *rss_key)
{
	__u32 i, j, map, ret = 0;

#pragma unroll
	for (j = 0; j < input_len; j++) {
#pragma unroll
		for (map = input_tuple[j]; map; map &= (map - 1)) {
			i = bsf32(map);
			ret ^= ((const __u32 *)rss_key)[j] << (31 - i) |
				(__u32)((__u64)(((const __u32 *)rss_key)[j + 1]) >> (i + 1));
		}
	}
	return ret;
}

static __u32 get_cpu_num_by_rss(struct fullnat_info *fnat)
{
	struct rss_ipv4_tuple tuple;
	__u32 map_key = 0, hash;
	struct rss_hash_key_s *rss_key_be;

	rss_key_be = bpf_map_lookup_elem(&rss_hash_key, &map_key);
	if (!rss_key_be) {
		return 0;
	}

	__builtin_memset(&tuple, 0, sizeof(tuple));
	tuple.saddr = fnat->dst;
	tuple.daddr = fnat->src;
	tuple.sport = fnat->port16[1];
	tuple.dport = fnat->port16[0];
	hash = softrss_be((__u32 *)&tuple,
				THASH_IPV4_L4_LEN, rss_key_be->hash_key);
	return (hash % INDIR_TABLE_LEN) % RX_RINGS_NUM;
}
#endif

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
	struct smac_dmac_s *smac, *dmac;
	__u32 mac_key = 0;
	__be32 snat_key, *snat_value;
	int l4proto;
	__u32 cpu_num, cpu_num_from_server;
	void *session_nat_table_inner;
	struct flow_key sess_key;
	struct flow_value *sess_value = NULL, sess_value_from_client, sess_value_from_server;
	struct vip_vport_policy_key_s policy_key;
	struct vip_vport_policy_value_s *policy_value;
	__u32 bip_index;

	xdp_stats_pkt(ctx, STATS_GLOBAL_PKT_ALL);

	__builtin_memset(&vlans, 0, sizeof(vlans));

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
	if (eth_type < 0) {
		pkt_type_key = STATS_GLOBAL_PKT_ETH_HEADER_INVALID;
		pkt_validity_key = STATS_GLOBAL_VALIDITY_ETHERNET_HEADER_MALFORM;
		goto error;
	}

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

	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto done;
	}

	l4proto = parse_iphdr(&nh, data_end, &iphdr);
	if (l4proto == -1) {
		pkt_validity_key = STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM;
		goto error;
	} else if (l4proto == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &uhdr) < 0) {
			action = XDP_DROP;
			pkt_validity_key = STATS_GLOBAL_VALIDITY_UDP_HEADER_MALFORM;
			goto error;
		}
	} else {
		/* support UDP only */
		goto done;
	}
#ifdef USE_GLOBAL_MAP_INSTEAD_OF_PERCPU
	cpu_num = 0;
#else
	cpu_num = bpf_get_smp_processor_id();
#endif
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
		goto modify_pkt;
	} else {
		if (vlans.id[0] == TAG_FROM_SERVER) {
			action = XDP_DROP;
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_NAT_DOES_NOT_EXIST);
			goto done;
		} else {
			__builtin_memset(&policy_key, 0, sizeof(policy_key));
			policy_key.vip = sess_key.dst;
			policy_key.vport = sess_key.port16[1];

			policy_value = bpf_map_lookup_elem(&vip_vport_policy, &policy_key);
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SESSION_FIRST_SEEN);
			if (!policy_value) {
				action = XDP_DROP;
				xdp_stats_events(ctx, STATS_GLOBAL_EVENT_POLICY_DOES_NOT_EXIST);
				goto done;
			}
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
	if (!policy_value->bip_num ||
		(policy_value->bip_num > BIP_CAPACITY)) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_BIP_DOES_NOT_EXIST);
		goto done;
	} else {
		bip_index = bpf_ktime_get_ns() % policy_value->bip_num;

		if (bip_index >= BIP_CAPACITY)
			bip_index = 0;
	}

	__builtin_memset(&sess_value_from_client, 0, sizeof(sess_value_from_client));
	sess_value_from_client.fnat.src = *snat_value;
	sess_value_from_client.fnat.dst = policy_value->bip[bip_index];
	sess_value_from_client.fnat.port16[0] = uhdr->source;
	sess_value_from_client.fnat.port16[1] = policy_value->bport;
	bpf_map_update_elem(session_nat_table_inner, &sess_key, &sess_value_from_client, 0);

#ifdef USE_GLOBAL_MAP_INSTEAD_OF_PERCPU
	cpu_num_from_server = 0;
#else
	cpu_num_from_server = get_cpu_num_by_rss(&sess_value_from_client.fnat);
#endif
	if (cpu_num != cpu_num_from_server) {
		session_nat_table_inner = bpf_map_lookup_elem(&session_nat_table_outer, &cpu_num_from_server);
		if (!session_nat_table_inner) {
			xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SESS_MAP_DOES_NOT_EXIST);
			goto done;
		}
	}
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
modify_pkt:
	/* Update UDP checksum */
#ifdef SUPPORT_UDP_CHECKSUM
	udp_checksum(iphdr, uhdr, &sess_value->fnat);
#else
	uhdr->check = 0;
#endif
	/* modify UDP Header */
	uhdr->source = sess_value->fnat.port16[0];
	uhdr->dest = sess_value->fnat.port16[1];

	/* Update IP checksum */
	ip_checksum(iphdr, &sess_value->fnat);
	/* modify IP Header */
	iphdr->saddr = sess_value->fnat.src;
	iphdr->daddr = sess_value->fnat.dst;
	ip_decrease_ttl(iphdr);

	mac_key = 0;
	smac = bpf_map_lookup_elem(&smac_dmac, &mac_key);
	if (!smac) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SMAC_DOES_NOT_EXIST);
		goto done;
	}
	mac_key = 1;
	dmac = bpf_map_lookup_elem(&smac_dmac, &mac_key);
	if (!dmac) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_DMAC_DOES_NOT_EXIST);
		goto done;
	}
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
	struct smac_dmac_s *smac, *dmac;
	__u32 mac_key = 0;
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
#ifdef SUPPORT_UDP_CHECKSUM
		struct fullnat_info fnat = {};
#endif
		if (parse_udphdr(&nh, data_end, &uhdr) < 0) {
			key2 = STATS_GLOBAL_VALIDITY_UDP_HEADER_MALFORM;
			goto error;
		}
#ifdef SUPPORT_UDP_CHECKSUM
		fnat.src = snat_ip;
		fnat.dst = iphdr->daddr;
		fnat.port16[0] = uhdr->source;
		fnat.port16[1] = uhdr->dest;
		udp_checksum(iphdr, uhdr, &fnat);
#else
		uhdr->check = 0;
#endif
	}

	mac_key = 0;
	smac = bpf_map_lookup_elem(&smac_dmac, &mac_key);
	if (!smac) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_SMAC_DOES_NOT_EXIST);
		goto done;
	}
	mac_key = 1;
	dmac = bpf_map_lookup_elem(&smac_dmac, &mac_key);
	if (!dmac) {
		xdp_stats_events(ctx, STATS_GLOBAL_EVENT_DMAC_DOES_NOT_EXIST);
		goto done;
	}

	/* Build Ethernet Header */
	vlh = (struct vlan_hdr *)(eth + 1);
	vlh->h_vlan_TCI = bpf_htons(TAG_TO_NEXTHOP | (vlh->h_vlan_TCI & ~VLAN_VID_MASK));
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);

	if (vlans.id[0] == TAG_FROM_CLIENT) {
		/* SNAT */
		struct fullnat_info fnat = {
			.src = snat_ip,
			.dst = iphdr->daddr,
		};
		ip_checksum(iphdr, &fnat);
		iphdr->saddr = snat_ip;
	}
	else {
		struct fullnat_info fnat = {
			.src = iphdr->saddr,
			.dst = dnat_ip,
		};
		ip_checksum(iphdr, &fnat);
		iphdr->daddr = dnat_ip;
	}
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
		if (ip_tot_len > data_end - (void *)iphdr) {
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
	csum_replace4(&icmphdr->cksum, (__be32)icmphdr->type, (__be32)echo_reply);
	icmphdr->type = echo_reply;
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
