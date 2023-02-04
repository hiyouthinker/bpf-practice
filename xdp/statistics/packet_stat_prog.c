/*
 * BigBro @2023
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/time.h>
//#include <linux/types.h>
//#include <linux/if_vlan.h> // for struct vlan_ethhdr
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common_structs.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */

struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, __STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} pkt_stat SEC(".maps");

static __always_inline void xdp_stats_events(__u32 key)
{
	__u64 *value;

	value = bpf_map_lookup_elem(&pkt_stat, &key);
	if (value) {
		lock_xadd(value, 1);
	}
}

static __always_inline int parse_eth_header(struct xdp_md *ctx, struct packet_description *pkt)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = (struct ethhdr *)data;;
	struct vlan_ethhdr *veth;

    if (eth + 1 > data_end)
		return -1;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q)) {
        pkt->next_hdr = eth + 1;

        pkt->vlanid = -1;
		xdp_stats_events(STAT_PKT_ETH);

        return eth->h_proto;
    }

    veth = (struct vlan_ethhdr *)eth;
    if (veth + 1 > data_end)
		return -1;

    pkt->vlanid = bpf_ntohs(veth->h_vlan_TCI) & VLAN_VID_MASK;
    pkt->next_hdr = veth + 1;

	xdp_stats_events(STAT_PKT_VLAN);

    return veth->h_vlan_encapsulated_proto;
}

static __always_inline int parse_ipv4_header(struct xdp_md *ctx, struct packet_description *pkt) {
    int hdrsize;
	struct iphdr *iph = (struct iphdr *)pkt->next_hdr;
	void *data_end = (void *)(long)ctx->data_end;

    if (iph + 1 > data_end)
		return -1;

    if (iph->version != 4)
		return -1;

    if (iph->ihl < 5)
		return -1;

    hdrsize = iph->ihl * 4;
    if ((void *)iph + hdrsize > data_end)
		return -1;

    if (bpf_ntohs(iph->tot_len) < sizeof(*iph))
		return -1;

    pkt->next_hdr = (char *)iph + hdrsize;

	xdp_stats_events(STAT_PKT_IPV4);

    return 0;
}

static __always_inline int pasre_packet(struct xdp_md *ctx, struct packet_description *pkt) {
	int eth_type;

	eth_type = parse_eth_header(ctx, pkt);

	if (eth_type < 0)
		return -1;

	if (eth_type != bpf_htons(ETH_P_IP)) {
		return -1;
	}

	if (parse_ipv4_header(ctx, pkt) < 0)
		return -1;

	return 0;
}

SEC("xdp_pass") int xdp_pass_prog(struct xdp_md *ctx)
{
	struct packet_description pkt = {};

	xdp_stats_events(STAT_PKT_ALL);

	if (pasre_packet(ctx, &pkt) < 0)
		goto done;

done:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
