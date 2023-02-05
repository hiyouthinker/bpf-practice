/*
 * BigBro @2023
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>
#include <stdbool.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common_structs.h"
#include "stat_helpers.h"

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */

struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};

static __always_inline bool is_tcp(struct iphdr *iph)
{
	return iph->protocol == IPPROTO_TCP;
}

static __always_inline bool is_udp(struct iphdr *iph)
{
	return iph->protocol == IPPROTO_UDP;
}

static __always_inline int parse_eth_header(struct xdp_md *ctx, struct packet_description *pkt)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = (struct ethhdr *)data;;
	struct vlan_ethhdr *veth;

	if (eth + 1 > data_end)
		return -1;

	pkt->l2_header = data;

	if (eth->h_proto != bpf_htons(ETH_P_8021Q)) {
		pkt->next_hdr = eth + 1;

		reason_add(pkt, STAT_PKT_ETH);

		return eth->h_proto;
	}

	veth = (struct vlan_ethhdr *)eth;
	if (veth + 1 > data_end)
		return -1;

	pkt->next_hdr = veth + 1;

	reason_add(pkt, STAT_PKT_VLAN);

    return veth->h_vlan_encapsulated_proto;
}

static __always_inline int parse_ipv4_header(struct xdp_md *ctx, struct packet_description *pkt)
{
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

	pkt->flow.src   = iph->saddr;
	pkt->flow.dst   = iph->daddr;
	pkt->flow.proto = iph->protocol;

	pkt->l3_header = iph;
	pkt->next_hdr = (char *)iph + hdrsize;

	reason_add(pkt, STAT_PKT_IPV4);

	return 0;
}

static __always_inline int parse_tcp_header(struct xdp_md *ctx, struct packet_description *pkt)
{
	struct tcphdr *tcph = (struct tcphdr *)pkt->next_hdr;
	void *data_end = (void *)(long)ctx->data_end;
	__u8 len;

	if (tcph + 1 > data_end)
		return -1;

	len = tcph->doff << 2;

	if (len < sizeof(*tcph))
		return -1;

	if ((void *)tcph + len > data_end)
		return -1;

	pkt->flow.port16[0] = tcph->source;
	pkt->flow.port16[1] = tcph->dest;

	if (tcph->syn) {
		if (tcph->fin || tcph->rst) {
			return -1;
		} else if (tcph->ack) {
			pkt->tcp_flags = TCP_SYNACK_FLAG;
		} else {
			pkt->tcp_flags = TCP_SYN_FLAG;
			reason_add(pkt, STAT_PKT_TCP_SYN);
		}
	} else if (tcph->fin && tcph->rst) {
		return -1;
	} else if (tcph->fin) {
		pkt->tcp_flags = TCP_FIN_FLAG;
		reason_add(pkt, STAT_PKT_TCP_FIN);
	} else if (tcph->rst) {
		pkt->tcp_flags = TCP_RST_FLAG;
	} else if (tcph->ack) {
		pkt->tcp_flags = TCP_ACK_FLAG;
	} else {
		pkt->tcp_flags = TCP_NONE_FLAG;
	}

	pkt->l4_header = tcph;

	reason_add(pkt, STAT_PKT_TCP);

	return 0;
}

static __always_inline int parse_udp_header(struct xdp_md *ctx, struct packet_description *pkt)
{
	return 0;
}

static __always_inline int pasre_packet(struct xdp_md *ctx, struct packet_description *pkt)
{
	int eth_type;

	eth_type = parse_eth_header(ctx, pkt);

	if (eth_type < 0)
		return -1;

	if (eth_type != bpf_htons(ETH_P_IP)) {
		return -1;
	}

	if (parse_ipv4_header(ctx, pkt) < 0)
		return -1;

	if (is_tcp(pkt->l3_header)) {
		if (parse_tcp_header(ctx, pkt) < 0)
			return -1;
	} else if (is_udp(pkt->l3_header)) {
		if (parse_udp_header(ctx, pkt) < 0)
			return -1;
	} else {
		// do something
	}

	return 0;
}

SEC("xdp_pass") int xdp_pass_prog(struct xdp_md *ctx)
{
	struct packet_description pkt = {};

	reason_add(&pkt, STAT_PKT_ALL);

	if (pasre_packet(ctx, &pkt) < 0)
		goto done;

	if (!packet_filter_match(ctx, &pkt)) {
		goto done;
	}

	reason_stat_all(&pkt);
done:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
