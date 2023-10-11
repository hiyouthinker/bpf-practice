/*
 * BigBro @2023
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/time.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common_structs.h"
#include "../common/parsing_helpers.h"

SEC("xdp_pkt_parse") int xdp_pkt_parse_prog(struct xdp_md *ctx)
{
	__u64 cpuid = bpf_get_smp_processor_id();

//	if (cpuid > 7) {
		int eth_type, ip_type;
		void *data_end = (void *)(long)ctx->data_end;
		void *data = (void *)(long)ctx->data;
		struct hdr_cursor nh;
		struct collect_vlans vlans = {};
		struct ethhdr *eth;
		struct iphdr *iphdr;
		struct tcphdr *thdr;

		nh.pos = data;

		eth_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);
		if (eth_type < 0) {
			goto done;
		}

		if (eth_type != bpf_htons(ETH_P_IP)) {
		//	bpf_printk("ether proto: 0x%04x", bpf_ntohs(eth_type));
			goto done;
		}

		ip_type = parse_iphdr(&nh, data_end, &iphdr);

		if (ip_type == IPPROTO_ICMP) {
			bpf_printk("cpuid is %d, ingress_ifindex: %d, rx_queue_index: %d", cpuid, ctx->ingress_ifindex, ctx->rx_queue_index);
			bpf_printk("ICMP: %pI4 => %pI4, vlan id: %d", &iphdr->saddr, &iphdr->daddr, vlans.id[0]);
			goto done;
		}

		if (ip_type != IPPROTO_TCP) {
			goto done;
		}

		if (parse_tcphdr(&nh, data_end, &thdr) < 0) {
			bpf_printk("invalid tcp header");
			goto done;
		}

		if (bpf_ntohs(thdr->source) != 8080 && bpf_ntohs(thdr->dest) != 8080
		    && bpf_ntohs(thdr->source) != 4080 && bpf_ntohs(thdr->dest) != 4080)
			goto done;

		if (vlans.id[0] == 0)
			goto done;

		bpf_printk("cpuid is %d, ingress_ifindex: %d, rx_queue_index: %d", cpuid, ctx->ingress_ifindex, ctx->rx_queue_index);
		bpf_printk("vlan id: %d, %d => %d", vlans.id[0], bpf_ntohs(thdr->source), bpf_ntohs(thdr->dest));

		bpf_printk("TCP: %pI4 => %pI4, rst: %d", &iphdr->saddr, &iphdr->daddr, thdr->rst);
		bpf_printk("TCP: syn: %d, ack: %d, fin: %d", thdr->syn, thdr->ack, thdr->fin);
//	}

done:
	return XDP_PASS;
}

SEC("xdp_pass") int xdp_pass_prog(struct xdp_md *ctx)
{
	static const char fmt[] = "in xdp_pass_prog";

	bpf_trace_printk(fmt, sizeof(fmt));
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
