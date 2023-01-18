#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static bool is_ICMP(void *data_begin, void *data_end)
{
	struct ethhdr *eth = data_begin;

	if ((void *)(eth + 1) > data_end)
		return false;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(eth + 1);

		if ((void *)(iph + 1) > data_end)
		return false;

		if (iph->protocol == IPPROTO_ICMP)
			return true;
	} else if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
		return false;
	}

	return false;
}

SEC("tc") int tc_drop_icmp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	if (is_ICMP(data, data_end))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
