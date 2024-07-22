/*
 * BigBro @2022 - 2023
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/lpm_structs.h"

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key);
	__type(value, __u32);
} ip_lpm_map SEC(".maps");

static __always_inline int ipv4_lpm_lookup(__be32 saddr, __u64 app_id, __u32 prefixlen)
 {
#if 0
	struct lpm_key key = {0};
	__u32 *value       = NULL;
	char fmt1[] = "value for %u: 0x%04x\n";
	char fmt2[] = "value is null for appid %u\n";

	key.prefixlen     = prefixlen;
	key.app_id_lo     = (__u32)app_id;
	key.app_id_hi     = (__u32)(app_id >> 32);
	key.addr.saddr[0] = saddr;

	value = bpf_map_lookup_elem(&ip_lpm_map, &key);
	if (value)
		bpf_trace_printk(fmt1, sizeof(fmt1), app_id, *value);
	else
		bpf_trace_printk(fmt2, sizeof(fmt2), app_id);
#endif

	return 0;
}

SEC("xdp")
int xdp_lpm_func(struct xdp_md *ctx)
{
	ipv4_lpm_lookup(0x01010101, 1, 64 + 32);
	return XDP_PASS;
}

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
