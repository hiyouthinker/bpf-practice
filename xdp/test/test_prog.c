/*
 * BigBro @2023
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/time.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../include/common_structs.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_SUPPORTED_CPUS);
	__type(key, __u32);
	__type(value, __u32);
} session_nat_table_outer SEC(".maps");

#ifdef USE_BPF_TIMER
static int my_timer(void *map, struct flow_key *key, struct flow_value *val)
{
	return 0;
}
#endif

SEC("xdp_test") int xdp_test_prog(struct xdp_md *ctx)
{
	/* 10.10.1.63:60897 -> 10.10.2.112:8080 | 10.10.11.112:8080 -> 10.10.10.100:60897 */
	flow_key_t key = {
		.src = bpf_htonl(0x0a0a013f),
		.dst = bpf_htonl(0x0a0a0270),
		.port16 = {
			[0] = bpf_htons(60897),
			[1] = bpf_htons(8080),
		},
		.proto = IPPROTO_TCP,
	};
	flow_value_t *val;
	void *inner_map;
	int cpu_id = 6;
	static const char fmt1[] = "inner_map map does not exist - CPU%d";
	static const char fmt2[] = "val does not exist - key %pI4:%d => %pI4";
	static const char fmt3[] = "val: %pI4:%d => %pI4";

	inner_map = bpf_map_lookup_elem(&session_nat_table_outer, &cpu_id);
	if (!inner_map) {
		bpf_trace_printk(fmt1, sizeof(fmt1), cpu_id);
		goto done;
	}

	val = bpf_map_lookup_elem(inner_map, &key);
	if (!val) {
		bpf_trace_printk(fmt2, sizeof(fmt2), &key.src, bpf_ntohs(key.port16[0]), &key.dst);
		goto done;
	}

	bpf_trace_printk(fmt3, sizeof(fmt3), &val->key.src, bpf_ntohs(val->key.port16[0]), &val->key.dst);

#ifdef USE_BPF_TIMER
	if (!bpf_timer_init(&val->timer, inner_map, CLOCK_BOOTTIME)) {
		bpf_timer_set_callback(&val->timer, my_timer);
		bpf_timer_start(&val->timer, 9 * 1000000000, 0);
	}
#endif

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
