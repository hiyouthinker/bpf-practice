/*
 * Author: BigBro / 2021.05
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MY_MAP_TOTAL_SIZE);
	__type(key, __u32);
	__type(value, __u64);
} my_map SEC(".maps");

SEC("sk_reuseport")
int bpf_reuseport_select(struct __sk_buff *skb)
{
	__u32 key;
	__u64 cur_time = bpf_ktime_get_ns();
	int *value;

	key = cur_time % MY_MAP_REUSEPORT_SIZE;

	value = bpf_map_lookup_elem(&my_map, &key);
	if (value) {
		int *stats;

		key = MY_MAP_STATS_SOCKET1 + *value;

		stats = bpf_map_lookup_elem(&my_map, &key);
		if (stats)
			__sync_fetch_and_add(stats, 1);
		return *value;
	} else {
		int *stats;

		key = MY_MAP_STATS_FAILURE;
		stats = bpf_map_lookup_elem(&my_map, &key);
		if (stats)
			__sync_fetch_and_add(stats, 1);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
