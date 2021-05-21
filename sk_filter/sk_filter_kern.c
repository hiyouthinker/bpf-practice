/*
 * Author: BigBro / 2021.05
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/bpf_helpers.h>
#include "common_kern_user.h"

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(int),
	.max_entries = MY_MAP_TOTAL_SIZE,
};

SEC("reuseport")
int bpf_reuseport_select(struct __sk_buff *skb)
{
	__u32 key;
	__u64 cur_time = bpf_ktime_get_ns();
	int *value;

	key = cur_time % MY_MAP_REUSEPORT_SIZE;

	value = bpf_map_lookup_elem(&my_map, &key);
	if (value) {
		int *stats;

		if (*value == 0)
			key = MY_MAP_STATS_SUCCESS_FIRST;
		else
			key = MY_MAP_STATS_SUCCESS_SECOND;

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
