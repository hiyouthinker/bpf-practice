#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common_kern_user.h"

struct bpf_map_def SEC("maps") xdp_version = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = 128,
	.max_entries = 1,
};

SEC(".text.version") char version[] = "Version: BigBro/0.1 - 2021";

struct bpf_map_def SEC("maps") xdp_test_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct stats_common_s),
	.max_entries = STATS_SITE_ARRAY_MAP_SIZE,
};

SEC("xdp_test")
int xdp_test_func(struct xdp_md *ctx)
{
	__u32 key, value;
	__u64 cur_time = bpf_ktime_get_ns();

	key = cur_time % __STATS_SITE_MAX;
	key = STATS_SITE_KEY(key, 10, 0);
	value = 1;

	struct stats_common_s *rec = bpf_map_lookup_elem(&xdp_test_map, &key);
	if (!rec)
		return XDP_DROP;

	rec->total_packets++;
	rec->total_bytes += value;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
