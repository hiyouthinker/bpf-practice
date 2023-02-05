/*
 * BigBro @2023
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, __STAT_PKT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} pkt_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct filter);
} pkt_filter SEC(".maps");

static __always_inline void reason_stat(__u32 key)
{
	__u64 *value;

	value = bpf_map_lookup_elem(&pkt_stat, &key);
	if (value) {
		lock_xadd(value, 1);
	}
}

static __always_inline void reason_stat_all(struct packet_description *pkt)
{
	__u64 *value;
	__u32 reason;

	for (reason = 0; reason < __STAT_PKT_MAX; reason++) {
		if (pkt->stat.reason[reason]) {
			__u32 key = reason;

			value = bpf_map_lookup_elem(&pkt_stat, &key);
			if (value)
				lock_xadd(value, 1);
		}
	}
}

static __always_inline void reason_add(struct packet_description *pkt, __u32 reason)
{
	if (reason < __STAT_PKT_MAX)
		pkt->stat.reason[reason] = 1;
}

static __always_inline bool packet_filter_match(struct xdp_md *ctx, struct packet_description *pkt)
{
	__u32 key = 0;
	struct filter *value;

	value = bpf_map_lookup_elem(&pkt_filter, &key);
	if (!value)
		return true;
	
	if (value->flow.src) {
		if (pkt->flow.src != value->flow.src)
			return false;
	}

	if (value->flow.dst) {
		if (pkt->flow.dst != value->flow.dst)
			return false;
	}

	if (value->flow.port16[0]) {
		if (pkt->flow.port16[0] != value->flow.port16[0])
			return false;
	}

	if (value->flow.port16[1]) {
		if (pkt->flow.port16[1] != value->flow.port16[1])
			return false;
	}

	if (value->flow.proto) {
		if (pkt->flow.proto != value->flow.proto)
			return false;
	}

	if (value->filter_flags & FILTER_FLAG_TCP_FLAG) {
		if (pkt->tcp_flags != value->tcp_flags)
			return false;
	}

	return true;
}