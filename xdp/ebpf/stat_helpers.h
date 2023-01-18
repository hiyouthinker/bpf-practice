
/*
 * BigBro @2021 - 2023
 */

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct bpf_map_def SEC("maps") stats_action = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),	/* Note: 8-bytes alignment in kernel */
	.max_entries = __XDP_ACTION_MAX,
};

struct bpf_map_def SEC("maps") stats_pkt = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct pkt_stats),
	.max_entries = __STATS_GLOBAL_PKT_MAX,
};

struct bpf_map_def SEC("maps") stats_validity = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct pkt_stats),
	.max_entries = __STATS_GLOBAL_VALIDITY_MAX,
};

struct bpf_map_def SEC("maps") stats_events = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = __STATS_GLOBAL_EVENT_MAX,
};

static __always_inline
__u32 xdp_stats_action(struct xdp_md *ctx, __u32 key)
{
	__u32 *rec;

	if (key >= __XDP_ACTION_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&stats_action, &key);
	if (!rec)
		return -1;

	*rec += 1;
	return 0;
}

static __always_inline
__u32 xdp_stats_pkt(struct xdp_md *ctx, __u32 key)
{
	struct pkt_stats *rec;

	if (key >= __STATS_GLOBAL_PKT_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&stats_pkt, &key);
	if (!rec)
		return -1;

	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, (ctx->data_end - ctx->data));

	return 0;
}

static __always_inline
__u32 xdp_stats_validity(struct xdp_md *ctx, __u32 key)
{
	struct pkt_stats *rec;

	if (key >= __STATS_GLOBAL_VALIDITY_MAX)
		return -1;

	rec = bpf_map_lookup_elem(&stats_validity, &key);
	if (!rec)
		return -1;

	lock_xadd(&rec->rx_packets, 1);
	lock_xadd(&rec->rx_bytes, (ctx->data_end - ctx->data));

	return 0;
}

static __always_inline
__u32 xdp_stats_events(struct xdp_md *ctx, __u32 key)
{
	__u32 *value;

	if (key >= __STATS_GLOBAL_EVENT_MAX)
		return -1;

	value = bpf_map_lookup_elem(&stats_events, &key);
	if (!value)
		return -1;

	lock_xadd(value, 1);
	return 0;
}
