/*
 * BigBro/2021
 */

#ifndef __MAPS_KERN_H
#define __MAPS_KERN_H

#include "structs_kern_user.h"

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

struct bpf_map_def SEC("maps") session_nat_table_outer = {
	.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_SUPPORTED_CPUS,
};

struct bpf_map_def SEC("maps") snat_ip_pool = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = SNAT_IP_POOL_CAPACITY,
};
#endif
