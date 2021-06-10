/*
 * BigBro/2021
 */

#ifndef __MAPS_KERN_H
#define __MAPS_KERN_H

#include "structs_kern_user.h"

struct bpf_map_def SEC("maps") stats_action = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct pkt_stats),
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

struct bpf_map_def SEC("maps") session_nat_table_outer = {
	.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_SUPPORTED_CPUS,
};
#endif
