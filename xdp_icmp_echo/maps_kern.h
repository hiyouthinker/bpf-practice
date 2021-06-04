/*
 * BigBro/2021
 */

#ifndef __MAPS_KERN_H
#define __MAPS_KERN_H

#include "structs_kern_user.h"

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct pkt_stats),
	.max_entries = __STATS_GLOBAL_MAX,
};

#endif
