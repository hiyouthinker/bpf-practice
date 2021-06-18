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

struct bpf_map_def SEC("maps") vip_vport_policy = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct vip_vport_policy_key_s),
	.value_size = sizeof(struct vip_vport_policy_value_s),
	.max_entries = VIP_VPORT_POLICY_CAPACITY,
};

struct bpf_map_def SEC("maps") rss_hash_key = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct rss_hash_key_s),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") smac_dmac = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct smac_dmac_s),
	.max_entries = 2,
};
#endif
