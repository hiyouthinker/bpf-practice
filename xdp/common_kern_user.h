/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct datarec_s {
	__u64 rx_packets;
	__u64 rx_bytes;
};

typedef	unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;

enum {
	STATS_SITE_DROP_UNKNOWN_PORT,
	STATS_SITE_DROP_IP_FRAGMENT_FORBID,
	STATS_SITE_DROP_GRE_FORBID,
	STATS_SITE_DROP_PING_FORBID,
	STATS_SITE_DROP_PING_TOO_BIG,
	STATS_SITE_DROP_PING_PPS_OVERFLOW,
	STATS_SITE_DROP_INVALID_L4PROTO,
	STATS_SITE_PASS_IP_FRAGMENT,
	STATS_SITE_PASS_GRE,
	STATS_SITE_PASS_PING_REPLY,
	__STATS_SITE_MAX
};
	
#define STATS_SITE_INDEX(index, is_ipv6)		(index + __STATS_SITE_MAX * is_ipv6)
#define STATS_SITE_KEY(index, id, is_ipv6)		(__STATS_SITE_MAX * 2 * id + STATS_SITE_INDEX(index, is_ipv6))
#define STATS_SITE_ARRAY_MAP_SIZE 				(__STATS_SITE_MAX * 2 * 100)

struct stats_common_s {
	struct {
		uint64_t total_packets;
		uint64_t total_bytes;
	};
};

struct site_policy_value_s {
	uint32_t site_id;
	uint32_t internal_id;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
