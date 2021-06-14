/*
 * BigBro/2021
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "structs_kern_user.h"

#include <bpf/libbpf.h>
#include <bpf/bpf_endian.h>	/* for bpf_htonl etc. */

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

struct common_stats_s {
	char value[256];
};

typedef struct info_collection_s {
	char map_name[64];
	const char **titles;
	void (*print)(struct common_stats_s *, int, const char **, int);
	struct bpf_map_info info;
} info_collection_t;

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"verbose",	no_argument, 		NULL, 'v' },
	 "Show all statstics"},

	{{0, 0, NULL,  0 }}
};

static void map_get_value_array(int fd, __u32 key, void *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

static void map_get_value_percpu_array(int fd, __u32 key, void *value)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}
	memcpy(value, &values, sizeof(values));
}

static bool map_collect(int fd, int map_type, __u32 key, void *value)
{
	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}
	return true;
}

static void stats_collect(int map_fd, int map_type, struct common_stats_s value[], int max_entries)
{
	__u32 key;

	for (key = 0; key < max_entries; key++) {
		map_collect(map_fd, map_type, key, &value[key]);
	}
}

static const char *reason_names_pkt[__STATS_GLOBAL_PKT_MAX] = {
	[STATS_GLOBAL_PKT_ALL]					= "All pkts",
	[STATS_GLOBAL_PKT_VLAN]					= "VLAN",
	[STATS_GLOBAL_PKT_VLAN_FROM_CLIENT]		= "  from client",
	[STATS_GLOBAL_PKT_VLAN_FROM_SERVER] 	= "  from server",
	[STATS_GLOBAL_PKT_OTHER_VLAN] 			= "  Other",
	[STATS_GLOBAL_PKT_L3_UNKNOWN]     		= "Unknown L3 PKT",
	[STATS_GLOBAL_PKT_ARP]     				= "ARP",
	[STATS_GLOBAL_PKT_IPv4_UNKNOWN]     	= "Unknown IPv4 PKT",
	[STATS_GLOBAL_PKT_IPv4_HEADER_INVALID] 	= "Invalid IPv4 Header",
	[STATS_GLOBAL_PKT_ICMPv4_ECHO]  		= "ICMPv4 Echo",
	[STATS_GLOBAL_PKT_ICMPv4_ECHOREPLY]		= "ICMPv4 Reply",
	[STATS_GLOBAL_PKT_ICMPv4_OTHER]			= "ICMPv4 Other",
	[STATS_GLOBAL_PKT_TCPv4]   				= "TCPv4",
	[STATS_GLOBAL_PKT_UDPv4]	   			= "UDPv4",
	[STATS_GLOBAL_PKT_IPv6_UNKNOWN]     	= "Unknown IPv6 PKT",
	[STATS_GLOBAL_PKT_IPv6_HEADER_INVALID]	= "Invalid IPv6 Header",
	[STATS_GLOBAL_PKT_ICMPv6_ECHO]			= "ICMPv6 Echo",
	[STATS_GLOBAL_PKT_ICMPv6_ECHOREPLY]		= "ICMPv6 Reply",
	[STATS_GLOBAL_PKT_ICMPv6_OTHER]			= "ICMPv6 Other",
	[STATS_GLOBAL_PKT_TCPv6]				= "TCPv6",
	[STATS_GLOBAL_PKT_UDPv6]				= "UDPv6",
};

static const char *reason_names_validity[__STATS_GLOBAL_VALIDITY_MAX] = {
	[STATS_GLOBAL_VALIDITY_NONE_TAG]				= "Without Tag",
	[STATS_GLOBAL_VALIDITY_UNKNOWN_TAG]				= "Unknown Tag",
	[STATS_GLOBAL_VALIDITY_ETHERNET_HEADER_MALFORM]	= "Abnormal Ethernet Header",
	[STATS_GLOBAL_VALIDITY_IPv4_HEADER_MALFORM]		= "Abnormal IPv4 Header",
	[STATS_GLOBAL_VALIDITY_UDP_HEADER_MALFORM]		= "Abnormal UDP Header",
	[STATS_GLOBAL_VALIDITY_IPv6_HEADER_MALFORM]		= "Abnormal IPv6 Header",
};

static const char *reason_names_action[__XDP_ACTION_MAX] = {
	[XDP_ABORTED]	= "ABORTED",
	[XDP_DROP]		= "DROP",
	[XDP_PASS]		= "PASS",
	[XDP_TX]		= "TX",
	[XDP_REDIRECT]	= "REDIRECT",
};

static const char *reason_names_event[__STATS_GLOBAL_EVENT_MAX] = {
	[STATS_GLOBAL_EVENT_SESS_MAP_DOES_NOT_EXIST]		= "MAP - Not Exist",
	[STATS_GLOBAL_EVENT_SNAT_IP_DOES_NOT_EXIST]			= "SNAT IP - Not Exist",
	[STATS_GLOBAL_EVENT_SESSION_FIRST_SEEN]				= "Session First seen",
	[STATS_GLOBAL_EVENT_SESSION_HIT]					= "Session Hit",
	[STATS_GLOBAL_EVENT_NAT_HIT]						= "NAT Hit",
	[STATS_GLOBAL_EVENT_NAT_DOES_NOT_EXIST]				= "NAT - Not Exist",
	[STATS_GLOBAL_EVENT_POLICY_DOES_NOT_EXIST]			= "Policy - Not Exist",
	[STATS_GLOBAL_EVENT_BIP_DOES_NOT_EXIST]				= "BIP - Not Exist",
};

static void stats_print(struct common_stats_s value[], int max_entries, const char *titles[], int verbose)
{
	__u32 key;
	int printed = 0;

	for (key = 0; key < max_entries; key++) {
		char *fmt = "%-50s %'11lld pkts %'11lld bytes\n";
		const char *reason = titles[key];
		struct pkt_stats *stats = (struct pkt_stats *)&value[key];

		if (verbose	|| (!verbose && stats->rx_packets)) {
			printf(fmt, reason, stats->rx_packets, stats->rx_bytes);
			printed = 1;
		}
	}
	if (printed)
		printf("-----------------------------------------\n");
}

static void actions_stats_print(struct common_stats_s value[], int max_entries, const char *titles[], int verbose)
{
	__u32 key;
	int printed = 0, cpu, cpu_num = libbpf_num_possible_cpus();

	for (key = 0; key < max_entries; key++) {
		char *fmt = "CPU%02d: %-50s %'11lld\n";
		const char *reason = titles[key];
		__u64 *stats = (__u64 *)&value[key];
		for (cpu = 0; cpu < cpu_num; cpu++) {
			if (verbose	|| (!verbose && *stats)) {
				printf(fmt, cpu, reason, *stats);
				printed = 1;
			}
			stats++;
		}
	}
	if (printed)
		printf("-----------------------------------------\n");
}

static void events_stats_print(struct common_stats_s value[], int max_entries, const char *titles[], int verbose)
{
	__u32 key;
	int printed = 0;

	for (key = 0; key < max_entries; key++) {
		char *fmt = "%-50s %'11lld\n";
		const char *reason = titles[key];
		__u32 stats = *(__u32 *)&value[key];

		if (verbose	|| (!verbose && stats)) {
			printf(fmt, reason, stats);
			printed = 1;
		}
	}
	if (printed)
		printf("-----------------------------------------\n");
}

static void stats_poll(int map_fd, info_collection_t *real, int verbose)
{
	struct common_stats_s value[512] = {};
	int cpu = -1;

	if (real->info.type == BPF_MAP_TYPE_LRU_HASH) {
		struct flow_key sess_key, *keyp = &sess_key, *prev_keyp = NULL;
		struct flow_value sess_value;
		int err, printed = 0;

		while (true) {
			err = bpf_map_get_next_key(map_fd, prev_keyp, keyp);
			if (err) {
				/* ENOENT: iterated over all buckets and all elements */
				if (errno != ENOENT)
					fprintf(stderr, "ERR: bpf_map_get_next_key failed, error: %s@%s\n", strerror(errno), real->map_name);
				break;
			}
			if ((bpf_map_lookup_elem(map_fd, keyp, &sess_value)) != 0) {
				fprintf(stderr, "ERR: bpf_map_lookup_elem failed\n");
				continue;
			}
			printf(NIPQUAD_FMT ":%u -> " NIPQUAD_FMT ":%u\t=>\t"
				, NIPQUAD(sess_key.src), bpf_ntohs(sess_key.port16[0])
				, NIPQUAD(sess_key.dst), bpf_ntohs(sess_key.port16[1]));
			printf(NIPQUAD_FMT ":%u -> " NIPQUAD_FMT ":%u\n"
				, NIPQUAD(sess_value.fnat.src), bpf_ntohs(sess_value.fnat.port16[0])
				, NIPQUAD(sess_value.fnat.dst), bpf_ntohs(sess_value.fnat.port16[1]));
			prev_keyp = keyp;
			if (!printed) {
				printed = 1;
				sscanf(real->map_name, SESSION_NAT_INNER_MAP_NAME "_cpu%d", &cpu);
			}
		}
		if (printed)
			printf("----------------------------------------- @CPU%d\n", cpu);
		return;
	}

	stats_collect(map_fd, real->info.type, value, real->info.max_entries);
	if (real->print)
		real->print(value, real->info.max_entries, real->titles, verbose);
	else
		stats_print(value, real->info.max_entries, real->titles, verbose);
}

static int global_index;
static void get_map_fd_and_check(const char *pin_dir
				, info_collection_t reals[], info_collection_t *expect
				, char *map_name, int map_fd[])
{
	int err;
	map_fd[global_index] = open_bpf_map_file(pin_dir, map_name, &reals[global_index].info);
	if (map_fd[global_index] < 0) {
		exit(-1);
	}
	err = check_map_fd_info(&reals[global_index].info, &expect->info);
	if (err) {
		fprintf(stderr, "ERR: map %s via FD not compatible\n", map_name);
		exit(-1);
	}
	strcpy(reals[global_index].map_name, map_name);
	reals[global_index].titles = expect->titles;
	reals[global_index].print = expect->print;
	if (verbose) {
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			   " key_size:%d value_size:%d max_entries:%d\n",
			   reals[global_index].info.type, reals[global_index].info.id, reals[global_index].info.name,
			   reals[global_index].info.key_size, reals[global_index].info.value_size, reals[global_index].info.max_entries);
	}
	global_index++;
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP stats program\n"
		" - Finding xdp_stats_map via --dev name info\n";
	info_collection_t expects[] = {
		{
			"stats_pkt",
			reason_names_pkt,
			NULL,
			{
				.type = BPF_MAP_TYPE_ARRAY,
				.key_size    = sizeof(__u32),
				.value_size  = sizeof(struct pkt_stats),
				.max_entries = __STATS_GLOBAL_PKT_MAX,
			}
		},
		{
			"stats_validity",
			reason_names_validity,
			NULL,
			{
				.type = BPF_MAP_TYPE_ARRAY,
				.key_size	 = sizeof(__u32),
				.value_size  = sizeof(struct pkt_stats),
				.max_entries = __STATS_GLOBAL_VALIDITY_MAX,
			}
		},
		{
			"stats_action",
			reason_names_action,
			actions_stats_print,
			{
				.type = BPF_MAP_TYPE_PERCPU_ARRAY,
				.key_size	 = sizeof(__u32),
				.value_size  = sizeof(__u64),
				.max_entries = __XDP_ACTION_MAX,
			}
		},
		{
			"stats_events",
			reason_names_event,
			events_stats_print,
			{
				.type = BPF_MAP_TYPE_ARRAY,
				.key_size	 = sizeof(__u32),
				.value_size  = sizeof(__u32),
				.max_entries = __STATS_GLOBAL_EVENT_MAX,
			}
		},
		{
			SESSION_NAT_INNER_MAP_NAME,
			NULL,
			NULL,
			{
				.type = BPF_MAP_TYPE_LRU_HASH,
				.key_size = sizeof(struct flow_key),
				.value_size = sizeof(struct flow_value),
				.max_entries = SESS_NAT_TABLE_PERCPU_CAPACITY,
			}
		},
	};
	int cpu_num = libbpf_num_possible_cpus(), cpu;
	info_collection_t reals[16 + cpu_num];
	int map_fd[16 + cpu_num];
	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};
	char pin_dir[1024];
	int len, i;

	memset(reals, 0, sizeof(reals));
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, sizeof(pin_dir), "%s/%s", PIN_BASEDIR, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (verbose)
		printf("\nCollecting stats from BPF map\n");

	for (i = 0; i < sizeof(expects)/sizeof(expects[0]); i++) {
		char map_name[128];
		if (expects[i].info.type == BPF_MAP_TYPE_LRU_HASH) {
			for (cpu = 0; cpu < cpu_num; cpu++) {
				snprintf(map_name, sizeof(map_name), "%s_cpu%d", expects[i].map_name, cpu);
				get_map_fd_and_check(pin_dir, reals, &expects[i], map_name, map_fd);
			}
		} else {
			strcpy(map_name, (expects)[i].map_name);
			get_map_fd_and_check(pin_dir, reals, &expects[i], map_name, map_fd);
		}
	}
	while (1) {
		static int loop = 0;
		printf("=============================================================================== %03d\n", loop++);
		for (i = 0; i < global_index; i++) {
			stats_poll(map_fd[i], &reals[i], cfg.verbose);
		}
		sleep(3);
	}
	return EXIT_OK;
}
