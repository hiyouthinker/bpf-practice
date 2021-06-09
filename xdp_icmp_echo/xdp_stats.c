/*
 * (reference xdp_tutorial)
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

#include "bpf_util.h" /* bpf_num_possible_cpus */

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

static void map_get_value_array(int fd, __u32 key, struct pkt_stats *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

static void map_get_value_percpu_array(int fd, __u32 key, struct pkt_stats *value)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct pkt_stats values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}

static bool map_collect(int fd, int map_type, __u32 key, struct pkt_stats *value)
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

static void stats_collect(int map_fd, int map_type, struct pkt_stats *value, int flag)
{
	__u32 key;
	int loop;

	if (flag == 0)
		loop = __STATS_GLOBAL_PKT_MAX;
	else if (flag == 1)
		loop = __STATS_GLOBAL_VALIDITY_MAX;
	else
		loop = __XDP_ACTION_MAX;

	for (key = 0; key < loop; key++) {
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

static const char *reason2str(__u32 reason, int flag)
{
	int limit;
	const char **names;

	if (flag == 0) {
		limit = __STATS_GLOBAL_PKT_MAX;
		names = reason_names_pkt;
	}
	else if (flag == 1) {
		limit = __STATS_GLOBAL_VALIDITY_MAX;
		names = reason_names_validity;
	}
	else {
		limit = __XDP_ACTION_MAX;
		names = reason_names_action;
	}

	if (reason < limit)
		return names[reason];

	return "Unkown";
}

static void stats_print(struct pkt_stats *value, int flag, int verbose)
{
	__u32 key;
	int loop;

	if (flag == 0)
		loop = __STATS_GLOBAL_PKT_MAX;
	else if (flag == 1)
		loop = __STATS_GLOBAL_VALIDITY_MAX;
	else
		loop = __XDP_ACTION_MAX;

	for (key = 0; key < loop; key++) {
		char *fmt = "%-50s %'11lld pkts %'11lld bytes\n";
		const char *reason = reason2str(key, flag);

		if (verbose	|| (!verbose && value[key].rx_packets))
			printf(fmt, reason, value[key].rx_packets, value[key].rx_bytes);
	}
	printf("\n");
}

static void stats_poll(int map_fd1, int map_type1
	, int map_fd2, int map_type2
	, int map_fd3, int map_type3, int interval, int verbose)
{
	struct pkt_stats value[__STATS_GLOBAL_PKT_MAX];
	while (1) {
		printf("===============================================================================\n");
		stats_collect(map_fd1, map_type1, value, 0);
		stats_print(value, 0, verbose);
	//	sleep(1);
		printf("---------------------------\n");
		stats_collect(map_fd2, map_type2, value, 1);
		stats_print(value, 1, verbose);
	//	sleep(1);
		printf("---------------------------\n");
		stats_collect(map_fd3, map_type3, value, 2);
		stats_print(value, 2, verbose);
		sleep(interval + 2);
	}
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP stats program\n"
		" - Finding xdp_stats_map via --dev name info\n";
	struct bpf_map_info pkt_info = {0}, validity_info = {0}, action_info = {0};
	const struct bpf_map_info pkt_map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct pkt_stats),
		.max_entries = __STATS_GLOBAL_PKT_MAX,
	};
	const struct bpf_map_info validity_map_expect = {
		.key_size	 = sizeof(__u32),
		.value_size  = sizeof(struct pkt_stats),
		.max_entries = __STATS_GLOBAL_VALIDITY_MAX,
	};
	const struct bpf_map_info action_map_expect = {
		.key_size	 = sizeof(__u32),
		.value_size  = sizeof(struct pkt_stats),
		.max_entries = __XDP_ACTION_MAX,
	};
	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};
	char pin_dir[1024];
	int pkt_map_fd, validity_map_fd, action_map_fd;
	int interval = 2;
	int len, err;

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
	pkt_map_fd = open_bpf_map_file(pin_dir, "xdp_stats_pkt_map", &pkt_info);
	if (pkt_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	err = check_map_fd_info(&pkt_info, &pkt_map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(pkt_map_fd);
		return err;
	}
	validity_map_fd = open_bpf_map_file(pin_dir, "xdp_stats_validity_map", &validity_info);
	if (validity_map_fd < 0) {
		close(pkt_map_fd);
		return EXIT_FAIL_BPF;
	}

	err = check_map_fd_info(&validity_info, &validity_map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(pkt_map_fd);
		close(validity_map_fd);
		return err;
	}

	action_map_fd = open_bpf_map_file(pin_dir, "xdp_stats_action_map", &action_info);
	if (action_map_fd < 0) {
		close(pkt_map_fd);
		close(validity_map_fd);
		return EXIT_FAIL_BPF;
	}

	err = check_map_fd_info(&action_info, &action_map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(pkt_map_fd);
		close(validity_map_fd);
		close(action_map_fd);
		return err;
	}

	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			   " key_size:%d value_size:%d max_entries:%d\n",
			   pkt_info.type, pkt_info.id, pkt_info.name,
			   pkt_info.key_size, pkt_info.value_size, pkt_info.max_entries);
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			   " key_size:%d value_size:%d max_entries:%d\n",
			   validity_info.type, validity_info.id, validity_info.name,
			   validity_info.key_size, validity_info.value_size, validity_info.max_entries);
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			   " key_size:%d value_size:%d max_entries:%d\n",
			   action_info.type, action_info.id, action_info.name,
			   action_info.key_size, action_info.value_size, action_info.max_entries);
	}

	stats_poll(pkt_map_fd, pkt_info.type
		, validity_map_fd, validity_info.type
		, action_map_fd, action_info.type
		, interval, cfg.verbose);
	return EXIT_OK;
}
