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

static void stats_collect(int map_fd, int map_type, struct pkt_stats value[__STATS_GLOBAL_MAX])
{
	__u32 key;

	for (key = 0; key < __STATS_GLOBAL_MAX; key++) {
		map_collect(map_fd, map_type, key, &value[key]);
	}
}

static const char *reason_names[__STATS_GLOBAL_MAX] = {
	[STATS_GLOBAL_PKT_XDP_PASS]   		= "Pass to Kernel",
	[STATS_GLOBAL_PKT_XDP_TX]      		= "XDP TX",
	[STATS_GLOBAL_PKT_L3_UNKNOWN]     	= "Unknown L3 PKT",
	[STATS_GLOBAL_PKT_ARP]     			= "ARP",
	[STATS_GLOBAL_PKT_IPv4_UNKNOWN]     = "Unknown IPv4 PKT",
	[STATS_GLOBAL_PKT_IPv6_UNKNOWN]     = "Unknown IPv6 PKT",
	[STATS_GLOBAL_PKT_IPv6_NOT_SUPPORT] = "IPv6 (Not Support)",
	[STATS_GLOBAL_PKT_ICMPv4_ECHO]  	= "ICMPv4 Echo",
	[STATS_GLOBAL_PKT_ICMPv4_NON_ECHO]	= "ICMPv4 Non-Echo",
	[STATS_GLOBAL_PKT_TCPv4]   			= "TCPv4",
	[STATS_GLOBAL_PKT_UDPv4]	   		= "UDPv4",
	[STATS_GLOBAL_PKT_ICMPv6_ECHO]		= "ICMPv6 Echo",
	[STATS_GLOBAL_PKT_ICMPv6_NON_ECHO]	= "ICMPv6 Non-Echo",
	[STATS_GLOBAL_PKT_TCPv6]			= "TCPv6",
	[STATS_GLOBAL_PKT_UDPv6]			= "UDPv6",
};

const char *reason2str(__u32 reason)
{
	if (reason < __STATS_GLOBAL_MAX)
		return reason_names[reason];
	return "Unkown";
}

static void stats_print(struct pkt_stats value[__STATS_GLOBAL_MAX])
{
	__u32 key;

	printf("==========================================================\n");
	for (key = 0; key < __STATS_GLOBAL_MAX; key++) {
		char *fmt = "%-20s %'11lld pkts %'11lld bytes\n";
		const char *reason = reason2str(key);

		printf(fmt, reason, value[key].rx_packets, value[key].rx_bytes);
	}
	printf("\n");
}

static void stats_poll(int map_fd, int map_type, int interval)
{
	struct pkt_stats value[__STATS_GLOBAL_MAX];
	while (1) {
		stats_collect(map_fd, map_type, value);
		stats_print(value);
		sleep(interval + 2);
	}
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP stats program\n"
		" - Finding xdp_stats_map via --dev name info\n";
	struct bpf_map_info info = { 0 };
	const struct bpf_map_info map_expect = {
		.key_size    = sizeof(__u32),
		.value_size  = sizeof(struct pkt_stats),
		.max_entries = __STATS_GLOBAL_MAX,
	};
	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};
	char pin_dir[1024];
	int stats_map_fd;
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

	stats_map_fd = open_bpf_map_file(pin_dir, "xdp_stats_map", &info);
	if (stats_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	err = check_map_fd_info(&info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		close(stats_map_fd);
		return err;
	}

	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
			   " key_size:%d value_size:%d max_entries:%d\n",
			   info.type, info.id, info.name,
			   info.key_size, info.value_size, info.max_entries
			   );
	}

	stats_poll(stats_map_fd, info.type, interval);
	return EXIT_OK;
}
