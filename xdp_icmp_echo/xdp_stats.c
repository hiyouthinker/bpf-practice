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
#include "common_kern_user.h"

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

static bool map_collect(int fd, __u32 key, struct pkt_stats *value)
{
	map_get_value_array(fd, key, value);
	return true;
}

static void stats_collect(int map_fd, struct pkt_stats value[XDP_ACTION_MAX])
{
	__u32 key;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		map_collect(map_fd, key, &value[key]);
	}
}

static void stats_print(struct pkt_stats value[XDP_ACTION_MAX])
{
	__u32 key;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		char *fmt = "%-12s %'11lld pkts %'11lld bytes\n";
		const char *action = action2str(key);

		printf(fmt, action, value[key].rx_bytes, value[key].rx_packets);
	}
	printf("\n");
}

static void stats_poll(int map_fd, int interval)
{
	struct pkt_stats value[XDP_ACTION_MAX];
	while (1) {
		stats_collect(map_fd, value);
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
		.max_entries = XDP_ACTION_MAX,
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

	stats_poll(stats_map_fd, interval);
	return EXIT_OK;
}
