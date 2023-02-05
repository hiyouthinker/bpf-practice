/*
 * BigBro @2023
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
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf_endian.h>	/* for bpf_htonl etc. */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../include/common_structs.h"

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"show",           no_argument,	NULL, 's' },
	 "show statistics"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static const char *pkt_stat_titles[] = {
	[STAT_PKT_ALL]        = "STAT_PKT_ALL",
	[STAT_PKT_ETH]        = "STAT_PKT_ETH",
	[STAT_PKT_VLAN]       = "STAT_PKT_VLAN",
	[STAT_PKT_IPV4]       = "STAT_PKT_IPV4",
	[STAT_PKT_IPV6]       = "STAT_PKT_IPV6",
	[STAT_PKT_TCP]        = "STAT_PKT_TCP",
	[STAT_PKT_TCP_SYN]    = "STAT_PKT_TCP_SYN",
	[STAT_PKT_TCP_SYNACK] = "STAT_PKT_TCP_SYNACK",
	[STAT_PKT_TCP_FIN]    = "STAT_PKT_TCP_FIN",
	[STAT_PKT_UDP]        = "STAT_PKT_UDP",
	[__STAT_PKT_MAX]      = "-",
};

static int get_map_fd_and_check(const char *pin_dir, char *map_name)
{
	int fd;
	struct bpf_map_info info = {0};
	struct bpf_map_info exp = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u64),
		.max_entries = __STAT_PKT_MAX,
	};

	fd = open_bpf_map_file(pin_dir, map_name, &info);
	if (fd < 0) {
		return -1;
	}

	if (check_map_fd_info(&info, &exp)) {
		printf("ERR: map %s via FD not compatible\n", map_name);
		close(fd);
		return -1;
	}

	if (verbose) {
		printf(" - BPF map (bpf_map_type:%d) id: %d, name: %s,"
			   " key_size: %d, value_size: %d, max_entries: %d\n",
			   info.type, info.id, info.name,
			   info.key_size, info.value_size, info.max_entries);
	}

	return fd;
}

static int lookup_elem_and_show(int fd)
{
	__u32 key = 0;
	__u64 value;

	for (key = 0; key < __STAT_PKT_MAX; key++) {
		if (bpf_map_lookup_elem(fd, &key, &value) < 0) {
			printf("failed to lookup map: %s\n", strerror(errno));
			return -1;
		}

		if (value)
			printf("%-20s: %llu\n", pkt_stat_titles[key], value);
	}

	return 0;
}

static int lookup_elem_and_statistic(int fd)
{
	__u32 key = STAT_PKT_TCP_SYN;
	__u64 value, prev, diff;

	if (bpf_map_lookup_elem(fd, &key, &prev) < 0) {
		printf("failed to lookup map: %s\n", strerror(errno));
		return -1;
	}

	if (bpf_map_lookup_elem(fd, &key, &value) < 0)
		return 0;

	while (1) {
		sleep(2);

		if (bpf_map_lookup_elem(fd, &key, &value) < 0) {
			printf("failed to lookup map: %s\n", strerror(errno));
			break;
		}

		diff = value - prev;
		prev = value;

		printf("pps for TCP SYN: %llu\n", diff/2);
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP reader program\n";
	int fd;
	struct config cfg = {
		.ifname = "ens192",
	};
	char pin_dir[128];

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	sprintf(pin_dir, "%s/%s", PIN_BASEDIR, cfg.ifname);

	if (verbose)
		printf("Prepare to read data from %s/%s map\n", pin_dir, "pkt_stat");

	fd = get_map_fd_and_check(pin_dir, "pkt_stat");
	if (fd < 0)
		return 0;

	if (cfg.flags & FLAG_SHOW_STATISTICS) {
		lookup_elem_and_show(fd);
	} else {
		lookup_elem_and_statistic(fd);
	}

	return 0;
}
