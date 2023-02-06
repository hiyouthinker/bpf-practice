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

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"show",        no_argument,	NULL, 's' },
	 "show statistics"},

	{{"debug",       no_argument,		NULL, 'D' },
	 "enable debug mode"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"saddr",       required_argument,	NULL, 4 },
	 "source ip address", "<IP>[/<MASK>]"},

	{{"daddr",       required_argument,	NULL, 5 },
	 "destination ip address", "<IP>[/<MASK>]"},

	{{"sport",       required_argument,	NULL, 6 },
	 "source port", "<PORT>"},

	{{"dport",       required_argument,	NULL, 7 },
	 "destination port", "<PORT>"},

	{{"proto",       required_argument,	NULL, 8 },
	 "tcp or udp", "<L4 Protocol>"},

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

static int get_map_fd_and_check(const char *pin_dir, char *map_name, struct bpf_map_info *exp)
{
	int fd;
	struct bpf_map_info info = {0};


	fd = open_bpf_map_file(pin_dir, map_name, &info);
	if (fd < 0) {
		return -1;
	}

	if (check_map_fd_info(&info, exp)) {
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

		printf("packets: %llu, pps: %llu\n", value, diff/2);
	}

	return 0;
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP reader program\n";
	struct bpf_map_info exp1 = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u64),
		.max_entries = __STAT_PKT_MAX,
	};
	struct bpf_map_info exp2 = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(struct filter),
		.max_entries = 1,
	};
	int stat_fd, filter_fd = -1;
	struct config cfg = {
		.ifname = "ens192",
	};
	char pin_dir[128];
	struct filter filter = {};

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	sprintf(pin_dir, "%s/%s", PIN_BASEDIR, cfg.ifname);

	if (verbose)
		printf("Prepare to read data from %s/%s map\n", pin_dir, "pkt_stat");

	stat_fd = get_map_fd_and_check(pin_dir, "pkt_stat", &exp1);
	if (stat_fd < 0)
		goto done;

	if (cfg.flags & FLAG_SHOW_STATISTICS) {
		lookup_elem_and_show(stat_fd);
	} else {
		__u32 key = 0;

		filter.flow.src = cfg.saddr;
		filter.src_mask = cfg.smask;
		filter.flow.dst = cfg.daddr;
		filter.dst_mask = cfg.dmask;
		filter.flow.port16[0] = cfg.sport;
		filter.flow.port16[1] = cfg.dport;
		filter.flow.proto = cfg.proto;

		filter_fd = get_map_fd_and_check(pin_dir, "pkt_filter", &exp2);

		if (cfg.debug) {
			printf("%d " NIPQUAD_FMT ":%d => " NIPQUAD_FMT ":%d " NIPQUAD_FMT " - " NIPQUAD_FMT "\n",
				cfg.proto,
				NIPQUAD(cfg.saddr), ntohs(cfg.sport),
				NIPQUAD(cfg.daddr), ntohs(cfg.dport),
				NIPQUAD(cfg.smask), NIPQUAD(cfg.dmask));
		}

		if (bpf_map_update_elem(filter_fd, &key, &filter, 0)) {
			fprintf(stderr, "Failed to update pkt_filter maps: %s\n", strerror(errno));
			goto done;
		}

		lookup_elem_and_statistic(stat_fd);
	}

done:
	if (stat_fd >= 0)
		close(stat_fd);
	if (filter_fd >= 0)
		close(filter_fd);

	return 0;
}
