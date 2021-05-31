static const char *__doc__ = "XDP stats program\n"
	" - Finding xdp_stats_map via --dev name info\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
/* Lesson#1: this prog does not need to #include <bpf/libbpf.h> as it only uses
 * the simple bpf-syscall wrappers, defined in libbpf #include<bpf/bpf.h>
 */

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

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};

struct stats_record {
	struct record stats[XDP_ACTION_MAX];
};

static void map_get_value_array(int fd, __u32 key, struct stats_common_s *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

static bool map_collect(int fd, __u32 key, struct stats_common_s *value)
{
	map_get_value_array(fd, key, value);
	return true;
}

static void stats_collect(int map_fd)
{
	__u32 key, i;
	struct stats_common_s value;

	for (i = 0; i < __STATS_SITE_MAX; i++) {
		key = STATS_SITE_KEY(i, 10, 0);
		map_collect(map_fd, key, &value);
		if (value.total_bytes)
			printf("IPv4: key: %u, value: %lu\n", key, value.total_bytes);
	}

	for (i = 0; i < __STATS_SITE_MAX; i++) {
		key = STATS_SITE_KEY(i, 10, 1);
		map_collect(map_fd, key, &value);
		if (value.total_bytes)
			printf("IPv6: key: %u, value: %lu\n", key, value.total_bytes);
	}
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	__u64 utime;

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	while (1) {
		utime = gettime();
		stats_collect(map_fd);
		utime = gettime() - utime;
	//	printf("interval:  %llu ns, %llu ms\n", utime, utime / 1000000);
		sleep(interval + 2);
	}
}

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	struct bpf_map_info info = { 0 };
	char pin_dir[PATH_MAX];
	int stats_map_fd;
	int interval = 2;
	int len;

	struct config cfg = {
		.ifindex   = -1,
		.do_unload = false,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Use the --dev name as subdir for finding pinned maps */
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	{
		int version_map_fd;
		int key = 0;
		char value[] = "Version: BigBro/0.1 - 2021 - testing";

		version_map_fd = open_bpf_map_file(pin_dir, "xdp_version", &info);
		if ((bpf_map_update_elem(version_map_fd, &key, value, 0)) != 0) {
			fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		}

		memset(value, 0, sizeof(value));

		if ((bpf_map_lookup_elem(version_map_fd, &key, value)) != 0) {
			fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		} else {
			printf("Version: %s\n", value);
		}
	}

	stats_map_fd = open_bpf_map_file(pin_dir, "xdp_test_map", &info);
	if (stats_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	stats_poll(stats_map_fd, info.type, interval);
	return EXIT_OK;
}
