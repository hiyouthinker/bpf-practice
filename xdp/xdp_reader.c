/*
 * BigBro/2022
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

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int get_map_fd_and_check(const char *pin_dir, char *map_name)
{
	int fd;
	struct bpf_map_info info = {0};
	struct bpf_map_info exp = {
   		.type = BPF_MAP_TYPE_LPM_TRIE,
    	.key_size = sizeof(struct lpm_key),
    	.value_size = sizeof(__u32),
    	.max_entries = 1024,
	};

	fd = open_bpf_map_file(pin_dir, map_name, &info);
	if (fd < 0) {
		exit(-1);
	}

	if (check_map_fd_info(&info, &exp)) {
		fprintf(stderr, "ERR: map %s via FD not compatible\n", map_name);
		exit(-1);
	}

	if (verbose) {
		printf(" - BPF map (bpf_map_type:%d) id: %d, name: %s,"
			   " key_size: %d, value_size: %d, max_entries: %d\n",
			   info.type, info.id, info.name,
			   info.key_size, info.value_size, info.max_entries);
	}

	return fd;
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP reader program\n";
	int fd;
	struct lpm_key key, *prev_keyp = NULL;
	__u32 value;
	struct config cfg = {
		.ifname = "ens192"
	};
	char pin_dir[128];

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (verbose)
		printf("\nReading data from BPF map\n");

	sprintf(pin_dir, "%s/%s", PIN_BASEDIR, cfg.ifname);
	fd = get_map_fd_and_check(pin_dir, "ip_lpm_map");

	while (1) {
		if (bpf_map_get_next_key(fd, prev_keyp, &key)) {
			/* ENOENT: iterated over all buckets and all elements */
			if (errno != ENOENT)
				fprintf(stderr, "ERR: bpf_map_get_next_key failed, error: %s@%s\n", strerror(errno), "ip_lpm_map");
			break;
		}

		if ((bpf_map_lookup_elem(fd, &key, &value)) != 0) {
			fprintf(stderr, "ERR: bpf_map_lookup_elem failed\n");
			continue;
		}

		printf(NIPQUAD_FMT "/%d: " NIPQUAD_FMT "\n",
			NIPQUAD(key.addr.saddr[0]), key.prefixlen - 64, NIPQUAD(value));

		prev_keyp = &key;
	}

	sleep(100);
	return 0;
}
