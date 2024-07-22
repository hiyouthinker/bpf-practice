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
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>		/* for htonl */
#include <linux/err.h>	/* for IS_ERR_OR_NULL */

#include "../../common/common_params.h"
#include "../../common/common_user_bpf.h"
#include "../../common/common_user_bpf_xdp.h"
#include "../include/common_structs.h"

static int inner_map_fd[MAX_SUPPORTED_CPUS];

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"reuse-maps",  no_argument,		NULL, 'M' },
	 "Reuse pinned maps"},

	{{"use-map-in-map",  no_argument,	NULL, 'm' },
	 "use map in map"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"debug",       no_argument,		NULL, 'D' },
	 "enable debug mode"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{"progname",    required_argument,	NULL,  14  },
	 "Load program by name", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int my_print(enum libbpf_print_level level, const char *format,
		     va_list args)
{
	return vfprintf(stderr, format, args);
}

static int map_in_map_inner_create(struct bpf_object *obj)
{
	struct bpf_map *outer_map;
	int cpu_num = libbpf_num_possible_cpus();
	int cpu = 0, err;

	if (cpu_num < 0) {
		fprintf(stderr, "ERROR: Failed to get the cpu number\n");
		return -1;
	}
	if (cpu_num > MAX_SUPPORTED_CPUS) {
		fprintf(stderr, "ERROR: cpu number %d > %d, please correct MAX_SUPPORTED_CPUSr\n"
			, cpu_num, MAX_SUPPORTED_CPUS);
		return -1;
	}

	for (cpu = 0; cpu < cpu_num; cpu++) {
		inner_map_fd[cpu] = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, SESSION_NAT_INNER_MAP_NAME
							, sizeof(struct flow_key), sizeof(struct flow_value), SESS_NAT_TABLE_PERCPU_CAPACITY, NULL);
		if (inner_map_fd[cpu] < 0) {
			fprintf(stderr, "ERROR: creating map %s%d failed (%s)\n", SESSION_NAT_INNER_MAP_NAME, cpu, strerror(errno));
			goto error;
		}
	}

	outer_map = bpf_object__find_map_by_name(obj, "session_nat_table_outer");
	if (IS_ERR_OR_NULL(outer_map)) {
		printf("Failed to get map %s\n", "session_nat_table_outer");
		goto error;
	}
	err = bpf_map__set_inner_map_fd(outer_map, inner_map_fd[0]);
	if (err) {
		printf("Failed to set inner_map_fd for array of maps\n");
		goto error;
	}
	return 0;
error:
	while (cpu--) {
		close(inner_map_fd[cpu]);
	}
	return -1;
}

static int map_in_map_outer_update(struct bpf_object *obj)
{
	int outer_map_fd, err;
	int cpu_num = libbpf_num_possible_cpus(), cpu;

	outer_map_fd = bpf_object__find_map_fd_by_name(obj, "session_nat_table_outer");
	if (outer_map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "session_nat_table_outer");
		return -1;
	}

	for (cpu = 0; cpu < cpu_num; cpu++) {
		err = bpf_map_update_elem(outer_map_fd, &cpu, &inner_map_fd[cpu], 0);
		if (err) {
			fprintf(stderr, "Failed to update array of maps\n");
			return -1;
		} else {
			printf("The fd of %s%d in %s is %d\n"
				, SESSION_NAT_INNER_MAP_NAME, cpu, "session_nat_table_outer", inner_map_fd[cpu]);
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const char *__doc__ = "XDP loader\n"
		" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";
	struct bpf_object *bpf_obj;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex = {
			[0 ... INTERFACE_NUM_MAX - 1] = -1,
		},
		.do_unload = false,
	};

	strcpy(cfg.filename, "test_prog.o");
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (verbose) {
		libbpf_set_print(my_print);
	}

	if (cfg.ifindex[0] == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return 0;
	}

	if (cfg.do_unload) {
		int i = 0;

		for (i = 0; i < INTERFACE_NUM_MAX; i++) {
			if (cfg.ifindex[i] <= 0) {
				break;
			}
			bpf_xdp_detach(cfg.ifindex[i], cfg.xdp_flags, NULL);
		}

		return 0;
	}

	if (snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s/%s", PIN_BASEDIR, cfg.ifname) < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return 0;
	}

	if (cfg.flags & FLAG_USE_MAP_IN_MAP)
		bpf_obj = load_bpf_and_xdp_attach(&cfg, map_in_map_inner_create, map_in_map_outer_update);
	else
		bpf_obj = load_bpf_and_xdp_attach(&cfg, NULL, NULL);

	if (!bpf_obj)
		return 0;

	if (!cfg.reuse_maps) {
		if (pin_maps_in_bpf_object(bpf_obj, &cfg)) {
			fprintf(stderr, "ERR: pinning maps\n");
			return 0;
		}
	}

	return 0;
}
