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
#include "../include/forward_structs.h"

#define ARRAY_ELEM_NUM(array) (sizeof(array) / sizeof((array)[0]))
#define IPv4(a,b,c,d) ((__u32)(((a) & 0xff) << 24) | \
					   (((b) & 0xff) << 16) | \
					   (((c) & 0xff) << 8)  | \
					   ((d) & 0xff))

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

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"debug",       no_argument,		NULL, 'D' },
	 "enable debug mode"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

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

static int map_in_map_inner_unpin(struct config *cfg)
{
	char map_path[512];
	int cpu_num = libbpf_num_possible_cpus();
	int cpu = cpu_num, err = 0, len;

	for (cpu = 0; cpu < cpu_num; cpu++) {
		len = snprintf(map_path, sizeof(map_path), "%s/%s_cpu%d", cfg->pin_dir, SESSION_NAT_INNER_MAP_NAME, cpu);
		if (len < 0)
			return -EINVAL;
		if (access(map_path, F_OK ) < 0)
			continue;
		if (unlink(map_path) < 0) {
			fprintf(stderr, "ERROR: unlink %s failed, error (%d): %s\n"
				, map_path, errno, strerror(errno));
			err = -errno;
			break;
		}
	}
	return err;
}

static int map_in_map_inner_pin(struct config *cfg)
{
	char map_path[512];
	int cpu_num = libbpf_num_possible_cpus();
	int cpu = 0, err, len;

	if (map_in_map_inner_unpin(cfg) < 0) {
		fprintf(stderr, "ERROR: unlink map failed, error (%d): %s\n"
				, errno, strerror(errno));
		return -1;
	}

	for (cpu = 0; cpu < cpu_num; cpu++) {
		len = snprintf(map_path, sizeof(map_path), "%s/%s_cpu%d", cfg->pin_dir, SESSION_NAT_INNER_MAP_NAME, cpu);
		if (len < 0) {
			err = -EINVAL;
			goto unpin;
		}
		err = bpf_obj_pin(inner_map_fd[cpu], map_path);
		if (err) {
			fprintf(stderr, "ERROR: pin %s failed, error (%d): %s\n"
				, map_path, errno, strerror(errno));
			goto unpin;
		}
	}
	return 0;
unpin:
	while (cpu--) {
		len = snprintf(map_path, sizeof(map_path), "%s/%s_cpu%d", cfg->pin_dir, SESSION_NAT_INNER_MAP_NAME, cpu);
		if (len < 0)
			return -EINVAL;
		if (unlink(map_path) < 0) {
			fprintf(stderr, "ERROR: unlink %s failed, error (%d): %s\n"
				, map_path, errno, strerror(errno));
			err = -errno;
			break;
		}
	}
	return err;
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

static int snat_ip_pool_init(struct bpf_object *obj)
{
	int map_fd, err, index;
	__u32 snat_ip[] = {
#if 0
		htonl(IPv4(172,50,2,73)),
		htonl(IPv4(172,50,2,173)),
		htonl(IPv4(172,50,2,174)),
		htonl(IPv4(172,50,2,175)),
#else
		htonl(IPv4(172,51,2,72)),
		htonl(IPv4(172,51,2,172)),
		htonl(IPv4(172,51,2,173)),
		htonl(IPv4(172,51,2,174)),
#endif
	};

	map_fd = bpf_object__find_map_fd_by_name(obj, "snat_ip_pool");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "snat_ip_pool");
		return -1;
	}

	for (index = 0; index < SNAT_IP_POOL_CAPACITY; index++) {
		err = bpf_map_update_elem(map_fd, &index, &snat_ip[index], 0);
		if (err) {
			fprintf(stderr, "Failed to update snat_ip_pool maps\n");
			return -1;
		}
	}
	return 0;
}

static int vip_vport_policy_init(struct bpf_object *obj)
{
	int map_fd, err, i;
	struct vip_vport_policy_key_s front[] = {
		{htonl(IPv4(172,50,10,74)), htons(8000)},
		{htonl(IPv4(172,50,10,75)), htons(8080)},
		{htonl(IPv4(172,51,10,74)), htons(8000)},
		{htonl(IPv4(172,51,10,75)), htons(8080)},
		{htonl(IPv4(172,51,10,76)), htons(9000)},
	};
	struct vip_vport_policy_value_s backend[] = {
		{
			{htonl(IPv4(172,50,10,91)), htonl(IPv4(172,50,10,92))}, 2, htons(3456)
		},
		{
			{htonl(IPv4(172,50,10,93)), htonl(IPv4(172,50,10,94))}, 2, htons(3456)
		},
		{
			{htonl(IPv4(172,51,10,91)), htonl(IPv4(172,51,10,92))}, 2, htons(3456)
		},
		{
			{htonl(IPv4(172,51,10,93)), htonl(IPv4(172,51,10,94))}, 2, htons(3456)
		},
		{
			{htonl(IPv4(172,51,2,74)), htonl(IPv4(172,51,2,74))}, 2, htons(3456)
		},
	};

	if (ARRAY_ELEM_NUM(front) != ARRAY_ELEM_NUM(backend)) {
		fprintf(stderr, "ERROR: key and value do not match\n");
		return -1;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "vip_vport_policy");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "vip_vport_policy");
		return -1;
	}

	for (i = 0; i < ARRAY_ELEM_NUM(front); i++) {
		err = bpf_map_update_elem(map_fd, &front[i], &backend[i], 0);
		if (err) {
			fprintf(stderr, "Failed to update vip_vport_policy maps\n");
			return -1;
		}
	}
	return 0;
}

static inline void
convert_rss_key(const __u32 *origin, __u32 *target, int len)
{
	int i;

	for (i = 0; i < (len >> 2); i++)
		target[i] = htonl(origin[i]);
}

static int rss_hash_key_init(struct bpf_object *obj)
{
	int map_fd, key  = 0;
#if 0
	struct rss_hash_key_s rss_key = {
		{
			0xcc, 0x0d, 0xed, 0x90, 0xc4, 0xf8, 0x81, 0xb5,
			0xab, 0x54, 0xf5, 0x1f, 0x7a, 0x99, 0xf0, 0x0c,
			0x9e, 0xf7, 0x5d, 0x76, 0x41, 0xfa, 0x1c, 0x21,
			0x9f, 0xf7, 0x83, 0x45, 0x51, 0x97, 0x96, 0x7d,
			0xdc, 0xca, 0x81, 0x0d, 0x8d, 0x4f, 0x76, 0x81,
			0xc1, 0xaf, 0x18, 0x35, 0x9d, 0xbf, 0x06, 0x21,
			0x62, 0xf7, 0xf5, 0x2d
		}
	};
#else
	struct rss_hash_key_s rss_key = {
		{
			0xfa, 0xe6, 0x51, 0x09, 0x1a, 0x1e, 0x32, 0xea,
			0x55, 0x63, 0x46, 0x4f, 0xc9, 0x2a, 0x1b, 0x9a,
			0xed, 0x63, 0x97, 0x90, 0x91, 0x23, 0x97, 0x03,
			0xec, 0x09, 0x37, 0x04, 0xe8, 0x3c, 0x19, 0xe2,
			0x68, 0xdf, 0x85, 0x88, 0xb0, 0xd6, 0x1d, 0x1a
		}
	};
#endif
	struct rss_hash_key_s rss_key_be;

	map_fd = bpf_object__find_map_fd_by_name(obj, "rss_hash_key");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "rss_hash_key");
		return -1;
	}
	convert_rss_key((uint32_t *)&rss_key, (__u32 *)rss_key_be.hash_key, ARRAY_ELEM_NUM(rss_key.hash_key));

	if (bpf_map_update_elem(map_fd, &key, &rss_key_be, 0) < 0) {
		fprintf(stderr, "Failed to update vip_vport_policy maps\n");
		return -1;
	}
	return 0;
}

static int smac_dmac_init(struct bpf_object *obj)
{
	int map_fd, key  = 0;
#if 0
	struct smac_dmac_s mac[] = {
		{0x9c, 0x69, 0xb4, 0x60, 0x35, 0x61},
		{0x68, 0x91, 0xd0, 0x61, 0x94, 0xca}
	};
#else
	struct smac_dmac_s mac[] = {
		{{0xa0, 0x36, 0x9f, 0xba, 0x20, 0x10}},
		{{0xa0, 0x36, 0x9f, 0xba, 0x1f, 0xcc}}
	};
#endif

	map_fd = bpf_object__find_map_fd_by_name(obj, "smac_dmac");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "smac_dmac");
		return -1;
	}

	for (key = 0; key < ARRAY_ELEM_NUM(mac); key++) {
		if (bpf_map_update_elem(map_fd, &key, &mac[key], 0) < 0) {
			fprintf(stderr, "Failed to update vip_vport_policy maps\n");
			return -1;
		}
	}
	return 0;
}

static int my_print(enum libbpf_print_level level, const char *format,
		     va_list args)
{
	return vfprintf(stderr, format, args);
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

	strcpy(cfg.filename, "xdp_prog_kern.o");
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
		bpf_xdp_detach(cfg.ifindex[0], cfg.xdp_flags, NULL);
		return 0;
	}

	if (snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s/%s", PIN_BASEDIR, cfg.ifname) < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return 0;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg, map_in_map_inner_create, map_in_map_outer_update);
	if (!bpf_obj)
		return 0;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex[0]);
	}

	if ((snat_ip_pool_init(bpf_obj) < 0)
		|| (vip_vport_policy_init(bpf_obj) < 0)
		|| (rss_hash_key_init(bpf_obj) < 0)
		|| (smac_dmac_init(bpf_obj) < 0))
		return 0;

	if (!cfg.reuse_maps) {
		int err1, err2;
		err1 = pin_maps_in_bpf_object(bpf_obj, &cfg);
		err2 = map_in_map_inner_pin(&cfg);
		if (err1 || err2) {
			fprintf(stderr, "ERR: pinning maps\n");
			return 0;
		}
	}

	return 0;
}
