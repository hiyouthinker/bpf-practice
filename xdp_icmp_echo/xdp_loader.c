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

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "structs_kern_user.h"

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

	{{"verbose",	no_argument,		NULL, 'v' },
		 "set level to debug"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int pin_maps_in_bpf_object(struct bpf_object *obj, struct config *cfg)
{
	int err;
	struct bpf_map *map;
	char buf[512];

	bpf_object__for_each_map(map, obj) {
		int len = snprintf(buf, sizeof(buf), "%s/%s", cfg->pin_dir, bpf_map__name(map));
		if (len < 0)
			return -EINVAL;
		else if (len >= sizeof(buf))
			return -ENAMETOOLONG;
		if (access(buf, F_OK ) < 0)
			continue;
		if (unlink(buf) < 0) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", buf);
			return EXIT_FAIL_BPF;
		}
	}

	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	err = bpf_object__pin_maps(obj, cfg->pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
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
		inner_map_fd[cpu] = bpf_create_map_name(BPF_MAP_TYPE_LRU_HASH, SESSION_NAT_INNER_MAP_NAME
							, sizeof(struct flow_key), sizeof(struct flow_value), SESS_NAT_TABLE_PERCPU_CAPACITY, 0);
		if (inner_map_fd[cpu] < 0) {
			fprintf(stderr, "ERROR: creating map %s failed\n", SESSION_NAT_INNER_MAP_NAME);
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
	__u32 snat_ip[4] = {htonl(0xAC320249), htonl(0xAC3202ad), htonl(0xAC3202ae), htonl(0xAC3202af)};

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
	int map_fd, err;
	struct vip_vport_policy_key_s key;
	struct vip_vport_policy_value_s value;

	map_fd = bpf_object__find_map_fd_by_name(obj, "vpi_vport_policy");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "vpi_vport_policy");
		return -1;
	}

	memset(&key, 0, sizeof(key));
	key.vip = htonl(0xAC320a4a);
	key.vport = htons(8000);
	memset(&value, 0, sizeof(value));
	value.bip[0] = htonl(0xAC320a5b);
	value.bip[1] = htonl(0xAC320a5c);
	value.bip_num = 2;
	value.bport = htons(3456);

	err = bpf_map_update_elem(map_fd, &key, &value, 0);
	if (err) {
		fprintf(stderr, "Failed to update vpi_vport_policy maps\n");
		return -1;
	}

	memset(&key, 0, sizeof(key));
	key.vip = htonl(0xAC320a4b);
	key.vport = htons(8080);
	memset(&value, 0, sizeof(value));
	value.bip[0] = htonl(0xAC320a5d);
	value.bip[1] = htonl(0xAC320a5e);
	value.bip_num = 2;
	value.bport = htons(3456);
	err = bpf_map_update_elem(map_fd, &key, &value, 0);
	if (err) {
		fprintf(stderr, "Failed to update vpi_vport_policy maps\n");
		return -1;
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
	int len;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

	strcpy(cfg.filename, "xdp_prog_kern.o");
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.verbose) {
		libbpf_set_print(my_print);
	}

	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}

	len = snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s/%s", PIN_BASEDIR, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg, map_in_map_inner_create, map_in_map_outer_update);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	if ((snat_ip_pool_init(bpf_obj) < 0)
		|| (vip_vport_policy_init(bpf_obj) < 0))
		return EXIT_FAIL_BPF;

	if (!cfg.reuse_maps) {
		int err1, err2;
		err1 = pin_maps_in_bpf_object(bpf_obj, &cfg);
		err2 = map_in_map_inner_pin(&cfg);
		if (err1 || err2) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err1;
		}
	}
	return EXIT_OK;
}
