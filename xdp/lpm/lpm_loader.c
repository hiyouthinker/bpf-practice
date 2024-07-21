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
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>		/* for htonl */

#include "../../common/common_params.h"
#include "../../common/common_user_bpf.h"
#include "../../common/common_user_bpf_xdp.h"
#include "../include/lpm_structs.h"

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

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"debug",       no_argument,		NULL, 'D' },
	 "enable debug mode"},

	{{"lpm",	required_argument,		NULL, 'l' },
	 "ip: 1.1.1.1,2.2.2.0/24"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int my_print(enum libbpf_print_level level, const char *format,
		     va_list args)
{
	return vfprintf(stderr, format, args);
}

static int load_lpm_map(struct bpf_object *obj, struct config *cfg, __u64 app_id)
{
	int fd;
	struct lpm_key key = {0};
	__u32 value;
	char *ips = cfg->ips;

	if (!ips)
		return -1;

	if (cfg->debug)
		printf("ips: [%s]\n", ips);

	if (!*ips)
		return 0;

	fd = bpf_object__find_map_fd_by_name(obj, "ip_lpm_map");
	if (fd < 0) {
		fprintf(stderr, "ERROR: finding a map by name %s in obj file failed\n", "ip_lpm_map");
		return -1;
	}

	while (1) {
		char *p, *next = NULL;
		struct in_addr addr;
		int mask = 32;

		p = strchr(ips, ',');
		if (p) {
			*p = 0;
			next = p + 1;
		}

		p = strchr(ips, '/');
		if (p) {
			*p = 0;
			p++;
			mask = atoi(p);
			if (mask <= 0 || mask > 32) {
				fprintf(stderr, "invalid mask: %s\n", p);
				return -1;
			}
		}
		if (!inet_aton(ips, &addr)) {
			fprintf(stderr, "invalid addr: %s\n", ips);
			return -1;
		}

		if (cfg->debug) {
			printf("ip/mask: %s/%d\n", ips, mask);
		}

		key.prefixlen = 64 + mask;
		key.app_id_lo = app_id & 0xffffffff;
		key.app_id_hi = app_id >> 32;
		key.addr.saddr[0] = addr.s_addr;

		value = addr.s_addr;

		if (bpf_map_update_elem(fd, &key, &value, 0) < 0) {
			fprintf(stderr, "failed to update map: %s\n", strerror(errno));
			return -1;
		}

		value = 0;
		if (bpf_map_lookup_elem(fd, &key, &value) < 0) {
			fprintf(stderr, "failed to lookup map: %s\n", strerror(errno));
			return -1;
		}

		if (cfg->debug) {
			struct in_addr in;

			in.s_addr = key.addr.saddr[0];
			printf("key: %s, ", inet_ntoa(in));

			in.s_addr = value;
			printf("value: %s\n", inet_ntoa(in));
		}

		ips = next;
		if (!next || !*next)
			break;
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

	strcpy(cfg.filename, "lpm_prog.o");
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
			if (cfg.ifname[i] <= 0) {
				break;
			}
			bpf_xdp_detach(cfg.ifindex[i], cfg.xdp_flags, NULL);
		}

		return 0;
	}

	bpf_obj = load_bpf_and_xdp_attach(&cfg, NULL, NULL);
	if (!bpf_obj)
		return 0;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex[0]);
	}

	if (cfg.ips[0]) {
		if (load_lpm_map(bpf_obj, &cfg, 1) < 0)
			return 0;
	}

	if (snprintf(cfg.pin_dir, sizeof(cfg.pin_dir), "%s/%s", PIN_BASEDIR, cfg.ifname) < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return 0;
	}

	if (pin_maps_in_bpf_object(bpf_obj, &cfg)) {
		fprintf(stderr, "ERR: pinning maps\n");
	}

	return 0;
}
