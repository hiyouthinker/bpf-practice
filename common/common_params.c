#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>

#include <arpa/inet.h>		/* for struct in_addr */

#include "common_params.h"

int verbose = 1;

#define BUFSIZE 30

void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		if (long_options[i].required != required)
			continue;

		if (long_options[i].option.val > 64) /* ord('A') = 65 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);
		printf("  %s", long_options[i].help);
		printf("\n");
	}
}

void usage(const char *prog_name, const char *doc,
           const struct option_wrapper *long_options, bool full)
{
	printf("Usage: %s [options]\n", prog_name);

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	printf("\nDOCUMENTATION:\n %s\n", doc);
	printf("Required options:\n");
	_print_options(long_options, true);
	printf("\n");
	printf("Other options:\n");
	_print_options(long_options, false);
	printf("\n");
}

int option_wrappers_to_options(const struct option_wrapper *wrapper,
				struct option **options)
{
	int i, num;
	struct option *new_options;
	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	*options = new_options;
	return 0;
}

#ifdef __BIGBRO__
static int parse_ip_mask(char *input, __be32 *ip, __be32 *mask)
{
	char *p;
	char param[64];
	struct in_addr addr;

	strcpy(param, input);

	p = strchr(param, '/');
	if (p) {
		int num;
		__u32 one = 1;

		*p++ = '\0';

		num = atoi(p);
		if (num <= 0 || num > 32) {
			fprintf(stderr, "invalid mask of saddr: %s\n", p);
			return -1;
		}

		*mask = htonl(~((one << (32 - num)) - 1));
	} else {
		*mask = 0xffffffff;
	}

	if (!inet_aton(param, &addr)) {
		fprintf(stderr, "invalid ip: %s\n", param);
		return -1;
	}

	*ip = addr.s_addr;
	*ip &= *mask;

	return 0;
}
#endif

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        struct config *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	char *dest;
	int opt, num;

	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:r:L:R:ASNFUMQ:czpqDl:i:ms",
				  long_options, &longindex)) != -1) {
		switch (opt) {
#ifdef __BIGBRO__
		case 'd':
			char *str = optarg, *ifname;
			int i = 0;

			memset(cfg->ifindex, 0, sizeof(cfg->ifindex));

			while ((ifname = strsep(&str, ",")) != NULL) {
					if (strlen(ifname) >= IF_NAMESIZE) {
					fprintf(stderr, "ERR: --dev name too long\n");
					goto error;
				}

				if (i >= INTERFACE_NUM_MAX) {
					fprintf(stderr, "ERR: --dev name too many\n");
					goto error;
				}

				if (i == 0) {
					cfg->ifname = (char *)&cfg->ifname_buf;
					snprintf(cfg->ifname, IF_NAMESIZE, "%s", ifname);
				}

				cfg->ifindex[i] = if_nametoindex(ifname);
				if (cfg->ifindex[i] == 0) {
					fprintf(stderr,
						"ERR: --dev name unknown err(%d):%s\n",
						errno, strerror(errno));
					goto error;
				}

				i++;
			}
			break;
#else
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
#endif
		case 'r':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --redirect-dev name too long\n");
				goto error;
			}
			cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
			strncpy(cfg->redirect_ifname, optarg, IF_NAMESIZE);
			cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
			if (cfg->redirect_ifindex == 0) {
				fprintf(stderr,
						"ERR: --redirect-dev name unknown err(%d):%s\n",
						errno, strerror(errno));
				goto error;
			}
			break;
		case 'A':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			break;
		case 'S':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'N':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
			break;
		case 3: /* --offload-mode */
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_HW_MODE;   /* Set   flag */
			break;
		case 'F':
			cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'M':
			cfg->reuse_maps = true;
			break;
		case 'U':
			cfg->do_unload = true;
			break;
		case 'p':
			cfg->xsk_poll_mode = true;
			break;
		case 'q':
			verbose = false;
			break;
#ifdef __BIGBRO__
		case 'D':
			cfg->debug++;
			break;
		case 'l':
			strcpy(cfg->ips, optarg);
			break;
		case 'i':
			cfg->id = atoi(optarg);
			break;
		case 'm':
			cfg->flags |= FLAG_USE_MAP_IN_MAP;
			break;
		case 's':
			cfg->flags |= FLAG_SHOW_STATISTICS;
			break;
		case 4:
			if (parse_ip_mask(optarg, &cfg->saddr, &cfg->smask) < 0)
				goto error;
			break;
		case 5:
			if (parse_ip_mask(optarg, &cfg->daddr, &cfg->dmask) < 0)
				goto error;
			break;
		case 6:
			num = atoi(optarg);
			if (num <= 0 || num > 65535) {
				fprintf(stderr, "invalid sport: %s\n", optarg);
				goto error;
			}
			cfg->sport = htons(num);
			break;
		case 7:
			num = atoi(optarg);
			if (num <= 0 || num > 65535) {
				fprintf(stderr, "invalid dport: %s\n", optarg);
				goto error;
			}
			cfg->dport = htons(num);
			break;
		case 8:
			if (!strcasecmp(optarg, "tcp")) {
				cfg->proto = IPPROTO_TCP;
			} else if (!strcasecmp(optarg, "udp")) {
				cfg->proto = IPPROTO_UDP;
			} else {
				fprintf(stderr, "invalid protocol: %s\n", optarg);
				goto error;
			}
			break;
		case 9:
			cfg->show_flags = SHOW_FLAG_TCP_FLAG;
			break;
		case 10:
			cfg->show_flags = SHOW_FLAG_TCP_SYN_FLAG;
			break;
		case 11:
			cfg->show_flags = SHOW_FLAG_TCP_SYNACK_FLAG;
			break;
		case 12:
			cfg->show_flags = SHOW_FLAG_TCP_FIN_FLAG;
			break;
		case 13:
			cfg->show_flags = SHOW_FLAG_UDP_FLAG;
			break;
		case 14: /* --progname */
			dest  = (char *)&cfg->progname;
			strncpy(dest, optarg, sizeof(cfg->progname));
			break;
#endif
		case 'Q':
			cfg->xsk_if_queue = atoi(optarg);
			break;
		case 1: /* --filename */
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progsec */
			dest  = (char *)&cfg->progsec;
			strncpy(dest, optarg, sizeof(cfg->progsec));
			break;
		case 'L': /* --src-mac */
			dest  = (char *)&cfg->src_mac;
			strncpy(dest, optarg, sizeof(cfg->src_mac));
			break;
		case 'R': /* --dest-mac */
			dest  = (char *)&cfg->dest_mac;
			strncpy(dest, optarg, sizeof(cfg->dest_mac));
		case 'c':
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'z':
			cfg->xsk_bind_flags &= XDP_COPY;
			cfg->xsk_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'h':
			full_help = true;
			/* fall-through */
		error:
		default:
			usage(argv[0], doc, options_wrapper, full_help);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	free(long_options);
}
