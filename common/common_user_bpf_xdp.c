#include <bpf/libbpf.h>
#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/if_link.h> /* Need XDP flags */
#include <linux/err.h>

#include "common_defines.h"
#include "common_user_bpf.h"

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg,
						int (*create)(struct bpf_object *obj),
						int (*update)(struct bpf_object *obj))
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int prog_fd = -1;
	int err;

	if (cfg->reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename, cfg->pin_dir);
	else
		bpf_obj = load_bpf_object_file(cfg->filename, create, update);

	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}

	if (cfg->progsec[0])
		/* Find a matching BPF prog section name */
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	else if (cfg->progname[0])
		bpf_prog = bpf_object__find_program_by_name(bpf_obj, cfg->progname);
	else
		/* Find the first program */
		bpf_prog = bpf_object__next_program(bpf_obj, NULL);

	if (!bpf_prog) {
		if (cfg->progsec[0])
			fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
		else if (cfg->progname[0])
			fprintf(stderr, "ERR: couldn't find a program by program name '%s'\n", cfg->progname);
		else
			fprintf(stderr, "ERR: couldn't find any program\n");
		exit(EXIT_FAIL_BPF);
	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

#ifdef __BIGBRO__
	{
		int i = 0, ifindex;

		for (i = 0; i < INTERFACE_NUM_MAX; i++) {
			ifindex = cfg->ifindex[i];
			if (ifindex <= 0) {
				break;
			}

			err = bpf_xdp_attach(ifindex, prog_fd, cfg->xdp_flags, NULL);
			if (err)
				exit(err);
		}
	}

#else
	err = bpf_xdp_attach(cfg->ifindex, prog_fd, cfg->xdp_flags, NULL);
	if (err)
		exit(err);
#endif

	return bpf_obj;
}
