#include <bpf/libbpf.h> /* bpf_get_link_xdp_id + bpf_set_link_xdp_id */
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

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int xdp_link_attach(int ifindex, __u32 flags, int prog_fd)
{
	return bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
}

int xdp_link_detach(int ifindex, __u32 flags, __u32 expected_prog_id)
{
	return bpf_xdp_detach(ifindex, flags, NULL);
}

static int reuse_maps(struct bpf_object *obj, const char *path)
{
	struct bpf_map *map;

	if (!obj)
		return -ENOENT;

	if (!path)
		return -EINVAL;

	bpf_object__for_each_map(map, obj) {
		int len, err;
		int pinned_map_fd;
		char buf[PATH_MAX];

		len = snprintf(buf, PATH_MAX, "%s/%s", path, bpf_map__name(map));
		if (len < 0) {
			return -EINVAL;
		} else if (len >= PATH_MAX) {
			return -ENAMETOOLONG;
		}

		pinned_map_fd = bpf_obj_get(buf);
		if (pinned_map_fd < 0) {
			if (strstr(buf, ".rodata")) {
				printf("Warning: .rodata does not need reuse\n");
				continue;
			}
			printf("failed to get %s\n", buf);
			return pinned_map_fd;
		}

		err = bpf_map__reuse_fd(map, pinned_map_fd);
		if (err)
			return err;
	}

	return 0;
}

struct bpf_object *load_bpf_object_file_reuse_maps(const char *file,
						   int ifindex,
						   const char *pin_dir)
{
	int err;
	struct bpf_object *obj;

	obj = bpf_object__open(file);
	if (!obj) {
		fprintf(stderr, "ERR: failed to open object %s\n", file);
		return NULL;
	}

	err = reuse_maps(obj, pin_dir);
	if (err) {
		fprintf(stderr, "ERR: failed to reuse maps for object %s, pin_dir=%s, error: %s\n",
				file, pin_dir, strerror(-err));
		return NULL;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			file, err, strerror(-err));
		return NULL;
	}

	return obj;
}

struct bpf_object *load_bpf_object_file(char *filename,
							int (*create)(struct bpf_object *obj),
							int (*update)(struct bpf_object *obj))
{
	struct bpf_object *obj;
	int err;

	if (!filename) {
		fprintf(stderr, "ERR: filename is null\n");
		return NULL;
	}

	obj = bpf_object__open(filename);
	if (IS_ERR_OR_NULL(obj)) {
		int err_num;

		if (!obj)
			err_num = ENOENT;
		else
			err_num = -(int)PTR_ERR(obj);

		fprintf(stderr, "ERR: opening BPF-OBJ file(%s) (%d): %s\n",
			filename, err_num, strerror(err_num));
		return NULL;
	}

	if (create) {
		if (create(obj) < 0)
			return NULL;
	}

	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	if (update) {
		if (update(obj) < 0)
			return NULL;
	}

	return obj;
}

struct bpf_program *bpf_object__find_program_by_title(const struct bpf_object *obj,
				  const char *title)
{
	struct bpf_program *pos;

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__section_name(pos) && !strcmp(bpf_program__section_name(pos), title))
			return pos;
	}
	return NULL;
}

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg,
						int (*create)(struct bpf_object *obj),
						int (*update)(struct bpf_object *obj))
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int err;

	/* If flags indicate hardware offload, supply ifindex */
	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
		offload_ifindex = cfg->ifindex[0];

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
	if (cfg->reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
							  offload_ifindex,
							  cfg->pin_dir);
	else
		bpf_obj = load_bpf_object_file(cfg->filename, create, update);

	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	if (cfg->progsec[0])
		/* Find a matching BPF prog section name */
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
	else
		/* Find the first program */
		bpf_prog = bpf_object__next_program(bpf_obj, NULL);

	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
		exit(EXIT_FAIL_BPF);
	}

	strncpy(cfg->progsec, bpf_program__section_name(bpf_prog), sizeof(cfg->progsec));

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
#ifdef __BIGBRO__
	{
		int i = 0, ifindex;

		for (i = 0; i < INTERFACE_NUM_MAX; i++) {
			ifindex = cfg->ifindex[i];
			if (ifindex <= 0) {
				break;
			}

			err = xdp_link_attach(ifindex, cfg->xdp_flags, prog_fd);
			if (err)
				exit(err);
		}
	}

#else
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
	if (err)
		exit(err);

#endif

	return bpf_obj;
}

int check_map_fd_info(const struct bpf_map_info *info,
		      const struct bpf_map_info *exp)
{
	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}

int open_bpf_map_file(const char *pin_dir,
		      const char *mapname, struct bpf_map_info *info)
{
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		fprintf(stderr, "ERR: constructing full mapname path\n");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file:%s err(%d):%s\n",
			filename, errno, strerror(errno));
		return fd;
	}

	if (info) {
		err = bpf_obj_get_info_by_fd(fd, info, &info_len);
		if (err) {
			fprintf(stderr, "ERR: %s() can't get info for %s - %s\n",
				__func__, filename, strerror(errno));
			return -EXIT_FAIL_BPF;
		}
	}

	return fd;
}

struct my_bpf_map {
	int fd;
	char *name;
};

static int change_map_name(void *ptr)
{
	struct my_bpf_map *map = ptr;
	char *p;

	p = strchr(map->name, '.');
	if (p)
		*p = '_';

	return 0;
}

int pin_maps_in_bpf_object(struct bpf_object *obj, struct config *cfg)
{
	int err;
	struct bpf_map *map;
	char buf[512];
	bool has_map;

	bpf_object__for_each_map(map, obj) {
		int len;

		change_map_name(map);

		len = snprintf(buf, sizeof(buf), "%s/%s", cfg->pin_dir, bpf_map__name(map));
		if (len < 0)
			return -EINVAL;
		else if (len >= sizeof(buf))
			return -ENAMETOOLONG;

		has_map = true;

		if (verbose)
			printf("Pin %s map to %s\n", bpf_map__name(map), cfg->pin_dir);

		if (access(buf, F_OK ) < 0)
			continue;
		if (unlink(buf) < 0) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", buf);
			return -1000;
		}
	}

	if (!has_map) {
		if (verbose)
			printf("No map\n");
		return 0;
	}

	err = bpf_object__pin_maps(obj, cfg->pin_dir);
	if (err)
		return -1001;

	return 0;
}
