#ifndef __COMMON_USER_BPF_H
#define __COMMON_USER_BPF_H

struct config;

struct bpf_object *load_bpf_object_file_reuse_maps(const char *file, const char *pin_dir);

struct bpf_object *load_bpf_object_file(const char *filename, int (*create)(struct bpf_object *obj), int (*update)(struct bpf_object *obj));

struct bpf_program *bpf_object__find_program_by_title(const struct bpf_object *obj, const char *title);

int check_map_fd_info(const struct bpf_map_info *info, const struct bpf_map_info *exp);

int open_bpf_map_file(const char *pin_dir, const char *mapname, struct bpf_map_info *info);

int pin_maps_in_bpf_object(struct bpf_object *obj, struct config *cfg);

#endif
