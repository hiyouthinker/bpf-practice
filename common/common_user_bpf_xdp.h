/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex);
struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg
	, int (*create)(struct bpf_object *obj), int (*update)(struct bpf_object *obj));

int check_map_fd_info(const struct bpf_map_info *info,
                      const struct bpf_map_info *exp);

int open_bpf_map_file(const char *pin_dir,
		      const char *mapname,
		      struct bpf_map_info *info);

int pin_maps_in_bpf_object(struct bpf_object *obj, struct config *cfg);

#endif /* __COMMON_USER_BPF_XDP_H */
