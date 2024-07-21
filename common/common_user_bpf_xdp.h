#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg, int (*create)(struct bpf_object *obj), int (*update)(struct bpf_object *obj));

#endif /* __COMMON_USER_BPF_XDP_H */
