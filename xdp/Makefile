XDP_TARGETS  := forward/forward_prog
XDP_TARGETS  += lpm/lpm_prog
XDP_TARGETS  += test/test_prog
XDP_TARGETS  += statistics/packet_stat_prog
XDP_TARGETS  += iter/bpf_iter_bpf_array_map
XDP_TARGETS  += iter/bpf_iter_bpf_hash_map

USER_TARGETS := common/common_loader
USER_TARGETS += common/common_reader
USER_TARGETS += forward/forward_loader
USER_TARGETS += forward/forward_reader
USER_TARGETS += lpm/lpm_loader
USER_TARGETS += lpm/lpm_reader
USER_TARGETS += iter/bpf_iter_array_map_user
USER_TARGETS += iter/bpf_iter_hash_map_user

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk

# bpftool gen object iter/bpf_iter_bpf_array_map.link.o iter/bpf_iter_bpf_array_map.o
# bpftool gen skeleton iter/bpf_iter_bpf_array_map.link.o name bpf_iter_bpf_array_map > iter/bpf_iter_bpf_array_map.skel.h

# bpftool gen object iter/bpf_iter_bpf_hash_map.link.o iter/bpf_iter_bpf_hash_map.o
# bpftool gen skeleton iter/bpf_iter_bpf_hash_map.link.o name bpf_iter_bpf_hash_map > iter/bpf_iter_bpf_hash_map.skel.h
