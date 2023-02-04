XDP_TARGETS  := forward/forward_prog
XDP_TARGETS  += lpm/lpm_prog
XDP_TARGETS  += test/test_prog
XDP_TARGETS  += statistics/packet_stat_prog

USER_TARGETS := common/common_loader
USER_TARGETS += forward/forward_loader
USER_TARGETS += forward/forward_reader
USER_TARGETS += lpm/lpm_loader
USER_TARGETS += lpm/lpm_reader

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk
