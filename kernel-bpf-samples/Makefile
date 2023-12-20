# tprogs-y += xdp_rxq_info
# xdp_rxq_info-objs := xdp_rxq_info_user.o
# always-y += xdp_rxq_info_kern.o

XDP_TARGETS  := xdp_rxq_info_kern
# XDP_TARGETS  += xdp_xxx_kern

USER_TARGETS := xdp_rxq_info_user
# USER_TARGETS += xdp_xxx_user

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk

CFLAGS += -D __BIGBRO__