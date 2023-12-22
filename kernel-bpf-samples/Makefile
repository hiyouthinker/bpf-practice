XDP_TARGETS  := xdp_rxq_info_kern
XDP_TARGETS  += napi_monitor_kern

USER_TARGETS := xdp_rxq_info_user
# USER_TARGETS += xdp_xxx_user

LIBBPF_DIR = ../libbpf/src/
COMMON_DIR = ../common/

include $(COMMON_DIR)/common.mk

EXTRA_CFLAGS += -D __BIGBRO__

all:
	mv xdp_rxq_info_user xdp_rxq_info
