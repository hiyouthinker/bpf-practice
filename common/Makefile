# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: common_params.o common_user_bpf.o common_user_bpf_xdp.o

CFLAGS := -g -Wall

LIBBPF_DIR = ../libbpf/src/
CFLAGS += -I$(LIBBPF_DIR)/build/usr/include/  -I../headers
# TODO: Do we need to make libbpf from this make file too?

common_params.o: common_params.c common_params.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_user_bpf.o: common_user_bpf.c common_user_bpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

common_user_bpf_xdp.o: common_user_bpf_xdp.c common_user_bpf_xdp.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
