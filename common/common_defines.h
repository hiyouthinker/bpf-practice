#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>

#define __BIGBRO__

#ifdef __BIGBRO__
#define PIN_BASEDIR		"/sys/fs/bpf"
#define FLAG_USE_MAP_IN_MAP  0x01
#define FLAG_SHOW_STATISTICS 0x02

#define INTERFACE_NUM_MAX 4

enum {
	SHOW_FLAG_TCP_FLAG = 1,
	SHOW_FLAG_TCP_SYN_FLAG,
	SHOW_FLAG_TCP_SYNACK_FLAG,
	SHOW_FLAG_TCP_FIN_FLAG,
	SHOW_FLAG_UDP_FLAG,
};
#endif

struct config {
	__u32 xdp_flags;
#ifdef __BIGBRO__
	int ifindex[INTERFACE_NUM_MAX];
#else
	int ifindex;
#endif
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
#ifdef __BIGBRO__
	char progname[32];
#endif
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
#ifdef __BIGBRO__
	__u8 debug;
	char ips[128];
	int id;
	__u8 flags;

	/* for filter */
	__be32 saddr;
	__be32 smask;
	__be32 daddr;
	__be32 dmask;
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 show_flags;
#endif
};

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
