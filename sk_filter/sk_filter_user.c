/*
 * Author: BigBro / 2021.05 - 2024
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "common_kern_user.h"
#include "../common/common_user_bpf.h"

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-f\tfile path (default: sk_filter_kern.o)\n");
	printf("\t-l\tlocal ip\n");
	printf("\t-p\tlocal port\n");
	printf("\t-r\tThe ratio of first program (x/10, pls input the x, x is [0 and 10]\n");
	exit(0);
}

int main(int argc, char **argv)
{
	char *filename = "sk_filter_kern.o";
	int opt, port, ratio = 5;
	int fd, one = 1;
	struct sockaddr_in addr;
	struct bpf_object *obj;
	int prog_fd, map_fd, i;
	char *local_ip = "0.0.0.0";
	__u32 key;
	__u64 value1, value2, prev, diff;

	while ((opt = getopt(argc, argv, "f:l:p:r:h")) != -1) {
		switch (opt) {
		case 'f':
			filename = optarg;
			break;
		case 'l':
			local_ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			if (port <= 0)
				port = 80;
			break;
		case 'r':
			ratio = atoi(optarg);
			if (ratio < 0 || ratio > 10)
				usage(argv[0]);
			break;
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
	}

	obj = load_bpf_object_file(filename, NULL, NULL);
	if (!obj) {
		exit(0);
	}

	map_fd = find_map_fd_by_name(obj, "my_map");
	if (map_fd < 0) {
		printf("find_map_fd_by_name error...\n");
		exit(0);
	}

	prog_fd = find_prog_fd_by_name(obj, "bpf_reuseport_select");
	if (prog_fd < 0) {
		printf("find_prog_fd_by_name error\n");
		exit(0);
	}

	for (i = 0; i < MY_MAP_REUSEPORT_SIZE; i++) {
		int value = 1;

		if (i < ratio)
			value = 0;

		bpf_map_update_elem(map_fd, &i, &value, BPF_ANY);
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("socket: %s\n", strerror(errno));
		exit(0);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))) {
		printf("setsockopt: %s\n", strerror(errno));
		exit(0);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(local_ip);
	addr.sin_port = htons(port);

	printf("Prepare to bind to %s:%d\n", local_ip, port);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		printf("bind: %s\n", strerror(errno));
		exit(0);
	}

	if (listen(fd, 20)) {
		printf("listen: %s\n", strerror(errno));
		exit(0);
	}

	if(setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) < 0) {
		printf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %s\n", strerror(errno));
	}

	printf("reuse / bind / listen / attach_ebpf success!\n");

	key = MY_MAP_STATS_SOCKET1;
	bpf_map_lookup_elem(map_fd, &key, &value1);

	key = MY_MAP_STATS_SOCKET2;
	bpf_map_lookup_elem(map_fd, &key, &value2);

	prev = value1 + value2;

	while (1) {
		__u64 tmp;

		key = MY_MAP_STATS_SOCKET1;
		bpf_map_lookup_elem(map_fd, &key, &value1);

		key = MY_MAP_STATS_SOCKET2;
		bpf_map_lookup_elem(map_fd, &key, &value2);

		tmp = value1 + value2;
		diff = tmp - prev;
		prev = tmp;

		printf("packet: %llu(%llu + %llu), cps: %llu\n", tmp, value1, value2, diff/2);
		sleep(2);
	}

	close(fd);
	return 0;
}
