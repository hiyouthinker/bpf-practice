/*
 * Author: BigBro / 2021.05
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

static int __find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* Lesson#3: bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
	if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-f\tfull path of program\n");
	printf("\t-p\tlocal IP\n");
	printf("\t-r\tThe proportion of first program (x/10, pls input the x, x is [0 and 10]\n");
	exit(0);
}

int main(int argc, char **argv)
{
	char *filename = "sk_filter_kern.o";
	int opt, port, proportion;
	int fd, one = 1;
	struct sockaddr_in addr;
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_SOCKET_FILTER,
	};
	struct bpf_object *obj;
	int prog_fd, map_fd, i;
	char *local_ip = "0.0.0.0";

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
			proportion = atoi(optarg);
			if (proportion < 0 || proportion > 10)
				usage(argv[0]);
			break;
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
	}

	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;
	if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		exit(0);
	}

	map_fd = __find_map_fd(obj, "my_map");
	if (map_fd < 0) {
		printf("find_map_fd error\n");
		exit(0);
	}

	for (i = 0; i < MY_MAP_REUSEPORT_SIZE; i++) {
		int value = 1;

		if (i < proportion)
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

	if (listen(fd, 5)) {
		printf("listen: %s\n", strerror(errno));
		exit(0);
	}

	if(setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) < 0) {
		printf("setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: %s\n", strerror(errno));
	}
	close(fd);
	printf("reuse / bind / listen / attach_ebpf success!\n");

	while (1) {
		int key, value1, value2, value3;

		key = MY_MAP_STATS_SUCCESS_FIRST;
		bpf_map_lookup_elem(map_fd, &key, &value1);

		key = MY_MAP_STATS_SUCCESS_SECOND;
		bpf_map_lookup_elem(map_fd, &key, &value2);

		key = MY_MAP_STATS_FAILURE;
		bpf_map_lookup_elem(map_fd, &key, &value3);

		printf("success: %d/%d, failure: %d\n", value1, value2, value3);
		sleep(1);
	}
	return 0;
}
