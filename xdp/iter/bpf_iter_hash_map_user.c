#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"

/*
 * from linux/tools/testing/selftests/bpf/bpf_iter_bpf_hash_map.skel.h
 */
#include "bpf_iter_bpf_hash_map.skel.h"
#include "check.h"

static void test_bpf_hash_map(void)
{
	__u32 expected_key_a = 0, expected_key_b = 0, expected_key_c = 0;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct bpf_iter_bpf_hash_map *skel;
	int err, i, len, map_fd, iter_fd;
	union bpf_iter_link_info linfo;
	__u64 val, expected_val = 0;
	struct bpf_link *link;
	struct key_t {
		int a;
		int b;
		int c;
	} key;
	char buf[64];

	skel = bpf_iter_bpf_hash_map__open();
	if (!skel) {
		printf("bpf_iter_bpf_hash_map__open: skeleton open failed\n");
		return;
	}

	skel->bss->in_test_mode = true;

	err = bpf_iter_bpf_hash_map__load(skel);
	if (!skel) {
		printf("bpf_iter_bpf_hash_map__load: skeleton load failed\n");
		goto out;
	}

	/* iterator with hashmap2 and hashmap3 should fail */
	memset(&linfo, 0, sizeof(linfo));
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	linfo.map.map_fd = bpf_map__fd(skel->maps.hashmap2);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_ERR_PTR(link, "attach_iter"))
		goto out;

	linfo.map.map_fd = bpf_map__fd(skel->maps.hashmap3);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_ERR_PTR(link, "attach_iter"))
		goto out;

	/* hashmap1 should be good, update map values here */
	map_fd = bpf_map__fd(skel->maps.hashmap1);
	for (i = 0; i < bpf_map__max_entries(skel->maps.hashmap1); i++) {
		key.a = i + 1;
		key.b = i + 2;
		key.c = i + 3;
		val = i + 4;
		expected_key_a += key.a;
		expected_key_b += key.b;
		expected_key_c += key.c;
		expected_val += val;

		err = bpf_map_update_elem(map_fd, &key, &val, BPF_ANY);
		if (err) {
            printf("map_update failed\n");
			goto out;
        }
	}

	linfo.map.map_fd = map_fd;
	link = bpf_program__attach_iter(skel->progs.dump_bpf_hash_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0) {
        printf("create_iter failed\n");
		goto free_link;
    }

	/* do some tests */
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0) {
		printf("buf: %s\n", buf);
	}

	if (len < 0) {
		printf("read failed: %s\n", strerror(errno));
		goto close_iter;
	} else {
        printf("len: %d\n", len);
    }

	printf("max_entries: %d\n", bpf_map__max_entries(skel->maps.hashmap1));
	printf("expected_key_a: %d\n", expected_key_a);
	printf("expected_key_b: %d\n", expected_key_b);
	printf("expected_key_c: %d\n", expected_key_c);
	printf("expected_key_c: %d\n", expected_key_c);

	/* test results */
	if (skel->bss->key_sum_a != expected_key_a) {
		printf("key_sum_a: got %u expected %u\n", skel->bss->key_sum_a, expected_key_a);
		goto close_iter;
    }

	if (skel->bss->key_sum_b != expected_key_b) {
		printf("key_sum_b: got %u expected %u\n", skel->bss->key_sum_b, expected_key_b);
		goto close_iter;
    }

	if (skel->bss->val_sum != expected_val) {
		printf("val_sum: got %llu expected %llu\n", skel->bss->val_sum, expected_val);
		goto close_iter;
    }

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_hash_map__destroy(skel);
}

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	vfprintf(stdout, format, args);
	return 0;
}

int main(int argc, char *argv[])
{
	libbpf_set_print(libbpf_print_fn);

	printf("====begin====\n");
	test_bpf_hash_map();
	printf("====end====\n");
}
