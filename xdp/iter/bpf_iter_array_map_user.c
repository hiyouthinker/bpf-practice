#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"

/*
 * from linux/tools/testing/selftests/bpf/bpf_iter_bpf_array_map.skel.h
 */
#include "bpf_iter_bpf_array_map.skel.h"
#include "check.h"

static int duration;

static void test_bpf_array_map(void)
{
	__u64 val, expected_val = 0, res_first_val, first_val = 0;
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	__u32 expected_key = 0, res_first_key;
	struct bpf_iter_bpf_array_map *skel;
	union bpf_iter_link_info linfo;
	int err, i, map_fd, iter_fd;
	struct bpf_link *link;
	char buf[64] = {};
	int len, start;

	skel = bpf_iter_bpf_array_map__open_and_load();
	if (CHECK(!skel, "bpf_iter_bpf_array_map__open_and_load",
		  "skeleton open_and_load failed\n"))
		return;

	map_fd = bpf_map__fd(skel->maps.arraymap1);
	for (i = 0; i < bpf_map__max_entries(skel->maps.arraymap1); i++) {
		val = i + 4;
		expected_key += i;
		expected_val += val;

		if (i == 0)
			first_val = val;

		err = bpf_map_update_elem(map_fd, &i, &val, BPF_ANY);
		if (CHECK(err, "map_update", "map_update failed\n"))
			goto out;
	}

	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = map_fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.dump_bpf_array_map, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		goto out;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (CHECK(iter_fd < 0, "create_iter", "create_iter failed\n"))
		goto free_link;

	/* do some tests */
	start = 0;
	while ((len = read(iter_fd, buf + start, sizeof(buf) - start)) > 0)
		start += len;
	if (CHECK(len < 0, "read", "read failed: %s\n", strerror(errno)))
		goto close_iter;

	/* test results */
	res_first_key = *(__u32 *)buf;
	res_first_val = *(__u64 *)(buf + sizeof(__u32));
	if (CHECK(res_first_key != 0 || res_first_val != first_val,
		  "bpf_seq_write",
		  "seq_write failure: first key %u vs expected 0, "
		  " first value %llu vs expected %llu\n",
		  res_first_key, res_first_val, first_val))
		goto close_iter;

	if (CHECK(skel->bss->key_sum != expected_key,
		  "key_sum", "got %u expected %u\n",
		  skel->bss->key_sum, expected_key))
		goto close_iter;
	if (CHECK(skel->bss->val_sum != expected_val,
		  "val_sum", "got %llu expected %llu\n",
		  skel->bss->val_sum, expected_val))
		goto close_iter;

	for (i = 0; i < bpf_map__max_entries(skel->maps.arraymap1); i++) {
		err = bpf_map_lookup_elem(map_fd, &i, &val);
		if (CHECK(err, "map_lookup", "map_lookup failed\n"))
			goto out;
		if (CHECK(i != val, "invalid_val",
			  "got value %llu expected %u\n", val, i))
			goto out;
	}

close_iter:
	close(iter_fd);
free_link:
	bpf_link__destroy(link);
out:
	bpf_iter_bpf_array_map__destroy(skel);
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
	test_bpf_array_map();
	printf("====end====\n");
}
