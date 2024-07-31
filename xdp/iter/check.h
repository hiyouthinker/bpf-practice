#define _CHECK(condition, tag, duration, format...) ({			\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		fprintf(stdout, "%s:FAIL:%s ", __func__, tag);		\
		fprintf(stdout, ##format);				\
	} else {							\
		fprintf(stdout, "%s:PASS:%s %d nsec\n",			\
		       __func__, tag, duration);			\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define CHECK_FAIL(condition) ({					\
	int __ret = !!(condition);					\
	int __save_errno = errno;					\
	if (__ret) {							\
		fprintf(stdout, "%s:FAIL:%d\n", __func__, __LINE__);	\
	}								\
	errno = __save_errno;						\
	__ret;								\
})

#define CHECK(condition, tag, format...) \
	_CHECK(condition, tag, duration, format)
#define CHECK_ATTR(condition, tag, format...) \
	_CHECK(condition, tag, tattr.duration, format)

#define ASSERT_OK_PTR(ptr, name) ({					\
	static int duration = 0;					\
	const void *___res = (ptr);					\
	int ___err = libbpf_get_error(___res);				\
	bool ___ok = ___err == 0;					\
	CHECK(!___ok, (name), "unexpected error: %d\n", ___err);	\
	___ok;								\
})

#define ASSERT_ERR_PTR(ptr, name) ({					\
	static int duration = 0;					\
	const void *___res = (ptr);					\
	int ___err = libbpf_get_error(___res);				\
	bool ___ok = ___err != 0;					\
	CHECK(!___ok, (name), "unexpected pointer: %p\n", ___res);	\
	___ok;								\
})
