DIRS = sk_filter tc xdp_test xdp_icmp_echo
DIRS_CLEAN = $(addsuffix _clean,$(DIRS))

.PHONY: clean $(DIRS) $(DIRS_CLEAN)

all: $(DIRS)
clean: $(DIRS_CLEAN)

$(DIRS):
	$(MAKE) -C $@

$(DIRS_CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean
