CFLAGS += -O2 -Wall -g -I./ -I../../../../usr/include/ -L./ -Wl,-rpath=./

# Own dependencies because we only want to build against 1st prerequisite, but
# still track changes to header files and depend on shared object.
OVERRIDE_TARGETS = 1

TEST_GEN_PROGS = basic_cpu_opv_test

TEST_GEN_PROGS_EXTENDED = libcpu-op.so

include ../lib.mk

$(OUTPUT)/libcpu-op.so: cpu-op.c cpu-op.h
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(OUTPUT)/%: %.c $(TEST_GEN_PROGS_EXTENDED) cpu-op.h
	$(CC) $(CFLAGS) $< -lcpu-op -o $@
