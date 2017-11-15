CFLAGS += -O2 -Wall -g -I./ -I../cpu-opv/ -I../../../../usr/include/ -L./ -Wl,-rpath=./
LDLIBS += -lpthread

# Own dependencies because we only want to build against 1st prerequisite, but
# still track changes to header files and depend on shared object.
OVERRIDE_TARGETS = 1

TEST_GEN_PROGS = basic_test basic_percpu_ops_test param_test

TEST_GEN_PROGS_EXTENDED = librseq.so libcpu-op.so

TEST_PROGS = run_param_test.sh

include ../lib.mk

$(OUTPUT)/librseq.so: rseq.c rseq.h rseq-*.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/libcpu-op.so: ../cpu-opv/cpu-op.c ../cpu-opv/cpu-op.h
	$(CC) $(CFLAGS) -shared -fPIC $< $(LDLIBS) -o $@

$(OUTPUT)/%: %.c $(TEST_GEN_PROGS_EXTENDED) rseq.h rseq-*.h ../cpu-opv/cpu-op.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -lrseq -lcpu-op -o $@
