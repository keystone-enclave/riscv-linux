/*
 * rseq-arm.h
 *
 * (C) Copyright 2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define RSEQ_SIG	0x53053053

#define rseq_smp_mb()	__asm__ __volatile__ ("dmb" : : : "memory")
#define rseq_smp_rmb()	__asm__ __volatile__ ("dmb" : : : "memory")
#define rseq_smp_wmb()	__asm__ __volatile__ ("dmb" : : : "memory")

#define rseq_smp_load_acquire(p)					\
__extension__ ({							\
	__typeof(*p) ____p1 = RSEQ_READ_ONCE(*p);			\
	rseq_smp_mb();							\
	____p1;								\
})

#define rseq_smp_acquire__after_ctrl_dep()	rseq_smp_rmb()

#define rseq_smp_store_release(p, v)					\
do {									\
	rseq_smp_mb();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define RSEQ_ASM_DEFINE_TABLE(section, version, flags,			\
			start_ip, post_commit_offset, abort_ip)		\
		".pushsection " __rseq_str(section) ", \"aw\"\n\t"	\
		".balign 32\n\t"					\
		".word " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		".word " __rseq_str(start_ip) ", 0x0, " __rseq_str(post_commit_offset) ", 0x0, " __rseq_str(abort_ip) ", 0x0\n\t" \
		".popsection\n\t"

#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)		\
		__rseq_str(label) ":\n\t"				\
		RSEQ_INJECT_ASM(1)					\
		"adr r0, " __rseq_str(cs_label) "\n\t"			\
		"str r0, %[" __rseq_str(rseq_cs) "]\n\t"

#define RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, label)		\
		RSEQ_INJECT_ASM(2)					\
		"ldr r0, %[" __rseq_str(current_cpu_id) "]\n\t"	\
		"cmp %[" __rseq_str(cpu_id) "], r0\n\t"		\
		"bne " __rseq_str(label) "\n\t"

#define RSEQ_ASM_DEFINE_ABORT(table_label, label, section, sig,		\
			teardown, abort_label, version, flags, start_ip,\
			post_commit_offset, abort_ip)			\
		__rseq_str(table_label) ":\n\t" 			\
		".word " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		".word " __rseq_str(start_ip) ", 0x0, " __rseq_str(post_commit_offset) ", 0x0, " __rseq_str(abort_ip) ", 0x0\n\t" \
		".word " __rseq_str(RSEQ_SIG) "\n\t"			\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"b %l[" __rseq_str(abort_label) "]\n\t"

#define RSEQ_ASM_DEFINE_CMPFAIL(label, section, teardown, cmpfail_label) \
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"b %l[" __rseq_str(cmpfail_label) "]\n\t"

static inline __attribute__((always_inline))
int rseq_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expect], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* final store */
		"str %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(5)
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG, "", abort,
			0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}

static inline __attribute__((always_inline))
int rseq_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
		off_t voffp, intptr_t *load, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expectnot], r0\n\t"
		"beq 5f\n\t"
		RSEQ_INJECT_ASM(4)
		"str r0, %[load]\n\t"
		"add r0, %[voffp]\n\t"
		"ldr r0, [r0]\n\t"
		/* final store */
		"str r0, %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(5)
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG, "", abort,
			0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [expectnot]"r"(expectnot),
		  [voffp]"Ir"(voffp),
		  [load]"m"(*load)
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}

static inline __attribute__((always_inline))
int rseq_addv(intptr_t *v, intptr_t count, int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"add r0, %[count]\n\t"
		/* final store */
		"str r0, %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(4)
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG, "", abort,
			0x0, 0x0, 1b, 2b-1b, 4f)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  [v]"m"(*v),
		  [count]"Ir"(count)
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
}

static inline __attribute__((always_inline))
int rseq_cmpeqv_trystorev_storev(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t newv2, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expect], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try store */
		"str %[newv2], %[v2]\n\t"
		RSEQ_INJECT_ASM(5)
		/* final store */
		"str %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG, "", abort,
			0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* try store input */
		  [v2]"m"(*v2),
		  [newv2]"r"(newv2),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}

static inline __attribute__((always_inline))
int rseq_cmpeqv_trystorev_storev_release(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t newv2, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expect], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try store */
		"str %[newv2], %[v2]\n\t"
		RSEQ_INJECT_ASM(5)
		"dmb\n\t"	/* full mb provides store-release */
		/* final store */
		"str %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG, "", abort,
			0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* try store input */
		  [v2]"m"(*v2),
		  [newv2]"r"(newv2),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}

static inline __attribute__((always_inline))
int rseq_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t expect2, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expect], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(4)
		"ldr r0, %[v2]\n\t"
		"cmp %[expect2], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(5)
		/* final store */
		"str %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG, "", abort,
			0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* cmp2 input */
		  [v2]"m"(*v2),
		  [expect2]"r"(expect2),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}

static inline __attribute__((always_inline))
int rseq_cmpeqv_trymemcpy_storev(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu)
{
	uint32_t rseq_scratch[3];

	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		"str %[src], %[rseq_scratch0]\n\t"
		"str %[dst], %[rseq_scratch1]\n\t"
		"str %[len], %[rseq_scratch2]\n\t"
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expect], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		"cmp %[len], #0\n\t" \
		"beq 333f\n\t" \
		"222:\n\t" \
		"ldrb %%r0, [%[src]]\n\t" \
		"strb %%r0, [%[dst]]\n\t" \
		"adds %[src], #1\n\t" \
		"adds %[dst], #1\n\t" \
		"subs %[len], #1\n\t" \
		"bne 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(5)
		/* final store */
		"str %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		/* teardown */
		"ldr %[len], %[rseq_scratch2]\n\t"
		"ldr %[dst], %[rseq_scratch1]\n\t"
		"ldr %[src], %[rseq_scratch0]\n\t"
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG,
			/* teardown */
			"ldr %[len], %[rseq_scratch2]\n\t"
			"ldr %[dst], %[rseq_scratch1]\n\t"
			"ldr %[src], %[rseq_scratch0]\n\t",
			abort, 0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure,
			/* teardown */
			"ldr %[len], %[rseq_scratch2]\n\t"
			"ldr %[dst], %[rseq_scratch1]\n\t"
			"ldr %[src], %[rseq_scratch0]\n\t",
			cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv),
		  /* try memcpy input */
		  [dst]"r"(dst),
		  [src]"r"(src),
		  [len]"r"(len),
		  [rseq_scratch0]"m"(rseq_scratch[0]),
		  [rseq_scratch1]"m"(rseq_scratch[1]),
		  [rseq_scratch2]"m"(rseq_scratch[2])
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}

static inline __attribute__((always_inline))
int rseq_cmpeqv_trymemcpy_storev_release(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu)
{
	uint32_t rseq_scratch[3];

	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(__rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		"str %[src], %[rseq_scratch0]\n\t"
		"str %[dst], %[rseq_scratch1]\n\t"
		"str %[len], %[rseq_scratch2]\n\t"
		RSEQ_ASM_STORE_RSEQ_CS(1, 3f, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"ldr r0, %[v]\n\t"
		"cmp %[expect], r0\n\t"
		"bne 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		"cmp %[len], #0\n\t" \
		"beq 333f\n\t" \
		"222:\n\t" \
		"ldrb %%r0, [%[src]]\n\t" \
		"strb %%r0, [%[dst]]\n\t" \
		"adds %[src], #1\n\t" \
		"adds %[dst], #1\n\t" \
		"subs %[len], #1\n\t" \
		"bne 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(5)
		"dmb\n\t"	/* full mb provides store-release */
		/* final store */
		"str %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		/* teardown */
		"ldr %[len], %[rseq_scratch2]\n\t"
		"ldr %[dst], %[rseq_scratch1]\n\t"
		"ldr %[src], %[rseq_scratch0]\n\t"
		"b 6f\n\t"
		RSEQ_ASM_DEFINE_ABORT(3, 4, __rseq_failure, RSEQ_SIG,
			/* teardown */
			"ldr %[len], %[rseq_scratch2]\n\t"
			"ldr %[dst], %[rseq_scratch1]\n\t"
			"ldr %[src], %[rseq_scratch0]\n\t",
			abort, 0x0, 0x0, 1b, 2b-1b, 4f)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure,
			/* teardown */
			"ldr %[len], %[rseq_scratch2]\n\t"
			"ldr %[dst], %[rseq_scratch1]\n\t"
			"ldr %[src], %[rseq_scratch0]\n\t",
			cmpfail)
		"6:\n\t"
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv),
		  /* try memcpy input */
		  [dst]"r"(dst),
		  [src]"r"(src),
		  [len]"r"(len),
		  [rseq_scratch0]"m"(rseq_scratch[0]),
		  [rseq_scratch1]"m"(rseq_scratch[1]),
		  [rseq_scratch2]"m"(rseq_scratch[2])
		  RSEQ_INJECT_INPUT
		: "r0", "memory", "cc"
		  RSEQ_INJECT_CLOBBER
		: abort, cmpfail
	);
	return 0;
abort:
	RSEQ_INJECT_FAILED
	return -1;
cmpfail:
	return 1;
}
