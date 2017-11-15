/*
 * rseq-ppc.h
 *
 * (C) Copyright 2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * (C) Copyright 2016 - Boqun Feng <boqun.feng@gmail.com>
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

#define rseq_smp_mb()		__asm__ __volatile__ ("sync" : : : "memory")
#define rseq_smp_lwsync()	__asm__ __volatile__ ("lwsync" : : : "memory")
#define rseq_smp_rmb()		rseq_smp_lwsync()
#define rseq_smp_wmb()		rseq_smp_lwsync()

#define rseq_smp_load_acquire(p)					\
__extension__ ({							\
	__typeof(*p) ____p1 = RSEQ_READ_ONCE(*p);			\
	rseq_smp_lwsync();						\
	____p1;								\
})

#define rseq_smp_acquire__after_ctrl_dep()	rseq_smp_lwsync()

#define rseq_smp_store_release(p, v)					\
do {									\
	rseq_smp_lwsync();						\
	RSEQ_WRITE_ONCE(*p, v);						\
} while (0)

/*
 * The __rseq_table section can be used by debuggers to better handle
 * single-stepping through the restartable critical sections.
 */

#ifdef __PPC64__

#define STORE_WORD	"std "
#define LOAD_WORD	"ld "
#define LOADX_WORD	"ldx "
#define CMP_WORD	"cmpd "

#define RSEQ_ASM_DEFINE_TABLE(label, section, version, flags,			\
			start_ip, post_commit_offset, abort_ip)			\
		".pushsection " __rseq_str(section) ", \"aw\"\n\t"		\
		".balign 32\n\t"						\
		__rseq_str(label) ":\n\t"					\
		".long " __rseq_str(version) ", " __rseq_str(flags) "\n\t"	\
		".quad " __rseq_str(start_ip) ", " __rseq_str(post_commit_offset) ", " __rseq_str(abort_ip) "\n\t" \
		".popsection\n\t"

#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)			\
		__rseq_str(label) ":\n\t"					\
		RSEQ_INJECT_ASM(1)						\
		"lis %%r17, (" __rseq_str(cs_label) ")@highest\n\t"		\
		"ori %%r17, %%r17, (" __rseq_str(cs_label) ")@higher\n\t"	\
		"rldicr %%r17, %%r17, 32, 31\n\t"				\
		"oris %%r17, %%r17, (" __rseq_str(cs_label) ")@high\n\t"	\
		"ori %%r17, %%r17, (" __rseq_str(cs_label) ")@l\n\t"		\
		"std %%r17, %[" __rseq_str(rseq_cs) "]\n\t"

#else /* #ifdef __PPC64__ */

#define STORE_WORD	"stw "
#define LOAD_WORD	"lwz "
#define LOADX_WORD	"lwzx "
#define CMP_WORD	"cmpw "

#define RSEQ_ASM_DEFINE_TABLE(label, section, version, flags,			\
			start_ip, post_commit_offset, abort_ip)			\
		".pushsection " __rseq_str(section) ", \"aw\"\n\t"		\
		".balign 32\n\t"						\
		__rseq_str(label) ":\n\t"					\
		".long " __rseq_str(version) ", " __rseq_str(flags) "\n\t"	\
		/* 32-bit only supported on BE */				\
		".long 0x0, " __rseq_str(start_ip) ", 0x0, " __rseq_str(post_commit_offset) ", 0x0, " __rseq_str(abort_ip) "\n\t" \
		".popsection\n\t"

#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)			\
		__rseq_str(label) ":\n\t"					\
		RSEQ_INJECT_ASM(1)						\
		"lis %%r17, (" __rseq_str(cs_label) ")@ha\n\t"			\
		"addi %%r17, %%r17, (" __rseq_str(cs_label) ")@l\n\t"		\
		"stw %%r17, %[" __rseq_str(rseq_cs) "]\n\t"

#endif /* #ifdef __PPC64__ */

#define RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, label)			\
		RSEQ_INJECT_ASM(2)						\
		"lwz %%r17, %[" __rseq_str(current_cpu_id) "]\n\t"		\
		"cmpw cr7, %[" __rseq_str(cpu_id) "], %%r17\n\t"		\
		"bne- cr7, " __rseq_str(label) "\n\t"

#define RSEQ_ASM_DEFINE_ABORT(label, section, sig, teardown, abort_label)	\
		".pushsection " __rseq_str(section) ", \"ax\"\n\t"		\
		".long " __rseq_str(sig) "\n\t"					\
		__rseq_str(label) ":\n\t"					\
		teardown							\
		"b %l[" __rseq_str(abort_label) "]\n\t"			\
		".popsection\n\t"

#define RSEQ_ASM_DEFINE_CMPFAIL(label, section, teardown, cmpfail_label)	\
		".pushsection " __rseq_str(section) ", \"ax\"\n\t"		\
		__rseq_str(label) ":\n\t"					\
		teardown							\
		"b %l[" __rseq_str(cmpfail_label) "]\n\t"			\
		".popsection\n\t"


/*
 * RSEQ_ASM_OPs: asm operations for rseq
 * 	RSEQ_ASM_OP_R_*: has hard-code registers in it
 * 	RSEQ_ASM_OP_* (else): doesn't have hard-code registers(unless cr7)
 */
#define RSEQ_ASM_OP_CMPEQ(var, expect, label)					\
		LOAD_WORD "%%r17, %[" __rseq_str(var) "]\n\t"			\
		CMP_WORD "cr7, %%r17, %[" __rseq_str(expect) "]\n\t"		\
		"bne- cr7, " __rseq_str(label) "\n\t"

#define RSEQ_ASM_OP_CMPNE(var, expectnot, label)				\
		LOAD_WORD "%%r17, %[" __rseq_str(var) "]\n\t"			\
		CMP_WORD "cr7, %%r17, %[" __rseq_str(expectnot) "]\n\t"	\
		"beq- cr7, " __rseq_str(label) "\n\t"

#define RSEQ_ASM_OP_STORE(value, var)						\
		STORE_WORD "%[" __rseq_str(value) "], %[" __rseq_str(var) "]\n\t"

/* Load @var to r17 */
#define RSEQ_ASM_OP_R_LOAD(var)							\
		LOAD_WORD "%%r17, %[" __rseq_str(var) "]\n\t"

/* Store r17 to @var */
#define RSEQ_ASM_OP_R_STORE(var)						\
		STORE_WORD "%%r17, %[" __rseq_str(var) "]\n\t"

/* Add @count to r17 */
#define RSEQ_ASM_OP_R_ADD(count)						\
		"add %%r17, %[" __rseq_str(count) "], %%r17\n\t"

/* Load (r17 + voffp) to r17 */
#define RSEQ_ASM_OP_R_LOADX(voffp)						\
		LOADX_WORD "%%r17, %[" __rseq_str(voffp) "], %%r17\n\t"

/* TODO: implement a faster memcpy. */
#define RSEQ_ASM_OP_R_MEMCPY() \
		"cmpdi %%r19, 0\n\t" \
		"beq 333f\n\t" \
		"addi %%r20, %%r20, -1\n\t" \
		"addi %%r21, %%r21, -1\n\t" \
		"222:\n\t" \
		"lbzu %%r18, 1(%%r20)\n\t" \
		"stbu %%r18, 1(%%r21)\n\t" \
		"addi %%r19, %%r19, -1\n\t" \
		"cmpdi %%r19, 0\n\t" \
		"bne 222b\n\t" \
		"333:\n\t" \

#define RSEQ_ASM_OP_R_FINAL_STORE(var, post_commit_label)			\
		STORE_WORD "%%r17, %[" __rseq_str(var) "]\n\t"			\
		__rseq_str(post_commit_label) ":\n\t"

#define RSEQ_ASM_OP_FINAL_STORE(value, var, post_commit_label)			\
		STORE_WORD "%[" __rseq_str(value) "], %[" __rseq_str(var) "]\n\t"	\
		__rseq_str(post_commit_label) ":\n\t"

static inline __attribute__((always_inline))
int rseq_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v equal to @expect */
		RSEQ_ASM_OP_CMPEQ(v, expect, 5f)
		RSEQ_INJECT_ASM(4)
		/* final store */
		RSEQ_ASM_OP_FINAL_STORE(newv, v, 2)
		RSEQ_INJECT_ASM(5)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "r17"
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
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v not equal to @expectnot */
		RSEQ_ASM_OP_CMPNE(v, expectnot, 5f)
		RSEQ_INJECT_ASM(4)
		/* load the value of @v */
		RSEQ_ASM_OP_R_LOAD(v)
		/* store it in @load */
		RSEQ_ASM_OP_R_STORE(load)
		/* dereference voffp(v) */
		RSEQ_ASM_OP_R_LOADX(voffp)
		/* final store the value at voffp(v) */
		RSEQ_ASM_OP_R_FINAL_STORE(v, 2)
		RSEQ_INJECT_ASM(5)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [expectnot]"r"(expectnot),
		  [voffp]"b"(voffp),
		  [load]"m"(*load)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "r17"
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
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* load the value of @v */
		RSEQ_ASM_OP_R_LOAD(v)
		/* add @count to it */
		RSEQ_ASM_OP_R_ADD(count)
		/* final store */
		RSEQ_ASM_OP_R_FINAL_STORE(v, 2)
		RSEQ_INJECT_ASM(4)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [count]"r"(count)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "r17"
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
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v equal to @expect */
		RSEQ_ASM_OP_CMPEQ(v, expect, 5f)
		RSEQ_INJECT_ASM(4)
		/* try store */
		RSEQ_ASM_OP_STORE(newv2, v2)
		RSEQ_INJECT_ASM(5)
		/* final store */
		RSEQ_ASM_OP_FINAL_STORE(newv, v, 2)
		RSEQ_INJECT_ASM(6)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
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
		: "memory", "cc", "r17"
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
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v equal to @expect */
		RSEQ_ASM_OP_CMPEQ(v, expect, 5f)
		RSEQ_INJECT_ASM(4)
		/* try store */
		RSEQ_ASM_OP_STORE(newv2, v2)
		RSEQ_INJECT_ASM(5)
		/* for 'release' */
		"lwsync\n\t"
		/* final store */
		RSEQ_ASM_OP_FINAL_STORE(newv, v, 2)
		RSEQ_INJECT_ASM(6)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
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
		: "memory", "cc", "r17"
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
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v equal to @expect */
		RSEQ_ASM_OP_CMPEQ(v, expect, 5f)
		RSEQ_INJECT_ASM(4)
		/* cmp @v2 equal to @expct2 */
		RSEQ_ASM_OP_CMPEQ(v2, expect2, 5f)
		RSEQ_INJECT_ASM(5)
		/* final store */
		RSEQ_ASM_OP_FINAL_STORE(newv, v, 2)
		RSEQ_INJECT_ASM(6)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
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
		: "memory", "cc", "r17"
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
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		/* setup for mempcy */
		"mr %%r19, %[len]\n\t" \
		"mr %%r20, %[src]\n\t" \
		"mr %%r21, %[dst]\n\t" \
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v equal to @expect */
		RSEQ_ASM_OP_CMPEQ(v, expect, 5f)
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		RSEQ_ASM_OP_R_MEMCPY()
		RSEQ_INJECT_ASM(5)
		/* final store */
		RSEQ_ASM_OP_FINAL_STORE(newv, v, 2)
		RSEQ_INJECT_ASM(6)
		/* teardown */
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
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
		  [len]"r"(len)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "r17", "r18", "r19", "r20", "r21"
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
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		/* setup for mempcy */
		"mr %%r19, %[len]\n\t" \
		"mr %%r20, %[src]\n\t" \
		"mr %%r21, %[dst]\n\t" \
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		/* cmp cpuid */
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* cmp @v equal to @expect */
		RSEQ_ASM_OP_CMPEQ(v, expect, 5f)
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		RSEQ_ASM_OP_R_MEMCPY()
		RSEQ_INJECT_ASM(5)
		/* for 'release' */
		"lwsync\n\t"
		/* final store */
		RSEQ_ASM_OP_FINAL_STORE(newv, v, 2)
		RSEQ_INJECT_ASM(6)
		/* teardown */
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
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
		  [len]"r"(len)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "r17", "r18", "r19", "r20", "r21"
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

#undef STORE_WORD
#undef LOAD_WORD
#undef LOADX_WORD
#undef CMP_WORD
