/*
 * rseq-x86.h
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

#include <stdint.h>

#define RSEQ_SIG	0x53053053

#ifdef __x86_64__

#define rseq_smp_mb()	__asm__ __volatile__ ("mfence" : : : "memory")
#define rseq_smp_rmb()	barrier()
#define rseq_smp_wmb()	barrier()

#define rseq_smp_load_acquire(p)					\
__extension__ ({							\
	__typeof(*p) ____p1 = RSEQ_READ_ONCE(*p);			\
	barrier();							\
	____p1;								\
})

#define rseq_smp_acquire__after_ctrl_dep()	rseq_smp_rmb()

#define rseq_smp_store_release(p, v)					\
do {									\
	barrier();							\
	RSEQ_WRITE_ONCE(*p, v);						\
} while (0)

#define RSEQ_ASM_DEFINE_TABLE(label, section, version, flags,		\
			start_ip, post_commit_offset, abort_ip)		\
		".pushsection " __rseq_str(section) ", \"aw\"\n\t"	\
		".balign 32\n\t"					\
		__rseq_str(label) ":\n\t"				\
		".long " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		".quad " __rseq_str(start_ip) ", " __rseq_str(post_commit_offset) ", " __rseq_str(abort_ip) "\n\t" \
		".popsection\n\t"

#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)		\
		__rseq_str(label) ":\n\t"				\
		RSEQ_INJECT_ASM(1)					\
		"leaq " __rseq_str(cs_label) "(%%rip), %%rax\n\t"	\
		"movq %%rax, %[" __rseq_str(rseq_cs) "]\n\t"

#define RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, label)		\
		RSEQ_INJECT_ASM(2)					\
		"cmpl %[" __rseq_str(cpu_id) "], %[" __rseq_str(current_cpu_id) "]\n\t" \
		"jnz " __rseq_str(label) "\n\t"

#define RSEQ_ASM_DEFINE_ABORT(label, section, sig, teardown, abort_label) \
		".pushsection " __rseq_str(section) ", \"ax\"\n\t"	\
		/* Disassembler-friendly signature: nopl <sig>(%rip). */\
		".byte 0x0f, 0x1f, 0x05\n\t"				\
		".long " __rseq_str(sig) "\n\t"			\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"jmp %l[" __rseq_str(abort_label) "]\n\t"		\
		".popsection\n\t"

#define RSEQ_ASM_DEFINE_CMPFAIL(label, section, teardown, cmpfail_label) \
		".pushsection " __rseq_str(section) ", \"ax\"\n\t"	\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"jmp %l[" __rseq_str(cmpfail_label) "]\n\t"		\
		".popsection\n\t"

static inline __attribute__((always_inline))
int rseq_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpq %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* final store */
		"movq %[newv], %[v]\n\t"
		"2:\n\t"
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
		: "memory", "cc", "rax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpq %[v], %[expectnot]\n\t"
		"jz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		"movq %[v], %%rax\n\t"
		"movq %%rax, %[load]\n\t"
		"addq %[voffp], %%rax\n\t"
		"movq (%%rax), %%rax\n\t"
		/* final store */
		"movq %%rax, %[v]\n\t"
		"2:\n\t"
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
		  [voffp]"er"(voffp),
		  [load]"m"(*load)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "rax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* final store */
		"addq %[count], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(4)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [count]"er"(count)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "rax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpq %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try store */
		"movq %[newv2], %[v2]\n\t"
		RSEQ_INJECT_ASM(5)
		/* final store */
		"movq %[newv], %[v]\n\t"
		"2:\n\t"
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
		: "memory", "cc", "rax"
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

/* x86-64 is TSO. */
static inline __attribute__((always_inline))
int rseq_cmpeqv_trystorev_storev_release(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t newv2, intptr_t newv,
		int cpu)
{
	return rseq_cmpeqv_trystorev_storev(v, expect, v2, newv2,
			newv, cpu);
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpq %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		"cmpq %[v2], %[expect2]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(5)
		/* final store */
		"movq %[newv], %[v]\n\t"
		"2:\n\t"
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
		: "memory", "cc", "rax"
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
	uint64_t rseq_scratch[3];

	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		"movq %[src], %[rseq_scratch0]\n\t"
		"movq %[dst], %[rseq_scratch1]\n\t"
		"movq %[len], %[rseq_scratch2]\n\t"
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpq %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		"test %[len], %[len]\n\t" \
		"jz 333f\n\t" \
		"222:\n\t" \
		"movb (%[src]), %%al\n\t" \
		"movb %%al, (%[dst])\n\t" \
		"inc %[src]\n\t" \
		"inc %[dst]\n\t" \
		"dec %[len]\n\t" \
		"jnz 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(5)
		/* final store */
		"movq %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		/* teardown */
		"movq %[rseq_scratch2], %[len]\n\t"
		"movq %[rseq_scratch1], %[dst]\n\t"
		"movq %[rseq_scratch0], %[src]\n\t"
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG,
			"movq %[rseq_scratch2], %[len]\n\t"
			"movq %[rseq_scratch1], %[dst]\n\t"
			"movq %[rseq_scratch0], %[src]\n\t",
			abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure,
			"movq %[rseq_scratch2], %[len]\n\t"
			"movq %[rseq_scratch1], %[dst]\n\t"
			"movq %[rseq_scratch0], %[src]\n\t",
			cmpfail)
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
		: "memory", "cc", "rax"
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

/* x86-64 is TSO. */
static inline __attribute__((always_inline))
int rseq_cmpeqv_trymemcpy_storev_release(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu)
{
	return rseq_cmpeqv_trymemcpy_storev(v, expect, dst, src,
			len, newv, cpu);
}

#elif __i386__

/*
 * Support older 32-bit architectures that do not implement fence
 * instructions.
 */
#define rseq_smp_mb()	\
	__asm__ __volatile__ ("lock; addl $0,0(%%esp)" : : : "memory")
#define rseq_smp_rmb()	\
	__asm__ __volatile__ ("lock; addl $0,0(%%esp)" : : : "memory")
#define rseq_smp_wmb()	\
	__asm__ __volatile__ ("lock; addl $0,0(%%esp)" : : : "memory")

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
	RSEQ_WRITE_ONCE(*p, v);						\
} while (0)

/*
 * Use eax as scratch register and take memory operands as input to
 * lessen register pressure. Especially needed when compiling in O0.
 */
#define RSEQ_ASM_DEFINE_TABLE(label, section, version, flags,		\
			start_ip, post_commit_offset, abort_ip)		\
		".pushsection " __rseq_str(section) ", \"aw\"\n\t"	\
		".balign 32\n\t"					\
		__rseq_str(label) ":\n\t"				\
		".long " __rseq_str(version) ", " __rseq_str(flags) "\n\t" \
		".long " __rseq_str(start_ip) ", 0x0, " __rseq_str(post_commit_offset) ", 0x0, " __rseq_str(abort_ip) ", 0x0\n\t" \
		".popsection\n\t"

#define RSEQ_ASM_STORE_RSEQ_CS(label, cs_label, rseq_cs)		\
		__rseq_str(label) ":\n\t"				\
		RSEQ_INJECT_ASM(1)					\
		"movl $" __rseq_str(cs_label) ", %[rseq_cs]\n\t"

#define RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, label)		\
		RSEQ_INJECT_ASM(2)					\
		"cmpl %[" __rseq_str(cpu_id) "], %[" __rseq_str(current_cpu_id) "]\n\t" \
		"jnz " __rseq_str(label) "\n\t"

#define RSEQ_ASM_DEFINE_ABORT(label, section, sig, teardown, abort_label) \
		".pushsection " __rseq_str(section) ", \"ax\"\n\t"	\
		/* Disassembler-friendly signature: nopl <sig>. */\
		".byte 0x0f, 0x1f, 0x05\n\t"				\
		".long " __rseq_str(sig) "\n\t"			\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"jmp %l[" __rseq_str(abort_label) "]\n\t"		\
		".popsection\n\t"

#define RSEQ_ASM_DEFINE_CMPFAIL(label, section, teardown, cmpfail_label) \
		".pushsection " __rseq_str(section) ", \"ax\"\n\t"	\
		__rseq_str(label) ":\n\t"				\
		teardown						\
		"jmp %l[" __rseq_str(cmpfail_label) "]\n\t"		\
		".popsection\n\t"

static inline __attribute__((always_inline))
int rseq_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
		int cpu)
{
	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpl %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* final store */
		"movl %[newv], %[v]\n\t"
		"2:\n\t"
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
		: "memory", "cc", "eax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpl %[v], %[expectnot]\n\t"
		"jz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		"movl %[v], %%eax\n\t"
		"movl %%eax, %[load]\n\t"
		"addl %[voffp], %%eax\n\t"
		"movl (%%eax), %%eax\n\t"
		/* final store */
		"movl %%eax, %[v]\n\t"
		"2:\n\t"
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
		  [voffp]"ir"(voffp),
		  [load]"m"(*load)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		/* final store */
		"addl %[count], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(4)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [count]"ir"(count)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpl %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try store */
		"movl %[newv2], %%eax\n\t"
		"movl %%eax, %[v2]\n\t"
		RSEQ_INJECT_ASM(5)
		/* final store */
		"movl %[newv], %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG, "", abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure, "", cmpfail)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* try store input */
		  [v2]"m"(*v2),
		  [newv2]"m"(newv2),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"r"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"movl %[expect], %%eax\n\t"
		"cmpl %[v], %%eax\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try store */
		"movl %[newv2], %[v2]\n\t"
		RSEQ_INJECT_ASM(5)
		"lock; addl $0,0(%%esp)\n\t"
		/* final store */
		"movl %[newv], %[v]\n\t"
		"2:\n\t"
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
		  [expect]"m"(expect),
		  [newv]"r"(newv)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"cmpl %[v], %[expect]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		"cmpl %[expect2], %[v2]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(5)
		"movl %[newv], %%eax\n\t"
		/* final store */
		"movl %%eax, %[v]\n\t"
		"2:\n\t"
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
		  [newv]"m"(newv)
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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

/* TODO: implement a faster memcpy. */
static inline __attribute__((always_inline))
int rseq_cmpeqv_trymemcpy_storev(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu)
{
	uint32_t rseq_scratch[3];

	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		"movl %[src], %[rseq_scratch0]\n\t"
		"movl %[dst], %[rseq_scratch1]\n\t"
		"movl %[len], %[rseq_scratch2]\n\t"
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"movl %[expect], %%eax\n\t"
		"cmpl %%eax, %[v]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		"test %[len], %[len]\n\t" \
		"jz 333f\n\t" \
		"222:\n\t" \
		"movb (%[src]), %%al\n\t" \
		"movb %%al, (%[dst])\n\t" \
		"inc %[src]\n\t" \
		"inc %[dst]\n\t" \
		"dec %[len]\n\t" \
		"jnz 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(5)
		"movl %[newv], %%eax\n\t"
		/* final store */
		"movl %%eax, %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		/* teardown */
		"movl %[rseq_scratch2], %[len]\n\t"
		"movl %[rseq_scratch1], %[dst]\n\t"
		"movl %[rseq_scratch0], %[src]\n\t"
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG,
			"movl %[rseq_scratch2], %[len]\n\t"
			"movl %[rseq_scratch1], %[dst]\n\t"
			"movl %[rseq_scratch0], %[src]\n\t",
			abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure,
			"movl %[rseq_scratch2], %[len]\n\t"
			"movl %[rseq_scratch1], %[dst]\n\t"
			"movl %[rseq_scratch0], %[src]\n\t",
			cmpfail)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"m"(expect),
		  [newv]"m"(newv),
		  /* try memcpy input */
		  [dst]"r"(dst),
		  [src]"r"(src),
		  [len]"r"(len),
		  [rseq_scratch0]"m"(rseq_scratch[0]),
		  [rseq_scratch1]"m"(rseq_scratch[1]),
		  [rseq_scratch2]"m"(rseq_scratch[2])
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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

/* TODO: implement a faster memcpy. */
static inline __attribute__((always_inline))
int rseq_cmpeqv_trymemcpy_storev_release(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu)
{
	uint32_t rseq_scratch[3];

	RSEQ_INJECT_C(9)

	__asm__ __volatile__ goto (
		RSEQ_ASM_DEFINE_TABLE(3, __rseq_table, 0x0, 0x0, 1f, 2f-1f, 4f)
		"movl %[src], %[rseq_scratch0]\n\t"
		"movl %[dst], %[rseq_scratch1]\n\t"
		"movl %[len], %[rseq_scratch2]\n\t"
		RSEQ_ASM_STORE_RSEQ_CS(1, 3b, rseq_cs)
		RSEQ_ASM_CMP_CPU_ID(cpu_id, current_cpu_id, 4f)
		RSEQ_INJECT_ASM(3)
		"movl %[expect], %%eax\n\t"
		"cmpl %%eax, %[v]\n\t"
		"jnz 5f\n\t"
		RSEQ_INJECT_ASM(4)
		/* try memcpy */
		"test %[len], %[len]\n\t" \
		"jz 333f\n\t" \
		"222:\n\t" \
		"movb (%[src]), %%al\n\t" \
		"movb %%al, (%[dst])\n\t" \
		"inc %[src]\n\t" \
		"inc %[dst]\n\t" \
		"dec %[len]\n\t" \
		"jnz 222b\n\t" \
		"333:\n\t" \
		RSEQ_INJECT_ASM(5)
		"lock; addl $0,0(%%esp)\n\t"
		"movl %[newv], %%eax\n\t"
		/* final store */
		"movl %%eax, %[v]\n\t"
		"2:\n\t"
		RSEQ_INJECT_ASM(6)
		/* teardown */
		"movl %[rseq_scratch2], %[len]\n\t"
		"movl %[rseq_scratch1], %[dst]\n\t"
		"movl %[rseq_scratch0], %[src]\n\t"
		RSEQ_ASM_DEFINE_ABORT(4, __rseq_failure, RSEQ_SIG,
			"movl %[rseq_scratch2], %[len]\n\t"
			"movl %[rseq_scratch1], %[dst]\n\t"
			"movl %[rseq_scratch0], %[src]\n\t",
			abort)
		RSEQ_ASM_DEFINE_CMPFAIL(5, __rseq_failure,
			"movl %[rseq_scratch2], %[len]\n\t"
			"movl %[rseq_scratch1], %[dst]\n\t"
			"movl %[rseq_scratch0], %[src]\n\t",
			cmpfail)
		: /* gcc asm goto does not allow outputs */
		: [cpu_id]"r"(cpu),
		  [current_cpu_id]"m"(__rseq_abi.cpu_id),
		  [rseq_cs]"m"(__rseq_abi.rseq_cs),
		  /* final store input */
		  [v]"m"(*v),
		  [expect]"m"(expect),
		  [newv]"m"(newv),
		  /* try memcpy input */
		  [dst]"r"(dst),
		  [src]"r"(src),
		  [len]"r"(len),
		  [rseq_scratch0]"m"(rseq_scratch[0]),
		  [rseq_scratch1]"m"(rseq_scratch[1]),
		  [rseq_scratch2]"m"(rseq_scratch[2])
		  RSEQ_INJECT_INPUT
		: "memory", "cc", "eax"
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

#endif
