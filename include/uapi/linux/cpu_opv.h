#ifndef _UAPI_LINUX_CPU_OPV_H
#define _UAPI_LINUX_CPU_OPV_H

/*
 * linux/cpu_opv.h
 *
 * CPU preempt-off operation vector system call API
 *
 * Copyright (c) 2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifdef __KERNEL__
# include <linux/types.h>
#else	/* #ifdef __KERNEL__ */
# include <stdint.h>
#endif	/* #else #ifdef __KERNEL__ */

#include <asm/byteorder.h>

#ifdef __LP64__
# define CPU_OP_FIELD_u32_u64(field)			uint64_t field
# define CPU_OP_FIELD_u32_u64_INIT_ONSTACK(field, v)	field = (intptr_t)v
#elif defined(__BYTE_ORDER) ? \
	__BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
# define CPU_OP_FIELD_u32_u64(field)	uint32_t field ## _padding, field
# define CPU_OP_FIELD_u32_u64_INIT_ONSTACK(field, v)	\
	field ## _padding = 0, field = (intptr_t)v
#else
# define CPU_OP_FIELD_u32_u64(field)	uint32_t field, field ## _padding
# define CPU_OP_FIELD_u32_u64_INIT_ONSTACK(field, v)	\
	field = (intptr_t)v, field ## _padding = 0
#endif

#define CPU_OP_VEC_LEN_MAX		16
#define CPU_OP_ARG_LEN_MAX		24
/* Max. data len per operation. */
#define CPU_OP_DATA_LEN_MAX		PAGE_SIZE
/*
 * Max. data len for overall vector. We to restrict the amount of
 * user-space data touched by the kernel in non-preemptible context so
 * we do not introduce long scheduler latencies.
 * This allows one copy of up to 4096 bytes, and 15 operations touching
 * 8 bytes each.
 * This limit is applied to the sum of length specified for all
 * operations in a vector.
 */
#define CPU_OP_VEC_DATA_LEN_MAX		(4096 + 15*8)
#define CPU_OP_MAX_PAGES		4	/* Max. pages per op. */

enum cpu_op_type {
	CPU_COMPARE_EQ_OP,	/* compare */
	CPU_COMPARE_NE_OP,	/* compare */
	CPU_MEMCPY_OP,		/* memcpy */
	CPU_ADD_OP,		/* arithmetic */
	CPU_OR_OP,		/* bitwise */
	CPU_AND_OP,		/* bitwise */
	CPU_XOR_OP,		/* bitwise */
	CPU_LSHIFT_OP,		/* shift */
	CPU_RSHIFT_OP,		/* shift */
	CPU_MB_OP,		/* memory barrier */
};

/* Vector of operations to perform. Limited to 16. */
struct cpu_op {
	int32_t op;	/* enum cpu_op_type. */
	uint32_t len;	/* data length, in bytes. */
	union {
		struct {
			CPU_OP_FIELD_u32_u64(a);
			CPU_OP_FIELD_u32_u64(b);
			uint8_t expect_fault_a;
			uint8_t expect_fault_b;
		} compare_op;
		struct {
			CPU_OP_FIELD_u32_u64(dst);
			CPU_OP_FIELD_u32_u64(src);
			uint8_t expect_fault_dst;
			uint8_t expect_fault_src;
		} memcpy_op;
		struct {
			CPU_OP_FIELD_u32_u64(p);
			int64_t count;
			uint8_t expect_fault_p;
		} arithmetic_op;
		struct {
			CPU_OP_FIELD_u32_u64(p);
			uint64_t mask;
			uint8_t expect_fault_p;
		} bitwise_op;
		struct {
			CPU_OP_FIELD_u32_u64(p);
			uint32_t bits;
			uint8_t expect_fault_p;
		} shift_op;
		char __padding[CPU_OP_ARG_LEN_MAX];
	} u;
};

#endif /* _UAPI_LINUX_CPU_OPV_H */
