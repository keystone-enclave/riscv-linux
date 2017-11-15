/*
 * cpu-op.h
 *
 * (C) Copyright 2017 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef CPU_OPV_H
#define CPU_OPV_H

#include <stdlib.h>
#include <stdint.h>
#include <linux/cpu_opv.h>

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define barrier()		__asm__ __volatile__("" : : : "memory")

#define ACCESS_ONCE(x)		(*(__volatile__  __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v)	__extension__ ({ ACCESS_ONCE(x) = (v); })
#define READ_ONCE(x)		ACCESS_ONCE(x)

int cpu_opv(struct cpu_op *cpuopv, int cpuopcnt, int cpu, int flags);
int cpu_op_get_current_cpu(void);

int cpu_op_cmpxchg(void *v, void *expect, void *old, void *_new,
		size_t len, int cpu);
int cpu_op_add(void *v, int64_t count, size_t len, int cpu);

int cpu_op_cmpeqv_storev(intptr_t *v, intptr_t expect, intptr_t newv,
		int cpu);
int cpu_op_cmpnev_storeoffp_load(intptr_t *v, intptr_t expectnot,
		off_t voffp, intptr_t *load, int cpu);
int cpu_op_cmpeqv_storev_storev(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t newv2, intptr_t newv,
		int cpu);
int cpu_op_cmpeqv_storev_mb_storev(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t newv2, intptr_t newv,
		int cpu);
int cpu_op_cmpeqv_cmpeqv_storev(intptr_t *v, intptr_t expect,
		intptr_t *v2, intptr_t expect2, intptr_t newv,
		int cpu);
int cpu_op_cmpeqv_memcpy_storev(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu);
int cpu_op_cmpeqv_memcpy_mb_storev(intptr_t *v, intptr_t expect,
		void *dst, void *src, size_t len, intptr_t newv,
		int cpu);
int cpu_op_addv(intptr_t *v, int64_t count, int cpu);

#endif  /* CPU_OPV_H_ */
