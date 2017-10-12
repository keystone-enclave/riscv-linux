/*
 * CPU preempt-off operation vector system call
 *
 * It allows user-space to perform a sequence of operations on per-cpu
 * data with preemption disabled. Useful as single-stepping fall-back
 * for restartable sequences, and for performing more complex operations
 * on per-cpu data that would not be otherwise possible to do with
 * restartable sequences.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (C) 2017, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/cpu_opv.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <asm/ptrace.h>
#include <asm/byteorder.h>

#include "sched/sched.h"

#define TMP_BUFLEN			64
#define NR_PINNED_PAGES_ON_STACK	8

union op_fn_data {
	uint8_t _u8;
	uint16_t _u16;
	uint32_t _u32;
	uint64_t _u64;
#if (BITS_PER_LONG < 64)
	uint32_t _u64_split[2];
#endif
};

struct cpu_opv_pinned_pages {
	struct page **pages;
	size_t nr;
	bool is_kmalloc;
};

typedef int (*op_fn_t)(union op_fn_data *data, uint64_t v, uint32_t len);

static DEFINE_MUTEX(cpu_opv_offline_lock);

/*
 * The cpu_opv system call executes a vector of operations on behalf of
 * user-space on a specific CPU with preemption disabled. It is inspired
 * from readv() and writev() system calls which take a "struct iovec"
 * array as argument.
 *
 * The operations available are: comparison, memcpy, add, or, and, xor,
 * left shift, and right shift. The system call receives a CPU number
 * from user-space as argument, which is the CPU on which those
 * operations need to be performed. All preparation steps such as
 * loading pointers, and applying offsets to arrays, need to be
 * performed by user-space before invoking the system call. The
 * "comparison" operation can be used to check that the data used in the
 * preparation step did not change between preparation of system call
 * inputs and operation execution within the preempt-off critical
 * section.
 *
 * The reason why we require all pointer offsets to be calculated by
 * user-space beforehand is because we need to use get_user_pages_fast()
 * to first pin all pages touched by each operation. This takes care of
 * faulting-in the pages. Then, preemption is disabled, and the
 * operations are performed atomically with respect to other thread
 * execution on that CPU, without generating any page fault.
 *
 * A maximum limit of 16 operations per cpu_opv syscall invocation is
 * enforced, and a overall maximum length sum, so user-space cannot
 * generate a too long preempt-off critical section. Each operation is
 * also limited a length of PAGE_SIZE bytes, meaning that an operation
 * can touch a maximum of 4 pages (memcpy: 2 pages for source, 2 pages
 * for destination if addresses are not aligned on page boundaries).
 *
 * If the thread is not running on the requested CPU, a new
 * push_task_to_cpu() is invoked to migrate the task to the requested
 * CPU.  If the requested CPU is not part of the cpus allowed mask of
 * the thread, the system call fails with EINVAL. After the migration
 * has been performed, preemption is disabled, and the current CPU
 * number is checked again and compared to the requested CPU number. If
 * it still differs, it means the scheduler migrated us away from that
 * CPU. Return EAGAIN to user-space in that case, and let user-space
 * retry (either requesting the same CPU number, or a different one,
 * depending on the user-space algorithm constraints).
 */

/*
 * Check operation types and length parameters.
 */
static int cpu_opv_check(struct cpu_op *cpuop, int cpuopcnt)
{
	int i;
	uint32_t sum = 0;

	for (i = 0; i < cpuopcnt; i++) {
		struct cpu_op *op = &cpuop[i];

		switch (op->op) {
		case CPU_MB_OP:
			break;
		default:
			sum += op->len;
		}
		switch (op->op) {
		case CPU_COMPARE_EQ_OP:
		case CPU_COMPARE_NE_OP:
		case CPU_MEMCPY_OP:
			if (op->len > CPU_OP_DATA_LEN_MAX)
				return -EINVAL;
			break;
		case CPU_ADD_OP:
		case CPU_OR_OP:
		case CPU_AND_OP:
		case CPU_XOR_OP:
			switch (op->len) {
			case 1:
			case 2:
			case 4:
			case 8:
				break;
			default:
				return -EINVAL;
			}
			break;
		case CPU_LSHIFT_OP:
		case CPU_RSHIFT_OP:
			switch (op->len) {
			case 1:
				if (op->u.shift_op.bits > 7)
					return -EINVAL;
				break;
			case 2:
				if (op->u.shift_op.bits > 15)
					return -EINVAL;
				break;
			case 4:
				if (op->u.shift_op.bits > 31)
					return -EINVAL;
				break;
			case 8:
				if (op->u.shift_op.bits > 63)
					return -EINVAL;
				break;
			default:
				return -EINVAL;
			}
			break;
		case CPU_MB_OP:
			break;
		default:
			return -EINVAL;
		}
	}
	if (sum > CPU_OP_VEC_DATA_LEN_MAX)
		return -EINVAL;
	return 0;
}

static unsigned long cpu_op_range_nr_pages(unsigned long addr,
		unsigned long len)
{
	return ((addr + len - 1) >> PAGE_SHIFT) - (addr >> PAGE_SHIFT) + 1;
}

static int cpu_op_check_page(struct page *page)
{
	struct address_space *mapping;

	if (is_zone_device_page(page))
		return -EFAULT;
	page = compound_head(page);
	mapping = READ_ONCE(page->mapping);
	if (!mapping) {
		int shmem_swizzled;

		/*
		 * Check again with page lock held to guard against
		 * memory pressure making shmem_writepage move the page
		 * from filecache to swapcache.
		 */
		lock_page(page);
		shmem_swizzled = PageSwapCache(page) || page->mapping;
		unlock_page(page);
		if (shmem_swizzled)
			return -EAGAIN;
		return -EFAULT;
	}
	return 0;
}

/*
 * Refusing device pages, the zero page, pages in the gate area, and
 * special mappings. Inspired from futex.c checks.
 */
static int cpu_op_check_pages(struct page **pages,
		unsigned long nr_pages)
{
	unsigned long i;

	for (i = 0; i < nr_pages; i++) {
		int ret;

		ret = cpu_op_check_page(pages[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int cpu_op_pin_pages(unsigned long addr, unsigned long len,
		struct cpu_opv_pinned_pages *pin_pages, int write)
{
	struct page *pages[2];
	int ret, nr_pages;

	if (!len)
		return 0;
	nr_pages = cpu_op_range_nr_pages(addr, len);
	BUG_ON(nr_pages > 2);
	if (!pin_pages->is_kmalloc && pin_pages->nr + nr_pages
			> NR_PINNED_PAGES_ON_STACK) {
		struct page **pinned_pages =
			kzalloc(CPU_OP_VEC_LEN_MAX * CPU_OP_MAX_PAGES
				* sizeof(struct page *), GFP_KERNEL);
		if (!pinned_pages)
			return -ENOMEM;
		memcpy(pinned_pages, pin_pages->pages,
			pin_pages->nr * sizeof(struct page *));
		pin_pages->pages = pinned_pages;
		pin_pages->is_kmalloc = true;
	}
again:
	ret = get_user_pages_fast(addr, nr_pages, write, pages);
	if (ret < nr_pages) {
		if (ret > 0)
			put_page(pages[0]);
		return -EFAULT;
	}
	/*
	 * Refuse device pages, the zero page, pages in the gate area,
	 * and special mappings.
	 */
	ret = cpu_op_check_pages(pages, nr_pages);
	if (ret == -EAGAIN) {
		put_page(pages[0]);
		if (nr_pages > 1)
			put_page(pages[1]);
		goto again;
	}
	if (ret)
		goto error;
	pin_pages->pages[pin_pages->nr++] = pages[0];
	if (nr_pages > 1)
		pin_pages->pages[pin_pages->nr++] = pages[1];
	return 0;

error:
	put_page(pages[0]);
	if (nr_pages > 1)
		put_page(pages[1]);
	return -EFAULT;
}

static int cpu_opv_pin_pages(struct cpu_op *cpuop, int cpuopcnt,
		struct cpu_opv_pinned_pages *pin_pages)
{
	int ret, i;
	bool expect_fault = false;

	/* Check access, pin pages. */
	for (i = 0; i < cpuopcnt; i++) {
		struct cpu_op *op = &cpuop[i];

		switch (op->op) {
		case CPU_COMPARE_EQ_OP:
		case CPU_COMPARE_NE_OP:
			ret = -EFAULT;
			expect_fault = op->u.compare_op.expect_fault_a;
			if (!access_ok(VERIFY_READ,
					(void __user *)op->u.compare_op.a,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.compare_op.a,
					op->len, pin_pages, 0);
			if (ret)
				goto error;
			ret = -EFAULT;
			expect_fault = op->u.compare_op.expect_fault_b;
			if (!access_ok(VERIFY_READ,
					(void __user *)op->u.compare_op.b,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.compare_op.b,
					op->len, pin_pages, 0);
			if (ret)
				goto error;
			break;
		case CPU_MEMCPY_OP:
			ret = -EFAULT;
			expect_fault = op->u.memcpy_op.expect_fault_dst;
			if (!access_ok(VERIFY_WRITE,
					(void __user *)op->u.memcpy_op.dst,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.memcpy_op.dst,
					op->len, pin_pages, 1);
			if (ret)
				goto error;
			ret = -EFAULT;
			expect_fault = op->u.memcpy_op.expect_fault_src;
			if (!access_ok(VERIFY_READ,
					(void __user *)op->u.memcpy_op.src,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.memcpy_op.src,
					op->len, pin_pages, 0);
			if (ret)
				goto error;
			break;
		case CPU_ADD_OP:
			ret = -EFAULT;
			expect_fault = op->u.arithmetic_op.expect_fault_p;
			if (!access_ok(VERIFY_WRITE,
					(void __user *)op->u.arithmetic_op.p,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.arithmetic_op.p,
					op->len, pin_pages, 1);
			if (ret)
				goto error;
			break;
		case CPU_OR_OP:
		case CPU_AND_OP:
		case CPU_XOR_OP:
			ret = -EFAULT;
			expect_fault = op->u.bitwise_op.expect_fault_p;
			if (!access_ok(VERIFY_WRITE,
					(void __user *)op->u.bitwise_op.p,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.bitwise_op.p,
					op->len, pin_pages, 1);
			if (ret)
				goto error;
			break;
		case CPU_LSHIFT_OP:
		case CPU_RSHIFT_OP:
			ret = -EFAULT;
			expect_fault = op->u.shift_op.expect_fault_p;
			if (!access_ok(VERIFY_WRITE,
					(void __user *)op->u.shift_op.p,
					op->len))
				goto error;
			ret = cpu_op_pin_pages(
					(unsigned long)op->u.shift_op.p,
					op->len, pin_pages, 1);
			if (ret)
				goto error;
			break;
		case CPU_MB_OP:
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;

error:
	for (i = 0; i < pin_pages->nr; i++)
		put_page(pin_pages->pages[i]);
	pin_pages->nr = 0;
	/*
	 * If faulting access is expected, return EAGAIN to user-space.
	 * It allows user-space to distinguish between a fault caused by
	 * an access which is expect to fault (e.g. due to concurrent
	 * unmapping of underlying memory) from an unexpected fault from
	 * which a retry would not recover.
	 */
	if (ret == -EFAULT && expect_fault)
		return -EAGAIN;
	return ret;
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int do_cpu_op_compare_iter(void __user *a, void __user *b, uint32_t len)
{
	char bufa[TMP_BUFLEN], bufb[TMP_BUFLEN];
	uint32_t compared = 0;

	while (compared != len) {
		unsigned long to_compare;

		to_compare = min_t(uint32_t, TMP_BUFLEN, len - compared);
		if (__copy_from_user_inatomic(bufa, a + compared, to_compare))
			return -EFAULT;
		if (__copy_from_user_inatomic(bufb, b + compared, to_compare))
			return -EFAULT;
		if (memcmp(bufa, bufb, to_compare))
			return 1;	/* different */
		compared += to_compare;
	}
	return 0;	/* same */
}

/* Return 0 if same, > 0 if different, < 0 on error. */
static int do_cpu_op_compare(void __user *a, void __user *b, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
#if (BITS_PER_LONG < 64)
		uint32_t _u64_split[2];
#endif
	} tmp[2];

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp[0]._u8, (uint8_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u8, (uint8_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u8 != tmp[1]._u8);
		break;
	case 2:
		if (__get_user(tmp[0]._u16, (uint16_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u16, (uint16_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u16 != tmp[1]._u16);
		break;
	case 4:
		if (__get_user(tmp[0]._u32, (uint32_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u32, (uint32_t __user *)b))
			goto end;
		ret = !!(tmp[0]._u32 != tmp[1]._u32);
		break;
	case 8:
#if (BITS_PER_LONG >= 64)
		if (__get_user(tmp[0]._u64, (uint64_t __user *)a))
			goto end;
		if (__get_user(tmp[1]._u64, (uint64_t __user *)b))
			goto end;
#else
		if (__get_user(tmp[0]._u64_split[0], (uint32_t __user *)a))
			goto end;
		if (__get_user(tmp[0]._u64_split[1], (uint32_t __user *)a + 1))
			goto end;
		if (__get_user(tmp[1]._u64_split[0], (uint32_t __user *)b))
			goto end;
		if (__get_user(tmp[1]._u64_split[1], (uint32_t __user *)b + 1))
			goto end;
#endif
		ret = !!(tmp[0]._u64 != tmp[1]._u64);
		break;
	default:
		pagefault_enable();
		return do_cpu_op_compare_iter(a, b, len);
	}
end:
	pagefault_enable();
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_memcpy_iter(void __user *dst, void __user *src,
		uint32_t len)
{
	char buf[TMP_BUFLEN];
	uint32_t copied = 0;

	while (copied != len) {
		unsigned long to_copy;

		to_copy = min_t(uint32_t, TMP_BUFLEN, len - copied);
		if (__copy_from_user_inatomic(buf, src + copied, to_copy))
			return -EFAULT;
		if (__copy_to_user_inatomic(dst + copied, buf, to_copy))
			return -EFAULT;
		copied += to_copy;
	}
	return 0;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_memcpy(void __user *dst, void __user *src, uint32_t len)
{
	int ret = -EFAULT;
	union {
		uint8_t _u8;
		uint16_t _u16;
		uint32_t _u32;
		uint64_t _u64;
#if (BITS_PER_LONG < 64)
		uint32_t _u64_split[2];
#endif
	} tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)src))
			goto end;
		if (__put_user(tmp._u8, (uint8_t __user *)dst))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)src))
			goto end;
		if (__put_user(tmp._u16, (uint16_t __user *)dst))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)src))
			goto end;
		if (__put_user(tmp._u32, (uint32_t __user *)dst))
			goto end;
		break;
	case 8:
#if (BITS_PER_LONG >= 64)
		if (__get_user(tmp._u64, (uint64_t __user *)src))
			goto end;
		if (__put_user(tmp._u64, (uint64_t __user *)dst))
			goto end;
#else
		if (__get_user(tmp._u64_split[0], (uint32_t __user *)src))
			goto end;
		if (__get_user(tmp._u64_split[1], (uint32_t __user *)src + 1))
			goto end;
		if (__put_user(tmp._u64_split[0], (uint32_t __user *)dst))
			goto end;
		if (__put_user(tmp._u64_split[1], (uint32_t __user *)dst + 1))
			goto end;
#endif
		break;
	default:
		pagefault_enable();
		return do_cpu_op_memcpy_iter(dst, src, len);
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

static int op_add_fn(union op_fn_data *data, uint64_t count, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 += (uint8_t)count;
		break;
	case 2:
		data->_u16 += (uint16_t)count;
		break;
	case 4:
		data->_u32 += (uint32_t)count;
		break;
	case 8:
		data->_u64 += (uint64_t)count;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_or_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 |= (uint8_t)mask;
		break;
	case 2:
		data->_u16 |= (uint16_t)mask;
		break;
	case 4:
		data->_u32 |= (uint32_t)mask;
		break;
	case 8:
		data->_u64 |= (uint64_t)mask;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_and_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 &= (uint8_t)mask;
		break;
	case 2:
		data->_u16 &= (uint16_t)mask;
		break;
	case 4:
		data->_u32 &= (uint32_t)mask;
		break;
	case 8:
		data->_u64 &= (uint64_t)mask;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_xor_fn(union op_fn_data *data, uint64_t mask, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 ^= (uint8_t)mask;
		break;
	case 2:
		data->_u16 ^= (uint16_t)mask;
		break;
	case 4:
		data->_u32 ^= (uint32_t)mask;
		break;
	case 8:
		data->_u64 ^= (uint64_t)mask;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_lshift_fn(union op_fn_data *data, uint64_t bits, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 <<= (uint8_t)bits;
		break;
	case 2:
		data->_u16 <<= (uint16_t)bits;
		break;
	case 4:
		data->_u32 <<= (uint32_t)bits;
		break;
	case 8:
		data->_u64 <<= (uint64_t)bits;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int op_rshift_fn(union op_fn_data *data, uint64_t bits, uint32_t len)
{
	int ret = 0;

	switch (len) {
	case 1:
		data->_u8 >>= (uint8_t)bits;
		break;
	case 2:
		data->_u16 >>= (uint16_t)bits;
		break;
	case 4:
		data->_u32 >>= (uint32_t)bits;
		break;
	case 8:
		data->_u64 >>= (uint64_t)bits;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/* Return 0 on success, < 0 on error. */
static int do_cpu_op_fn(op_fn_t op_fn, void __user *p, uint64_t v,
		uint32_t len)
{
	int ret = -EFAULT;
	union op_fn_data tmp;

	pagefault_disable();
	switch (len) {
	case 1:
		if (__get_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		if (op_fn(&tmp, v, len))
			goto end;
		if (__put_user(tmp._u8, (uint8_t __user *)p))
			goto end;
		break;
	case 2:
		if (__get_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		if (op_fn(&tmp, v, len))
			goto end;
		if (__put_user(tmp._u16, (uint16_t __user *)p))
			goto end;
		break;
	case 4:
		if (__get_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		if (op_fn(&tmp, v, len))
			goto end;
		if (__put_user(tmp._u32, (uint32_t __user *)p))
			goto end;
		break;
	case 8:
#if (BITS_PER_LONG >= 64)
		if (__get_user(tmp._u64, (uint64_t __user *)p))
			goto end;
#else
		if (__get_user(tmp._u64_split[0], (uint32_t __user *)p))
			goto end;
		if (__get_user(tmp._u64_split[1], (uint32_t __user *)p + 1))
			goto end;
#endif
		if (op_fn(&tmp, v, len))
			goto end;
#if (BITS_PER_LONG >= 64)
		if (__put_user(tmp._u64, (uint64_t __user *)p))
			goto end;
#else
		if (__put_user(tmp._u64_split[0], (uint32_t __user *)p))
			goto end;
		if (__put_user(tmp._u64_split[1], (uint32_t __user *)p + 1))
			goto end;
#endif
		break;
	default:
		ret = -EINVAL;
		goto end;
	}
	ret = 0;
end:
	pagefault_enable();
	return ret;
}

static int __do_cpu_opv(struct cpu_op *cpuop, int cpuopcnt)
{
	int i, ret;

	for (i = 0; i < cpuopcnt; i++) {
		struct cpu_op *op = &cpuop[i];

		/* Guarantee a compiler barrier between each operation. */
		barrier();

		switch (op->op) {
		case CPU_COMPARE_EQ_OP:
			ret = do_cpu_op_compare(
					(void __user *)op->u.compare_op.a,
					(void __user *)op->u.compare_op.b,
					op->len);
			/* Stop execution on error. */
			if (ret < 0)
				return ret;
			/*
			 * Stop execution, return op index + 1 if comparison
			 * differs.
			 */
			if (ret > 0)
				return i + 1;
			break;
		case CPU_COMPARE_NE_OP:
			ret = do_cpu_op_compare(
					(void __user *)op->u.compare_op.a,
					(void __user *)op->u.compare_op.b,
					op->len);
			/* Stop execution on error. */
			if (ret < 0)
				return ret;
			/*
			 * Stop execution, return op index + 1 if comparison
			 * is identical.
			 */
			if (ret == 0)
				return i + 1;
			break;
		case CPU_MEMCPY_OP:
			ret = do_cpu_op_memcpy(
					(void __user *)op->u.memcpy_op.dst,
					(void __user *)op->u.memcpy_op.src,
					op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_ADD_OP:
			ret = do_cpu_op_fn(op_add_fn,
					(void __user *)op->u.arithmetic_op.p,
					op->u.arithmetic_op.count, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_OR_OP:
			ret = do_cpu_op_fn(op_or_fn,
					(void __user *)op->u.bitwise_op.p,
					op->u.bitwise_op.mask, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_AND_OP:
			ret = do_cpu_op_fn(op_and_fn,
					(void __user *)op->u.bitwise_op.p,
					op->u.bitwise_op.mask, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_XOR_OP:
			ret = do_cpu_op_fn(op_xor_fn,
					(void __user *)op->u.bitwise_op.p,
					op->u.bitwise_op.mask, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_LSHIFT_OP:
			ret = do_cpu_op_fn(op_lshift_fn,
					(void __user *)op->u.shift_op.p,
					op->u.shift_op.bits, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_RSHIFT_OP:
			ret = do_cpu_op_fn(op_rshift_fn,
					(void __user *)op->u.shift_op.p,
					op->u.shift_op.bits, op->len);
			/* Stop execution on error. */
			if (ret)
				return ret;
			break;
		case CPU_MB_OP:
			smp_mb();
			break;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int do_cpu_opv(struct cpu_op *cpuop, int cpuopcnt, int cpu)
{
	int ret;

	if (cpu != raw_smp_processor_id()) {
		ret = push_task_to_cpu(current, cpu);
		if (ret)
			goto check_online;
	}
	preempt_disable();
	if (cpu != smp_processor_id()) {
		ret = -EAGAIN;
		goto end;
	}
	ret = __do_cpu_opv(cpuop, cpuopcnt);
end:
	preempt_enable();
	return ret;

check_online:
	if (!cpu_possible(cpu))
		return -EINVAL;
	get_online_cpus();
	if (cpu_online(cpu)) {
		ret = -EAGAIN;
		goto put_online_cpus;
	}
	/*
	 * CPU is offline. Perform operation from the current CPU with
	 * cpu_online read lock held, preventing that CPU from coming online,
	 * and with mutex held, providing mutual exclusion against other
	 * CPUs also finding out about an offline CPU.
	 */
	mutex_lock(&cpu_opv_offline_lock);
	ret = __do_cpu_opv(cpuop, cpuopcnt);
	mutex_unlock(&cpu_opv_offline_lock);
put_online_cpus:
	put_online_cpus();
	return ret;
}

/*
 * cpu_opv - execute operation vector on a given CPU with preempt off.
 *
 * Userspace should pass current CPU number as parameter. May fail with
 * -EAGAIN if currently executing on the wrong CPU.
 */
SYSCALL_DEFINE4(cpu_opv, struct cpu_op __user *, ucpuopv, int, cpuopcnt,
		int, cpu, int, flags)
{
	struct cpu_op cpuopv[CPU_OP_VEC_LEN_MAX];
	struct page *pinned_pages_on_stack[NR_PINNED_PAGES_ON_STACK];
	struct cpu_opv_pinned_pages pin_pages = {
		.pages = pinned_pages_on_stack,
		.nr = 0,
		.is_kmalloc = false,
	};
	int ret, i;

	if (unlikely(flags))
		return -EINVAL;
	if (unlikely(cpu < 0))
		return -EINVAL;
	if (cpuopcnt < 0 || cpuopcnt > CPU_OP_VEC_LEN_MAX)
		return -EINVAL;
	if (copy_from_user(cpuopv, ucpuopv, cpuopcnt * sizeof(struct cpu_op)))
		return -EFAULT;
	ret = cpu_opv_check(cpuopv, cpuopcnt);
	if (ret)
		return ret;
	ret = cpu_opv_pin_pages(cpuopv, cpuopcnt, &pin_pages);
	if (ret)
		goto end;
	ret = do_cpu_opv(cpuopv, cpuopcnt, cpu);
	for (i = 0; i < pin_pages.nr; i++)
		put_page(pin_pages.pages[i]);
end:
	if (pin_pages.is_kmalloc)
		kfree(pin_pages.pages);
	return ret;
}
