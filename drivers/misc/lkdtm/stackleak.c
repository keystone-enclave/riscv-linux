/*
 * This code tests several aspects of the STACKLEAK feature:
 *  - the current task stack is properly erased (filled with STACKLEAK_POISON);
 *  - check_alloca() allows alloca calls which don't exhaust the kernel stack;
 *  - alloca calls which exhaust/overflow the kernel stack hit BUG() in
 *     check_alloca();
 *  - exhausting the current task stack with a deep recursion is detected by
 *     CONFIG_VMAP_STACK (which is implied by CONFIG_GCC_PLUGIN_STACKLEAK).
 *
 * Authors:
 *   Tycho Andersen <tycho@tycho.ws>
 *   Alexander Popov <alex.popov@linux.com>
 */

#include "lkdtm.h"
#include <linux/sched.h>
#include <linux/compiler.h>

#ifndef CONFIG_STACKLEAK_TRACK_MIN_SIZE
# define CONFIG_STACKLEAK_TRACK_MIN_SIZE 0
#endif

static noinline bool stack_is_erased(void)
{
	unsigned long *sp, left, found, i;
	const unsigned long check_depth = STACKLEAK_POISON_CHECK_DEPTH /
							sizeof(unsigned long);

	/*
	 * For the details about the alignment of the poison values, see
	 * the comment in track_stack().
	 */
	sp = PTR_ALIGN(&i, sizeof(unsigned long));

	left = ((unsigned long)sp & (THREAD_SIZE - 1)) / sizeof(unsigned long);
	sp--;

	/*
	 * One long int at the bottom of the thread stack is reserved
	 * and not poisoned.
	 */
	if (left > 1)
		left--;
	else
		return false;

	pr_info("checking unused part of the thread stack (%lu bytes)...\n",
					left * sizeof(unsigned long));

	/*
	 * Search for check_depth poison values in a row (just like
	 * erase_kstack() does).
	 */
	for (i = 0, found = 0; i < left && found <= check_depth; i++) {
		if (*(sp - i) == STACKLEAK_POISON)
			found++;
		else
			found = 0;
	}

	if (found <= check_depth) {
		pr_err("FAIL: thread stack is not erased (checked %lu bytes)\n",
						i * sizeof(unsigned long));
		return false;
	}

	pr_info("first %lu bytes are unpoisoned\n",
				(i - found) * sizeof(unsigned long));

	/* The rest of thread stack should be erased */
	for (; i < left; i++) {
		if (*(sp - i) != STACKLEAK_POISON) {
			pr_err("FAIL: thread stack is NOT properly erased\n");
			return false;
		}
	}

	pr_info("the rest of the thread stack is properly erased\n");
	return true;
}

static noinline void do_alloca(unsigned long size)
{
	char buf[size];

	/* So this doesn't get inlined or optimized out */
	snprintf(buf, size, "testing alloca...\n");
}

void lkdtm_STACKLEAK_ALLOCA(void)
{
	unsigned long left = (unsigned long)&left & (THREAD_SIZE - 1);

	if (!stack_is_erased())
		return;

	/* Try a small alloca to see if it works */
	pr_info("try a small alloca of 16 bytes...\n");
	do_alloca(16);
	pr_info("small alloca is successful\n");

	/* Try to hit the BUG() in check_alloca() */
	pr_info("try a large alloca of %lu bytes (stack overflow)...\n", left);
	do_alloca(left);
	pr_err("FAIL: large alloca overstepped the thread stack boundary\n");
}

/*
 * The stack frame size of recursion() is bigger than the
 * CONFIG_STACKLEAK_TRACK_MIN_SIZE, hence that function is instrumented
 * by the STACKLEAK gcc plugin and it calls track_stack() at the beginning.
 */
static noinline unsigned long recursion(unsigned long prev_sp)
{
	char buf[CONFIG_STACKLEAK_TRACK_MIN_SIZE + 42];
	unsigned long sp = (unsigned long)&sp;

	snprintf(buf, sizeof(buf), "testing deep recursion...\n");

	if (prev_sp < sp + THREAD_SIZE)
		sp = recursion(prev_sp);

	return sp;
}

void lkdtm_STACKLEAK_DEEP_RECURSION(void)
{
	unsigned long sp = (unsigned long)&sp;

	if (!stack_is_erased())
		return;

	/*
	 * Exhaust the thread stack with a deep recursion. It should hit the
	 * guard page provided by CONFIG_VMAP_STACK (which is implied by
	 * CONFIG_GCC_PLUGIN_STACKLEAK).
	 */
	pr_info("try to exhaust the thread stack with a deep recursion...\n");
	pr_err("FAIL: thread stack exhaustion (%lu bytes) is not detected\n",
							sp - recursion(sp));
}
