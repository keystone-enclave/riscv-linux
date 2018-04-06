#include <linux/bug.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <asm/linkage.h>
#include <asm/processor.h>

asmlinkage void erase_kstack(void)
{
	register unsigned long p = current->thread.lowest_stack;
	register unsigned long boundary = p & ~(THREAD_SIZE - 1);
	unsigned long poison = 0;
	const unsigned long check_depth = STACKLEAK_POISON_CHECK_DEPTH /
							sizeof(unsigned long);

	/*
	 * Let's search for the poison value in the stack.
	 * Start from the lowest_stack and go to the bottom.
	 */
	while (p > boundary && poison <= check_depth) {
		if (*(unsigned long *)p == STACKLEAK_POISON)
			poison++;
		else
			poison = 0;

		p -= sizeof(unsigned long);
	}

	/*
	 * One long int at the bottom of the thread stack is reserved and
	 * should not be poisoned (see CONFIG_SCHED_STACK_END_CHECK).
	 */
	if (p == boundary)
		p += sizeof(unsigned long);

#ifdef CONFIG_STACKLEAK_METRICS
	current->thread.prev_lowest_stack = p;
#endif

	/*
	 * So let's write the poison value to the kernel stack.
	 * Start from the address in p and move up till the new boundary.
	 */
	if (on_thread_stack())
		boundary = current_stack_pointer;
	else
		boundary = current_top_of_stack();

	BUG_ON(boundary - p >= THREAD_SIZE);

	while (p < boundary) {
		*(unsigned long *)p = STACKLEAK_POISON;
		p += sizeof(unsigned long);
	}

	/* Reset the lowest_stack value for the next syscall */
	current->thread.lowest_stack = current_top_of_stack() - 256;
}

