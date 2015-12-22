/*
 * Restartable sequences system call
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
 * Copyright (C) 2015, Google, Inc.,
 * Paul Turner <pjt@google.com> and Andrew Hunter <ahh@google.com>
 * Copyright (C) 2015-2016, EfficiOS Inc.,
 * Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/rseq.h>
#include <linux/types.h>
#include <asm/ptrace.h>

#define CREATE_TRACE_POINTS
#include <trace/events/rseq.h>

/*
 *
 * Restartable sequences are a lightweight interface that allows
 * user-level code to be executed atomically relative to scheduler
 * preemption and signal delivery. Typically used for implementing
 * per-cpu operations.
 *
 * It allows user-space to perform update operations on per-cpu data
 * without requiring heavy-weight atomic operations.
 *
 * Detailed algorithm of rseq user-space assembly sequences:
 *
 *   Steps [1]-[3] (inclusive) need to be a sequence of instructions in
 *   userspace that can handle being moved to the abort_ip between any
 *   of those instructions.
 *
 *   The abort_ip address needs to be less than start_ip, or
 *   greater-or-equal the post_commit_ip. Step [5] and the failure
 *   code step [F1] need to be at addresses lesser than start_ip, or
 *   greater-or-equal the post_commit_ip.
 *
 *       [start_ip]
 *   1.  Userspace stores the address of the struct rseq_cs assembly
 *       block descriptor into the rseq_cs field of the registered
 *       struct rseq TLS area. This update is performed through a single
 *       store, followed by a compiler barrier which prevents the
 *       compiler from moving following loads or stores before this
 *       store.
 *
 *   2.  Userspace tests to see whether the current cpu_id field
 *       match the cpu number loaded before start_ip. Manually jumping
 *       to [F1] in case of a mismatch.
 *
 *       Note that if we are preempted or interrupted by a signal
 *       after [1] and before post_commit_ip, then the kernel
 *       clears the rseq_cs field of struct rseq, then jumps us to
 *       abort_ip.
 *
 *   3.  Userspace critical section final instruction before
 *       post_commit_ip is the commit. The critical section is
 *       self-terminating.
 *       [post_commit_ip]
 *
 *   4.  success
 *
 *   On failure at [2]:
 *
 *       [abort_ip]
 *   F1. goto failure label
 */

static bool rseq_update_cpu_id(struct task_struct *t)
{
	uint32_t cpu_id = raw_smp_processor_id();

	if (__put_user(cpu_id, &t->rseq->cpu_id_start))
		return false;
	if (__put_user(cpu_id, &t->rseq->cpu_id))
		return false;
	trace_rseq_update(t);
	return true;
}

static bool rseq_reset_rseq_cpu_id(struct task_struct *t)
{
	uint32_t cpu_id_start = 0, cpu_id = -1U;

	/*
	 * Reset cpu_id_start to its initial state (0).
	 */
	if (__put_user(cpu_id_start, &t->rseq->cpu_id_start))
		return false;
	/*
	 * Reset cpu_id to -1U, so any user coming in after unregistration can
	 * figure out that rseq needs to be registered again.
	 */
	if (__put_user(cpu_id, &t->rseq->cpu_id))
		return false;
	return true;
}

static bool rseq_get_rseq_cs(struct task_struct *t,
		void __user **start_ip,
		unsigned long *post_commit_offset,
		void __user **abort_ip,
		uint32_t *cs_flags)
{
	unsigned long ptr;
	struct rseq_cs __user *urseq_cs;
	struct rseq_cs rseq_cs;
	u32 __user *usig;
	u32 sig;

	if (__get_user(ptr, &t->rseq->rseq_cs))
		return false;
	if (!ptr)
		return true;
	urseq_cs = (struct rseq_cs __user *)ptr;
	if (copy_from_user(&rseq_cs, urseq_cs, sizeof(rseq_cs)))
		return false;
	/*
	 * We need to clear rseq_cs upon entry into a signal handler
	 * nested on top of a rseq assembly block, so the signal handler
	 * will not be fixed up if itself interrupted by a nested signal
	 * handler or preempted.  We also need to clear rseq_cs if we
	 * preempt or deliver a signal on top of code outside of the
	 * rseq assembly block, to ensure that a following preemption or
	 * signal delivery will not try to perform a fixup needlessly.
	 */
	if (clear_user(&t->rseq->rseq_cs, sizeof(t->rseq->rseq_cs)))
		return false;
	if (rseq_cs.version > 0)
		return false;
	*cs_flags = rseq_cs.flags;
	*start_ip = (void __user *)rseq_cs.start_ip;
	*post_commit_offset = (unsigned long)rseq_cs.post_commit_offset;
	*abort_ip = (void __user *)rseq_cs.abort_ip;
	usig = (u32 __user *)(rseq_cs.abort_ip - sizeof(u32));
	if (get_user(sig, usig))
		return false;
	if (current->rseq_sig != sig) {
		printk_ratelimited(KERN_WARNING
			"Possible attack attempt. Unexpected rseq signature 0x%x, expecting 0x%x (pid=%d, addr=%p).\n",
			sig, current->rseq_sig, current->pid, usig);
		return false;
	}
	return true;
}

static int rseq_need_restart(struct task_struct *t, uint32_t cs_flags)
{
	bool need_restart = false;
	uint32_t flags;

	/* Get thread flags. */
	if (__get_user(flags, &t->rseq->flags))
		return -EFAULT;

	/* Take into account critical section flags. */
	flags |= cs_flags;

	/*
	 * Restart on signal can only be inhibited when restart on
	 * preempt and restart on migrate are inhibited too. Otherwise,
	 * a preempted signal handler could fail to restart the prior
	 * execution context on sigreturn.
	 */
	if (flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL) {
		if (!(flags & RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE))
			return -EINVAL;
		if (!(flags & RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT))
			return -EINVAL;
	}
	if (t->rseq_migrate
			&& !(flags & RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE))
		need_restart = true;
	else if (t->rseq_preempt
			&& !(flags & RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT))
		need_restart = true;
	else if (t->rseq_signal
			&& !(flags & RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL))
		need_restart = true;

	t->rseq_preempt = false;
	t->rseq_signal = false;
	t->rseq_migrate = false;
	if (need_restart)
		return 1;
	return 0;
}

static int rseq_ip_fixup(struct pt_regs *regs)
{
	struct task_struct *t = current;
	void __user *start_ip = NULL;
	unsigned long post_commit_offset = 0;
	void __user *abort_ip = NULL;
	uint32_t cs_flags = 0;
	int ret;

	ret = rseq_get_rseq_cs(t, &start_ip, &post_commit_offset, &abort_ip,
			&cs_flags);
	trace_rseq_ip_fixup((void __user *)instruction_pointer(regs),
		start_ip, post_commit_offset, abort_ip, ret);
	if (!ret)
		return -EFAULT;

	ret = rseq_need_restart(t, cs_flags);
	if (ret < 0)
		return -EFAULT;
	if (!ret)
		return 0;
	/*
	 * Handle potentially not being within a critical section.
	 * Unsigned comparison will be true when
	 * ip < start_ip (wrap-around to large values), and when
	 * ip >= start_ip + post_commit_offset.
	 */
	if ((unsigned long)instruction_pointer(regs) - (unsigned long)start_ip
			>= post_commit_offset)
		return 1;

	instruction_pointer_set(regs, (unsigned long)abort_ip);
	return 1;
}

/*
 * This resume handler should always be executed between any of:
 * - preemption,
 * - signal delivery,
 * and return to user-space.
 *
 * This is how we can ensure that the entire rseq critical section,
 * consisting of both the C part and the assembly instruction sequence,
 * will issue the commit instruction only if executed atomically with
 * respect to other threads scheduled on the same CPU, and with respect
 * to signal handlers.
 */
void __rseq_handle_notify_resume(struct pt_regs *regs)
{
	struct task_struct *t = current;
	int ret;

	if (unlikely(t->flags & PF_EXITING))
		return;
	if (unlikely(!access_ok(VERIFY_WRITE, t->rseq, sizeof(*t->rseq))))
		goto error;
	ret = rseq_ip_fixup(regs);
	if (unlikely(ret < 0))
		goto error;
	if (unlikely(!rseq_update_cpu_id(t)))
		goto error;
	return;

error:
	force_sig(SIGSEGV, t);
}

/*
 * sys_rseq - setup restartable sequences for caller thread.
 */
SYSCALL_DEFINE4(rseq, struct rseq __user *, rseq, uint32_t, rseq_len,
		int, flags, uint32_t, sig)
{
	if (flags & RSEQ_FLAG_UNREGISTER) {
		/* Unregister rseq for current thread. */
		if (current->rseq != rseq || !current->rseq)
			return -EINVAL;
		if (current->rseq_len != rseq_len)
			return -EINVAL;
		if (current->rseq_sig != sig)
			return -EPERM;
		if (!rseq_reset_rseq_cpu_id(current))
			return -EFAULT;
		current->rseq = NULL;
		current->rseq_len = 0;
		current->rseq_sig = 0;
		return 0;
	}

	if (unlikely(flags))
		return -EINVAL;

	if (current->rseq) {
		/*
		 * If rseq is already registered, check whether
		 * the provided address differs from the prior
		 * one.
		 */
		if (current->rseq != rseq
				|| current->rseq_len != rseq_len)
			return -EINVAL;
		if (current->rseq_sig != sig)
			return -EPERM;
		return -EBUSY;	/* Already registered. */
	} else {
		/*
		 * If there was no rseq previously registered,
		 * we need to ensure the provided rseq is
		 * properly aligned and valid.
		 */
		if (!IS_ALIGNED((unsigned long)rseq, __alignof__(*rseq))
				|| rseq_len != sizeof(*rseq))
			return -EINVAL;
		if (!access_ok(VERIFY_WRITE, rseq, rseq_len))
			return -EFAULT;
		current->rseq = rseq;
		current->rseq_len = rseq_len;
		current->rseq_sig = sig;
		/*
		 * If rseq was previously inactive, and has just been
		 * registered, ensure the cpu_id_start and cpu_id fields
		 * are updated before returning to user-space.
		 */
		rseq_set_notify_resume(current);
	}

	return 0;
}
