/* Minimal Linux Intel Processor Trace driver. */

/*
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively you can use this file under the GPLv2.
 */


/* Notebook:
   Auto probe largest buffer
   Test old kernels
   Test 32bit
   */

#define DEBUG 1

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <linux/syscore_ops.h>
#include <trace/events/sched.h>
#include <asm/msr.h>
#include <asm/processor.h>
#define CREATE_TRACE_POINTS
#include "pttp.h"

#include "compat.h"
#include "simple-pt.h"

#define MSR_IA32_RTIT_OUTPUT_BASE	0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS	0x00000561
#define MSR_IA32_RTIT_CTL		0x00000570
#define TRACE_EN	BIT_ULL(0)
#define CYC_EN		BIT_ULL(1)
#define CTL_OS		BIT_ULL(2)
#define CTL_USER	BIT_ULL(3)
#define PT_ERROR	BIT_ULL(4)
#define CR3_FILTER	BIT_ULL(7)
#define TO_PA		BIT_ULL(8)
#define MTC_EN		BIT_ULL(9)
#define TSC_EN		BIT_ULL(10)
#define DIS_RETC	BIT_ULL(11)
#define BRANCH_EN	BIT_ULL(13)
#define MTC_MASK	(0xf << 14)
#define CYC_MASK	(0xf << 19)
#define PSB_MASK	(0xf << 24)
#define ADDR0_SHIFT	32
#define ADDR1_SHIFT	32
#define ADDR0_MASK	(0xfULL << ADDR0_SHIFT)
#define ADDR1_MASK	(0xfULL << ADDR1_SHIFT)
#define MSR_IA32_RTIT_STATUS		0x00000571
#define MSR_IA32_CR3_MATCH		0x00000572
#define TOPA_STOP	BIT_ULL(4)
#define TOPA_INT	BIT_ULL(2)
#define TOPA_END	BIT_ULL(0)
#define TOPA_SIZE_SHIFT 6
#define MSR_IA32_ADDR0_START		0x00000580
#define MSR_IA32_ADDR0_END		0x00000581
#define MSR_IA32_ADDR1_START		0x00000582
#define MSR_IA32_ADDR1_END		0x00000583

static void do_enumerate_all(void);
static int enumerate_all;

static int enumerate_set(const char *val, const struct kernel_param *kp)
{
	int ret = param_set_int(val, kp);
	if (enumerate_all)
		do_enumerate_all();
	return ret;
}

static struct kernel_param_ops enumerate_ops = {
	.set = enumerate_set,
	.get = param_get_int,
};

static bool has_cr3_match;

static char comm_filter[100];
module_param_string(comm_filter, comm_filter, sizeof(comm_filter), 0644);
MODULE_PARM_DESC(comm_filter, "Process name to set CR3 filter for");

static int enumerate_all = 0;
module_param_cb(enumerate_all, &enumerate_ops, &enumerate_all, 0644);
MODULE_PARM_DESC(enumerate_all, "Enumerate all processes CR3s (only use after initialization)");

static unsigned long tasklist_lock_ptr;
module_param(tasklist_lock_ptr, ulong, 0400);
MODULE_PARM_DESC(tasklist_lock_ptr, "Set address of tasklist_lock (for kernels without CONFIG_KALLSYMS_ALL)");

static DEFINE_MUTEX(restart_mutex);

static inline int pt_wrmsrl_safe(unsigned msr, u64 val)
{
	int ret = wrmsrl_safe(msr, val);
	trace_msr(msr, val, ret != 0, 0);
	return ret;
}

static inline int pt_rdmsrl_safe(unsigned msr, u64 *val)
{
	int ret = rdmsrl_safe(msr, val);
	trace_msr(msr, *val, ret != 0, 1);
	return ret;
}

static void init_mask_ptrs(void)
{
//	if (single_range)
//		pt_wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS,
//			((1ULL << (PAGE_SHIFT + pt_buffer_order)) - 1));
//	else
		pt_wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0ULL);
}

/* Log CR3 of all already running processes. */
static void do_enumerate_all(void)
{
	struct task_struct *t;
	/* XXX, better way? */
	rwlock_t *my_tasklist_lock = (rwlock_t *)tasklist_lock_ptr;
	if (!my_tasklist_lock)
		my_tasklist_lock = (rwlock_t *)kallsyms_lookup_name("tasklist_lock");
	if (!my_tasklist_lock) {
		pr_err("Cannot find tasklist_lock. CONFIG_KALLSYMS_ALL disabled?\n");
		pr_err("Specify tasklist_lock_ptr parameter at module load\n");
		return;
	}

	read_lock(my_tasklist_lock);
	for_each_process (t) {
		if ((t->flags & PF_KTHREAD) || !t->mm)
			continue;
		/* Cannot get the file name here, leave that to user space */
        printk("enum all : Tracing %d\n", t->pid);
		trace_process_cr3(t->pid, __pa(t->mm->pgd), t->comm);
	}
	read_unlock(my_tasklist_lock);
}

static void simple_pt_init_msrs(void)
{
	init_mask_ptrs();
	pt_wrmsrl_safe(MSR_IA32_RTIT_STATUS, 0ULL);
}

static void set_cr3_filter(void *arg)
{
	u64 val;

	if (pt_rdmsrl_safe(MSR_IA32_RTIT_CTL, &val) < 0)
		return;
	if ((val & TRACE_EN) && pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val & ~TRACE_EN) < 0)
		return;
	if (pt_wrmsrl_safe(MSR_IA32_CR3_MATCH, *(u64 *)arg) < 0)
		pr_err("cpu %d, cannot set cr3 filter\n", smp_processor_id());
	if ((val & TRACE_EN) && pt_wrmsrl_safe(MSR_IA32_RTIT_CTL, val) < 0)
		return;
}

static bool match_comm(void)
{
	char *s;

	s = strchr(comm_filter, '\n');
	if (s)
		*s = 0;
	if (comm_filter[0] == 0) {
		return true;
    }
	return !strcmp(current->comm, comm_filter);
}

static u64 retrieve_cr3(void)
{
	u64 cr3;
	asm volatile("mov %%cr3,%0" : "=r" (cr3));
	return cr3;
}

static void probe_sched_process_exec(void *arg,
				     struct task_struct *p, pid_t old_pid,
				     struct linux_binprm *bprm)
{
	u64 cr3 = retrieve_cr3();
	char *pathbuf, *path;

	if (!match_comm())
		return;

	pathbuf = (char *)__get_free_page(GFP_KERNEL);
	if (!pathbuf)
		return;

	/* mmap_sem needed? */
	path = d_path(&current->mm->exe_file->f_path, pathbuf, PAGE_SIZE);
	if (IS_ERR(path))
		goto out;
	trace_exec_cr3(cr3, path, current->pid);
	if (comm_filter[0] && has_cr3_match) {
		mutex_lock(&restart_mutex);
		on_each_cpu(set_cr3_filter, &cr3, 1);
		mutex_unlock(&restart_mutex);
	}
out:
	free_page((unsigned long)pathbuf);
}

static int probe_mmap_region(struct kprobe *kp, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
	struct file *file = (struct file *)regs->di;
	unsigned long addr = regs->si;
	unsigned long len = regs->dx;
	unsigned long vm_flags = regs->cx;
	unsigned long pgoff = regs->r8;
#else
	/* Assume regparm(3) */
	struct file *file = (struct file *)regs->ax;
	unsigned long addr = regs->dx;
	unsigned long len = regs->cx;
	unsigned long vm_flags = ((u32 *)(regs->sp))[1];
	unsigned long pgoff = ((u32 *)(regs->sp))[2];
#endif
	char *pathbuf, *path;

	if (!(vm_flags & VM_EXEC) || !file)
		return 0;

	if (!match_comm())
		return 0;

	pathbuf = (char *)__get_free_page(GFP_KERNEL);
	if (!pathbuf)
		return 0;

	path = d_path(&file->f_path, pathbuf, PAGE_SIZE);
	if (IS_ERR(path))
		goto out;

	trace_mmap_cr3(retrieve_cr3(), path, pgoff, addr, len,
		       current->pid);
out:
	free_page((unsigned long)pathbuf);
	return 0;
}

static struct kprobe mmap_kp = {
	.symbol_name = "mmap_region",
	.pre_handler = probe_mmap_region,
};


static int simple_pt_init(void)
{
	int err;

	if (THIS_MODULE->taints)
		fix_tracepoints();
    simple_pt_init_msrs();
	
    /* Trace exec->cr3 */
	err = compat_register_trace_sched_process_exec(probe_sched_process_exec, NULL);
	if (err)
		pr_info("Cannot register exec tracepoint: %d\n", err);

	/* Trace mmap */
	err = register_kprobe(&mmap_kp);
	if (err < 0) {
		pr_err("registering mmap_region kprobe failed: %d\n", err);
		/* Ignore error */
	}
	return err;
}

static void simple_pt_exit(void)
{
	compat_unregister_trace_sched_process_exec(probe_sched_process_exec, NULL);
	unregister_kprobe(&mmap_kp);
	pr_info("exited\n");
}

module_init(simple_pt_init);
module_exit(simple_pt_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Suchakra Sharma");
