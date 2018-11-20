#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <asm/sbi.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/idr.h>

#include <linux/file.h>
#include "keystone-page.h"

#define SBI_SM_CREATE_ENCLAVE   101
#define SBI_SM_DESTROY_ENCLAVE  102
#define SBI_SM_RUN_ENCLAVE      105
#define SBI_SM_STOP_ENCLAVE     106
#define SBI_SM_RESUME_ENCLAVE   107

/* error codes: need to add more */
#define ENCLAVE_INTERRUPTED     2

/* don't want to taint asm/sbi.h, so just copied SBI_CALL and increased # args */
#define _SBI_CALL(which, arg0, arg1, arg2, arg3, arg4, arg5) ({			\
	register uintptr_t a0 asm ("a0") = (uintptr_t)(arg0);	\
	register uintptr_t a1 asm ("a1") = (uintptr_t)(arg1);	\
	register uintptr_t a2 asm ("a2") = (uintptr_t)(arg2);	\
	register uintptr_t a3 asm ("a3") = (uintptr_t)(arg3);	\
	register uintptr_t a4 asm ("a4") = (uintptr_t)(arg4);	\
	register uintptr_t a5 asm ("a5") = (uintptr_t)(arg5);	\
	register uintptr_t a7 asm ("a7") = (uintptr_t)(which);	\
	asm volatile ("ecall"					\
		      : "+r" (a0)				\
		      : "r" (a1), "r" (a2), "r" (a3), "r" (a4), "r"(a5), "r" (a7)		\
		      : "memory");				\
	a0;							\
})

#define SBI_CALL_3(which, arg0, arg1, arg2) SBI_CALL(which,arg0, arg1, arg2)
#define SBI_CALL_4(which, arg0, arg1, arg2, arg3) _SBI_CALL(which, arg0, arg1, arg2, arg3, 0, 0)
#define SBI_CALL_5(which, arg0, arg1, arg2, arg3, arg4) _SBI_CALL(which, arg0, arg1, arg2, arg3, arg4, 0)
#define SBI_CALL_6(which, arg0, arg1, arg2, arg3, arg4, arg5) _SBI_CALL(which, arg0, arg1, arg2, arg3, arg4, arg5)

long keystone_ioctl(struct file* filep, unsigned int cmd, unsigned long arg);
int keystone_mmap(struct file *filp, struct vm_area_struct *vma);

typedef struct keystone_enclave_t 
{
  unsigned int eid;
  struct utm_t* utm;
  struct epm_t* epm;
} enclave_t;


// global debug functions
void debug_dump(char* ptr, unsigned long size);

// runtime/app loader
int keystone_rtld_init_runtime(enclave_t* enclave, void* __user rt_ptr, size_t rt_sz, unsigned long rt_stack_sz, unsigned long* rt_offset);

int keystone_rtld_init_app(enclave_t* enclave, void* __user app_ptr, size_t app_sz, size_t app_stack_sz, unsigned long stack_offset);

// untrusted memory mapper
int keystone_rtld_init_untrusted(enclave_t* enclave, void* untrusted_ptr, size_t untrusted_size);

enclave_t* get_enclave_by_id(unsigned int ueid);
enclave_t* create_epm(unsigned long min_pages);
int destroy_epm(enclave_t* enclave);

unsigned int enclave_idr_alloc(enclave_t* enclave);
enclave_t* enclave_idr_remove(unsigned int ueid);
enclave_t* get_enclave_by_id(unsigned int ueid);

unsigned long calculate_required_pages(
    unsigned long eapp_sz,
    unsigned long eapp_stack_sz,
    unsigned long rt_sz,
    unsigned long rt_stack_sz);

#define keystone_info(fmt, ...) \
  pr_info("keystone_enclave: " fmt, ##__VA_ARGS__)
#define keystone_err(fmt, ...) \
  pr_err("keystone_enclave: " fmt, ##__VA_ARGS__)
#define keystone_warn(fmt, ...) \
  pr_warn("keystone_enclave: " fmt, ##__VA_ARGS__)
#endif
