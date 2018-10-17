#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <linux/file.h>
#include "keystone-page.h"

#define SBI_SM_CREATE_ENCLAVE   101
#define SBI_SM_DESTROY_ENCLAVE  102
#define SBI_SM_COPY_TO_ENCLAVE  103
#define SBI_SM_COPY_FROM_ENCLAVE  104
#define SBI_SM_RUN_ENCLAVE      105

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

struct keystone_enclave_t 
{
  int eid;
  uintptr_t epm_ptr;
  uintptr_t epm_sz;
};

// global debug functions
void debug_dump(char* ptr, unsigned long size);

// keystone enclave functions
int keystone_create_enclave(unsigned long arg); 
int keystone_destroy_enclave(unsigned long arg);
int keystone_copy_to_enclave(unsigned long arg);
int keystone_copy_from_enclave(unsigned long arg);
// runtime loader
int keystone_rtld_init_runtime(epm_t* epm, unsigned long epm_vaddr, unsigned long*  rt_offset);

// elf loading
int keystone_app_load_elf_region(epm_t* epm, unsigned long elf_usr_region, void* target_vaddr, size_t len);
int keystone_app_load_elf(epm_t* epm, unsigned long elf_usr_ptr, size_t len);
#endif
