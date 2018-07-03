#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <linux/file.h>

#define SBI_SM_CREATE_ENCLAVE   101
#define SBI_SM_DESTROY_ENCLAVE  102

long keystone_ioctl(struct file* filep, unsigned int cmd, unsigned long arg);

struct keystone_enclave_t 
{
  int eid;
  uintptr_t epm_ptr;
  uintptr_t epm_sz;
};

// keystone enclave functions
long keystone_create_enclave(int* eid); 
long keystone_destroy_enclave(int eid);

#endif
