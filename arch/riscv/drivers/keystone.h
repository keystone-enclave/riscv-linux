#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <linux/file.h>

#define SBI_SM_CREATE_ENCLAVE   101
#define SBI_SM_DESTROY_ENCLAVE  102
#define SBI_SM_COPY_TO_ENCLAVE  103
#define SBI_SM_COPY_FROM_ENCLAVE  104

long keystone_ioctl(struct file* filep, unsigned int cmd, unsigned long arg);

struct keystone_enclave_t 
{
  int eid;
  uintptr_t epm_ptr;
  uintptr_t epm_sz;
};

// keystone enclave functions
int keystone_create_enclave(unsigned long arg); 
int keystone_destroy_enclave(unsigned long arg);
int keystone_copy_to_enclave(unsigned long arg);
int keystone_copy_from_enclave(unsigned long arg);
#endif
