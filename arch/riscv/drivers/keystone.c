#include <asm/sbi.h>
#include "keystone.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
//#include <asm/io.h>
//#include <asm/page.h>

#define   DRV_DESCRIPTION   "keystone enclave"
#define   DRV_VERSION       "0.1"

static const struct file_operations keystone_fops = {
    .owner        = THIS_MODULE,
    .unlocked_ioctl        = keystone_ioctl
};

static struct miscdevice keystone_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "keystone_enclave",
  .fops = &keystone_fops,
  .mode = 0666,
};

#define SM_CALL_TRAP  8 // ecall from u-mode trap vector

#define ABI_SM_DEADBEEF   999
#define ABI_SM_GET_FIELD  1000
#define ABI_SM_AES        1001
#define ABI_SM_SIGN       1002
#define ABI_SM_POET       1003

#define SM_FIELD_PK_D     100
#define SM_FIELD_H_SM     101
#define SM_FIELD_PK_SM    102
#define SM_FIELD_SIGN_D   103


unsigned long keystone_sm_call(unsigned int sm_abi_function_id)
{
  return SBI_CALL_0( sm_abi_function_id );
  /*
  pr_info("sm_call input %d", sm_abi_function_id);
  register uintptr_t a0 asm("a0");
  register uintptr_t a1 asm("a1");
  register uintptr_t a7 asm("a7");
  a7 = (uintptr_t)(sm_abi_function_id);
  pr_info("sm_call a7 %ld, a0 %ld, a1 %ld", a7, a0, a1);
  asm volatile("ecall"
      : "+r" (a0)
      : "r" (a7)
      : "memory");
  pr_info("sm_call returns with %ld", a0);
  return a0;
  */
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  pr_info("keystone_enclave: ioctl called , cmd: %d\n",cmd);
  unsigned long ret;
  ret = keystone_sm_call(cmd);
  pr_info("keystone_enclave: sm return %ld\n", ret);
  return 0;
}

static int __init keystone_dev_init(void)
{
  int  ret;
  pr_info("keystone_enclave: " DRV_DESCRIPTION " v" DRV_VERSION "\n"); 
  ret = misc_register(&keystone_dev);
  if (ret < 0)
  {
    pr_err("keystone_enclave: misc_register() failed\n"); 
  }
  return ret;
}

static void __exit keystone_dev_exit(void)
{
  pr_info("keystone_enclave: keystone_dev_exit()\n");
  misc_deregister(&keystone_dev);
  return;
}

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Dayeol Lee <dayeol@berkeley.edu>");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

module_init(keystone_dev_init);
module_exit(keystone_dev_exit);
