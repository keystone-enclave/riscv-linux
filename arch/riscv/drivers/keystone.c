#include <asm/sbi.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
//#include <asm/io.h>
//#include <asm/page.h>
#include "keystone.h"

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

long keystone_create_enclave(int __user* eid)
{
  int ret;
  // allocate a page for initial EPM
  unsigned long epm_v = __get_free_page(GFP_HIGHUSER);
  unsigned long epm = __pa(epm_v);
  //unsigned long epm = __pa(get_zeroed_page(GFP_KERNEL)); 

  pr_info("keystone_create_enclave: epmv = 0x%lx, epm = 0x%lx, &eid = 0x%lx\n", epm_v, epm, (long unsigned) eid);
  // SM Call
  ret = SBI_CALL_2(SBI_SM_CREATE_ENCLAVE, epm, PAGE_SIZE);
  if (ret < 0)
  {
    goto fail_after_epm_alloc;
  }
  
  pr_info("keystone_create_enclave: eid = %d\n", ret);
  ret = __copy_to_user(eid, &ret, sizeof(eid));
  return 0;

fail_after_epm_alloc:
  free_pages(epm_v, 0);
  return ret;
}

long keystone_destroy_enclave(int __user eid)
{
  int ret;
  ret = SBI_CALL_1(SBI_SM_DESTROY_ENCLAVE, eid);

  return 0;
}

long keystone_sm_call(unsigned int sm_sbi_function_id, unsigned long arg)
{
  long ret;
  switch(sm_sbi_function_id)
  {
    case SBI_SM_CREATE_ENCLAVE:
      ret = keystone_create_enclave((int __user *)arg);
      break;
    case SBI_SM_DESTROY_ENCLAVE:
      ret = keystone_destroy_enclave((int __user)arg);
      break;
    default:
      return -ENOSYS;
  }
  return ret;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  
  pr_info("keystone_enclave: keystone_ioctl() command = %d\n",cmd);
 
  if(!arg)
  {
    return -EINVAL;
  }

  ret = keystone_sm_call(cmd, arg);
  if(ret)
  {
    pr_err("keystone_enclave: sm returns error %ld\n", ret);
  }
  return ret;
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
