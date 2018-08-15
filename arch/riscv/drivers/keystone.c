#include <asm/sbi.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

//#include <asm/io.h>
//#include <asm/page.h>
#include "keystone.h"
#include "keystone-page.h"

#include "keystone_user.h"
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

int keystone_create_enclave(unsigned long arg)
{
  int ret;
  pg_list_t* pglist;
  struct keystone_ioctl_enclave_id *enclp = (struct keystone_ioctl_enclave_id*) arg;
  // allocate a page for initial EPM
  // minimum # of pages:
  // 1st-level pg table: 1
  // 2nd-level pg table: 1
  // 3rd-level pg table: 1
  // enclave page: 1
  // total: 4 pages = order of 2
  int order = 2;
  int count = 0x1 << order;
  unsigned long epm_v = __get_free_pages(GFP_HIGHUSER, order);
  unsigned long epm = __pa(epm_v);

  pr_info("keystone_create_enclave: epm_v = 0x%lx, epm = 0x%lx\n", epm_v, epm);

  pglist = kmalloc(sizeof(pg_list_t), GFP_KERNEL);
  
  init_free_pages(pglist, epm_v, count);

  keystone_rtld_init_runtime(epm_v);
  
  enclp->eid = SBI_CALL_2(SBI_SM_CREATE_ENCLAVE, epm, PAGE_SIZE*count);
  if (enclp->eid < 0)
  {
    ret = enclp->eid;
    goto error_free_epm;
  }
  pr_info("keystone_create_enclave: eid = %lld\n", enclp->eid);

  kfree(pglist);
  return 0;

error_free_pglist:
  kfree(pglist);

error_free_epm:
  free_pages(epm_v, order);
  return ret;
}

int keystone_destroy_enclave(unsigned long arg)
{
  int ret;
  struct keystone_ioctl_enclave_id *enclp = (struct keystone_ioctl_enclave_id*) arg;
  ret = SBI_CALL_1(SBI_SM_DESTROY_ENCLAVE, enclp->eid);
  if(ret < 0)
    return ret;

  return 0;
}

int keystone_copy_to_enclave(unsigned long arg)
{
  int ret = 0;
  struct keystone_ioctl_enclave_data *datap = (struct keystone_ioctl_enclave_data*) arg;

  unsigned long eid = datap->eid;
  unsigned long size = datap->size;
  unsigned long ptr = __get_free_page(GFP_KERNEL);

  if(size > 0x1000) {
    ret = -EINVAL;
    goto cleanup_copy_to;
  }

  pr_info("keystone_copy_to_enclave() 0x%lx <-- 0x%llx, %ld\n",ptr, datap->ptr, size);

  if(copy_from_user((void*) ptr, (void*) datap->ptr, size))
    return -EFAULT;

  ret = SBI_CALL_4(SBI_SM_COPY_TO_ENCLAVE, eid, datap->ptr, __pa(ptr), size);

cleanup_copy_to:
  free_pages(ptr, 0);
  return ret;
}

int keystone_copy_from_enclave(unsigned long arg)
{
  int ret = 0;
  struct keystone_ioctl_enclave_data *datap = (struct keystone_ioctl_enclave_data*) arg;

  unsigned long eid = datap->eid;
  unsigned long size = datap->size;
  unsigned long ptr = __get_free_page(GFP_KERNEL);

  if(size > 0x1000) {
    ret = -EINVAL;
    goto cleanup_copy_from;
  }
  pr_info("keystone_copy_from_enclave()\n");
  ret = SBI_CALL(SBI_SM_COPY_FROM_ENCLAVE, eid, __pa(ptr), size);
  
  if(copy_to_user((void*) datap->ptr, (void*) ptr, size))
    return -EFAULT;

cleanup_copy_from:
  free_pages(ptr, 0);
  return ret;
}


int keystone_run_enclave(unsigned long arg)
{
  int ret = 0;
  struct keystone_ioctl_run_enclave *run = (struct keystone_ioctl_run_enclave*) arg;
  ret = SBI_CALL_2(SBI_SM_RUN_ENCLAVE, run->eid, run->ptr);
  
  return ret;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  char data[256];

  pr_info("keystone_enclave: keystone_ioctl() command = %d\n",cmd);

  if(!arg)
    return -EINVAL;
  
  if(copy_from_user(data, (void __user*) arg, _IOC_SIZE(cmd)))
    return -EFAULT;

  switch(cmd)
  {
    case KEYSTONE_IOC_CREATE_ENCLAVE:
      ret = keystone_create_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_DESTROY_ENCLAVE:
      ret = keystone_destroy_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_COPY_TO_ENCLAVE:
      ret = keystone_copy_to_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_COPY_FROM_ENCLAVE:
      ret = keystone_copy_from_enclave((unsigned long) data);
      break;
    case KEYSTONE_IOC_RUN_ENCLAVE:
      ret = keystone_run_enclave((unsigned long) data);
      break;
    default:
      return -ENOSYS;
  }

  if(copy_to_user((void __user*) arg, data, _IOC_SIZE(cmd)))
    return -EFAULT;
  
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
