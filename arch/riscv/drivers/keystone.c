//#include <asm/io.h>
//#include <asm/page.h>
#include "keystone.h"
#include "keystone-sbi-arg.h"
#include "keystone-page.h"

#include <linux/mm.h>

#include "keystone_user.h"
#define   DRV_DESCRIPTION   "keystone enclave"
#define   DRV_VERSION       "0.1"

static const struct file_operations keystone_fops = {
    .owner          = THIS_MODULE,
    .mmap           = keystone_mmap,
    .unlocked_ioctl = keystone_ioctl
};

static struct miscdevice keystone_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = "keystone_enclave",
  .fops = &keystone_fops,
  .mode = 0666,
};

int keystone_mmap(struct file* filp, struct vm_area_struct *vma)
{
  struct utm_t* utm;
  utm = filp->private_data;
  unsigned long vsize = vma->vm_end - vma->vm_start;
  unsigned long psize = utm->size;
  if (vsize > psize)
    return -EINVAL;

  remap_pfn_range(vma, 
      vma->vm_start, 
      __pa(utm->ptr) >> PAGE_SHIFT,
      vsize, vma->vm_page_prot);
  return 0;
}

static int __init keystone_dev_init(void)
{
  int  ret;

  ret = misc_register(&keystone_dev);
  if (ret < 0)
  {
    pr_err("keystone_enclave: misc_register() failed\n"); 
  }
  pr_info("keystone_enclave: " DRV_DESCRIPTION " v" DRV_VERSION "\n"); 
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
