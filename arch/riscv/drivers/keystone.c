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
  epm_t* epm;
  struct keystone_ioctl_enclave_id *enclp = (struct keystone_ioctl_enclave_id*) arg;
  unsigned long code_size = enclp->code_size;
  unsigned long ptr = enclp->ptr;
  unsigned long rt_offset;
  unsigned long epm_vaddr, epm_paddr;
  unsigned long encl_stack_size = PAGE_UP(enclp->mem_size);
  // TODO: Do we want to require that requests are page sized?
  unsigned long req_pages = ((enclp->mem_size + enclp->code_size) / PAGE_SIZE);
  // Must allocate 3(enclave) + 2(runtime) pages for pg tables
  // Plus pages requested
  // rounded up to order of 2
  unsigned long min_pages = req_pages + 16;
  int order = ilog2(min_pages) + 1;
  int count = 0x1 << order;
  unsigned long vaddr;
  
  //pr_info("EPM pages allocated: %d\n", count);
  epm_vaddr = __get_free_pages(GFP_HIGHUSER, order);

  if(!epm_vaddr){
    ret = -ENOMEM;
    pr_err("keystone_create_enclave: Cannot get contiguous memory for enclave. (Tried order %ul)\n", order);
    return ret;
  }
  memset(epm_vaddr, 0, PAGE_SIZE*count);
  epm_paddr = __pa(epm_vaddr);
  ret = -ENOMEM;
  epm = kmalloc(sizeof(epm_t), GFP_KERNEL);
  if(!epm)
    return ret;
  
  epm_init(epm, epm_vaddr, count);

  /* initialize runtime */
  keystone_rtld_init_runtime(epm, epm_vaddr, &rt_offset);

  /* initialize enclave */

  /* setup enclave's stack */

  for(vaddr = rt_offset - encl_stack_size; vaddr < rt_offset; vaddr+= PAGE_SIZE)
  {
    epm_alloc_user_page_noexec(epm, vaddr);
  }
  //pr_info("keystone enclave stack size: %d\n",encl_stack_size);

  // TODO fix code_size so that its smaller, more accurate. right now its the whole elf
  
  ret = keystone_app_load_elf(epm, ptr, code_size);
  if( ret != 0){
    goto error_free_epm;
  }
  //  debug_dump(epm_vaddr, PAGE_SIZE*count);

  enclp->eid = SBI_CALL_2(SBI_SM_CREATE_ENCLAVE, epm_paddr, PAGE_SIZE*count);
  if (enclp->eid < 0)
  {
    ret = enclp->eid;
    pr_err("keystone_create_enclave: SBI call failed\n");
    goto error_free_epm;
  }
  //pr_info("keystone_create_enclave: eid = %lld, page order = %lu, epm_v = 0x%lx,  epm_p = 0x%lx\n", enclp->eid, order, epm_vaddr, epm_paddr );

  kfree(epm);
  return 0;

error_free_epm:
  kfree(epm);
  free_pages(epm_vaddr, order);
  return ret;
}

int keystone_app_load_elf_region(epm_t* epm, unsigned long elf_usr_region, void* target_vaddr, size_t len){ 
  unsigned long va;
  unsigned long encl_page;
  int k, ret = 0;
  size_t copy_size;
  for(va=target_vaddr, k=0; va < target_vaddr+len; va += PAGE_SIZE, k++){

    encl_page = epm_alloc_user_page(epm, va);

    copy_size = (k+1)*PAGE_SIZE > len ? len%PAGE_SIZE : PAGE_SIZE;
    pr_info("Copy elf page to:%x, from: %x, sz:%i\n",
	    encl_page, elf_usr_region + (k * PAGE_SIZE), copy_size);
    // TODO zero out the other part of the last page
    if(copy_from_user((void*) encl_page,
		      (void*) elf_usr_region + (k * PAGE_SIZE),
		      copy_size )){;
      ret = -EFAULT;
      break;
    }
  }
 
  return ret;
}

int keystone_app_load_elf(epm_t* epm, unsigned long elf_usr_ptr, size_t len){
  int retval, error, i;
  struct elf_phdr eppnt;
  struct elfhdr elf_ex;
  struct elf_phdr* next_usr_phoff;
  unsigned long vaddr;
  unsigned long size = 0;
  
  error = -EFAULT;
  
  // TODO safety checks based on len

  if(copy_from_user(&elf_ex, (void*)elf_usr_ptr, sizeof(struct elfhdr)) != 0){
    goto out;
  }


  // check ELF header
  if(memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
    goto out;

  
  // Sanity check on elf type that its been linked as EXEC
  if(elf_ex.e_type != ET_EXEC || !elf_check_arch(&elf_ex))
    goto out;


  // Get each elf_phdr in order and deal with it
  next_usr_phoff = (void*)elf_usr_ptr + elf_ex.e_phoff;
  for(i=0; i<elf_ex.e_phnum; i++, next_usr_phoff++) {

    pr_info("loading ph %i\n",i);
    
    // Copy next phdr
    if(copy_from_user(&eppnt, (void*)next_usr_phoff, sizeof(struct elf_phdr)) != 0){
      //bad
      continue;
    }

    // Create and copy
    if(eppnt.p_type != PT_LOAD) {
      pr_warn("keystone runtime includes an inconsistent program header\n");
      continue;
    }
    vaddr = eppnt.p_vaddr;
    //vaddr sanity check?
    size = eppnt.p_filesz;
    pr_info("loading vaddr: %x, sz:%i\n",vaddr,size);


    retval = keystone_app_load_elf_region(epm,
					  elf_usr_ptr + eppnt.p_offset,
					  (void*)vaddr,
					  size);
    if(retval != 0){
      error = retval;
      break;
    }

  }

  error = 0;

  out:
    return error;
  
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

  //pr_info("keystone_copy_to_enclave() 0x%lx <-- 0x%llx, %ld\n",ptr, datap->ptr, size);

  if(copy_from_user((void*) ptr, (void*) datap->ptr, size)){
    ret = -EFAULT;
    goto cleanup_copy_to;
  }

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
  //pr_info("keystone_copy_from_enclave()\n");
  ret = SBI_CALL(SBI_SM_COPY_FROM_ENCLAVE, eid, __pa(ptr), size);
  
  if(copy_to_user((void*) datap->ptr, (void*) ptr, size)){
    ret = -EFAULT;
    goto cleanup_copy_from;
  }

cleanup_copy_from:
  free_pages(ptr, 0);
  return ret;
}


int keystone_run_enclave(unsigned long arg)
{
  int ret = 0;
  struct keystone_ioctl_run_enclave *run = (struct keystone_ioctl_run_enclave*) arg;
  run->ret = SBI_CALL_2(SBI_SM_RUN_ENCLAVE, run->eid, run->ptr);
  return ret;
}

long keystone_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
  long ret;
  char data[256];

  //pr_info("keystone_enclave: keystone_ioctl() command = %d\n",cmd);

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
