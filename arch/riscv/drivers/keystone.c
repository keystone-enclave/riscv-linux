//#include <asm/io.h>
//#include <asm/page.h>
#include "keystone.h"
#include "keystone-sbi-arg.h"
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
int keystone_app_load_elf_region(epm_t* epm, unsigned long elf_usr_region, void* target_vaddr, size_t len){ 
  unsigned long va;
  unsigned long encl_page;
  int k, ret = 0;
  size_t copy_size;
  for(va=target_vaddr, k=0; va < target_vaddr+len; va += PAGE_SIZE, k++){

    encl_page = epm_alloc_user_page(epm, va);

    copy_size = (k+1)*PAGE_SIZE > len ? len%PAGE_SIZE : PAGE_SIZE;
    //pr_info("Copy elf page to:%x, from: %x, sz:%i\n",
    //	    encl_page, elf_usr_region + (k * PAGE_SIZE), copy_size);
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
  next_usr_phoff = (void*) elf_usr_ptr + elf_ex.e_phoff;
  for(i=0; i<elf_ex.e_phnum; i++, next_usr_phoff++) {

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
    //pr_info("loading vaddr: %x, sz:%i\n",vaddr,size);

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
