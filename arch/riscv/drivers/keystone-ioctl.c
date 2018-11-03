#include "keystone.h"
#include "keystone-sbi-arg.h"
#include "keystone-page.h"
#include "keystone_user.h"
#include <linux/uaccess.h>

int keystone_create_enclave(unsigned long arg)
{
  int ret;
  epm_t* epm;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave*) arg;
  unsigned long eapp_sz = enclp->eapp_sz;
  unsigned long eapp_ptr = enclp->eapp_ptr;
  unsigned long eapp_stack_sz = PAGE_UP(enclp->eapp_stack_sz);
  unsigned long rt_ptr = enclp->runtime_ptr;
  unsigned long rt_sz = enclp->runtime_sz;
  unsigned long rt_stack_sz = PAGE_UP(enclp->runtime_stack_sz);

  unsigned long rt_offset;
  unsigned long epm_vaddr, epm_paddr;

  unsigned long req_pages = ((enclp->eapp_stack_sz + enclp->eapp_sz + PAGE_SIZE - 1) / PAGE_SIZE);
  // FIXME: calculate the required number of pages!
  // For now, we must allocate at least 1 (top) + 2 (enclave) + 2 (runtime) pages for pg tables
  // Plus pages requested for the stack
  // rounded up to order of 2
  unsigned long min_pages = req_pages + 15; // TODO: calculate req_pages + # page tables + runtime size
  int order = ilog2(min_pages) + 1;
  int count = 0x1 << order;
  unsigned long vaddr;
 
  /* allocate contiguous memory */
  epm_vaddr = __get_free_pages(GFP_HIGHUSER, order);
  if(!epm_vaddr){
    ret = -ENOMEM;
    keystone_err("keystone_create_enclave(): failed to allocate %d page(s)\n", count);
    return ret;
  }

  /* initialize */
  memset(epm_vaddr, 0, PAGE_SIZE*count);
  epm_paddr = __pa(epm_vaddr);

  ret = -ENOMEM;
  epm = kmalloc(sizeof(epm_t), GFP_KERNEL);
  if(!epm)
    return ret;
  
  epm_init(epm, epm_vaddr, count);

  /* initialize runtime */
  if(keystone_rtld_init_runtime(epm, epm_vaddr, rt_ptr, rt_sz, &rt_offset)) {
    keystone_err("failed to initialize runtime");
  }

  /* initialize enclave */
  
  /* setup enclave's stack */
  for(vaddr = rt_offset - eapp_stack_sz; vaddr < rt_offset; vaddr+= PAGE_SIZE)
  {
    epm_alloc_user_page_noexec(epm, vaddr);
  }

  // TODO fix eapp_sz so that its smaller, more accurate. right now its the whole elf
  
  ret = keystone_app_load_elf(epm, eapp_ptr, eapp_sz);
  if( ret != 0){
    goto error_free_epm;
  }
  //  debug_dump(epm_vaddr, PAGE_SIZE*count);

  struct keystone_sbi_create_t create_args;
  create_args.epm_region.paddr = epm_paddr;
  create_args.epm_region.size = PAGE_SIZE*count;
  create_args.copy_region.paddr = 0;
  create_args.copy_region.size = 0;
  create_args.eid_pptr =  __pa(&enclp->eid);

  ret = SBI_CALL_1(SBI_SM_CREATE_ENCLAVE, __pa(&create_args));
  if (ret)
  {
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


int keystone_destroy_enclave(unsigned long arg)
{
  int ret;
  //TODO: free EPM memory!!
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave*) arg;
  ret = SBI_CALL_1(SBI_SM_DESTROY_ENCLAVE, enclp->eid);
  if(ret)
    return ret;

  return 0;
}

int keystone_run_enclave(unsigned long arg)
{
  int ret = 0;
  struct keystone_ioctl_run_enclave *run = (struct keystone_ioctl_run_enclave*) arg;

  struct keystone_sbi_run_t run_args;
  run_args.eid = run->eid;
  run_args.entry_ptr = run->entry;
  run_args.ret_ptr = __pa(&run->ret);
  
  ret = SBI_CALL_1(SBI_SM_RUN_ENCLAVE, __pa(&run_args));
  while(ret == 2)
  {
    ret = SBI_CALL_1(SBI_SM_RESUME_ENCLAVE, run->eid);
  }
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


