#include "keystone.h"
#include "keystone-sbi-arg.h"
#include "keystone-page.h"
#include "keystone_user.h"
#include <linux/uaccess.h>

int keystone_create_enclave(unsigned long arg)
{
  int ret;
  
  /* create parameters */
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave*) arg;
  unsigned long eapp_sz = enclp->eapp_sz;
  unsigned long eapp_ptr = enclp->eapp_ptr;
  unsigned long eapp_stack_sz = enclp->eapp_stack_sz;
  unsigned long rt_ptr = enclp->runtime_ptr;
  unsigned long rt_sz = enclp->runtime_sz;
  unsigned long rt_stack_sz = enclp->runtime_stack_sz;

  /* enclave data*/
  enclave_t* enclave;

  /* local variables */
  unsigned long rt_offset;
  unsigned long min_pages = calculate_required_pages(eapp_sz, eapp_stack_sz, rt_sz, rt_stack_sz);

  enclave = create_enclave(min_pages);
  if(enclave == NULL)
    return -ENOMEM;

  /* initialize runtime */
  if (keystone_rtld_init_runtime(enclave, rt_ptr, rt_sz, rt_stack_sz, &rt_offset)) {
    keystone_err("failed to initialize runtime\n");
    goto error_free_enclave;
  }

  if (keystone_rtld_init_app(enclave, eapp_ptr, eapp_sz, eapp_stack_sz, rt_offset)) {
    keystone_err("failed to initialize app\n");
    goto error_free_enclave;
  }

  struct keystone_sbi_create_t create_args;
  create_args.epm_region.paddr = enclave->epm->pa;
  create_args.epm_region.size = enclave->epm->total;
  create_args.copy_region.paddr = 0;
  create_args.copy_region.size = 0;
  // SM will write the eid to enclave_t.eid
  create_args.eid_pptr =  __pa(&enclave->eid);

  ret = SBI_CALL_1(SBI_SM_CREATE_ENCLAVE, __pa(&create_args));
  if (ret)
  {
    keystone_err("keystone_create_enclave: SBI call failed\n");
    goto error_free_enclave;
  }

  /* allocate UID */
  enclp->eid = enclave_idr_alloc(enclave);
  
  return 0;

error_free_enclave:
  destroy_enclave(enclave);
  return -EFAULT;
}

int keystone_destroy_enclave(unsigned long arg)
{
  int ret;
  struct keystone_ioctl_create_enclave *enclp = (struct keystone_ioctl_create_enclave*) arg;
  unsigned long ueid = enclp->eid;
  enclave_t* enclave;
  enclave = get_enclave_by_id(ueid);

  ret = SBI_CALL_1(SBI_SM_DESTROY_ENCLAVE, enclave->eid);
  if(ret) {
    keystone_err("fatal: cannot destroy enclave: SBI failed\n");
    return ret;
  }

  destroy_enclave(enclave);
  enclave_idr_remove(ueid);

  return 0;
}

int keystone_run_enclave(unsigned long arg)
{
  int ret = 0;
  struct keystone_ioctl_run_enclave *run = (struct keystone_ioctl_run_enclave*) arg;
  unsigned long ueid = run->eid;
  enclave_t* enclave;
  enclave = get_enclave_by_id(ueid);

  struct keystone_sbi_run_t run_args;
  run_args.eid = enclave->eid;
  run_args.entry_ptr = run->entry;
  run_args.ret_ptr = __pa(&run->ret);

  keystone_info("enclave_ptr: 0x%lx, eid: %d, ueid: %d\n", enclave, enclave->eid, run->eid);
  
  ret = SBI_CALL_1(SBI_SM_RUN_ENCLAVE, __pa(&run_args));
  while(ret == 2)
  {
    ret = SBI_CALL_1(SBI_SM_RESUME_ENCLAVE, run_args.eid);
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


