// Filename: keystone-rtld.c
// Description: Keystone enclave runtime loader
// Author: Dayeol Lee <dayeol@berkeley.edu> 

#include <linux/elf.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>

#define KEYSTONE_RUNTIME_FILEPATH "/lib/keystone-rt"

int keystone_rtld_init_runtime(unsigned long epm_paddr)
{
  int retval, error, i, j;
  struct elf_phdr *elf_phdata;
  struct elf_phdr *eppnt;
  unsigned long elf_bss, bss, len;
  struct elfhdr elf_ex;
  loff_t pos = 0;
  struct file *file;
  const char *fname = KEYSTONE_RUNTIME_FILEPATH;

  file = filp_open(fname, O_RDONLY, 0600);
  error = PTR_ERR(file);
  if (IS_ERR(file))
    goto out;

  error = -ENOEXEC;
  if(kernel_read(file, &elf_ex, sizeof(elf_ex), &pos) != sizeof(elf_ex))
    goto out;

  // check ELF header
  if(memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
    goto out;

  // check runtime consistency
  if(elf_ex.e_type != ET_EXEC || !elf_check_arch(&elf_ex) || !file->f_op->mmap)
    goto out;

  j = sizeof(struct elf_phdr) * elf_ex.e_phnum;

  error = -ENOMEM;
  elf_phdata = kmalloc(j, GFP_KERNEL);
  if(!elf_phdata)
    goto out;

  eppnt = elf_phdata;
  error = -ENOEXEC;
  pos = elf_ex.e_phoff;
  retval = kernel_read(file, eppnt, j, &pos);
  if(retval != j)
    goto out_free_ph;
  
  pr_info("%d\n",__LINE__);
  for(j=0, i=0; i<elf_ex.e_phnum; i++)
    if((eppnt + i)->p_type == PT_LOAD)
      j++;

  //if(j != 1)
  //  goto out_free_ph;

  pr_info("%d\n",__LINE__);
  while (eppnt->p_type != PT_LOAD)
    eppnt++;
  
  error = 0;
out_free_ph:
  kfree(elf_phdata);
out:
  return error;
}

