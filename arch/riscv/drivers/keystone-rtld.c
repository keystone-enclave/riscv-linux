// Filename: keystone-rtld.c
// Description: Keystone enclave runtime loader
// Author: Dayeol Lee <dayeol@berkeley.edu> 

#include <linux/elf.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include "keystone-page.h"

#define KEYSTONE_RUNTIME_FILEPATH "/lib/keystone-rt"

void encl_mm_init(encl_mm_t* mm)
{
  mm->start_vm = 0;
  mm->end_vm = 0;
  mm->text = 0;
  mm->end_text = 0;
  mm->data = 0;
  mm->end_data = 0;
  mm->bss = 0;
  mm->end_bss = 0;
  mm->stack_top = 0;
  mm->brk = 0;
  mm->start_brk = 0;
}

vaddr_t encl_vm_mmap(epm_t* epm, vaddr_t encl_addr, unsigned long size,
   struct file* file, struct elf_phdr* phdr)
{
  unsigned int k, retval;
  loff_t pos = 0;
  vaddr_t va_start = PAGE_DOWN(encl_addr);
  vaddr_t va_end = PAGE_UP(encl_addr + size);
  vaddr_t va;

  pr_info("va_start: 0x%lx, va_end: 0x%lx\n", va_start, va_end);

  pos = phdr->p_offset;
  for(va=va_start, k=0; va < va_end; va += PAGE_SIZE, k++)
  {
    int i;
    vaddr_t epm_page;
    epm_page = epm_alloc_page(epm, va);
    pr_info("encl_mmap va: 0x%lx, target: 0x%lx\n", va, epm_page);
    retval = kernel_read(file, epm_page, PAGE_SIZE, &pos);
   
    pr_info("debug dump:\n"); 
    for(i=0; i<PAGE_SIZE; i++)
    {
      //pr_info("%02x ", *((char*) epm_page + i) & 0xff );
    }
  }
} 

int keystone_rtld_init_runtime(epm_t* epm, unsigned long epm_vaddr)
{
  int retval, error, i, j;
  int total_size;
  struct elf_phdr *elf_phdata;
  struct elf_phdr *eppnt;
  struct elfhdr elf_ex;
  loff_t pos = 0;
  struct file *file;
  const char *fname = KEYSTONE_RUNTIME_FILEPATH;
  encl_mm_t* rt_mm;
  unsigned long rt_offset = 0xffffffffc0000000; // last entry in the top page table

  pr_info("%s: %d\n", __func__, __LINE__);
  file = filp_open(fname, O_RDONLY, 0600);
  error = PTR_ERR(file);
  if (IS_ERR(file))
    goto out;

  error = -ENOEXEC;
  if(kernel_read(file, &elf_ex, sizeof(elf_ex), &pos) != sizeof(elf_ex))
    goto out;
  pr_info("%s: %d\n", __func__, __LINE__);

  // check ELF header
  if(memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
    goto out;

  pr_info("%s: %d\n", __func__, __LINE__);
  // check runtime consistency
  if(elf_ex.e_type != ET_EXEC || !elf_check_arch(&elf_ex) || !file->f_op->mmap)
    goto out;

  j = sizeof(struct elf_phdr) * elf_ex.e_phnum;

  error = -ENOMEM;
  elf_phdata = kmalloc(j, GFP_KERNEL);
  if(!elf_phdata)
    goto out;

  rt_mm = kmalloc(sizeof(encl_mm_t), GFP_KERNEL);
  if(!rt_mm)
    goto out_free_ph;

  pr_info("%s: %d\n", __func__, __LINE__);
  eppnt = elf_phdata;
  encl_mm_init(rt_mm);
  pr_info("%s: %d\n", __func__, __LINE__);

  error = -ENOEXEC;
  pos = elf_ex.e_phoff;
  retval = kernel_read(file, eppnt, j, &pos);
  pr_info("%s: %d\n", __func__, __LINE__);
  if(retval != j)
    goto out_free_rtmm;
  
  pr_info("%s: %d\n", __func__, __LINE__);
  for(eppnt = elf_phdata, i=0; i<elf_ex.e_phnum; eppnt++, i++) {
    unsigned long vaddr;
    unsigned long size = 0;

    pr_info("%s: %d\n", __func__, __LINE__);
    if(eppnt->p_type != PT_LOAD) {
      pr_warn("keystone runtime includes an inconsistent program header\n");
      continue;
    }
    vaddr = eppnt->p_vaddr + rt_offset;
    size = eppnt->p_filesz;
    if(size != eppnt->p_memsz)
     pr_info("unexpected mismatch!\n"); 
    encl_vm_mmap(epm, vaddr, size, file, eppnt);
    pr_info("%s: %d\n", __func__, __LINE__);
  }

  //if(j != 1)
  //  goto out_free_ph;
  /*
  pr_info("%d\n",__LINE__);
  while (eppnt->p_type != PT_LOAD)
    eppnt++;
  */
  error = 0;
out_free_rtmm:
  kfree(rt_mm);
out_free_ph:
  kfree(elf_phdata);
out:
  return error;
}

