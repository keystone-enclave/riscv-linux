// Filename: keystone-rtld.c
// Description: Keystone enclave runtime loader
// Author: Dayeol Lee <dayeol@berkeley.edu> 

#include <linux/elf.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "keystone.h"
#include "keystone-page.h"

#define RT_STACK_SIZE 1024*4

void debug_dump(char* ptr, unsigned long size)
{
  pr_info("debug memory dump from virtual address 0x%lx (%lu bytes)\n", ptr, size); 
  int i, j;
  char buf[16];
  int allzeroline = 0;
  int lineiszero = 1;
  for (i=0; i<size; i++) {
    buf[i%16] = ptr[i];
    if(ptr[i] != '\0') {
      lineiszero = 0;
    }

    if(i % 16 == 15) {
      if(lineiszero) {
        allzeroline++;
      }
      else {
        if(allzeroline > 0)
          pr_info("*\n");
        allzeroline = 0;
        pr_info("%08x: %04x %04x %04x %04x %04x %04x %04x %04x\n",
          i-0xf, 
          *((uint16_t*)&buf[0]), 
          *((uint16_t*)&buf[2]), 
          *((uint16_t*)&buf[4]), 
          *((uint16_t*)&buf[6]), 
          *((uint16_t*)&buf[8]), 
          *((uint16_t*)&buf[10]), 
          *((uint16_t*)&buf[12]), 
          *((uint16_t*)&buf[14]));
      }
      lineiszero = 1;
    }
  }
}

vaddr_t rtld_setup_stack(epm_t* epm, vaddr_t stack_addr, unsigned long size)
{
  vaddr_t va_start = PAGE_DOWN(stack_addr - (size - 1));
  vaddr_t va_end = PAGE_UP(stack_addr - 1);
  vaddr_t va;
  int i;

  //pr_info("[rt stack] va_start: 0x%lx, va_end: 0x%lx\n", va_start, va_end);

  for(i=0, va=va_start; i< (size>>12); i++, va+=PAGE_SIZE) 
  {
    //pr_info("mapping: %lx\n",va);
    vaddr_t epm_page;
    epm_page = epm_alloc_rt_page_noexec(epm, va);
  }
}


vaddr_t rtld_vm_mmap(epm_t* epm, vaddr_t encl_addr, unsigned long size,
   void* __user rt_ptr, struct elf_phdr* phdr)
{
  unsigned int k, retval;
  vaddr_t va_start = PAGE_DOWN(encl_addr);
  vaddr_t va_end = PAGE_UP(encl_addr + size);
  vaddr_t va;

  //pr_info("va_start: 0x%lx, va_end: 0x%lx\n", va_start, va_end);

  unsigned long pos = phdr->p_offset;
  for(va=va_start, k=0; va < va_end; va += PAGE_SIZE, k++)
  {
    int i;
    vaddr_t epm_page;
    epm_page = epm_alloc_rt_page(epm, va);
    //pr_info("encl_mmap va: 0x%lx, target: 0x%lx\n", va, epm_page);
    if(copy_from_user(epm_page, rt_ptr + pos, PAGE_SIZE)){
      keystone_err("failed to copy runtime\n");
    }
    pos += PAGE_SIZE;
   
    //debug_dump(epm_page, PAGE_SIZE);
  }
} 

int keystone_rtld_init_runtime(epm_t* epm, unsigned long epm_vaddr, void* __user rt_ptr, size_t rt_sz, unsigned long* rt_offset)
{
  int retval, error, i, j;
  int total_size;
  struct elf_phdr *elf_phdata;
  struct elf_phdr *eppnt;
  struct elfhdr elf_ex;
  *rt_offset = -1UL;

  error = -ENOEXEC;
  if(copy_from_user(&elf_ex, rt_ptr, sizeof(struct elfhdr)) != 0){
    keystone_err("failed to read runtime header\n");
    goto out;
  }

  // check ELF header
  if(memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0) {
    keystone_err("invalid runtime executable\n");
    goto out;
  }

  // check runtime consistency
  if(elf_ex.e_type != ET_EXEC || !elf_check_arch(&elf_ex)) {
    keystone_err("invalid runtime executable\n");
    goto out;
  }

  j = sizeof(struct elf_phdr) * elf_ex.e_phnum;

  error = -ENOMEM;
  elf_phdata = kmalloc(j, GFP_KERNEL);
  if(!elf_phdata)
    goto out;

  eppnt = elf_phdata;

  error = -ENOEXEC;
  retval = copy_from_user(eppnt, rt_ptr + elf_ex.e_phoff, j);
  if(retval != 0) {
    keystone_err("failed to copy runtime phdr\n");
    goto out_free_ph;
  }
  
  for(eppnt = elf_phdata, i=0; i<elf_ex.e_phnum; eppnt++, i++) {
    unsigned long vaddr;
    unsigned long size = 0;

    if(eppnt->p_type != PT_LOAD) {
      keystone_warn("keystone runtime includes an inconsistent program header\n");
      continue;
    }
    vaddr = eppnt->p_vaddr;
    if(vaddr < *rt_offset) {
      *rt_offset = vaddr;
    }
    size = eppnt->p_filesz;
    if(size > eppnt->p_memsz) {
      pr_info("unexpected mismatch in elf program header: filesz %ld, memsz %ld\n", size, eppnt->p_memsz);
    }
    rtld_vm_mmap(epm, vaddr, size, rt_ptr, eppnt);
  }

  rtld_setup_stack(epm, -1UL, RT_STACK_SIZE);

  error = 0;
out_free_ph:
  kfree(elf_phdata);
out:
  return error;
}
