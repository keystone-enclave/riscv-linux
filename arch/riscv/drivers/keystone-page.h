#ifndef _PAGE_H_
#define _PAGE_H_

/* IMPORTANT: This code assumes Sv39 */
#include "riscv64.h"

typedef unsigned long vaddr_t;
typedef unsigned long paddr_t;

typedef struct pg_list_t
{
  vaddr_t head;
  vaddr_t tail;
  unsigned int count;
} pg_list_t;

//enclave private memory;
typedef struct epm_t {
  struct pg_list_t freelist;
  pte_t* root_page_table;
  vaddr_t base;
  paddr_t pa;
  unsigned long order;
  unsigned int total;
} epm_t;

static inline uintptr_t  epm_satp(epm_t* epm) {
  return ((uintptr_t)epm->root_page_table >> RISCV_PGSHIFT | SATP_MODE_CHOICE);
}
void init_free_pages(pg_list_t* pg_list, vaddr_t base, unsigned int count);
void put_free_page(pg_list_t* pg_list, vaddr_t page_addr);
vaddr_t get_free_page(pg_list_t* pg_list);

void epm_init(epm_t* epm, vaddr_t base, unsigned int count);

vaddr_t epm_alloc_rt_page(epm_t* epm, vaddr_t addr);
vaddr_t epm_alloc_rt_page_noexec(epm_t* epm, vaddr_t addr);
vaddr_t epm_alloc_user_page(epm_t* epm, vaddr_t addr);
vaddr_t epm_alloc_user_page_noexec(epm_t* epm, vaddr_t addr);
void epm_free_page(epm_t* epm, vaddr_t addr);

#endif
