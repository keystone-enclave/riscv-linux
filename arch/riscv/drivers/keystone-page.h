#ifndef _PAGE_H_
#define _PAGE_H_

/* IMPORTANT: This code assumes Sv39 */
#include "riscv64.h"
#include <linux/fs.h>

typedef uintptr_t vaddr_t;
typedef uintptr_t paddr_t;

struct free_page_t {
  vaddr_t vaddr;
  struct list_head freelist;
};

/* enclave private memory */
typedef struct epm_t {
  struct list_head epm_free_list;
  pte_t* root_page_table;
  vaddr_t base;
  paddr_t pa;
  unsigned long order;
  unsigned int total;
} epm_t;

typedef struct utm_t {
  struct list_head utm_free_list;
  pte_t* root_page_table;
  void* ptr;
  size_t size;
} utm_t;

static inline uintptr_t  epm_satp(epm_t* epm) {
  return ((uintptr_t)epm->root_page_table >> RISCV_PGSHIFT | SATP_MODE_CHOICE);
}
void init_free_pages(struct list_head* pg_list, vaddr_t base, unsigned int count);
void put_free_page(struct list_head* pg_list, vaddr_t page_addr);
vaddr_t get_free_page(struct list_head* pg_list);

void epm_init(epm_t* epm, vaddr_t base, unsigned int count);
void utm_init(utm_t* utm);

vaddr_t utm_alloc_page(utm_t* utm, epm_t* epm, vaddr_t addr, unsigned long flags);
vaddr_t epm_alloc_rt_page(epm_t* epm, vaddr_t addr);
vaddr_t epm_alloc_rt_page_noexec(epm_t* epm, vaddr_t addr);
vaddr_t epm_alloc_user_page(epm_t* epm, vaddr_t addr);
vaddr_t epm_alloc_user_page_noexec(epm_t* epm, vaddr_t addr);
void epm_free_page(epm_t* epm, vaddr_t addr);

#endif
