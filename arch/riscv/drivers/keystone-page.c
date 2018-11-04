#include "riscv64.h"
#include "keystone-page.h"
#include <linux/kernel.h>

#define NEXT_PAGE(pa) *((vaddr_t*)pa)

void init_free_pages(pg_list_t* pg_list, vaddr_t base, unsigned int count)
{
  unsigned int i;
  vaddr_t cur;
  pg_list->count = 0;
  pg_list->head = 0;
  pg_list->tail = 0;

  cur = base;
  for(i=0; i<count; i++)
  {
    put_free_page(pg_list, cur);
    cur += RISCV_PGSIZE;
  }
  return;
}

vaddr_t get_free_page(pg_list_t* pg_list)
{
  vaddr_t free_page;
  if(pg_list->head != 0) {
    free_page = pg_list->head;
    if(pg_list->head == pg_list->tail) {
      pg_list->head = 0;
      pg_list->tail = 0;
    } else {
      vaddr_t next = NEXT_PAGE(pg_list->head);
      pg_list->head = next;
    }
    pg_list->count--;
    //pr_info("get_free_page: free_page = 0x%llx\n", free_page);
    return free_page;
  }
  //pr_info("out of free page\n");
  return 0;
}

void put_free_page(pg_list_t* pg_list, vaddr_t page_addr)
{
  vaddr_t prev = pg_list->tail;
  if(prev != 0) {
    NEXT_PAGE(prev) = page_addr;
    NEXT_PAGE(page_addr) = 0;
    pg_list->tail = page_addr;
  } else {
    pg_list->head = page_addr;
    NEXT_PAGE(page_addr) = 0;
    pg_list->tail = page_addr;
  }
  pg_list->count++;
  return;
}

void epm_init(epm_t* epm, vaddr_t base, unsigned int count)
{
  pte_t* t;
  //pr_info("epm_init\n");
  init_free_pages(&epm->freelist, base, count); 
  epm->base = base;
  epm->total = count * PAGE_SIZE; 

  t = (pte_t*) get_free_page(&epm->freelist);
  epm->root_page_table = t;
  
  return;
}

static paddr_t pte_ppn(pte_t pte)
{
  return pte_val(pte) >> PTE_PPN_SHIFT;
}

static paddr_t ppn(vaddr_t addr)
{
  return __pa(addr) >> RISCV_PGSHIFT;
}

static size_t pt_idx(vaddr_t addr, int level)
{
  size_t idx = addr >> (RISCV_PGLEVEL_BITS*level + RISCV_PGSHIFT);
  return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}

static pte_t* __ept_walk_create(epm_t* epm, vaddr_t addr);

static pte_t* __ept_continue_walk_create(epm_t* epm, vaddr_t addr, pte_t* pte)
{
  unsigned long free_ppn = ppn(get_free_page(&epm->freelist));
  *pte = ptd_create(free_ppn);
  //pr_info("ptd_create: ppn = %u, pte = 0x%lx\n", free_ppn,  *pte);
  return __ept_walk_create(epm, addr);
}

static pte_t* __ept_walk_internal(epm_t* epm, vaddr_t addr, int create)
{
  pte_t* t = epm->root_page_table;
  //pr_info("  page walk:\n");
  int i;
  for (i = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1; i > 0; i--) {
    size_t idx = pt_idx(addr, i);
    //pr_info("    level %d: pt_idx %d (%x)\n", i, idx, idx);
    if (unlikely(!(pte_val(t[idx]) & PTE_V)))
      return create ? __ept_continue_walk_create(epm, addr, &t[idx]) : 0;
    t = (pte_t*) __va(pte_ppn(t[idx]) << RISCV_PGSHIFT);
  }
  return &t[pt_idx(addr, 0)];
}

static pte_t* __ept_walk(epm_t* epm, vaddr_t addr)
{
  return __ept_walk_internal(epm, addr, 0);
}

static pte_t* __ept_walk_create(epm_t* epm, vaddr_t addr)
{
  //pr_info("__ept_walk_create: addr = 0x%llx\n", addr);
  return __ept_walk_internal(epm, addr, 1);
}

static int __ept_va_avail(epm_t* epm, vaddr_t vaddr)
{
  pte_t* pte = __ept_walk(epm, vaddr);
  return pte == 0 || pte_val(*pte) == 0;
}

vaddr_t epm_alloc_page(epm_t* epm, vaddr_t addr, unsigned long flags)
{
  //pr_info("epm_alloc_page: \n");
  //pr_info("  addr(V) = 0x%llx\n", addr);
  pte_t* pte = __ept_walk_create(epm, addr);
  vaddr_t page_addr = get_free_page(&epm->freelist);
  //pr_info("  free(V) = 0x%llx\n", page_addr);
  *pte = pte_create(ppn(page_addr), flags | PTE_V);
  //pr_info("  free(PPN) = 0x%llx\n", ppn(page_addr));
  return page_addr;
}

vaddr_t epm_alloc_rt_page_noexec(epm_t* epm, vaddr_t addr)
{
  return epm_alloc_page(epm, addr, PTE_D | PTE_A | PTE_R | PTE_W);
}

vaddr_t epm_alloc_rt_page(epm_t* epm, vaddr_t addr)
{
  return epm_alloc_page(epm, addr, PTE_A | PTE_R | PTE_W | PTE_X);
}

vaddr_t epm_alloc_user_page_noexec(epm_t* epm, vaddr_t addr)
{
  return epm_alloc_page(epm, addr, PTE_D | PTE_A | PTE_R | PTE_W | PTE_U);
}

vaddr_t epm_alloc_user_page(epm_t* epm, vaddr_t addr)
{
  return epm_alloc_page(epm, addr, PTE_A | PTE_R | PTE_X | PTE_W | PTE_U);
}

void epm_free_page(epm_t* epm, vaddr_t addr)
{
  /* TODO: Must Implement Quickly */
}
