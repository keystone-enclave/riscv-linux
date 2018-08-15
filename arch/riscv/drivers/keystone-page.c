#include "riscv64.h"
#include "keystone-page.h"

#define NEXT_PAGE(pa) *((paddr_t*)pa)

void init_free_pages(pg_list_t* pg_list, paddr_t base, unsigned int count)
{
  unsigned int i;
  paddr_t cur;
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

paddr_t get_free_page(pg_list_t* pg_list)
{
  paddr_t free_page;
  if(pg_list->head != 0) {
    free_page = pg_list->head;
    if(pg_list->head == pg_list->tail) {
      pg_list->head = 0;
      pg_list->tail = 0;
    } else {
      paddr_t next = NEXT_PAGE(pg_list->head);
      pg_list->head = next;
    }
    pg_list->count--;
    //printm("get_free_page: free_page = 0x%llx\n", free_page);
    return free_page;
  }
  //printm("out of free page\n");
  return 0;
}

void put_free_page(pg_list_t* pg_list, paddr_t page_addr)
{
  paddr_t prev = pg_list->tail;
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

void epm_init(epm_t* epm, paddr_t base, unsigned int count)
{
  pte_t* t;
  //printm("epm_init\n");
  init_free_pages(&epm->freelist, base, count); 
  epm->base = base;
  epm->total = count; 

  t = (pte_t*) get_free_page(&epm->freelist);
  epm->root_page_table = t;
  
  return;
}

static uintptr_t pte_ppn(pte_t pte)
{
  return pte_val(pte) >> PTE_PPN_SHIFT;
}

static uintptr_t ppn(uintptr_t addr)
{
  return addr >> RISCV_PGSHIFT;
}

static size_t pt_idx(uintptr_t addr, int level)
{
  size_t idx = addr >> (RISCV_PGLEVEL_BITS*level + RISCV_PGSHIFT);
  return idx & ((1 << RISCV_PGLEVEL_BITS) - 1);
}

static pte_t* __ept_walk_create(epm_t* epm, uintptr_t addr);

static pte_t* __ept_continue_walk_create(epm_t* epm, uintptr_t addr, pte_t* pte)
{
  *pte = ptd_create(ppn(get_free_page(&epm->freelist)));
  return __ept_walk_create(epm, addr);
}

static pte_t* __ept_walk_internal(epm_t* epm, uintptr_t addr, int create)
{
  pte_t* t = epm->root_page_table;
  int i;
  for (i = (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS - 1; i > 0; i--) {
    size_t idx = pt_idx(addr, i);
    if (unlikely(!(pte_val(t[idx]) & PTE_V)))
      return create ? __ept_continue_walk_create(epm, addr, &t[idx]) : 0;
    t = (pte_t*)(pte_ppn(t[idx]) << RISCV_PGSHIFT);
  }
  return &t[pt_idx(addr, 0)];
}

static pte_t* __ept_walk(epm_t* epm, uintptr_t addr)
{
  return __ept_walk_internal(epm, addr, 0);
}

static pte_t* __ept_walk_create(epm_t* epm, uintptr_t addr)
{
  //printm("__ept_walk_create: addr = 0x%llx\n", addr);
  return __ept_walk_internal(epm, addr, 1);
}

static int __ept_va_avail(epm_t* epm, uintptr_t vaddr)
{
  pte_t* pte = __ept_walk(epm, vaddr);
  return pte == 0 || pte_val(*pte) == 0;
}

paddr_t epm_alloc_page(epm_t* epm, vaddr_t addr)
{
  //printm("epm_alloc_page: addr = 0x%llx\n", addr);
  pte_t* pte = __ept_walk_create(epm, addr);
  paddr_t page_addr = get_free_page(&epm->freelist);
  //printm("epm_alloc_page: page_addr = 0x%llx\n", page_addr);
  *pte = pte_create(ppn(page_addr), PTE_R | PTE_W | PTE_X | PTE_V | PTE_U);
  return page_addr;
}

paddr_t epm_virt_to_phys(epm_t* epm, vaddr_t addr)
{
  pte_t* pte = __ept_walk(epm, addr);
  return pte_ppn(*pte) << RISCV_PGSHIFT;
}

void epm_free_page(epm_t* epm, vaddr_t addr)
{
}
