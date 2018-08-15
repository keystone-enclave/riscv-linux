#ifndef _PAGE_H_
#define _PAGE_H_

/* IMPORTANT: This code assumes Sv39 */
#include "riscv64.h"

typedef uintptr_t paddr_t;
typedef uintptr_t vaddr_t;

typedef struct pg_list_t
{
  paddr_t head;
  paddr_t tail;
  unsigned int count;
} pg_list_t;

//enclave private memory;
typedef struct epm_t {
  struct pg_list_t freelist;
  pte_t* root_page_table;
  paddr_t base;
  unsigned int total;
} epm_t;

static inline uintptr_t  epm_satp(epm_t* epm) {
  return ((uintptr_t)epm->root_page_table >> RISCV_PGSHIFT | SATP_MODE_CHOICE);
}
void init_free_pages(pg_list_t* pg_list, paddr_t base, unsigned int count);
void put_free_page(pg_list_t* pg_list, paddr_t page_addr);
paddr_t get_free_page(pg_list_t* pg_list);

void epm_init(epm_t* epm, paddr_t base, unsigned int count);

paddr_t epm_alloc_page(epm_t* epm, vaddr_t addr);
void epm_free_page(epm_t* epm, vaddr_t addr);
//pfn_t epm_alloc_pages(epm_t* epm, va_t va, int order);

//// TODO: put below code to a separate file e.g., mm.h

#define MAX_STACK_SIZE  8192 // 8KB
/* - start_vm and end_vm are for validating enclave vm.
 * U-mode enclave cannot access beyond these pointers.
 * - hooks are copied below .text section
 * - the stack cannot grow larger than MAX_STACK_SIZE
 * - brk can grow as large as possible, but cannot grow beyond stack_top
 * - each segment is aligned with RISCV_PGSIZE
 * - user permissions
 *   .text: RX
 *   .data: R
 *   .bss : RW
 *   brk: RW
 *   stack: RW
 *   hooks: RX
 * +-------+
 * | hooks |
 * +-------+ 
 * |       |
 *    ...    <-- somewhere in the middle: PAGE_OFFSET
 * |       |
 * +-------+ <-- end_vm (0x
 * | Stack |
 * +-------+ <-- stack_top
 * |       |
 * +-------+ <-- brk
 * | Heap  |
 * +-------+ <-- start_brk
 * | .bss  |
 * +-------+ <-- bss
 * | .data |
 * +-------+ <-- data
 * | .text |
 * +-------+ <-- text (usually entry point)
 * |       |
 * +-------+ <-- start_vm (usually 0x0)
 */
typedef struct mm_t {
  unsigned long start_vm, end_vm;
  unsigned long text, end_text;
  unsigned long data, end_data;
  unsigned long bss, end_bss;
  unsigned long stack_top;
  unsigned long brk, start_brk;
} mm_t;

void mm_init(mm_t* mm);
int mm_set_stack(mm_t* mm, unsigned int size);
// int mm_sbrk(mm_t* mm, unsigned int size);

#endif
