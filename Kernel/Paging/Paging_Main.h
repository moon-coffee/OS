#pragma once
#ifndef PAGING_MAIN_H
#define PAGING_MAIN_H

#include <stdint.h>
#include <stddef.h>

#define PAGE_PRESENT (1ULL << 0)
#define PAGE_RW      (1ULL << 1)
#define PAGE_USER    (1ULL << 2)
#define PAGE_PS      (1ULL << 7)
#define PAGE_SIZE 4096ULL
#define PAGE_MASK 0xFFFFFFFFFFFFF000ULL

#define PML4_INDEX(x) (((x) >> 39) & 0x1FF)
#define PDPT_INDEX(x) (((x) >> 30) & 0x1FF)
#define PD_INDEX(x)   (((x) >> 21) & 0x1FF)
#define PT_INDEX(x)   (((x) >> 12) & 0x1FF)

void init_paging(void);
void *map_mmio_virt(uint64_t phys_addr);
uint64_t paging_get_kernel_cr3(void);
void paging_switch_cr3(uint64_t cr3);
uint64_t paging_create_process_space(void);
void paging_destroy_process_space(uint64_t cr3);
int paging_set_user_access(uint64_t cr3, uint64_t start, uint64_t size, int enable_user);
void *pmm_alloc_pages(size_t num_pages);
void pmm_free_pages(void *virt, size_t num_pages);
uint64_t get_phys_base(void);
uint64_t get_virt_base(void);

#endif
