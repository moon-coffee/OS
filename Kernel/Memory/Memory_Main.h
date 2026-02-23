#ifndef MEMORY_MAIN_H
#define MEMORY_MAIN_H

#include <stdint.h>
#include <stddef.h>

void* kmalloc(uint32_t size);
void kfree(void* ptr);
void* kcalloc(uint32_t num, uint32_t size);
void* krealloc(void* ptr, uint32_t new_size);

void memory_init(void);
void init_physical_memory(void *memory_map, size_t map_size, size_t desc_size);

void* alloc_page(void);
void free_page(void* addr);
void* alloc_contiguous_pages(uint32_t page_count, uint32_t align_pages);
void free_contiguous_pages(void* addr, uint32_t page_count);

uint32_t get_free_memory(void);
uint32_t get_used_memory(void);

#endif
