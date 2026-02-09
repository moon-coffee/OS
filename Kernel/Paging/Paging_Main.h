#ifndef PAGING_MAIN_H
#define PAGING_MAIN_H

#include <stdint.h>

#define PAGE_SIZE 4096

#define PAGE_PRESENT (1ULL << 0)
#define PAGE_RW      (1ULL << 1)
#define PAGE_USER    (1ULL << 2)
#define PAGE_PS      (1ULL << 7)

void init_paging(uint64_t framebuffer_base, uint32_t framebuffer_size);

#endif
