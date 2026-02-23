#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool dma_init(void);
void* dma_alloc(size_t bytes, uint64_t *phys_out);
void dma_free(void *virt, size_t bytes);
uint64_t virt_to_phys(void *virt);
void dma_dump_stats(void);