#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "DMA_Memory.h"
#include "Memory_Main.h"
#include "../Paging/Paging_Main.h"
#include "../Serial.h"

#ifndef DMA_POOL_SIZE
#define DMA_POOL_SIZE   (4u * 1024u * 1024u)
#endif
#define DMA_MIN_ALIGN   64u
#define DMA_MAX_BLOCKS  512u
#ifndef VIRT_TO_PHYS_OFFSET
#define VIRT_TO_PHYS_OFFSET  0ULL
#endif

typedef struct {
    uintptr_t virt;
    size_t    size;
    bool      used;
} dma_block_t;

typedef struct {
    uint8_t     *base_virt;
    uint64_t     base_phys;
    size_t       total;
    size_t       offset;
    dma_block_t  blocks[DMA_MAX_BLOCKS];
    uint32_t     block_cnt;
    bool         initialized;
} dma_pool_t;

static dma_pool_t g_pool;

static volatile int g_lock = 0;

static inline void dma_lock(void)
{
    while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause");
}

static inline void dma_unlock(void)
{
    __atomic_clear(&g_lock, __ATOMIC_RELEASE);
}

bool dma_init(void)
{
    if (g_pool.initialized) return true;

    size_t num_pages = (DMA_POOL_SIZE + PAGE_SIZE - 1) / PAGE_SIZE;

    void *virt = pmm_alloc_pages(num_pages);
    if (!virt) {
        serial_write_string("[DMA] pool alloc failed\n");
        return false;
    }

    memset(virt, 0, num_pages * PAGE_SIZE);

    g_pool.base_virt   = (uint8_t*)virt;
    g_pool.base_phys = virt_to_phys(virt);
    g_pool.total       = num_pages * PAGE_SIZE;
    g_pool.offset      = 0;
    g_pool.block_cnt   = 0;
    g_pool.initialized = true;

    serial_write_string("[DMA] pool ready\n");
    return true;
}

void* dma_alloc(size_t bytes, uint64_t *phys_out)
{
    if (!bytes) return NULL;

    if (!g_pool.initialized) {
        if (!dma_init()) return NULL;
    }

    dma_lock();

    if (g_pool.block_cnt >= DMA_MAX_BLOCKS) {
        dma_unlock();
        serial_write_string("[DMA] block table full\n");
        return NULL;
    }

    size_t aligned_bytes = (bytes + DMA_MIN_ALIGN - 1) & ~(DMA_MIN_ALIGN - 1);

    size_t aligned_offset =
        (g_pool.offset + DMA_MIN_ALIGN - 1) & ~(DMA_MIN_ALIGN - 1);

    if (aligned_offset + aligned_bytes > g_pool.total) {
        uint32_t best_idx  = DMA_MAX_BLOCKS;
        size_t   best_diff = SIZE_MAX;

        for (uint32_t i = 0; i < g_pool.block_cnt; i++) {
            dma_block_t *b = &g_pool.blocks[i];
            if (!b->used && b->size >= aligned_bytes) {
                size_t diff = b->size - aligned_bytes;
                if (diff < best_diff) {
                    best_diff = diff;
                    best_idx  = i;
                }
            }
        }

        if (best_idx == DMA_MAX_BLOCKS) {
            dma_unlock();
            serial_write_string("[DMA] out of memory\n");
            return NULL;
        }

        dma_block_t *b = &g_pool.blocks[best_idx];
        b->used = true;
        memset((void*)b->virt, 0, b->size);

        uint64_t phys = g_pool.base_phys + (b->virt - (uintptr_t)g_pool.base_virt);
        if (phys_out) *phys_out = phys;

        dma_unlock();
        return (void*)b->virt;
    }

    uint8_t    *virt = g_pool.base_virt + aligned_offset;
    uint64_t    phys = g_pool.base_phys + aligned_offset;

    dma_block_t *b = &g_pool.blocks[g_pool.block_cnt++];
    b->virt = (uintptr_t)virt;
    b->size = aligned_bytes;
    b->used = true;

    g_pool.offset = aligned_offset + aligned_bytes;

    if (phys_out) *phys_out = phys;

    dma_unlock();
    return virt;
}

void dma_free(void *virt, size_t bytes)
{
    if (!virt || !g_pool.initialized) return;

    dma_lock();

    uintptr_t addr = (uintptr_t)virt;
    for (uint32_t i = 0; i < g_pool.block_cnt; i++) {
        dma_block_t *b = &g_pool.blocks[i];
        if (b->virt == addr && b->used) {
            memset(virt, 0, b->size);
            b->used = false;
            dma_unlock();
            return;
        }
    }

    dma_unlock();
    serial_write_string("[DMA] dma_free: unknown pointer\n");
    (void)bytes;
}

uint64_t virt_to_phys(void *virt)
{
    return (uint64_t)(uintptr_t)virt;
}

void dma_dump_stats(void)
{
    if (!g_pool.initialized) {
        serial_write_string("[DMA] not initialized\n");
        return;
    }

    dma_lock();

    uint32_t used_blocks = 0;
    size_t   used_bytes  = 0;
    size_t   free_bytes  = 0;

    for (uint32_t i = 0; i < g_pool.block_cnt; i++) {
        dma_block_t *b = &g_pool.blocks[i];
        if (b->used) {
            used_blocks++;
            used_bytes += b->size;
        } else {
            free_bytes += b->size;
        }
    }

    size_t bump_remaining = g_pool.total - g_pool.offset;

    dma_unlock();
    serial_write_string("\n");
}