#include "Paging_Main.h"
#include "../Serial.h"
#include <stdint.h>
#include <stddef.h>

#define GB (1024ULL * 1024ULL * 1024ULL)
#define MB2 (2ULL * 1024ULL * 1024ULL)
#define MAX_PDPT_ENTRIES 64

static uint64_t pml4[512] __attribute__((aligned(4096)));
static uint64_t pdpt[512] __attribute__((aligned(4096)));
static uint64_t pd[MAX_PDPT_ENTRIES][512] __attribute__((aligned(4096)));

void *memset(void *ptr, int value, size_t num);

static inline void write_cr3(uint64_t value) {
    __asm__ volatile ("mov %0, %%cr3" :: "r"(value) : "memory");
}

static inline void enable_paging(void) {
    uint64_t cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 5);
    __asm__ volatile ("mov %0, %%cr4" :: "r"(cr4));

    uint64_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1ULL << 31);
    __asm__ volatile ("mov %0, %%cr0" :: "r"(cr0));
}

void init_paging(uint64_t framebuffer_base, uint32_t framebuffer_size) {
    serial_write_string("[OS] [Memory] Start Initialize Paging.\n");

    memset(pml4, 0, sizeof(pml4));
    memset(pdpt, 0, sizeof(pdpt));
    memset(pd, 0, sizeof(pd));

    uint64_t fb_end = framebuffer_base + framebuffer_size;
    uint64_t min_required = 4ULL * GB;
    uint64_t max_addr = (fb_end > min_required) ? fb_end : min_required;
    
    uint64_t required_entries = (max_addr + GB - 1) / GB;
    if (required_entries > MAX_PDPT_ENTRIES) {
        serial_write_string("[OS] [Memory] Warning: mapping limited to MAX_PDPT_ENTRIES.\n");
        required_entries = MAX_PDPT_ENTRIES;
    }

    serial_write_string("[OS] [Memory] Mapping ");
    serial_write_uint64(required_entries);
    serial_write_string(" GB of memory.\n");

    pml4[0] = ((uint64_t)pdpt) | PAGE_PRESENT | PAGE_RW | PAGE_USER;

    for (uint64_t i = 0; i < required_entries; i++) {
        pdpt[i] = ((uint64_t)pd[i]) | PAGE_PRESENT | PAGE_RW | PAGE_USER;
        uint64_t base = i * GB;
        for (uint64_t j = 0; j < 512; j++) {
            pd[i][j] = (base + (j * MB2)) | PAGE_PRESENT | PAGE_RW | PAGE_PS | PAGE_USER;
        }
    }

    write_cr3((uint64_t)pml4);
    enable_paging();

    serial_write_string("[OS] [Memory] Success Initialize Paging.\n");
}