#include "Paging_Main.h"

#include "../Memory/Memory_Main.h"
#include "../Serial.h"

#include <stddef.h>
#include <stdint.h>

#define GB (1024ULL * 1024ULL * 1024ULL)
#define MB2 (2ULL * 1024ULL * 1024ULL)
#define MAX_PDPT_ENTRIES 64
#define MMIO_WINDOW_BASE 0x00000000F0000000ULL
#define MMIO_WINDOW_SLOTS 16
#define MAX_PROCESS_SPACES 32

#define PAGE_SIZE_BYTES 4096ULL

typedef struct {
    uint8_t used;
    uint64_t cr3;
    uint64_t *pml4;
    uint64_t *pdpt;
    uint64_t *pd_tables[MAX_PDPT_ENTRIES];
} paging_space_t;

static uint64_t g_kernel_pml4[512] __attribute__((aligned(4096)));
static uint64_t g_kernel_pdpt[512] __attribute__((aligned(4096)));
static uint64_t g_kernel_pd[MAX_PDPT_ENTRIES][512] __attribute__((aligned(4096)));
static uint64_t g_mmio_phys_base[MMIO_WINDOW_SLOTS];
static uint32_t g_mmio_slots_used = 0;
static uint64_t g_required_entries = 0;
static paging_space_t g_process_spaces[MAX_PROCESS_SPACES];

void *memset(void *ptr, int value, size_t num);

static inline uint64_t read_cr3(void)
{
    uint64_t value;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline void write_cr3(uint64_t value)
{
    __asm__ volatile ("mov %0, %%cr3" :: "r"(value) : "memory");
}

static inline void enable_paging(void)
{
    uint64_t cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= (1ULL << 5);
    __asm__ volatile ("mov %0, %%cr4" :: "r"(cr4));

    uint64_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1ULL << 31);
    __asm__ volatile ("mov %0, %%cr0" :: "r"(cr0));
}

static inline void invlpg_addr(uint64_t addr)
{
    __asm__ volatile ("invlpg (%0)" :: "r"(addr) : "memory");
}

static void copy_page_entries(uint64_t *dst, const uint64_t *src)
{
    for (uint32_t i = 0; i < 512; ++i) {
        dst[i] = src[i];
    }
}

static uint64_t *alloc_zeroed_page_table(void)
{
    uint64_t *table = (uint64_t *)alloc_page();
    if (table == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < 512; ++i) {
        table[i] = 0;
    }
    return table;
}

static paging_space_t *find_space_by_cr3(uint64_t cr3)
{
    for (uint32_t i = 0; i < MAX_PROCESS_SPACES; ++i) {
        if (g_process_spaces[i].used && g_process_spaces[i].cr3 == cr3) {
            return &g_process_spaces[i];
        }
    }
    return NULL;
}

static paging_space_t *find_free_space_slot(void)
{
    for (uint32_t i = 0; i < MAX_PROCESS_SPACES; ++i) {
        if (!g_process_spaces[i].used) {
            return &g_process_spaces[i];
        }
    }
    return NULL;
}

static int pd_table_has_user_pages(const uint64_t *pd_table)
{
    for (uint32_t i = 0; i < 512; ++i) {
        if ((pd_table[i] & PAGE_PRESENT) != 0 &&
            (pd_table[i] & PAGE_USER) != 0) {
            return 1;
        }
    }
    return 0;
}

static int update_pdpt_user_flag(uint64_t cr3,
                                 uint64_t pdpt_index,
                                 uint64_t *pd_table)
{
    if (pdpt_index >= g_required_entries || pd_table == NULL) {
        return -1;
    }

    uint64_t flags = PAGE_PRESENT | PAGE_RW;
    if (pd_table_has_user_pages(pd_table)) {
        flags |= PAGE_USER;
    }

    if (cr3 == (uint64_t)g_kernel_pml4) {
        g_kernel_pdpt[pdpt_index] = ((uint64_t)pd_table) | flags;
        return 0;
    }

    paging_space_t *space = find_space_by_cr3(cr3);
    if (space == NULL) {
        return -1;
    }
    space->pdpt[pdpt_index] = ((uint64_t)pd_table) | flags;
    return 0;
}

static uint64_t *resolve_pd_table(uint64_t cr3, uint64_t pdpt_index)
{
    if (pdpt_index >= g_required_entries) {
        return NULL;
    }

    if (cr3 == (uint64_t)g_kernel_pml4) {
        return g_kernel_pd[pdpt_index];
    }

    paging_space_t *space = find_space_by_cr3(cr3);
    if (space == NULL) {
        return NULL;
    }
    return space->pd_tables[pdpt_index];
}

void *map_mmio_virt(uint64_t phys_addr)
{
    if (phys_addr < (4ULL * GB)) {
        return (void *)(uintptr_t)phys_addr;
    }

    uint64_t phys_base = phys_addr & ~(MB2 - 1ULL);
    uint64_t offset = phys_addr - phys_base;

    for (uint32_t i = 0; i < g_mmio_slots_used; ++i) {
        if (g_mmio_phys_base[i] == phys_base) {
            uint64_t virt_base = MMIO_WINDOW_BASE + ((uint64_t)i * MB2);
            return (void *)(uintptr_t)(virt_base + offset);
        }
    }

    if (g_mmio_slots_used >= MMIO_WINDOW_SLOTS) {
        serial_write_string("[OS] [Memory] MMIO window exhausted\n");
        return NULL;
    }

    uint64_t virt_base = MMIO_WINDOW_BASE + ((uint64_t)g_mmio_slots_used * MB2);
    uint64_t pdpt_index = (virt_base >> 30) & 0x1FFULL;
    uint64_t pd_index = (virt_base >> 21) & 0x1FFULL;

    if (pdpt_index >= MAX_PDPT_ENTRIES) {
        serial_write_string("[OS] [Memory] MMIO window index out of range\n");
        return NULL;
    }

    g_kernel_pdpt[pdpt_index] = ((uint64_t)g_kernel_pd[pdpt_index]) | PAGE_PRESENT | PAGE_RW;
    g_kernel_pd[pdpt_index][pd_index] = phys_base | PAGE_PRESENT | PAGE_RW | PAGE_PS;
    invlpg_addr(virt_base);

    g_mmio_phys_base[g_mmio_slots_used] = phys_base;
    g_mmio_slots_used++;

    return (void *)(uintptr_t)(virt_base + offset);
}

void init_paging(void)
{
    serial_write_string("[OS] [Memory] Start Initialize Paging.\n");

    memset(g_kernel_pml4, 0, sizeof(g_kernel_pml4));
    memset(g_kernel_pdpt, 0, sizeof(g_kernel_pdpt));
    memset(g_kernel_pd, 0, sizeof(g_kernel_pd));
    memset(g_mmio_phys_base, 0, sizeof(g_mmio_phys_base));
    memset(g_process_spaces, 0, sizeof(g_process_spaces));
    g_mmio_slots_used = 0;
    
    g_required_entries = 4;

    serial_write_string("[OS] [Memory] Mapping ");
    serial_write_uint64(g_required_entries);
    serial_write_string(" GB of memory.\n");

    g_kernel_pml4[0] = ((uint64_t)g_kernel_pdpt) | PAGE_PRESENT | PAGE_RW;

    for (uint64_t i = 0; i < g_required_entries; ++i) {
        g_kernel_pdpt[i] = ((uint64_t)g_kernel_pd[i]) | PAGE_PRESENT | PAGE_RW;
        uint64_t base = i * GB;
        for (uint64_t j = 0; j < 512; ++j) {
            g_kernel_pd[i][j] = (base + (j * MB2)) | PAGE_PRESENT | PAGE_RW | PAGE_PS;
        }
    }

    write_cr3((uint64_t)g_kernel_pml4);
    enable_paging();

    serial_write_string("[OS] [Memory] Success Initialize Paging.\n");
}

uint64_t paging_get_kernel_cr3(void)
{
    return (uint64_t)g_kernel_pml4;
}

void paging_switch_cr3(uint64_t cr3)
{
    if (cr3 == 0) {
        return;
    }
    write_cr3(cr3);
}

uint64_t paging_create_process_space(void)
{
    paging_space_t *space = find_free_space_slot();
    if (space == NULL) return 0;

    space->pml4 = alloc_zeroed_page_table();
    space->pdpt = alloc_zeroed_page_table();
    if (!space->pml4 || !space->pdpt) {
        free_page(space->pml4);
        free_page(space->pdpt);
        return 0;
    }
    
    copy_page_entries(space->pml4, g_kernel_pml4);
    copy_page_entries(space->pdpt, g_kernel_pdpt);

    space->pml4[0] = ((uint64_t)space->pdpt) | PAGE_PRESENT | PAGE_RW | PAGE_USER;

    for (uint64_t i = 0; i < g_required_entries; ++i) {
        space->pd_tables[i] = alloc_zeroed_page_table();
        if (space->pd_tables[i] == NULL) {
            for (uint64_t j = 0; j < i; ++j) {
                free_page(space->pd_tables[j]);
            }
            free_page(space->pml4);
            free_page(space->pdpt);
            return 0;
        }

        copy_page_entries(space->pd_tables[i], g_kernel_pd[i]);
        
        space->pdpt[i] = ((uint64_t)space->pd_tables[i]) | PAGE_PRESENT | PAGE_RW;
    }

    space->cr3 = (uint64_t)space->pml4;
    space->used = 1;
    return space->cr3;
}

void paging_destroy_process_space(uint64_t cr3)
{
    if (cr3 == 0 || cr3 == (uint64_t)g_kernel_pml4) {
        return;
    }

    paging_space_t *space = find_space_by_cr3(cr3);
    if (space == NULL) {
        return;
    }

    if (read_cr3() == cr3) {
        write_cr3((uint64_t)g_kernel_pml4);
    }

    for (uint64_t i = 0; i < g_required_entries; ++i) {
        if (space->pd_tables[i] != NULL) {
            free_page(space->pd_tables[i]);
            space->pd_tables[i] = NULL;
        }
    }
    if (space->pdpt != NULL) {
        free_page(space->pdpt);
        space->pdpt = NULL;
    }
    if (space->pml4 != NULL) {
        free_page(space->pml4);
        space->pml4 = NULL;
    }
    space->cr3 = 0;
    space->used = 0;
}

int paging_set_user_access(uint64_t cr3,
                           uint64_t start,
                           uint64_t size,
                           int enable_user)
{
    if (cr3 == 0 || size == 0)
        return -1;

    uint64_t end = start + size;
    if (end <= start)
        return -1;

    uint64_t aligned_start = start & ~(MB2 - 1ULL);
    uint64_t aligned_end   = (end + MB2 - 1ULL) & ~(MB2 - 1ULL);

    for (uint64_t addr = aligned_start;
         addr < aligned_end;
         addr += MB2)
    {
        uint64_t pdpt_index = (addr >> 30) & 0x1FFULL;
        uint64_t pd_index   = (addr >> 21) & 0x1FFULL;

        uint64_t *pd_table = resolve_pd_table(cr3, pdpt_index);
        if (pd_table == NULL)
            return -1;

        uint64_t pde = pd_table[pd_index];

        if ((pde & PAGE_PRESENT) == 0) {
            uint64_t phys_base = addr & ~(MB2 - 1ULL);
            pde = phys_base | PAGE_PRESENT | PAGE_RW | PAGE_PS;
        }

        if (enable_user)
            pde |= PAGE_USER;
        else
            pde &= ~PAGE_USER;

        pd_table[pd_index] = pde;
        if (update_pdpt_user_flag(cr3, pdpt_index, pd_table) < 0) {
            return -1;
        }
    }

    if (read_cr3() == cr3)
        write_cr3(cr3);

    return 0;
}

void *pmm_alloc_pages(size_t num_pages)
{
    return alloc_contiguous_pages(num_pages, 1);
}

void paging_map_user_page(uint64_t cr3,
                          uint64_t virt_addr,
                          uint64_t phys_addr,
                          uint64_t flags)
{
    uint64_t* pml4 = (uint64_t*)(cr3 & PAGE_MASK);

    uint16_t i4 = PML4_INDEX(virt_addr);
    uint16_t i3 = PDPT_INDEX(virt_addr);
    uint16_t i2 = PD_INDEX(virt_addr);
    uint16_t i1 = PT_INDEX(virt_addr);

    uint64_t* pdpt;
    uint64_t* pd;
    uint64_t* pt;

    if (!(pml4[i4] & PAGE_PRESENT)) {
        pdpt = alloc_page();
        memset(pdpt, 0, PAGE_SIZE);
        pml4[i4] = ((uint64_t)pdpt)
                    | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    }
    pml4[i4] |= PAGE_USER;
    pdpt = (uint64_t*)(pml4[i4] & PAGE_MASK);

    if (!(pdpt[i3] & PAGE_PRESENT)) {
        pd = alloc_page();
        memset(pd, 0, PAGE_SIZE);
        pdpt[i3] = ((uint64_t)pd)
                    | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    }
    pdpt[i3] |= PAGE_USER;
    pd = (uint64_t*)(pdpt[i3] & PAGE_MASK);

    if (!(pd[i2] & PAGE_PRESENT)) {
        pt = alloc_page();
        memset(pt, 0, PAGE_SIZE);
        pd[i2] = ((uint64_t)pt)
                  | PAGE_PRESENT | PAGE_RW | PAGE_USER;
    }
    pd[i2] |= PAGE_USER;
    pt = (uint64_t*)(pd[i2] & PAGE_MASK);

    pt[i1] = (phys_addr & PAGE_MASK)
              | flags
              | PAGE_PRESENT
              | PAGE_USER;

    __asm__ volatile("invlpg (%0)" :: "r"(virt_addr) : "memory");
}

void pmm_free_pages(void *virt, size_t num_pages)
{
    if (virt == NULL || num_pages == 0) return;

    uint8_t *p = (uint8_t *)virt;
    for (size_t i = 0; i < num_pages; ++i) {
        free_page(p + i * PAGE_SIZE_BYTES);
    }
}

uint64_t get_phys_base(void)
{
    return 0ULL;
}

uint64_t get_virt_base(void)
{
    return 0ULL;
}
