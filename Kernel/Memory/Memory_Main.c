#include "Memory_Main.h"
#include "../Serial.h"
#include "../Kernel_Main.h"
#include "../ProcessManager/ProcessManager.h"
#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE 4096
#define MAX_PAGES 262144
#define USER_RESERVED_TOP USER_STACK_TOP

static uint8_t page_bitmap[MAX_PAGES];

extern uint8_t _kernel_end;

enum {
    EFI_LOADER_CODE          = 1,
    EFI_LOADER_DATA          = 2,
    EFI_BOOT_SERVICES_CODE   = 3,
    EFI_BOOT_SERVICES_DATA   = 4,
    EFI_CONVENTIONAL_MEMORY  = 7
};

typedef struct memory_block {
    uint32_t size;
    int is_free;
    struct memory_block* next;
} memory_block_t;

static memory_block_t* heap_start = NULL;
static memory_block_t* heap_search_hint = NULL;
static uint32_t heap_initialized = 0;
static uint32_t total_allocated = 0;
static uint32_t total_freed = 0;

#define HEAP_PAGE_COUNT 4096

static uint32_t heap_start_page = 0;
static volatile uint32_t heap_lock = 0;
static volatile uint32_t page_lock = 0;
static uint32_t page_alloc_hint = 0;

#define MIN_ALLOC_ALIGN 8u
#define MIN_SPLIT_REMAINDER 64u

static inline uint64_t irq_save_disable(void) {
    uint64_t flags;
    __asm__ volatile ("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

static inline void irq_restore(uint64_t flags) {
    if (flags & (1ull << 9)) {
        __asm__ volatile ("sti" ::: "memory");
    }
}

static inline void spin_lock(volatile uint32_t *lock) {
    while (__sync_lock_test_and_set(lock, 1) != 0) {
        while (*lock != 0) {
            __asm__ volatile ("pause");
        }
    }
}

static inline void spin_unlock(volatile uint32_t *lock) {
    __sync_lock_release(lock);
}

static inline uint32_t align_up(uint32_t value, uint32_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

static memory_block_t* find_block_by_payload(void *ptr, memory_block_t **prev_out) {
    memory_block_t *prev = NULL;
    memory_block_t *current = heap_start;
    uintptr_t target = (uintptr_t)ptr;

    while (current != NULL) {
        uintptr_t payload = (uintptr_t)current + sizeof(memory_block_t);
        if (payload == target) {
            if (prev_out != NULL) {
                *prev_out = prev;
            }
            return current;
        }
        prev = current;
        current = current->next;
    }
    return NULL;
}

static memory_block_t* split_block_if_needed(memory_block_t *block, uint32_t size) {
    if (block->size >= size + sizeof(memory_block_t) + MIN_SPLIT_REMAINDER) {
        memory_block_t* new_block =
            (memory_block_t*)((uint8_t*)block + sizeof(memory_block_t) + size);
        new_block->size = block->size - size - sizeof(memory_block_t);
        new_block->is_free = 1;
        new_block->next = block->next;

        block->size = size;
        block->next = new_block;
    }
    return block;
}

static void* kmalloc_locked(uint32_t size) {
    if (heap_search_hint == NULL) {
        heap_search_hint = heap_start;
    }

    memory_block_t *start = heap_search_hint;
    memory_block_t *current = start;
    int wrapped = 0;

    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            current = split_block_if_needed(current, size);
            current->is_free = 0;
            total_allocated += current->size;
            heap_search_hint = (current->next != NULL) ? current->next : heap_start;
            return (void*)((uint8_t*)current + sizeof(memory_block_t));
        }

        current = current->next;
        if (current == NULL && !wrapped) {
            current = heap_start;
            wrapped = 1;
        }
        if (wrapped && current == start) {
            break;
        }
    }
    return NULL;
}

static uint32_t calc_heap_start_page(void) {
    if (heap_start_page != 0) return heap_start_page;
    uintptr_t end = (uintptr_t)&_kernel_end;
    uint32_t kernel_end_page = (uint32_t)((end + PAGE_SIZE - 1) / PAGE_SIZE);
    uint32_t user_reserved_page = (uint32_t)(USER_RESERVED_TOP / PAGE_SIZE);
    heap_start_page = (kernel_end_page > user_reserved_page) ? kernel_end_page : user_reserved_page;
    return heap_start_page;
}

static void mark_pages(uint64_t start_page, uint64_t page_count, uint8_t used) {
    if (start_page >= MAX_PAGES) return;
    uint64_t end_page = start_page + page_count;
    if (end_page > MAX_PAGES) end_page = MAX_PAGES;
    for (uint64_t i = start_page; i < end_page; i++) {
        page_bitmap[i] = used;
    }
}

static int is_usable_memory_type(uint32_t type) {
    return (type == EFI_LOADER_CODE) ||
           (type == EFI_LOADER_DATA) ||
           (type == EFI_BOOT_SERVICES_CODE) ||
           (type == EFI_BOOT_SERVICES_DATA) ||
           (type == EFI_CONVENTIONAL_MEMORY);
}

void init_physical_memory(void *memory_map, size_t map_size, size_t desc_size) {
    serial_write_string("[OS] [Memory] Start Initialize Physical Memory.\n");
    
    for (size_t i = 0; i < MAX_PAGES; i++)
        page_bitmap[i] = 1;

    if (memory_map != NULL && desc_size != 0) {
        uint8_t* map = (uint8_t*)memory_map;
        for (size_t offset = 0; offset + desc_size <= map_size; offset += desc_size) {
            EFI_MEMORY_DESCRIPTOR* desc = (EFI_MEMORY_DESCRIPTOR*)(map + offset);
            if (is_usable_memory_type(desc->Type)) {
                uint64_t start_page = desc->PhysicalStart / PAGE_SIZE;
                uint64_t page_count = desc->NumberOfPages;
                mark_pages(start_page, page_count, 0);
            }
        }
    }

    uint32_t start_page = calc_heap_start_page();
    mark_pages(0, (uint64_t)start_page + HEAP_PAGE_COUNT, 1);

    serial_write_string("[OS] [Memory] Physical memory initialized.\n");
    serial_write_string("[OS] [Memory] Heap will start at page ");
    serial_write_uint32(start_page);
    serial_write_string("\n");
}

void memory_init(void) {
    if (heap_initialized) {
        serial_write_string("[OS] [Memory] Heap already initialized\n");
        return;
    }
    
    uint32_t start_page = calc_heap_start_page();
    heap_start = (memory_block_t*)((uintptr_t)start_page * PAGE_SIZE);
    
    heap_start->size = (HEAP_PAGE_COUNT * PAGE_SIZE) - sizeof(memory_block_t);
    heap_start->is_free = 1;
    heap_start->next = NULL;
    heap_search_hint = heap_start;
    
    heap_initialized = 1;
    total_allocated = 0;
    total_freed = 0;
    page_alloc_hint = 0;
    
    serial_write_string("[OS] [Memory] Heap initialized at ");
    serial_write_uint64((uint64_t)heap_start);
    serial_write_string(" with size ");
    serial_write_uint32(heap_start->size);
    serial_write_string(" bytes\n");
}

void* kmalloc(uint32_t size) {
    if (!heap_initialized) {
        serial_write_string("[OS] [Memory] kmalloc called before heap init!\n");
        return NULL;
    }
    
    if (size == 0) return NULL;
    
    size = align_up(size, MIN_ALLOC_ALIGN);

    uint64_t irq_flags = irq_save_disable();
    spin_lock(&heap_lock);
    void *ptr = kmalloc_locked(size);
    spin_unlock(&heap_lock);
    irq_restore(irq_flags);
    if (ptr != NULL) {
        return ptr;
    }
    
    serial_write_string("[OS] [Memory] kmalloc: Out of memory (requested ");
    serial_write_uint32(size);
    serial_write_string(" bytes)\n");
    return NULL;
}

void kfree(void* ptr) {
    if (ptr == NULL) return;
    
    if (!heap_initialized || heap_start == NULL) {
        serial_write_string("[OS] [Memory] kfree: Heap not initialized\n");
        return;
    }

    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t heap_start_addr = (uintptr_t)heap_start;
    uintptr_t heap_end_addr = heap_start_addr + (HEAP_PAGE_COUNT * PAGE_SIZE);
    
    if (addr < heap_start_addr + sizeof(memory_block_t) || addr >= heap_end_addr) {
        serial_write_string("[OS] [Memory] kfree: Invalid pointer\n");
        return;
    }

    uint64_t irq_flags = irq_save_disable();
    spin_lock(&heap_lock);
    memory_block_t* prev = NULL;
    memory_block_t* block = find_block_by_payload(ptr, &prev);
    if (block == NULL) {
        spin_unlock(&heap_lock);
        irq_restore(irq_flags);
        serial_write_string("[OS] [Memory] kfree: Pointer not tracked\n");
        return;
    }

    if (block->is_free) {
        spin_unlock(&heap_lock);
        irq_restore(irq_flags);
        serial_write_string("[OS] [Memory] kfree: Double free detected\n");
        return;
    }
    
    block->is_free = 1;
    total_freed += block->size;

    if (block->next != NULL && block->next->is_free) {
        block->size += sizeof(memory_block_t) + block->next->size;
        block->next = block->next->next;
    }

    if (prev != NULL && prev->is_free) {
        prev->size += sizeof(memory_block_t) + block->size;
        prev->next = block->next;
        block = prev;
    }

    heap_search_hint = block;
    spin_unlock(&heap_lock);
    irq_restore(irq_flags);
}

void* kcalloc(uint32_t num, uint32_t size) {
    if (num != 0 && size > UINT32_MAX / num) {
        serial_write_string("[OS] [Memory] kcalloc: Size overflow\n");
        return NULL;
    }
    uint32_t total_size = num * size;
    void* ptr = kmalloc(total_size);
    
    if (ptr != NULL) {
        uint8_t* byte_ptr = (uint8_t*)ptr;
        for (uint32_t i = 0; i < total_size; i++) {
            byte_ptr[i] = 0;
        }
    }
    
    return ptr;
}

void* krealloc(void* ptr, uint32_t new_size) {
    if (ptr == NULL) {
        return kmalloc(new_size);
    }
    
    if (new_size == 0) {
        kfree(ptr);
        return NULL;
    }
    
    new_size = align_up(new_size, MIN_ALLOC_ALIGN);

    uint32_t old_size = 0;
    uint64_t irq_flags = irq_save_disable();
    spin_lock(&heap_lock);
    memory_block_t* block = find_block_by_payload(ptr, NULL);
    if (block == NULL || block->is_free) {
        spin_unlock(&heap_lock);
        irq_restore(irq_flags);
        serial_write_string("[OS] [Memory] krealloc: Invalid pointer\n");
        return NULL;
    }
    old_size = block->size;

    if (new_size <= old_size) {
        split_block_if_needed(block, new_size);
        spin_unlock(&heap_lock);
        irq_restore(irq_flags);
        return ptr;
    }

    if (block->next != NULL &&
        block->next->is_free &&
        block->size + sizeof(memory_block_t) + block->next->size >= new_size) {
        block->size += sizeof(memory_block_t) + block->next->size;
        block->next = block->next->next;
        split_block_if_needed(block, new_size);
        spin_unlock(&heap_lock);
        irq_restore(irq_flags);
        return ptr;
    }
    spin_unlock(&heap_lock);
    irq_restore(irq_flags);
    
    void* new_ptr = kmalloc(new_size);
    if (new_ptr == NULL) {
        return NULL;
    }
    
    uint8_t* src = (uint8_t*)ptr;
    uint8_t* dst = (uint8_t*)new_ptr;
    for (uint32_t i = 0; i < old_size; i++) {
        dst[i] = src[i];
    }
    
    kfree(ptr);
    
    return new_ptr;
}

uint32_t get_free_memory(void) {
    if (!heap_initialized) return 0;
    
    uint64_t irq_flags = irq_save_disable();
    spin_lock(&heap_lock);
    uint32_t free_memory = 0;
    memory_block_t* current = heap_start;
    
    while (current != NULL) {
        if (current->is_free) {
            free_memory += current->size;
        }
        current = current->next;
    }
    spin_unlock(&heap_lock);
    irq_restore(irq_flags);
    return free_memory;
}

uint32_t get_used_memory(void) {
    uint64_t irq_flags = irq_save_disable();
    spin_lock(&heap_lock);
    uint32_t used = total_allocated - total_freed;
    spin_unlock(&heap_lock);
    irq_restore(irq_flags);
    return used;
}

void debug_print_memory_info(void) {
    if (!heap_initialized) {
        serial_write_string("[OS] [Memory] Heap not initialized\n");
        return;
    }
    
    uint64_t irq_flags = irq_save_disable();
    spin_lock(&heap_lock);
    memory_block_t* current = heap_start;
    int block_count = 0;
    uint32_t free_blocks = 0;
    uint32_t used_blocks = 0;
    
    while (current != NULL) {
        block_count++;
        if (current->is_free) {
            free_blocks++;
        } else {
            used_blocks++;
        }
        current = current->next;
    }
    
    serial_write_string("[OS] [Memory] Total blocks: ");
    serial_write_uint32(block_count);
    serial_write_string(" (Free: ");
    serial_write_uint32(free_blocks);
    serial_write_string(", Used: ");
    serial_write_uint32(used_blocks);
    serial_write_string(")\n");
    spin_unlock(&heap_lock);
    irq_restore(irq_flags);
}

void* alloc_page(void) {
    uint64_t irq_flags = irq_save_disable();
    spin_lock(&page_lock);
    for (size_t offset = 0; offset < MAX_PAGES; offset++) {
        size_t i = (page_alloc_hint + offset) % MAX_PAGES;
        if (page_bitmap[i] == 0) {
            page_bitmap[i] = 1;
            page_alloc_hint = (uint32_t)((i + 1) % MAX_PAGES);
            spin_unlock(&page_lock);
            irq_restore(irq_flags);
            return (void*)(i * PAGE_SIZE);
        }
    }
    spin_unlock(&page_lock);
    irq_restore(irq_flags);
    return NULL;
}

void* alloc_contiguous_pages(uint32_t page_count, uint32_t align_pages) {
    if (page_count == 0 || page_count > MAX_PAGES) {
        return NULL;
    }
    if (align_pages == 0) {
        align_pages = 1;
    }

    uint64_t irq_flags = irq_save_disable();
    spin_lock(&page_lock);

    uint32_t limit = (uint32_t)(MAX_PAGES - page_count);
    for (uint32_t start = 0; start <= limit; ++start) {
        if ((start % align_pages) != 0) {
            continue;
        }

        uint32_t run = 0;
        while (run < page_count && page_bitmap[start + run] == 0) {
            ++run;
        }
        if (run != page_count) {
            start += run;
            continue;
        }

        for (uint32_t i = 0; i < page_count; ++i) {
            page_bitmap[start + i] = 1;
        }
        page_alloc_hint = (start + page_count) % MAX_PAGES;
        spin_unlock(&page_lock);
        irq_restore(irq_flags);
        return (void *)((uintptr_t)start * PAGE_SIZE);
    }

    spin_unlock(&page_lock);
    irq_restore(irq_flags);
    return NULL;
}

void free_page(void* addr) {
    if (addr == NULL) return;

    uintptr_t page_num = (uintptr_t)addr / PAGE_SIZE;
    uint64_t irq_flags = irq_save_disable();
    spin_lock(&page_lock);
    if (page_num < MAX_PAGES) {
        page_bitmap[page_num] = 0;
        if (page_num < page_alloc_hint) {
            page_alloc_hint = (uint32_t)page_num;
        }
    }
    spin_unlock(&page_lock);
    irq_restore(irq_flags);
}

void free_contiguous_pages(void* addr, uint32_t page_count) {
    if (addr == NULL || page_count == 0) {
        return;
    }

    uintptr_t start_page = (uintptr_t)addr / PAGE_SIZE;
    if (start_page >= MAX_PAGES) {
        return;
    }

    uint64_t irq_flags = irq_save_disable();
    spin_lock(&page_lock);

    uint32_t max_pages = (uint32_t)(MAX_PAGES - start_page);
    if (page_count > max_pages) {
        page_count = max_pages;
    }

    for (uint32_t i = 0; i < page_count; ++i) {
        page_bitmap[start_page + i] = 0;
    }
    if (start_page < page_alloc_hint) {
        page_alloc_hint = (uint32_t)start_page;
    }

    spin_unlock(&page_lock);
    irq_restore(irq_flags);
}
