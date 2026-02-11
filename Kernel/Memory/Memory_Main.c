#include "Memory_Main.h"
#include "../Serial.h"
#include "../Kernel_Main.h"
#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE 4096
#define MAX_PAGES 262144

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
static uint32_t heap_initialized = 0;
static uint32_t total_allocated = 0;
static uint32_t total_freed = 0;

#define HEAP_PAGE_COUNT 4096

static uint32_t heap_start_page = 0;

static uint32_t calc_heap_start_page(void) {
    if (heap_start_page != 0) return heap_start_page;
    uintptr_t end = (uintptr_t)&_kernel_end;
    heap_start_page = (uint32_t)((end + PAGE_SIZE - 1) / PAGE_SIZE);
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
    
    heap_initialized = 1;
    total_allocated = 0;
    total_freed = 0;
    
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
    
    size = (size + 7) & ~7;
    
    memory_block_t* current = heap_start;
    
    while (current != NULL) {
        if (current->is_free && current->size >= size) {
            if (current->size >= size + sizeof(memory_block_t) + 64) {
                memory_block_t* new_block = (memory_block_t*)((uint8_t*)current + sizeof(memory_block_t) + size);
                new_block->size = current->size - size - sizeof(memory_block_t);
                new_block->is_free = 1;
                new_block->next = current->next;
                
                current->size = size;
                current->next = new_block;
            }
            
            current->is_free = 0;
            total_allocated += current->size;
            
            return (void*)((uint8_t*)current + sizeof(memory_block_t));
        }
        
        current = current->next;
    }
    
    serial_write_string("[OS] [Memory] kmalloc: Out of memory (requested ");
    serial_write_uint32(size);
    serial_write_string(" bytes)\n");
    return NULL;
}

void kfree(void* ptr) {
    if (ptr == NULL) return;
    
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t heap_start_addr = (uintptr_t)heap_start;
    uintptr_t heap_end_addr = heap_start_addr + (HEAP_PAGE_COUNT * PAGE_SIZE);
    
    if (addr < heap_start_addr || addr >= heap_end_addr) {
        serial_write_string("[OS] [Memory] kfree: Invalid pointer\n");
        return;
    }
    
    memory_block_t* block = (memory_block_t*)((uint8_t*)ptr - sizeof(memory_block_t));
    
    if (block->is_free) {
        serial_write_string("[OS] [Memory] kfree: Double free detected\n");
        return;
    }
    
    block->is_free = 1;
    total_freed += block->size;
    
    // Coalesce adjacent free blocks
    memory_block_t* current = heap_start;
    
    while (current != NULL && current->next != NULL) {
        if (current->is_free && current->next->is_free) {
            current->size += sizeof(memory_block_t) + current->next->size;
            current->next = current->next->next;
        } else {
            current = current->next;
        }
    }
}

void* kcalloc(uint32_t num, uint32_t size) {
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
    
    memory_block_t* block = (memory_block_t*)((uint8_t*)ptr - sizeof(memory_block_t));
    uint32_t old_size = block->size;
    
    if (new_size <= old_size) {
        return ptr;
    }
    
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
    
    uint32_t free_memory = 0;
    memory_block_t* current = heap_start;
    
    while (current != NULL) {
        if (current->is_free) {
            free_memory += current->size;
        }
        current = current->next;
    }
    
    return free_memory;
}

uint32_t get_used_memory(void) {
    return total_allocated - total_freed;
}

void debug_print_memory_info(void) {
    if (!heap_initialized) {
        serial_write_string("[OS] [Memory] Heap not initialized\n");
        return;
    }
    
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
}

void* alloc_page(void) {
    for (size_t i = 0; i < MAX_PAGES; i++) {
        if (page_bitmap[i] == 0) {
            page_bitmap[i] = 1;
            return (void*)(i * PAGE_SIZE);
        }
    }
    return NULL;
}

void free_page(void* addr) {
    uintptr_t page_num = (uintptr_t)addr / PAGE_SIZE;
    if (page_num < MAX_PAGES) {
        page_bitmap[page_num] = 0;
    }
}