#include "Kernel_Main.h"
#include "Memory/Memory_Main.h"
#include "Paging/Paging_Main.h"
#include "IDT/IDT_Main.h"
#include "GDT/GDT_Main.h"
#include "IO/IO_Main.h"
#include "Drivers/FileSystem/FAT32/FAT32_Main.h"
#include "Memory/Other_Utils.h"
#include "Syscall/Syscall_Main.h"
#include "FrameBuffer/FrameBuffer_Main.h"
#include "Serial.h"

#define COM1_PORT 0x3F8

#define GDT_KERNEL_CODE 0x08
#define GDT_KERNEL_DATA 0x10
#define GDT_USER_CODE   0x18
#define GDT_USER_DATA   0x20
#define GDT_TSS         0x28

#define USER_STACK_SIZE 8192
__attribute__((aligned(16)))
static uint8_t user_stack[USER_STACK_SIZE];

#define PT_LOAD 1
static FRAMEBUFFER kernel_fb;

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

static uint64_t user_entry = 0;

void serial_init(void) {
    outb(COM1_PORT + 1, 0x00);
    outb(COM1_PORT + 3, 0x80);
    outb(COM1_PORT + 0, 0x03);
    outb(COM1_PORT + 1, 0x00);
    outb(COM1_PORT + 3, 0x03);
    outb(COM1_PORT + 2, 0xC7);
    outb(COM1_PORT + 4, 0x0B);
}

void serial_write_char(char c) {
    while ((inb(COM1_PORT + 5) & 0x20) == 0);
    outb(COM1_PORT, c);
}

void serial_write_string(const char* str) {
    while (*str) {
        if (*str == '\n')
            serial_write_char('\r');
        serial_write_char(*str++);
    }
}

void serial_write_uint64(uint64_t value) {
    char hex[] = "0123456789ABCDEF";
    serial_write_string("0x");
    for (int i = 60; i >= 0; i -= 4) {
        serial_write_char(hex[(value >> i) & 0xF]);
    }
}

void serial_write_uint32(uint32_t value) {
    serial_write_uint64((uint64_t)value);
}

void serial_write_uint16(uint16_t value) {
    serial_write_uint64((uint64_t)value);
}

void all_fs_initialize() {
    fat32_init();
}

static bool load_userland_elf(uint64_t *entry_out) {
    FAT32_FILE file;
    
    if (!fat32_find_file("URLD    ELF", &file)) {
        serial_write_string("[OS] [USER] File URLD.ELF not found\n");
        return false;
    }
    
    serial_write_string("[OS] [USER] File found, size: ");
    serial_write_uint32(file.size);
    serial_write_string("\n");
    
    if (file.size == 0 || file.size > 1024 * 1024) {
        serial_write_string("[OS] [USER] Invalid file size\n");
        return false;
    }
    
    uint8_t *buffer = (uint8_t*)kmalloc(file.size);
    if (!buffer) {
        serial_write_string("[OS] [USER] Out of memory\n");
        return false;
    }
    
    if (!fat32_read_file(&file, buffer)) {
        serial_write_string("[OS] [USER] File read failed\n");
        kfree(buffer);
        return false;
    }
    serial_write_string("[OS] [USER] File read successfully\n");
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)buffer;

    if (ehdr->e_ident[0] != 0x7F ||
        ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L' ||
        ehdr->e_ident[3] != 'F') {
        serial_write_string("[OS] [USER] Invalid ELF magic\n");
        kfree(buffer);
        return false;
    }
    
    serial_write_string("[OS] [USER] Valid ELF header\n");
    serial_write_string("[OS] [USER] Entry point: ");
    serial_write_uint64(ehdr->e_entry);
    serial_write_string("\n");

    Elf64_Phdr *phdrs = (Elf64_Phdr*)(buffer + ehdr->e_phoff);
    
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD) continue;
        
        serial_write_string("[OS] [USER] Loading segment ");
        serial_write_uint16(i);
        serial_write_string(" to vaddr ");
        serial_write_uint64(ph->p_vaddr);
        serial_write_string(", size ");
        serial_write_uint64(ph->p_memsz);
        serial_write_string("\n");
        
        if (ph->p_memsz < ph->p_filesz) {
            serial_write_string("[OS] [USER] Invalid segment: memsz < filesz\n");
            kfree(buffer);
            return false;
        }

        if (ph->p_vaddr < 0x400000 || ph->p_vaddr >= 0x80000000) {
            serial_write_string("[OS] [USER] Invalid virtual address\n");
            kfree(buffer);
            return false;
        }

        uint8_t *dst = (uint8_t*)(uint64_t)ph->p_vaddr;
        uint8_t *src = buffer + ph->p_offset;
        
        memcpy(dst, src, (size_t)ph->p_filesz);
        
        if (ph->p_memsz > ph->p_filesz) {
            memset(dst + ph->p_filesz, 0, (size_t)(ph->p_memsz - ph->p_filesz));
        }
    }

    *entry_out = ehdr->e_entry;
    kfree(buffer);
    serial_write_string("[OS] [USER] ELF loaded successfully\n");
    return true;
}

__attribute__((noreturn))
void entry_user_mode() {
    serial_write_string("[OS] Entering user mode...\n");
    serial_write_string("[OS] User entry: ");
    serial_write_uint64(user_entry);
    serial_write_string("\n");

    uint64_t user_rip = user_entry;
    uint64_t user_rsp = ((uint64_t)user_stack + USER_STACK_SIZE) & ~0xFULL;
    uint64_t rflags   = 0x202;

    uint64_t user_ss = GDT_USER_DATA | 3;
    uint64_t user_cs = GDT_USER_CODE | 3;

    __asm__ volatile (
        "cli\n"

        "mov %0, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"

        "pushq %1\n"
        "pushq %2\n"
        "pushq %3\n"
        "pushq %4\n"
        "pushq %5\n"
        "iretq\n"
        :
        : "r"((uint16_t)(user_ss)),
          "r"(user_ss),
          "r"(user_rsp),
          "r"(rflags),
          "r"(user_cs),
          "r"(user_rip)
        : "rax", "memory"
    );
    __builtin_unreachable();
}

__attribute__((noreturn))
void kernel_main(BOOT_INFO *boot_info) {
    serial_init();
    serial_write_string("\n[OS] ===== Kernel Starting =====\n");
    
    serial_write_string("[OS] Initializing physical memory...\n");
    init_physical_memory(
        boot_info->MemoryMap,
        boot_info->MemoryMapSize,
        boot_info->MemoryMapDescriptorSize
    );

    serial_write_string("[OS] Initializing paging...\n");
    init_paging(boot_info->FrameBufferBase, boot_info->FrameBufferSize);
    
    serial_write_string("[OS] Initializing memory manager...\n");
    memory_init();

    serial_write_string("[OS] Initializing IDT...\n");
    init_idt();
    
    serial_write_string("[OS] Initializing GDT...\n");
    init_gdt();

    serial_write_string("[OS] Initializing framebuffer...\n");
    kernel_fb.base   = boot_info->FrameBufferBase;
    kernel_fb.width  = boot_info->HorizontalResolution;
    kernel_fb.height = boot_info->VerticalResolution;
    kernel_fb.pitch  = boot_info->PixelsPerScanLine * 4;
    kernel_fb.bpp    = 32;

    framebuffer_init(&kernel_fb);
    
    serial_write_string("[OS] Initializing syscall...\n");
    syscall_init(); 

    serial_write_string("[OS] Initializing file system...\n");
    all_fs_initialize();

    serial_write_string("[OS] Loading userland ELF...\n");
    if (!load_userland_elf(&user_entry)) {
        serial_write_string("[OS] [ERROR] Failed to load userland ELF\n");
        serial_write_string("[OS] [ERROR] System halted\n");
        while (1) {
            __asm__("hlt");
        }
    }
    
    serial_write_string("[OS] ===== Kernel Init Complete =====\n");
    serial_write_string("[OS] Transferring control to userland...\n\n");
    
    entry_user_mode();
    __builtin_unreachable();
}