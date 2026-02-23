#include "Kernel_Main.h"
#include "Memory/Memory_Main.h"
#include "Paging/Paging_Main.h"
#include "IDT/IDT_Main.h"
#include "GDT/GDT_Main.h"
#include "IO/IO_Main.h"
#include "Drivers/FileSystem/FAT32/FAT32_Main.h"
#include "Drivers/DriverModule.h"
#include "Drivers/DriverSelect.h"
#include "Drivers/Display/Display_Main.h"
#include "Drivers/PS2/PS2_Input.h"
#include "ELF/ELF_Loader.h"
#include "Syscall/Syscall_Main.h"
#include "Syscall/Syscall_File.h"
#include "ProcessManager/ProcessManager.h"
#include "WindowManager/WindowManager.h"
#include "Serial.h"

#define COM1_PORT 0x3F8

#define GDT_KERNEL_CODE 0x08
#define GDT_KERNEL_DATA 0x10
#define GDT_USER_COMPAT_CODE 0x18
#define GDT_USER_DATA        0x20
#define GDT_USER_CODE        0x28
#define GDT_TSS              0x30

#define USER_ELF_MAX_SIZE (2ULL * 1024ULL * 1024ULL)

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
    elf_load_policy_t policy = {
        .max_file_size = USER_ELF_MAX_SIZE,
        .min_vaddr = USER_CODE_BASE,
        .max_vaddr = USER_CODE_LIMIT,
    };
    return elf_loader_load_from_path("Userland/Userland.ELF", &policy, entry_out);
}

__attribute__((noreturn))
void entry_user_mode() {
    uint64_t user_rip = user_entry;
    uint64_t user_rsp = process_get_current_user_rsp() - 128;
    uint64_t user_cr3 = process_get_current_cr3();
    
    paging_switch_cr3(user_cr3);

    uint64_t user_ss = GDT_USER_DATA | 3;
    uint64_t user_cs = GDT_USER_CODE | 3;
    uint64_t rflags  = 0x202;

    __asm__ volatile (
        "cli\n"
        "mov %0, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"

        "pushq %1\n"
        "pushq %2\n"
        "pushq %3\n"
        "pushq %4\n"
        "pushq %5\n"
        "iretq\n"
        :
        : "r"((uint16_t)user_ss), "r"(user_ss), "r"(user_rsp), "r"(rflags), "r"(user_cs), "r"(user_rip)
        : "rax", "memory"
    );
    __builtin_unreachable();
}

__attribute__((noreturn))
void kernel_main(BOOT_INFO *boot_info) {
    serial_init();
    serial_write_string("\n[OS] ===== Kernel Starting =====\n");

    driver_module_manager_init(boot_info);
    display_boot_framebuffer_t boot_fb = {
        .addr = (void *)(uintptr_t)boot_info->FrameBufferBase,
        .size_bytes = boot_info->FrameBufferSize,
        .width = boot_info->HorizontalResolution,
        .height = boot_info->VerticalResolution,
        .pixels_per_scan_line = boot_info->PixelsPerScanLine,
        .bytes_per_pixel = 4,
    };
    driver_select_set_boot_framebuffer(&boot_fb);
    
    serial_write_string("[OS] Initializing physical memory...\n");
    init_physical_memory(
        boot_info->MemoryMap,
        boot_info->MemoryMapSize,
        boot_info->MemoryMapDescriptorSize
    );

    serial_write_string("[OS] Initializing paging...\n");
    init_paging();

    serial_write_string("[OS] Initializing memory manager...\n");
    memory_init();

    serial_write_string("[OS] Initializing IDT...\n");
    init_idt();
    
    serial_write_string("[OS] Initializing GDT...\n");
    init_gdt();

    serial_write_string("[OS] Initializing file system...\n");
    all_fs_initialize();

    serial_write_string("[OS] Initializing display...\n");
    if (!display_init()) {
        serial_write_string("[OS] [WARN] Display init failed\n");
    }

    serial_write_string("[OS] Initializing PS/2 input...\n");
    ps2_input_init();
    
    serial_write_string("[OS] Initializing syscall...\n");
    syscall_init(); 

    serial_write_string("[OS] Initializing process manager...\n");
    process_manager_init();

    serial_write_string("[OS] Initializing window manager...\n");
    window_manager_init();

    syscall_file_init();

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

    if (process_register_boot_process(user_entry, 0) < 0) {
        serial_write_string("[OS] [ERROR] Failed to register boot process\n");
        while (1) {
            __asm__("hlt");
        }
    }
    
    entry_user_mode();
    __builtin_unreachable();
}
