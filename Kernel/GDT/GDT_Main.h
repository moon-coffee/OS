#pragma once
#include <stdint.h>

#define GDT_KERNEL_CODE 0x08
#define GDT_KERNEL_DATA 0x10
#define GDT_USER_COMPAT_CODE 0x18
#define GDT_USER_DATA        0x20
#define GDT_USER_CODE        0x28
#define GDT_TSS              0x30

struct __attribute__((packed)) GDTEntry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_mid;
    uint8_t  access;
    uint8_t  gran;
    uint8_t  base_high;
};

struct __attribute__((packed)) GDTEntry64 {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_mid;
    uint8_t  access;
    uint8_t  gran;
    uint8_t  base_high;
    uint32_t base_upper;
    uint32_t reserved;
};

struct __attribute__((packed)) GDTR {
    uint16_t limit;
    uint64_t base;
};

struct __attribute__((packed)) TSS {
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t io_map_base;
};

void init_gdt(void);
void gdt_set_kernel_rsp0(uint64_t rsp0);
