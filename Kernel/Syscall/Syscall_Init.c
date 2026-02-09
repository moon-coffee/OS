#include "Syscall_Main.h"
#include "GDT/GDT_Main.h"
#include <stdint.h>

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    __asm__ volatile ("wrmsr" :: "c"(msr), "a"(low), "d"(high));
}

#define IA32_STAR   0xC0000081
#define IA32_LSTAR  0xC0000082
#define IA32_FMASK  0xC0000084
#define IA32_EFER  0xC0000080
#define EFER_SCE   (1ULL << 0)

extern void syscall_entry(void);

void syscall_init(void) {
    uint64_t efer_low, efer_high;
    __asm__ volatile ("rdmsr" : "=a"(efer_low), "=d"(efer_high) : "c"(IA32_EFER));
    uint64_t efer = (efer_high << 32) | efer_low;
    efer |= EFER_SCE;
    wrmsr(IA32_EFER, efer);

    wrmsr(IA32_LSTAR, (uint64_t)syscall_entry);
    uint64_t star =
        ((uint64_t)GDT_KERNEL_CODE << 32) |
        ((uint64_t)(GDT_USER_CODE - 0x10) << 48);
    wrmsr(IA32_STAR, star);

    wrmsr(IA32_FMASK, 0);
}
