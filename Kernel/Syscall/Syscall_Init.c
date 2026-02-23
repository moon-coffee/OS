#include "Syscall_Main.h"
#include "GDT/GDT_Main.h"
#include <stdint.h>

#define SYSCALL_KERNEL_STACK_SIZE 4096

static inline void wrmsr(uint32_t msr, uint64_t value) {
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high = value >> 32;
    __asm__ volatile ("wrmsr" :: "c"(msr), "a"(low), "d"(high));
}

#define IA32_EFER           0xC0000080
#define IA32_STAR           0xC0000081
#define IA32_LSTAR          0xC0000082
#define IA32_FMASK          0xC0000084
#define IA32_GS_BASE        0xC0000101
#define IA32_KERNEL_GS_BASE 0xC0000102
#define EFER_SCE            (1ULL << 0)
#define RFLAGS_IF           (1ULL << 9)

typedef struct {
    uint64_t user_rsp;
    uint64_t kernel_rsp;
} syscall_cpu_state_t;

static syscall_cpu_state_t g_syscall_cpu_state;
static uint8_t g_syscall_kernel_stack[SYSCALL_KERNEL_STACK_SIZE] __attribute__((aligned(16)));

extern void syscall_entry(void);

uint64_t syscall_get_user_rsp(void)
{
    return g_syscall_cpu_state.user_rsp;
}

void syscall_set_user_rsp(uint64_t user_rsp)
{
    g_syscall_cpu_state.user_rsp = user_rsp;
}

uint64_t syscall_get_kernel_rsp(void)
{
    return g_syscall_cpu_state.kernel_rsp;
}

void syscall_set_kernel_rsp(uint64_t kernel_rsp)
{
    g_syscall_cpu_state.kernel_rsp = kernel_rsp & ~0xFULL;
}

void syscall_init(void) {
    uint64_t kernel_rsp = (uint64_t)(g_syscall_kernel_stack + SYSCALL_KERNEL_STACK_SIZE);
    g_syscall_cpu_state.user_rsp = 0;
    g_syscall_cpu_state.kernel_rsp = kernel_rsp & ~0xFULL;

    uint64_t efer_low, efer_high;
    __asm__ volatile ("rdmsr" : "=a"(efer_low), "=d"(efer_high) : "c"(IA32_EFER));
    uint64_t efer = (efer_high << 32) | efer_low;
    efer |= EFER_SCE;
    wrmsr(IA32_EFER, efer);

    wrmsr(IA32_LSTAR, (uint64_t)syscall_entry);
    uint64_t star =
        ((uint64_t)GDT_KERNEL_CODE << 32) |
        ((uint64_t)GDT_USER_COMPAT_CODE << 48);
    wrmsr(IA32_STAR, star);

    wrmsr(IA32_GS_BASE, 0);
    wrmsr(IA32_KERNEL_GS_BASE, (uint64_t)&g_syscall_cpu_state);
    wrmsr(IA32_FMASK, RFLAGS_IF);
}
