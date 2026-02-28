#include "IDT_Main.h"

#include "../IO/IO_Main.h"
#include "../Memory/Memory_Main.h"
#include "../Paging/Paging_Main.h"
#include "../ProcessManager/ProcessManager.h"
#include "../Serial.h"

#include <stdint.h>

#define MAX_IRQS 256
#define PANIC_STACK_DUMP_QWORDS 8

static IDT_Entry idt[IDT_ENTRIES];
static IDT_Ptr idt_ptr;
static isr_t irq_routines[MAX_IRQS] = {0};

extern void isr_default(void);
extern void isr_page_fault(void);
extern void isr_double_fault(void);
extern void isr_nmi(void);
extern void isr_general_protection(void);
extern void isr_machine_check(void);
extern void load_idt(IDT_Ptr *idt_ptr);
extern void page_fault_resume_user(uint64_t next_saved_rsp,
                                   uint64_t next_user_rsp);

static void panic_dump_stack_words(uint64_t rsp)
{
    serial_write_string("[OS] [PANIC] Stack snapshot:\n");
    if (rsp == 0) {
        serial_write_string("[OS] [PANIC]  <invalid rsp>\n");
        return;
    }

    const uint64_t *stack = (const uint64_t *)(uintptr_t)rsp;
    for (uint32_t i = 0; i < PANIC_STACK_DUMP_QWORDS; ++i) {
        serial_write_string("[OS] [PANIC]  [");
        serial_write_uint32(i);
        serial_write_string("] @ ");
        serial_write_uint64(rsp + ((uint64_t)i * sizeof(uint64_t)));
        serial_write_string(" = ");
        serial_write_uint64(stack[i]);
        serial_write_string("\n");
    }
}

static void panic_dump_stack_trace(uint64_t rbp)
{
    serial_write_string("[OS] [PANIC] Stack trace:\n");
    if (rbp == 0 || (rbp & 0x7ULL) != 0) {
        serial_write_string("[OS] [PANIC]  <invalid rbp>\n");
        return;
    }

    const uint64_t max_depth = 16;
    uint64_t current_rbp = rbp;
    for (uint64_t depth = 0; depth < max_depth; ++depth) {
        const uint64_t *frame = (const uint64_t *)(uintptr_t)current_rbp;
        uint64_t next_rbp = frame[0];
        uint64_t return_rip = frame[1];

        serial_write_string("[OS] [PANIC]  #");
        serial_write_uint64(depth);
        serial_write_string(" rbp=");
        serial_write_uint64(current_rbp);
        serial_write_string(" rip=");
        serial_write_uint64(return_rip);
        serial_write_string("\n");

        if (next_rbp <= current_rbp || (next_rbp & 0x7ULL) != 0 ||
            (next_rbp - current_rbp) > 0x10000ULL) {
            break;
        }
        current_rbp = next_rbp;
    }
}

__attribute__((noreturn))
static void panic_exception(const char *name,
                            uint64_t vector,
                            uint64_t error_code,
                            uint64_t rip,
                            uint64_t rsp,
                            uint64_t rbp,
                            uint64_t cr2)
{
    uint64_t cr0 = 0;
    uint64_t cr3 = 0;
    uint64_t cr4 = 0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));

    serial_write_string("\n[OS] [PANIC] Fatal exception\n");
    serial_write_string("[OS] [PANIC] name: ");
    serial_write_string(name);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] vector: ");
    serial_write_uint64(vector);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] error: ");
    serial_write_uint64(error_code);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] RIP: ");
    serial_write_uint64(rip);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] RSP: ");
    serial_write_uint64(rsp);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] RBP: ");
    serial_write_uint64(rbp);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] CR0: ");
    serial_write_uint64(cr0);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] CR3: ");
    serial_write_uint64(cr3);
    serial_write_string("\n");
    serial_write_string("[OS] [PANIC] CR4: ");
    serial_write_uint64(cr4);
    serial_write_string("\n");
    if (cr2 != 0) {
        serial_write_string("[OS] [PANIC] CR2: ");
        serial_write_uint64(cr2);
        serial_write_string("\n");
    }

    panic_dump_stack_words(rsp);
    panic_dump_stack_trace(rbp);
    memory_dump_virtual((const void *)(uintptr_t)rsp,
                        PANIC_STACK_DUMP_QWORDS * (uint32_t)sizeof(uint64_t));

    while (1) {
        __asm__ volatile ("hlt");
    }
}

void register_interrupt_handler(uint16_t irq, isr_t handler)
{
    if (irq < MAX_IRQS) {
        irq_routines[irq] = handler;
    }
}

void irq_handler(uint16_t irq_num)
{
    if (irq_num < MAX_IRQS && irq_routines[irq_num]) {
        irq_routines[irq_num]();
    }

    if (irq_num >= 32 && irq_num < 48) {
        outb(0x20, 0x20);
        if (irq_num >= 40) {
            outb(0xA0, 0x20);
        }
    }
}

void double_fault_handler(uint64_t error_code, uint64_t rip, uint64_t rsp, uint64_t rbp)
{
    panic_exception("double_fault", 8, error_code, rip, rsp, rbp, 0);
}

void nmi_handler(uint64_t rip, uint64_t rsp, uint64_t rbp)
{
    panic_exception("nmi", 2, 0, rip, rsp, rbp, 0);
}

void general_protection_fault_handler(uint64_t error_code,
                                      uint64_t rip,
                                      uint64_t rsp,
                                      uint64_t rbp)
{
    panic_exception("general_protection", 13, error_code, rip, rsp, rbp, 0);
}

void machine_check_handler(uint64_t rip, uint64_t rsp, uint64_t rbp)
{
    panic_exception("machine_check", 18, 0, rip, rsp, rbp, 0);
}

void set_interrupt_handler_with_ist(uint16_t n, void (*handler)(void), uint8_t ist)
{
    uint64_t addr = (uint64_t)handler;

    idt[n].offset_low = (uint16_t)(addr & 0xFFFF);
    idt[n].selector = 0x08;
    idt[n].ist = (uint8_t)(ist & 0x7u);
    idt[n].type_attr = 0x8E;
    idt[n].offset_mid = (uint16_t)((addr >> 16) & 0xFFFF);
    idt[n].offset_high = (uint32_t)((addr >> 32) & 0xFFFFFFFF);
    idt[n].zero = 0;
}

void set_interrupt_handler(uint16_t n, void (*handler)(void))
{
    set_interrupt_handler_with_ist(n, handler, 0);
}

void init_idt(void)
{
    serial_write_string("[OS] [IDT] Start Initialize IDT.\n");

    for (int i = 0; i < IDT_ENTRIES; i++) {
        set_interrupt_handler((uint16_t)i, isr_default);
    }

    set_interrupt_handler_with_ist(2, isr_nmi, 2);
    set_interrupt_handler_with_ist(8, isr_double_fault, 1);
    set_interrupt_handler(13, isr_general_protection);
    set_interrupt_handler(14, isr_page_fault);
    set_interrupt_handler(18, isr_machine_check);

    idt_ptr.limit = sizeof(idt) - 1;
    idt_ptr.base = (uint64_t)&idt;

    load_idt(&idt_ptr);

    serial_write_string("[OS] [IDT] Successfully Initialize IDT.\n");
}

int32_t page_fault_handler(uint64_t error_code,
                           uint64_t rip,
                           uint64_t rsp,
                           uint64_t cr2,
                           uint64_t rbp)
{
    const uint64_t PF_WRITE = (1ULL << 1);
    const uint64_t PF_USER = (1ULL << 2);
    const uint64_t PF_RSVD = (1ULL << 3);
    const uint64_t PF_INSTR = (1ULL << 4);

    serial_write_string("[OS] [PF] Page fault\n");
    serial_write_string("[OS] [PF] CR2: ");
    serial_write_uint64(cr2);
    serial_write_string("\n");
    serial_write_string("[OS] [PF] RIP: ");
    serial_write_uint64(rip);
    serial_write_string("\n");
    serial_write_string("[OS] [PF] RSP: ");
    serial_write_uint64(rsp);
    serial_write_string("\n");
    serial_write_string("[OS] [PF] Error: ");
    serial_write_uint64(error_code);
    serial_write_string("\n");

    serial_write_string("[OS] [PF] Access: ");
    serial_write_string((error_code & PF_WRITE) ? "write" : "read");
    serial_write_string(", mode: ");
    serial_write_string((error_code & PF_USER) ? "user" : "kernel");
    serial_write_string(", reserved: ");
    serial_write_string((error_code & PF_RSVD) ? "yes" : "no");
    serial_write_string(", exec: ");
    serial_write_string((error_code & PF_INSTR) ? "yes" : "no");
    serial_write_string("\n");

    int32_t pid = process_get_current_pid();
    if ((error_code & PF_USER) && pid >= 0) {
        uint64_t cr3 = process_get_current_cr3();
        int swap_rc = paging_handle_swap_fault(cr3, cr2);
        if (swap_rc > 0) {
            serial_write_string("[OS] [PF] Recovered via swap-in\n");
            return 0;
        }

        if (process_is_guard_page_fault(cr2)) {
            serial_write_string("[OS] [PF] Guard page hit (stack/heap overflow) pid=");
            serial_write_uint32((uint32_t)pid);
            serial_write_string("\n");
        } else {
            serial_write_string("[OS] [PF] Terminating process pid=");
            serial_write_uint32((uint32_t)pid);
            serial_write_string(" (mode=user)\n");
        }

        process_exit_current();

        uint64_t next_user_rsp = 0;
        uint64_t next_saved_rsp = process_schedule_after_exit(&next_user_rsp);

        int32_t next_pid = process_get_current_pid();
        serial_write_string("[OS] [PF] Switched to pid=");
        serial_write_uint32((uint32_t)next_pid);
        serial_write_string("\n");

        page_fault_resume_user(next_saved_rsp, next_user_rsp);
    }

    panic_exception("page_fault", 14, error_code, rip, rsp, rbp, cr2);
    return -1;
}

void unregister_interrupt_handler(uint16_t irq)
{
    if (irq < MAX_IRQS) {
        irq_routines[irq] = 0;
    }
}

void set_exception_handler(uint16_t exception_num, void (*handler)(void))
{
    if (exception_num < 32) {
        set_interrupt_handler(exception_num, handler);
    }
}

void set_irq_handler(uint16_t irq, void (*handler)(void))
{
    if (irq < 16) {
        set_interrupt_handler((uint16_t)(32 + irq), handler);
    }
}
