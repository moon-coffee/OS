#ifndef IDT_MAIN_H
#define IDT_MAIN_H

#include <stdint.h>

#define IDT_ENTRIES 256

typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t zero;
} __attribute__((packed)) IDT_Entry;

typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) IDT_Ptr;
typedef void(*isr_t)(void);

void register_interrupt_handler(uint16_t irq, isr_t handler);
void init_idt(void);
void set_interrupt_handler(uint16_t n, void (*handler)(void));

extern void load_idt(IDT_Ptr*);

#endif
