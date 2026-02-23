#include "GDT_Main.h"
#include "../Serial.h"

static struct {
    struct GDTEntry  null;
    struct GDTEntry  kernel_code;
    struct GDTEntry  kernel_data;
    struct GDTEntry  user_compat_code;
    struct GDTEntry  user_data;
    struct GDTEntry  user_code;
    struct GDTEntry64 tss;
} __attribute__((packed)) gdt;

static struct GDTR gdtr;
static struct TSS tss;

static uint8_t kernel_stack[4096 * 4];
extern void gdt_flush(uint64_t);
extern void tss_flush(uint16_t);

static struct GDTEntry make_gdt_entry(uint32_t limit, uint8_t access, uint8_t flags) {
    struct GDTEntry e = {0};
    e.limit_low = limit & 0xFFFF;
    e.access = access;
    e.gran   = ((limit >> 16) & 0x0F) | (flags & 0xF0);
    return e;
}

void init_gdt(void) {
    serial_write_string("[OS] [GDT] Start Initialize GDT.\n");
    gdt.null = make_gdt_entry(0, 0, 0);

    gdt.kernel_code = make_gdt_entry(0xFFFFF, 0x9A, 0xA0);
    gdt.kernel_data = make_gdt_entry(0xFFFFF, 0x92, 0x80);

    gdt.user_compat_code = make_gdt_entry(0xFFFFF, 0xFA, 0xC0);
    gdt.user_data = make_gdt_entry(0xFFFFF, 0xF2, 0x80);
    gdt.user_code = make_gdt_entry(0xFFFFF, 0xFA, 0xA0);

    uint64_t tss_base = (uint64_t)&tss;
    uint32_t tss_limit = sizeof(struct TSS) - 1;

    gdt.tss.limit_low  = tss_limit & 0xFFFF;
    gdt.tss.base_low   = tss_base & 0xFFFF;
    gdt.tss.base_mid   = (tss_base >> 16) & 0xFF;
    gdt.tss.access     = 0x89;
    gdt.tss.gran       = (tss_limit >> 16) & 0x0F;
    gdt.tss.base_high  = (tss_base >> 24) & 0xFF;
    gdt.tss.base_upper = (tss_base >> 32);
    gdt.tss.reserved   = 0;

    for (int i = 0; i < 7; i++) tss.ist[i] = 0;
    tss.rsp0 = (uint64_t)(kernel_stack + sizeof(kernel_stack));
    tss.io_map_base = sizeof(struct TSS);

    gdtr.limit = sizeof(gdt) - 1;
    gdtr.base  = (uint64_t)&gdt;

    gdt_flush((uint64_t)&gdtr);
    tss_flush(GDT_TSS);
    serial_write_string("[OS] [GDT] Successfully Initialize GDT.\n");
}

void gdt_set_kernel_rsp0(uint64_t rsp0)
{
    tss.rsp0 = rsp0 & ~0xFULL;
}
