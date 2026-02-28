#include "SMP_Main.h"

#include "../Serial.h"

static uint32_t g_cpu_count = 1;

void smp_init(void)
{
    g_cpu_count = 1;
    serial_write_string("[OS] [SMP] BSP online, AP startup pending\n");
}

uint32_t smp_get_cpu_count(void)
{
    return g_cpu_count;
}

uint32_t smp_get_current_cpu_id(void)
{
    return 0;
}
