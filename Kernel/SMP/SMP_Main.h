#pragma once

#include <stdint.h>

void smp_init(void);
uint32_t smp_get_cpu_count(void);
uint32_t smp_get_current_cpu_id(void);
