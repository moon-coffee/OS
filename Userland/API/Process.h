#pragma once

#include <stdint.h>

typedef void (*signal_handler_t)(int32_t signum);

signal_handler_t signal(int32_t signum, signal_handler_t handler);
void process_yield(void);
