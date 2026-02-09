#pragma once
#include <stdint.h>

#define SYSCALL_SERIAL_PUTCHAR  1
#define SYSCALL_SERIAL_PUTS     2
#define SYSCALL_SERIAL_FB_WHITE 3

void syscall_init(void);
