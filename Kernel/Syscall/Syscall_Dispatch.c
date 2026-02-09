#include "Syscall_Main.h"
#include "IO/IO_Main.h"
#include "../FrameBuffer/FrameBuffer_Main.h"
#include "../Serial.h"
#include <stdint.h>

void syscall_dispatch(uint64_t num,
                      uint64_t arg1,
                      uint64_t arg2,
                      uint64_t arg3,
                      uint64_t arg4,
                      uint64_t arg5)
{
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;

    switch (num) {
    case SYSCALL_SERIAL_PUTCHAR:
        serial_write_char((char)arg1);
        break;

    case SYSCALL_SERIAL_PUTS:
        serial_write_string((const char*)arg1);
        break;

    case SYSCALL_SERIAL_FB_WHITE:
        framebuffer_clear(0x00FFFFFF);
        break;

    default:
        serial_write_string("[SYSCALL] Unknown syscall\n");
        break;
    }
}
