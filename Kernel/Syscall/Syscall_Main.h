#pragma once
#include <stdint.h>

#define SYSCALL_SERIAL_PUTCHAR    1
#define SYSCALL_SERIAL_PUTS       2
#define SYSCALL_SERIAL_WRITE_U64  3
#define SYSCALL_SERIAL_WRITE_U32  4
#define SYSCALL_SERIAL_WRITE_U16  5
#define SYSCALL_PROCESS_CREATE    6
#define SYSCALL_PROCESS_YIELD     7
#define SYSCALL_PROCESS_EXIT      8
#define SYSCALL_THREAD_CREATE     9
#define SYSCALL_DRAW_PIXEL        13
#define SYSCALL_DRAW_FILL_RECT    14
#define SYSCALL_DRAW_PRESENT      15
#define SYSCALL_WM_CREATE_WINDOW  16
#define SYSCALL_FILE_OPEN         23
#define SYSCALL_FILE_READ         24
#define SYSCALL_FILE_WRITE        25
#define SYSCALL_FILE_CLOSE        26
#define SYSCALL_FILE_SEEK         34
#define SYSCALL_USER_KMALLOC      27
#define SYSCALL_USER_KFREE        28
#define SYSCALL_USER_MEMCPY       29
#define SYSCALL_USER_MEMCMP       30
#define SYSCALL_USER_MEMSET       31    
#define SYSCALL_INPUT_READ_KEYBOARD 32
#define SYSCALL_INPUT_READ_MOUSE  33
#define SYSCALL_PROCESS_SPAWN_ELF 36
#define SYSCALL_FILE_MKDIR        37
#define SYSCALL_FILE_OPENDIR      38
#define SYSCALL_FILE_READDIR      39
#define SYSCALL_FILE_CLOSEDIR     40
#define SYSCALL_FILE_UNLINK       41
#define SYSCALL_FILE_CREAT        42
#define SYSCALL_USER_MMAP         43
#define SYSCALL_PROCESS_SIGNAL    44

#define SYSCALL_FRAME_RAX  0
#define SYSCALL_FRAME_RDX  1
#define SYSCALL_FRAME_RSI  2
#define SYSCALL_FRAME_RDI  3
#define SYSCALL_FRAME_R8   4
#define SYSCALL_FRAME_R9   5
#define SYSCALL_FRAME_R10  6
#define SYSCALL_FRAME_R12  7
#define SYSCALL_FRAME_R13  8
#define SYSCALL_FRAME_R14  9
#define SYSCALL_FRAME_R15  10
#define SYSCALL_FRAME_RBX  11
#define SYSCALL_FRAME_RBP  12
#define SYSCALL_FRAME_RCX  13
#define SYSCALL_FRAME_R11  14
#define SYSCALL_FRAME_QWORDS 15

void     syscall_init(void);
uint64_t syscall_get_user_rsp(void);
void     syscall_set_user_rsp(uint64_t user_rsp);
uint64_t syscall_get_kernel_rsp(void);
void     syscall_set_kernel_rsp(uint64_t kernel_rsp);

uint64_t syscall_dispatch(uint64_t saved_rsp,
                          uint64_t num,
                          uint64_t arg1,
                          uint64_t arg2,
                          uint64_t arg3,
                          uint64_t arg4);
