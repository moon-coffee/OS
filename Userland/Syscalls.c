#include <stdint.h>
#include "../Kernel/Memory/Other_Utils.h"
#include "Syscalls.h"

#define SYSCALL_SERIAL_PUTCHAR    1ULL
#define SYSCALL_SERIAL_PUTS       2ULL
#define SYSCALL_SERIAL_WRITE_U64  3ULL
#define SYSCALL_SERIAL_WRITE_U32  4ULL
#define SYSCALL_SERIAL_WRITE_U16  5ULL
#define SYSCALL_PROCESS_CREATE    6ULL
#define SYSCALL_PROCESS_YIELD     7ULL
#define SYSCALL_PROCESS_EXIT      8ULL
#define SYSCALL_THREAD_CREATE     9ULL
#define SYSCALL_DRAW_PIXEL        13ULL
#define SYSCALL_DRAW_FILL_RECT    14ULL
#define SYSCALL_DRAW_PRESENT      15ULL
#define SYSCALL_WM_CREATE_WINDOW  16ULL
#define SYSCALL_FILE_OPEN         23ULL
#define SYSCALL_FILE_READ         24ULL
#define SYSCALL_FILE_WRITE        25ULL
#define SYSCALL_FILE_CLOSE        26ULL
#define SYSCALL_FILE_SEEK         34ULL
#define SYSCALL_USER_KMALLOC      27ULL
#define SYSCALL_USER_KFREE        28ULL
#define SYSCALL_USER_MEMCPY       29ULL
#define SYSCALL_USER_MEMCMP       30ULL
#define SYSCALL_USER_MEMSET       31ULL
#define SYSCALL_INPUT_READ_KEYBOARD 32ULL
#define SYSCALL_INPUT_READ_MOUSE  33ULL

static inline uint64_t syscall0(uint64_t num)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall1(uint64_t num, uint64_t arg1)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall2(uint64_t num, uint64_t arg1, uint64_t arg2)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall3(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall4(uint64_t num, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    uint64_t ret;
    register uint64_t r10 __asm__("r10") = arg4;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((unused)) int32_t file_open(const char *path, uint64_t flags)
{
    return (int32_t)syscall2(SYSCALL_FILE_OPEN, (uint64_t)path, flags);
}

__attribute__((unused)) int64_t file_read(int32_t fd, void *buffer, uint64_t len)
{
    return (int64_t)syscall3(SYSCALL_FILE_READ, (uint64_t)fd, (uint64_t)buffer, len);
}

__attribute__((unused)) int64_t file_write(int32_t fd, const void *buffer, uint64_t len)
{
    return (int64_t)syscall3(SYSCALL_FILE_WRITE, (uint64_t)fd, (uint64_t)buffer, len);
}

__attribute__((unused)) int32_t file_close(int32_t fd)
{
    return (int32_t)syscall1(SYSCALL_FILE_CLOSE, (uint64_t)fd);
}

__attribute__((unused)) int64_t file_seek(int32_t fd, int64_t offset, int32_t whence)
{
    return (int64_t)syscall3(SYSCALL_FILE_SEEK,
                             (uint64_t)fd,
                             (uint64_t)offset,
                             (uint64_t)whence);
}

void* kmalloc(uint32_t size) {
    return (void*)syscall1(SYSCALL_USER_KMALLOC, size);
}

void kfree(void* ptr) {
    (void)syscall1(SYSCALL_USER_KFREE, (uint64_t)ptr);
}

void* memcpy(void* dst, const void* src, size_t n) {
    return (void*)syscall3(SYSCALL_USER_MEMCPY,
                           (uint64_t)dst,
                           (uint64_t)src,
                           (uint64_t)n);
}

int memcmp(const void *s1, const void *s2, size_t n) {
    return (int)syscall3(SYSCALL_USER_MEMCMP,
                         (uint64_t)s1,
                         (uint64_t)s2,
                         (uint64_t)n);
}

void *memset(void *ptr, int value, size_t num) {
    return (void *)syscall3(SYSCALL_USER_MEMSET,
                            (uint64_t)ptr,
                            (uint64_t)value,
                            (uint64_t)num);
}

void serial_write_string(const char *str)
{
    (void)syscall1(SYSCALL_SERIAL_PUTS, (uint64_t)str);
}

void serial_write_uint64(uint64_t value)
{
    (void)syscall1(SYSCALL_SERIAL_WRITE_U64, (uint64_t)value);
}

void serial_write_uint32(uint32_t value)
{
    (void)syscall1(SYSCALL_SERIAL_WRITE_U32, (uint64_t)value);
}

void serial_write_uint16(uint16_t value)
{
    (void)syscall1(SYSCALL_SERIAL_WRITE_U16, (uint64_t)value);
}

int32_t wm_create_window(uint32_t width, uint32_t height)
{
    return (int32_t)syscall2(SYSCALL_WM_CREATE_WINDOW, width, height);
}

void draw_fill_rect(uint32_t x,
                    uint32_t y,
                    uint32_t w,
                    uint32_t h,
                    uint32_t color)
{
    uint64_t packed_wh = ((uint64_t)w << 32) | (uint64_t)h;
    (void)syscall4(SYSCALL_DRAW_FILL_RECT, x, y, packed_wh, color);
}

void draw_pixel(uint32_t x, uint32_t y, uint32_t color)
{
    (void)syscall3(SYSCALL_DRAW_PIXEL, x, y, color);
}

void draw_present(void)
{
    (void)syscall0(SYSCALL_DRAW_PRESENT);
}

void process_yield(void)
{
    (void)syscall0(SYSCALL_PROCESS_YIELD);
}

int32_t input_read_keyboard(input_keyboard_event_t *event_out)
{
    return (int32_t)syscall1(SYSCALL_INPUT_READ_KEYBOARD, (uint64_t)event_out);
}

int32_t input_read_mouse(input_mouse_event_t *event_out)
{
    return (int32_t)syscall1(SYSCALL_INPUT_READ_MOUSE, (uint64_t)event_out);
}
