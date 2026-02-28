#include <stddef.h>
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
#define SYSCALL_FILE_MKDIR        37ULL
#define SYSCALL_FILE_OPENDIR      38ULL
#define SYSCALL_FILE_READDIR      39ULL
#define SYSCALL_FILE_CLOSEDIR     40ULL
#define SYSCALL_FILE_UNLINK       41ULL
#define SYSCALL_FILE_CREAT        42ULL
#define SYSCALL_USER_MMAP         43ULL
#define SYSCALL_PROCESS_SIGNAL    44ULL

#define OS_STATUS_INVALID_ARG   (-22LL)
#define OS_STATUS_NOT_FOUND     (-2LL)
#define OS_STATUS_ACCESS_DENIED (-13LL)
#define OS_STATUS_LIMIT_REACHED (-24LL)
#define OS_STATUS_IO_ERROR      (-5LL)
#define OS_STATUS_FAULT         (-14LL)
#define OS_STATUS_NOT_SUPPORTED (-95LL)
#define OS_STATUS_INTERNAL      (-255LL)

int os_errno = 0;

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

int os_get_errno(void)
{
    return os_errno;
}

void os_set_errno(int value)
{
    os_errno = (value < 0) ? -value : value;
}

void os_clear_errno(void)
{
    os_errno = 0;
}

int os_status_is_error(int64_t status_code)
{
    return status_code < 0;
}

int os_status_to_errno(int64_t status_code)
{
    if (status_code >= 0) {
        return 0;
    }

    switch (status_code) {
        case OS_STATUS_INVALID_ARG:
            return 22;
        case OS_STATUS_NOT_FOUND:
            return 2;
        case OS_STATUS_ACCESS_DENIED:
            return 13;
        case OS_STATUS_LIMIT_REACHED:
            return 24;
        case OS_STATUS_IO_ERROR:
            return 5;
        case OS_STATUS_FAULT:
            return 14;
        case OS_STATUS_NOT_SUPPORTED:
            return 95;
        case OS_STATUS_INTERNAL:
            return 255;
        default:
            if (status_code <= -4096LL) {
                return 255;
            }
            return (int)(-status_code);
    }
}

static int32_t os_errno_from_i32_status(int32_t value)
{
    if (os_status_is_error((int64_t)value)) {
        os_set_errno(os_status_to_errno((int64_t)value));
    } else {
        os_clear_errno();
    }
    return value;
}

static int64_t os_errno_from_i64_status(int64_t value)
{
    if (os_status_is_error(value)) {
        os_set_errno(os_status_to_errno(value));
    } else {
        os_clear_errno();
    }
    return value;
}

size_t os_strnlen(const char *str, size_t max_len)
{
    if (str == NULL) {
        return 0;
    }

    size_t len = 0;
    while (len < max_len && str[len] != '\0') {
        ++len;
    }
    return len;
}

int os_strcpy_s(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || src == NULL || dst_size == 0) {
        return -1;
    }

    size_t src_len = os_strnlen(src, dst_size);
    if (src_len >= dst_size) {
        dst[0] = '\0';
        return -1;
    }

    for (size_t i = 0; i <= src_len; ++i) {
        dst[i] = src[i];
    }
    return 0;
}

int os_strcat_s(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || src == NULL || dst_size == 0) {
        return -1;
    }

    size_t dst_len = os_strnlen(dst, dst_size);
    if (dst_len >= dst_size) {
        return -1;
    }

    size_t remaining = dst_size - dst_len;
    size_t src_len = os_strnlen(src, remaining);
    if (src_len >= remaining) {
        return -1;
    }

    for (size_t i = 0; i <= src_len; ++i) {
        dst[dst_len + i] = src[i];
    }
    return 0;
}

__attribute__((unused)) int32_t file_open(const char *path, uint64_t flags)
{
    return os_errno_from_i32_status((int32_t)syscall2(SYSCALL_FILE_OPEN, (uint64_t)path, flags));
}

__attribute__((unused)) int32_t file_creat(const char *path)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_FILE_CREAT, (uint64_t)path));
}

__attribute__((unused)) int64_t file_read(int32_t fd, void *buffer, uint64_t len)
{
    return os_errno_from_i64_status((int64_t)syscall3(SYSCALL_FILE_READ, (uint64_t)fd, (uint64_t)buffer, len));
}

__attribute__((unused)) int64_t file_write(int32_t fd, const void *buffer, uint64_t len)
{
    return os_errno_from_i64_status((int64_t)syscall3(SYSCALL_FILE_WRITE, (uint64_t)fd, (uint64_t)buffer, len));
}

__attribute__((unused)) int32_t file_close(int32_t fd)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_FILE_CLOSE, (uint64_t)fd));
}

__attribute__((unused)) int32_t file_mkdir(const char *path)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_FILE_MKDIR, (uint64_t)path));
}

__attribute__((unused)) int32_t file_opendir(const char *path)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_FILE_OPENDIR, (uint64_t)path));
}

__attribute__((unused)) int32_t file_readdir(int32_t dir_handle, file_dirent_t *out_entry)
{
    return os_errno_from_i32_status((int32_t)syscall2(SYSCALL_FILE_READDIR, (uint64_t)dir_handle, (uint64_t)out_entry));
}

__attribute__((unused)) int32_t file_closedir(int32_t dir_handle)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_FILE_CLOSEDIR, (uint64_t)dir_handle));
}

__attribute__((unused)) int32_t file_unlink(const char *path)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_FILE_UNLINK, (uint64_t)path));
}

void *mmap(uint64_t length, uint64_t flags)
{
    void *ptr = (void *)(uintptr_t)syscall2(SYSCALL_USER_MMAP, length, flags);
    if (ptr == NULL && length != 0ULL) {
        os_set_errno(12);
    } else {
        os_clear_errno();
    }
    return ptr;
}

signal_handler_t signal(int32_t signum, signal_handler_t handler)
{
    uint64_t raw = syscall2(SYSCALL_PROCESS_SIGNAL,
                            (uint64_t)signum,
                            (uint64_t)(uintptr_t)handler);
    if (os_status_is_error((int64_t)raw)) {
        os_set_errno(os_status_to_errno((int64_t)raw));
        return (signal_handler_t)0;
    }
    os_clear_errno();
    return (signal_handler_t)(uintptr_t)raw;
}

__attribute__((unused)) int64_t file_seek(int32_t fd, int64_t offset, int32_t whence)
{
    return os_errno_from_i64_status((int64_t)syscall3(SYSCALL_FILE_SEEK,
                                                      (uint64_t)fd,
                                                      (uint64_t)offset,
                                                      (uint64_t)whence));
}

void* kmalloc(uint32_t size) {
    void *ptr = (void *)syscall1(SYSCALL_USER_KMALLOC, size);
    if (ptr == NULL && size != 0U) {
        os_set_errno(12);
    } else {
        os_clear_errno();
    }
    return ptr;
}

void kfree(void* ptr) {
    (void)syscall1(SYSCALL_USER_KFREE, (uint64_t)ptr);
    os_clear_errno();
}

void* memcpy(void* dst, const void* src, size_t n) {
    void *result = (void *)syscall3(SYSCALL_USER_MEMCPY,
                                    (uint64_t)dst,
                                    (uint64_t)src,
                                    (uint64_t)n);
    if (result == NULL && n != 0U) {
        os_set_errno(14);
    } else {
        os_clear_errno();
    }
    return result;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    return (int)syscall3(SYSCALL_USER_MEMCMP,
                         (uint64_t)s1,
                         (uint64_t)s2,
                         (uint64_t)n);
}

void *memset(void *ptr, int value, size_t num) {
    void *result = (void *)syscall3(SYSCALL_USER_MEMSET,
                                    (uint64_t)ptr,
                                    (uint64_t)value,
                                    (uint64_t)num);
    if (result == NULL && num != 0U) {
        os_set_errno(14);
    } else {
        os_clear_errno();
    }
    return result;
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
    return os_errno_from_i32_status((int32_t)syscall2(SYSCALL_WM_CREATE_WINDOW, width, height));
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
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_INPUT_READ_KEYBOARD, (uint64_t)event_out));
}

int32_t input_read_mouse(input_mouse_event_t *event_out)
{
    return os_errno_from_i32_status((int32_t)syscall1(SYSCALL_INPUT_READ_MOUSE, (uint64_t)event_out));
}
