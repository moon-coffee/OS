#include "Syscall_Main.h"
#include "Syscall_File.h"
#include "../Common/Status.h"
#include "../Drivers/PS2/PS2_Input.h"
#include "../ProcessManager/ProcessManager.h"
#include "../Serial.h"
#include "../WindowManager/WindowManager.h"

#include <stddef.h>
#include <stdint.h>

#define SYSCALL_MAX_PATH_LEN    128U
#define SYSCALL_MAX_PUTS_LEN    256U
#define SYSCALL_MAX_IO_BYTES    (1024ULL * 1024ULL)
#define SYSCALL_MAX_MEM_BYTES   (4ULL * 1024ULL * 1024ULL)
#define SYSCALL_MAX_ALLOC_BYTES (1024U * 1024U)
#define SYSCALL_MAX_WINDOW_SIZE 4096U
#define SYSCALL_U32_MASK        0xFFFFFFFFULL

static const char k_decimal_digits[10] = "0123456789";

static void set_syscall_result(uint64_t saved_rsp, uint64_t value)
{
    uint64_t *frame = (uint64_t *)(uintptr_t)saved_rsp;
    frame[SYSCALL_FRAME_RAX] = value;
}

static void set_syscall_status(uint64_t saved_rsp, os_status_t status)
{
    set_syscall_result(saved_rsp, os_status_to_u64(status));
}

static void set_syscall_i32(uint64_t saved_rsp, int32_t value)
{
    set_syscall_result(saved_rsp, os_status_to_u64(os_status_from_i32(value)));
}

static int user_buffer_ok(const void *ptr, uint64_t len)
{
    if (len == 0) {
        return 1;
    }
    if (ptr == NULL) {
        return 0;
    }
    return process_user_buffer_is_valid(ptr, len);
}

static int copy_user_cstring(char *dst, uint64_t dst_size, const char *src)
{
    if (dst == NULL || src == NULL || dst_size < 2ULL) {
        return -1;
    }

    uint64_t len = 0;
    if (process_user_cstring_length(src, dst_size - 1ULL, &len) < 0) {
        return -1;
    }
    if (len >= dst_size) {
        return -1;
    }

    for (uint64_t i = 0; i < len; ++i) {
        dst[i] = src[i];
    }
    dst[len] = '\0';
    return 0;
}

static void serial_write_status_with_name(os_status_t status)
{
    if (os_status_is_error(status)) {
        serial_write_char('-');
    }

    serial_write_uint64(os_status_abs_u64(status));
    serial_write_string(" (");
    serial_write_string(os_status_to_string(status));
    serial_write_char(')');
}

static void syscall_log_status(const char *function_name,
                               uint64_t syscall_number,
                               os_status_t status,
                               const char *reason)
{
    serial_write_string("[OS] [SYSCALL] fn=");
    serial_write_string(function_name);
    serial_write_string(" num=");
    serial_write_uint64(syscall_number);
    serial_write_string(" status=");
    serial_write_status_with_name(status);
    if (reason != NULL && reason[0] != '\0') {
        serial_write_string(" reason=");
        serial_write_string(reason);
    }
    serial_write_string("\n");
}

static void syscall_fail(uint64_t saved_rsp,
                         uint64_t syscall_number,
                         os_status_t status,
                         const char *reason)
{
    syscall_log_status("syscall_dispatch", syscall_number, status, reason);
    set_syscall_status(saved_rsp, status);
}

static void serial_write_unsigned_decimal(uint64_t value)
{
    char buffer[32];
    uint32_t index = (uint32_t)(sizeof(buffer) - 1U);
    buffer[index] = '\0';

    do {
        uint64_t digit = value % 10ULL;
        --index;
        buffer[index] = k_decimal_digits[(size_t)digit];
        value /= 10ULL;
    } while (value > 0ULL && index > 0U);

    serial_write_string(&buffer[index]);
}

static process_capability_mask_t syscall_required_capability(uint64_t syscall_number)
{
    switch (syscall_number) {
        case SYSCALL_SERIAL_PUTCHAR:
        case SYSCALL_SERIAL_PUTS:
        case SYSCALL_SERIAL_WRITE_U64:
        case SYSCALL_SERIAL_WRITE_U32:
        case SYSCALL_SERIAL_WRITE_U16:
            return PROCESS_CAP_SERIAL;

        case SYSCALL_PROCESS_CREATE:
        case SYSCALL_PROCESS_SPAWN_ELF:
        case SYSCALL_THREAD_CREATE:
            return PROCESS_CAP_PROCESS;

        case SYSCALL_WM_CREATE_WINDOW:
        case SYSCALL_DRAW_PIXEL:
        case SYSCALL_DRAW_FILL_RECT:
        case SYSCALL_DRAW_PRESENT:
            return PROCESS_CAP_WINDOW;

        case SYSCALL_FILE_OPEN:
        case SYSCALL_FILE_CREAT:
        case SYSCALL_FILE_READ:
        case SYSCALL_FILE_WRITE:
        case SYSCALL_FILE_CLOSE:
        case SYSCALL_FILE_SEEK:
        case SYSCALL_FILE_MKDIR:
        case SYSCALL_FILE_OPENDIR:
        case SYSCALL_FILE_READDIR:
        case SYSCALL_FILE_CLOSEDIR:
        case SYSCALL_FILE_UNLINK:
            return PROCESS_CAP_FILE;

        case SYSCALL_USER_MMAP:
        case SYSCALL_USER_KMALLOC:
        case SYSCALL_USER_KFREE:
        case SYSCALL_USER_MEMCPY:
        case SYSCALL_USER_MEMCMP:
        case SYSCALL_USER_MEMSET:
            return PROCESS_CAP_MEMORY;

        case SYSCALL_INPUT_READ_KEYBOARD:
        case SYSCALL_INPUT_READ_MOUSE:
            return PROCESS_CAP_INPUT;

        case SYSCALL_PROCESS_SIGNAL:
            return PROCESS_CAP_SIGNAL;

        case SYSCALL_PROCESS_YIELD:
        case SYSCALL_PROCESS_EXIT:
        default:
            return 0;
    }
}

uint64_t syscall_dispatch(uint64_t saved_rsp,
                          uint64_t num,
                          uint64_t arg1,
                          uint64_t arg2,
                          uint64_t arg3,
                          uint64_t arg4)
{
    int request_switch = 0;
    int32_t current_pid = process_get_current_pid();

    ps2_input_poll();

    process_capability_mask_t required_capability = syscall_required_capability(num);
    if (required_capability != 0 &&
        !process_current_has_capability(required_capability)) {
        syscall_fail(saved_rsp, num, OS_STATUS_ACCESS_DENIED, "capability_denied");
        goto schedule;
    }

    switch (num) {
        case SYSCALL_SERIAL_PUTCHAR:
            serial_write_char((char)arg1);
            set_syscall_result(saved_rsp, 0);
            break;

        case SYSCALL_SERIAL_PUTS: {
            char buffer[SYSCALL_MAX_PUTS_LEN];
            if (copy_user_cstring(buffer, sizeof(buffer),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_user_string");
                break;
            }
            serial_write_string(buffer);
            set_syscall_result(saved_rsp, 0);
            break;
        }

        case SYSCALL_SERIAL_WRITE_U64:
            serial_write_unsigned_decimal(arg1);
            set_syscall_result(saved_rsp, 0);
            break;

        case SYSCALL_SERIAL_WRITE_U32:
            serial_write_unsigned_decimal((uint64_t)(uint32_t)arg1);
            set_syscall_result(saved_rsp, 0);
            break;

        case SYSCALL_SERIAL_WRITE_U16:
            serial_write_unsigned_decimal((uint64_t)(uint16_t)arg1);
            set_syscall_result(saved_rsp, 0);
            break;

        case SYSCALL_PROCESS_CREATE: {
            int32_t pid = process_create_user(arg1);
            set_syscall_i32(saved_rsp, pid);
            break;
        }

        case SYSCALL_PROCESS_SPAWN_ELF: {
            char path[SYSCALL_MAX_PATH_LEN];
            if (copy_user_cstring(path, sizeof(path),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_path");
                break;
            }
            int32_t pid = process_spawn_user_elf(path);
            set_syscall_i32(saved_rsp, pid);
            break;
        }

        case SYSCALL_PROCESS_YIELD:
            set_syscall_result(saved_rsp, 0);
            request_switch = 1;
            break;

        case SYSCALL_PROCESS_EXIT:
            process_exit_current();
            request_switch = 1;
            set_syscall_result(saved_rsp, 0);
            break;

        case SYSCALL_THREAD_CREATE: {
            int32_t tid = process_create_user(arg1);
            set_syscall_i32(saved_rsp, tid);
            if (tid >= 0) {
                request_switch = 1;
            }
            break;
        }

        case SYSCALL_WM_CREATE_WINDOW: {
            uint32_t width = (uint32_t)arg1;
            uint32_t height = (uint32_t)arg2;
            if (current_pid < 0 || width == 0 || height == 0 ||
                width > SYSCALL_MAX_WINDOW_SIZE || height > SYSCALL_MAX_WINDOW_SIZE) {
                syscall_fail(saved_rsp, num, OS_STATUS_INVALID_ARG, "invalid_window_size_or_pid");
                break;
            }

            int32_t id = window_manager_create_window_for_process(current_pid, width, height);
            set_syscall_i32(saved_rsp, id);
            break;
        }

        case SYSCALL_DRAW_PIXEL: {
            if (current_pid < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_ACCESS_DENIED, "invalid_pid");
                break;
            }

            int32_t rc = window_manager_draw_pixel_for_process(current_pid,
                                                               (uint32_t)arg1,
                                                               (uint32_t)arg2,
                                                               (uint32_t)arg3);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_DRAW_FILL_RECT: {
            if (current_pid < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_ACCESS_DENIED, "invalid_pid");
                break;
            }

            uint32_t w = (uint32_t)(arg3 >> 32);
            uint32_t h = (uint32_t)(arg3 & SYSCALL_U32_MASK);
            if (w == 0 || h == 0 || w > SYSCALL_MAX_WINDOW_SIZE || h > SYSCALL_MAX_WINDOW_SIZE) {
                syscall_fail(saved_rsp, num, OS_STATUS_INVALID_ARG, "invalid_rect_size");
                break;
            }

            int32_t rc = window_manager_fill_rect_for_process(current_pid,
                                                              (uint32_t)arg1,
                                                              (uint32_t)arg2,
                                                              w,
                                                              h,
                                                              (uint32_t)arg4);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_DRAW_PRESENT: {
            if (current_pid < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_ACCESS_DENIED, "invalid_pid");
                break;
            }

            int32_t rc = window_manager_present_for_process(current_pid);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_FILE_OPEN: {
            char path[SYSCALL_MAX_PATH_LEN];
            if (copy_user_cstring(path, sizeof(path),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_path");
                break;
            }

            int32_t fd = syscall_file_open(path, arg2);
            set_syscall_i32(saved_rsp, fd);
            break;
        }

        case SYSCALL_FILE_CREAT: {
            char path[SYSCALL_MAX_PATH_LEN];
            if (copy_user_cstring(path, sizeof(path),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_path");
                break;
            }

            int32_t fd = syscall_file_creat(path);
            set_syscall_i32(saved_rsp, fd);
            break;
        }

        case SYSCALL_FILE_READ: {
            if (arg3 > SYSCALL_MAX_IO_BYTES ||
                !user_buffer_ok((const void *)(uintptr_t)arg2, arg3)) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_read_buffer");
                break;
            }

            int64_t n = syscall_file_read((int32_t)arg1,
                                          (uint8_t *)(uintptr_t)arg2,
                                          arg3);
            set_syscall_result(saved_rsp, (uint64_t)n);
            break;
        }

        case SYSCALL_FILE_WRITE: {
            if (arg3 > SYSCALL_MAX_IO_BYTES ||
                !user_buffer_ok((const void *)(uintptr_t)arg2, arg3)) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_write_buffer");
                break;
            }

            int64_t n = syscall_file_write((int32_t)arg1,
                                           (const uint8_t *)(uintptr_t)arg2,
                                           arg3);
            set_syscall_result(saved_rsp, (uint64_t)n);
            break;
        }

        case SYSCALL_FILE_CLOSE: {
            int32_t rc = syscall_file_close((int32_t)arg1);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_FILE_SEEK: {
            int64_t pos = syscall_file_seek((int32_t)arg1, (int64_t)arg2, (int32_t)arg3);
            set_syscall_result(saved_rsp, (uint64_t)pos);
            break;
        }

        case SYSCALL_FILE_MKDIR: {
            char path[SYSCALL_MAX_PATH_LEN];
            if (copy_user_cstring(path, sizeof(path),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_path");
                break;
            }

            int32_t rc = syscall_file_mkdir(path);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_FILE_OPENDIR: {
            char path[SYSCALL_MAX_PATH_LEN];
            if (copy_user_cstring(path, sizeof(path),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_path");
                break;
            }

            int32_t handle = syscall_file_opendir(path);
            set_syscall_i32(saved_rsp, handle);
            break;
        }

        case SYSCALL_FILE_READDIR: {
            FAT32_DIRENT *entry_out = (FAT32_DIRENT *)(uintptr_t)arg2;
            if (!user_buffer_ok(entry_out, sizeof(FAT32_DIRENT))) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_dirent_buffer");
                break;
            }

            int32_t rc = syscall_file_readdir((int32_t)arg1, entry_out);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_FILE_CLOSEDIR: {
            int32_t rc = syscall_file_closedir((int32_t)arg1);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_FILE_UNLINK: {
            char path[SYSCALL_MAX_PATH_LEN];
            if (copy_user_cstring(path, sizeof(path),
                                  (const char *)(uintptr_t)arg1) < 0) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_path");
                break;
            }

            int32_t rc = syscall_file_unlink(path);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_USER_MMAP: {
            void *mapped = process_user_mmap(arg1, arg2);
            set_syscall_result(saved_rsp, (uint64_t)(uintptr_t)mapped);
            break;
        }

        case SYSCALL_PROCESS_SIGNAL: {
            uint64_t previous = process_signal_set_handler((int32_t)arg1, arg2);
            set_syscall_result(saved_rsp, previous);
            break;
        }

        case SYSCALL_USER_KMALLOC: {
            uint32_t size = (uint32_t)arg1;
            if (size == 0 || size > SYSCALL_MAX_ALLOC_BYTES) {
                set_syscall_result(saved_rsp, 0);
                break;
            }

            void *ptr = process_user_alloc(size);
            set_syscall_result(saved_rsp, (uint64_t)(uintptr_t)ptr);
            break;
        }

        case SYSCALL_USER_KFREE: {
            int rc = process_user_free((void *)(uintptr_t)arg1);
            set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
            break;
        }

        case SYSCALL_USER_MEMCPY: {
            void *dst = (void *)(uintptr_t)arg1;
            const void *src = (const void *)(uintptr_t)arg2;
            uint64_t n = arg3;

            if (n > SYSCALL_MAX_MEM_BYTES ||
                !user_buffer_ok(dst, n) ||
                !user_buffer_ok(src, n)) {
                set_syscall_result(saved_rsp, 0);
                break;
            }

            uint8_t *d = (uint8_t *)dst;
            const uint8_t *s = (const uint8_t *)src;
            for (uint64_t i = 0; i < n; ++i) {
                d[i] = s[i];
            }

            set_syscall_result(saved_rsp, (uint64_t)(uintptr_t)dst);
            break;
        }

        case SYSCALL_USER_MEMCMP: {
            const uint8_t *s1 = (const uint8_t *)(uintptr_t)arg1;
            const uint8_t *s2 = (const uint8_t *)(uintptr_t)arg2;
            uint64_t n = arg3;

            if (n > SYSCALL_MAX_MEM_BYTES ||
                !user_buffer_ok(s1, n) ||
                !user_buffer_ok(s2, n)) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_memcmp_buffer");
                break;
            }

            int result = 0;
            for (uint64_t i = 0; i < n; ++i) {
                if (s1[i] != s2[i]) {
                    result = (int)s1[i] - (int)s2[i];
                    break;
                }
            }

            set_syscall_result(saved_rsp, (uint64_t)(int64_t)result);
            break;
        }

        case SYSCALL_USER_MEMSET: {
            uint8_t *dst = (uint8_t *)(uintptr_t)arg1;
            uint8_t value = (uint8_t)arg2;
            uint64_t n = arg3;

            if (n > SYSCALL_MAX_MEM_BYTES || !user_buffer_ok(dst, n)) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_memset_buffer");
                break;
            }

            for (uint64_t i = 0; i < n; ++i) {
                dst[i] = value;
            }

            set_syscall_result(saved_rsp, arg1);
            break;
        }

        case SYSCALL_INPUT_READ_KEYBOARD: {
            ps2_keyboard_event_t *event_out = (ps2_keyboard_event_t *)(uintptr_t)arg1;
            if (!user_buffer_ok(event_out, sizeof(ps2_keyboard_event_t))) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_keyboard_buffer");
                break;
            }

            int32_t rc = ps2_input_read_keyboard(event_out);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        case SYSCALL_INPUT_READ_MOUSE: {
            ps2_mouse_event_t *event_out = (ps2_mouse_event_t *)(uintptr_t)arg1;
            if (!user_buffer_ok(event_out, sizeof(ps2_mouse_event_t))) {
                syscall_fail(saved_rsp, num, OS_STATUS_FAULT, "invalid_mouse_buffer");
                break;
            }

            int32_t rc = ps2_input_read_mouse(event_out);
            set_syscall_i32(saved_rsp, rc);
            break;
        }

        default:
            syscall_fail(saved_rsp, num, OS_STATUS_NOT_SUPPORTED, "unknown_syscall");
            break;
    }

schedule:
    {
        uint64_t current_user_rsp = syscall_get_user_rsp();
        uint64_t next_user_rsp = current_user_rsp;
        uint64_t next_saved_rsp = process_schedule_on_syscall(saved_rsp,
                                                              current_user_rsp,
                                                              request_switch,
                                                              &next_user_rsp);
        syscall_set_user_rsp(next_user_rsp);
        return next_saved_rsp;
    }
}
