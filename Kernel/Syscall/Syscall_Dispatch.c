#include "Syscall_Main.h"
#include "Syscall_File.h"
#include "../ProcessManager/ProcessManager.h"
#include "../Serial.h"
#include "../Drivers/PS2/PS2_Input.h"
#include "../WindowManager/WindowManager.h"

#include <stddef.h>
#include <stdint.h>

#define SYSCALL_MAX_PATH_LEN  128
#define SYSCALL_MAX_PUTS_LEN  256
#define SYSCALL_MAX_IO_BYTES  (1024ULL * 1024ULL)
#define SYSCALL_MAX_MEM_BYTES (4ULL * 1024ULL * 1024ULL)
#define SYSCALL_MAX_ALLOC_BYTES (1024U * 1024U)
#define SYSCALL_MAX_WINDOW_SIZE 4096U

static void set_syscall_result(uint64_t saved_rsp, uint64_t value)
{
    uint64_t *frame = (uint64_t *)(uintptr_t)saved_rsp;
    frame[SYSCALL_FRAME_RAX] = value;
}

static int user_buffer_ok(const void *ptr, uint64_t len)
{
    if (len == 0) return 1;
    if (ptr == NULL) return 0;
    return process_user_buffer_is_valid(ptr, len);
}

static int copy_user_cstring(char *dst, uint64_t dst_size, const char *src)
{
    if (dst == NULL || src == NULL || dst_size < 2) return -1;
    uint64_t len = 0;
    if (process_user_cstring_length(src, dst_size - 1, &len) < 0) return -1;
    for (uint64_t i = 0; i < len; ++i) dst[i] = src[i];
    dst[len] = '\0';
    return 0;
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

    switch (num) {
    
    case SYSCALL_SERIAL_PUTCHAR:
        serial_write_char((char)arg1);
        set_syscall_result(saved_rsp, 0);
        break;

    case SYSCALL_SERIAL_PUTS: {
        char buffer[SYSCALL_MAX_PUTS_LEN];
        if (copy_user_cstring(buffer, sizeof(buffer),
                              (const char *)(uintptr_t)arg1) < 0) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        serial_write_string(buffer);
        set_syscall_result(saved_rsp, 0);
        break;
    }

    case SYSCALL_SERIAL_WRITE_U64: {
        uint64_t value = arg1;
        char buf[32];
        int i = 30;
        buf[31] = '\0';

        if (value == 0) {
        buf[i--] = '0';
        } else {
            while (value > 0 && i >= 0) {
                buf[i--] = '0' + (value % 10);
                value /= 10;
            }
        }

        serial_write_string(&buf[i + 1]);
        set_syscall_result(saved_rsp, 0);
        break;
    }

    case SYSCALL_SERIAL_WRITE_U32: {
        uint32_t value = (uint32_t)arg1;
        char buf[16];
        int i = 14;
        buf[15] = '\0';

        if (value == 0) {
        buf[i--] = '0';
        } else {
            while (value > 0 && i >= 0) {
                buf[i--] = '0' + (value % 10);
                value /= 10;
            }
    }

        serial_write_string(&buf[i + 1]);
        set_syscall_result(saved_rsp, 0);
        break;
    }

    case SYSCALL_SERIAL_WRITE_U16: {
        uint16_t value = (uint16_t)arg1;
        char buf[8];
        int i = 6;
        buf[7] = '\0';

        if (value == 0) {
            buf[i--] = '0';
        } else {
            while (value > 0 && i >= 0) {
                buf[i--] = '0' + (value % 10);
                value /= 10;
            }
    }

        serial_write_string(&buf[i + 1]);
        set_syscall_result(saved_rsp, 0);
        break;
    }

    case SYSCALL_PROCESS_CREATE: {
        int32_t pid = process_create_user(arg1);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)pid);
        break;
    }

    case SYSCALL_PROCESS_SPAWN_ELF: {
        char path[SYSCALL_MAX_PATH_LEN];
        if (copy_user_cstring(path, sizeof(path),
                              (const char *)(uintptr_t)arg1) < 0) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int32_t pid = process_spawn_user_elf(path);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)pid);
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
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)tid);
        if (tid >= 0) request_switch = 1;
        break;
    }

    case SYSCALL_WM_CREATE_WINDOW: {
        uint32_t width  = (uint32_t)arg1;
        uint32_t height = (uint32_t)arg2;
        if (current_pid < 0 || width == 0 || height == 0 ||
            width > SYSCALL_MAX_WINDOW_SIZE || height > SYSCALL_MAX_WINDOW_SIZE) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int32_t id = window_manager_create_window_for_process(current_pid, width, height);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)id);
        break;
    }

    case SYSCALL_DRAW_PIXEL: {
        if (current_pid < 0) { set_syscall_result(saved_rsp, (uint64_t)-1); break; }
        int32_t rc = window_manager_draw_pixel_for_process(current_pid,
                                                           (uint32_t)arg1,
                                                           (uint32_t)arg2,
                                                           (uint32_t)arg3);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
        break;
    }

    case SYSCALL_DRAW_FILL_RECT: {
        if (current_pid < 0) { set_syscall_result(saved_rsp, (uint64_t)-1); break; }
        uint32_t w = (uint32_t)(arg3 >> 32);
        uint32_t h = (uint32_t)(arg3 & 0xFFFFFFFFu);
        if (w == 0 || h == 0 || w > SYSCALL_MAX_WINDOW_SIZE || h > SYSCALL_MAX_WINDOW_SIZE) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int32_t rc = window_manager_fill_rect_for_process(current_pid,
                                                          (uint32_t)arg1,
                                                          (uint32_t)arg2,
                                                          w, h,
                                                          (uint32_t)arg4);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
        break;
    }

    case SYSCALL_DRAW_PRESENT: {
        if (current_pid < 0) { set_syscall_result(saved_rsp, (uint64_t)-1); break; }
        int32_t rc = window_manager_present_for_process(current_pid);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
        break;
    }

    case SYSCALL_FILE_OPEN: {
        char path[SYSCALL_MAX_PATH_LEN];
        if (copy_user_cstring(path, sizeof(path),
                              (const char *)(uintptr_t)arg1) < 0) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int32_t fd = syscall_file_open(path, arg2);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)fd);
        break;
    }

    case SYSCALL_FILE_READ: {
        if (arg3 > SYSCALL_MAX_IO_BYTES ||
            !user_buffer_ok((const void *)(uintptr_t)arg2, arg3)) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int64_t n = syscall_file_read((int32_t)arg1,
                                      (uint8_t *)(uintptr_t)arg2, arg3);
        set_syscall_result(saved_rsp, (uint64_t)n);
        break;
    }

    case SYSCALL_FILE_WRITE: {
        if (arg3 > SYSCALL_MAX_IO_BYTES ||
            !user_buffer_ok((const void *)(uintptr_t)arg2, arg3)) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int64_t n = syscall_file_write((int32_t)arg1,
                                       (const uint8_t *)(uintptr_t)arg2, arg3);
        set_syscall_result(saved_rsp, (uint64_t)n);
        break;
    }

    case SYSCALL_FILE_CLOSE: {
        int32_t rc = syscall_file_close((int32_t)arg1);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
        break;
    }

    case SYSCALL_FILE_SEEK: {
        int64_t pos = syscall_file_seek((int32_t)arg1, (int64_t)arg2, (int32_t)arg3);
        set_syscall_result(saved_rsp, (uint64_t)pos);
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
        void       *dst = (void *)(uintptr_t)arg1;
        const void *src = (const void *)(uintptr_t)arg2;
        uint64_t     n  = arg3;
        if (n > SYSCALL_MAX_MEM_BYTES ||
            !user_buffer_ok(dst, n) ||
            !user_buffer_ok(src, n)) {
            set_syscall_result(saved_rsp, 0);
            break;
        }
        uint8_t       *d = (uint8_t *)dst;
        const uint8_t *s = (const uint8_t *)src;
        for (uint64_t i = 0; i < n; ++i) d[i] = s[i];
        set_syscall_result(saved_rsp, (uint64_t)(uintptr_t)dst);
        break;
    }

    case SYSCALL_USER_MEMCMP: {
        const uint8_t *s1 = (const uint8_t *)(uintptr_t)arg1;
        const uint8_t *s2 = (const uint8_t *)(uintptr_t)arg2;
        uint64_t        n = arg3;
        if (n > SYSCALL_MAX_MEM_BYTES ||
            !user_buffer_ok(s1, n) ||
            !user_buffer_ok(s2, n)) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int result = 0;
        for (uint64_t i = 0; i < n; ++i) {
            if (s1[i] != s2[i]) { result = (int)s1[i] - (int)s2[i]; break; }
        }
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)result);
        break;
    }

    case SYSCALL_USER_MEMSET: {
        uint8_t *s = (uint8_t *)(uintptr_t)arg1;
        int      c = (int)arg2;
        uint64_t n = arg3;
        if (n > SYSCALL_MAX_MEM_BYTES ||
            !user_buffer_ok(s, n)) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        for (uint64_t i = 0; i < n; ++i) {
            s[i] = (uint8_t)c;
        }
        set_syscall_result(saved_rsp, arg1);
        break;
    }

    case SYSCALL_INPUT_READ_KEYBOARD: {
        ps2_keyboard_event_t *event_out =
            (ps2_keyboard_event_t *)(uintptr_t)arg1;
        if (!user_buffer_ok(event_out, sizeof(ps2_keyboard_event_t))) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int32_t rc = ps2_input_read_keyboard(event_out);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
        break;
    }

    case SYSCALL_INPUT_READ_MOUSE: {
        ps2_mouse_event_t *event_out =
            (ps2_mouse_event_t *)(uintptr_t)arg1;
        if (!user_buffer_ok(event_out, sizeof(ps2_mouse_event_t))) {
            set_syscall_result(saved_rsp, (uint64_t)-1);
            break;
        }
        int32_t rc = ps2_input_read_mouse(event_out);
        set_syscall_result(saved_rsp, (uint64_t)(int64_t)rc);
        break;
    }

    default:
        serial_write_string("[SYSCALL] Unknown syscall\n");
        set_syscall_result(saved_rsp, (uint64_t)-1);
        break;
    }

    uint64_t current_user_rsp = syscall_get_user_rsp();
    uint64_t next_user_rsp    = current_user_rsp;
    uint64_t next_saved_rsp   = process_schedule_on_syscall(saved_rsp,
                                                            current_user_rsp,
                                                            request_switch,
                                                            &next_user_rsp);
    syscall_set_user_rsp(next_user_rsp);
    return next_saved_rsp;
}
