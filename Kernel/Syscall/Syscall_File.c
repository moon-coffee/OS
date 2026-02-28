#include "Syscall_File.h"

#include "../Common/Status.h"
#include "../Drivers/FileSystem/FAT32/FAT32_Main.h"
#include "../KernelConfig.h"
#include "../ProcessManager/ProcessManager.h"
#include "../Serial.h"

#include <stddef.h>
#include <string.h>

enum {
    FILE_MAX_FD = FILE_MAX_FD_CONFIG,
    FILE_MAX_DIR_HANDLE = FILE_MAX_DIR_HANDLE_CONFIG
};

#define FILE_IO_CHUNK_SIZE   (64U * 1024U)
#define FILE_READ_CACHE_SIZE 4096U
#define FILE_SEEK_SET        0
#define FILE_SEEK_CUR        1
#define FILE_SEEK_END        2

typedef struct {
    uint8_t used;
    uint8_t writable;
    int32_t owner_pid;
    FAT32_FILE file;
    uint32_t offset;
    uint8_t cache_valid;
    uint32_t cache_offset;
    uint32_t cache_size;
    uint8_t cache_data[FILE_READ_CACHE_SIZE];
} kernel_file_t;

typedef struct {
    uint8_t used;
    int32_t owner_pid;
    int32_t fat32_handle;
} kernel_dir_t;

static kernel_file_t g_files[FILE_MAX_FD];
static kernel_dir_t g_dirs[FILE_MAX_DIR_HANDLE];

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

static void file_log_status(const char *function_name, os_status_t status, const char *reason)
{
    serial_write_string("[OS] [FILE] fn=");
    serial_write_string(function_name);
    serial_write_string(" status=");
    serial_write_status_with_name(status);
    if (reason != NULL && reason[0] != '\0') {
        serial_write_string(" reason=");
        serial_write_string(reason);
    }
    serial_write_string("\n");
}

static int32_t file_fail_i32(const char *function_name, os_status_t status, const char *reason)
{
    file_log_status(function_name, status, reason);
    return (int32_t)status;
}

static int64_t file_fail_i64(const char *function_name, os_status_t status, const char *reason)
{
    file_log_status(function_name, status, reason);
    return status;
}

static uint32_t count_used_file_slots(void)
{
    uint32_t used = 0;
    for (int32_t fd = 0; fd < FILE_MAX_FD; ++fd) {
        if (g_files[fd].used != 0) {
            ++used;
        }
    }
    return used;
}

static uint32_t count_used_dir_slots(void)
{
    uint32_t used = 0;
    for (int32_t i = 0; i < FILE_MAX_DIR_HANDLE; ++i) {
        if (g_dirs[i].used != 0) {
            ++used;
        }
    }
    return used;
}

static void file_cache_invalidate(kernel_file_t *file)
{
    if (file == NULL) {
        return;
    }

    file->cache_valid = 0;
    file->cache_offset = 0;
    file->cache_size = 0;
}

static int file_cache_refill(kernel_file_t *file, uint32_t offset)
{
    if (file == NULL) {
        return 0;
    }

    if (offset >= file->file.size) {
        file_cache_invalidate(file);
        return 1;
    }

    uint32_t remaining = file->file.size - offset;
    uint32_t to_cache = remaining;
    if (to_cache > FILE_READ_CACHE_SIZE) {
        to_cache = FILE_READ_CACHE_SIZE;
    }

    if (!fat32_read_at(&file->file, offset, file->cache_data, to_cache)) {
        file_cache_invalidate(file);
        return 0;
    }

    file->cache_valid = 1;
    file->cache_offset = offset;
    file->cache_size = to_cache;
    return 1;
}

static int fd_is_owned_by_current_process(int32_t fd)
{
    int32_t current_pid = process_get_current_pid();
    if (current_pid < 0) {
        return 0;
    }
    return (g_files[fd].owner_pid == current_pid);
}

static int dir_is_owned_by_current_process(int32_t dir_handle)
{
    int32_t current_pid = process_get_current_pid();
    if (current_pid < 0) {
        return 0;
    }
    return (g_dirs[dir_handle].owner_pid == current_pid);
}

void syscall_file_init(void)
{
    memset(g_files, 0, sizeof(g_files));
    memset(g_dirs, 0, sizeof(g_dirs));
}

int32_t syscall_file_open(const char *path, uint64_t flags)
{
    FAT32_FILE file;
    int32_t current_pid = process_get_current_pid();

    if (path == NULL || path[0] == '\0' || current_pid < 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_path_or_pid");
    }

    if (!fat32_find_file(path, &file)) {
        return file_fail_i32(__func__, OS_STATUS_NOT_FOUND, "file_not_found");
    }

    for (int32_t fd = 0; fd < FILE_MAX_FD; ++fd) {
        if (g_files[fd].used == 0) {
            g_files[fd].used = 1;
            g_files[fd].writable = ((flags & 1ULL) != 0ULL) ? 1u : 0u;
            g_files[fd].owner_pid = current_pid;
            g_files[fd].file = file;
            g_files[fd].offset = 0;
            file_cache_invalidate(&g_files[fd]);
            return fd;
        }
    }

    serial_write_string("[OS] [FILE] fn=");
    serial_write_string(__func__);
    serial_write_string(" status=");
    serial_write_status_with_name(OS_STATUS_LIMIT_REACHED);
    serial_write_string(" reason=fd_table_full used=");
    serial_write_uint32(count_used_file_slots());
    serial_write_string(" limit=");
    serial_write_uint32((uint32_t)FILE_MAX_FD);
    serial_write_string("\n");
    return (int32_t)OS_STATUS_LIMIT_REACHED;
}

int32_t syscall_file_creat(const char *path)
{
    if (path == NULL || path[0] == '\0' || process_get_current_pid() < 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_path_or_pid");
    }
    if (!fat32_creat(path)) {
        return file_fail_i32(__func__, OS_STATUS_IO_ERROR, "fat32_create_failed");
    }
    return syscall_file_open(path, 1ULL);
}

int64_t syscall_file_read(int32_t fd, uint8_t *buffer, uint64_t len)
{
    if (fd < 0 || fd >= FILE_MAX_FD || buffer == NULL || g_files[fd].used == 0) {
        return file_fail_i64(__func__, OS_STATUS_INVALID_ARG, "invalid_fd_or_buffer");
    }
    if (!fd_is_owned_by_current_process(fd)) {
        return file_fail_i64(__func__, OS_STATUS_ACCESS_DENIED, "fd_owner_mismatch");
    }
    if (len == 0) {
        return 0;
    }

    kernel_file_t *file = &g_files[fd];
    if (file->offset >= file->file.size) {
        return 0;
    }

    uint64_t remaining = (uint64_t)file->file.size - (uint64_t)file->offset;
    uint64_t to_read = (len < remaining) ? len : remaining;
    uint64_t read_total = 0;
    uint32_t cursor = file->offset;

    while (read_total < to_read) {
        uint32_t cache_end = file->cache_offset + file->cache_size;
        if (file->cache_valid == 0 || cursor < file->cache_offset || cursor >= cache_end) {
            if (!file_cache_refill(file, cursor)) {
                return file_fail_i64(__func__, OS_STATUS_IO_ERROR, "fat32_read_failed");
            }
            if (file->cache_size == 0) {
                break;
            }
            cache_end = file->cache_offset + file->cache_size;
        }

        uint32_t cache_index = cursor - file->cache_offset;
        uint32_t available = cache_end - cursor;
        uint64_t remaining_request = to_read - read_total;
        uint32_t chunk = available;
        if (remaining_request < (uint64_t)chunk) {
            chunk = (uint32_t)remaining_request;
        }

        memcpy(buffer + (size_t)read_total,
               file->cache_data + cache_index,
               (size_t)chunk);

        read_total += (uint64_t)chunk;
        cursor += chunk;
    }

    file->offset = cursor;
    return (int64_t)read_total;
}

int64_t syscall_file_write(int32_t fd, const uint8_t *buffer, uint64_t len)
{
    if (fd < 0 || fd >= FILE_MAX_FD || buffer == NULL || g_files[fd].used == 0) {
        return file_fail_i64(__func__, OS_STATUS_INVALID_ARG, "invalid_fd_or_buffer");
    }
    if (!fd_is_owned_by_current_process(fd)) {
        return file_fail_i64(__func__, OS_STATUS_ACCESS_DENIED, "fd_owner_mismatch");
    }
    if (g_files[fd].writable == 0) {
        return file_fail_i64(__func__, OS_STATUS_ACCESS_DENIED, "fd_not_writable");
    }
    if (len == 0) {
        return 0;
    }

    kernel_file_t *file = &g_files[fd];
    if (file->offset >= file->file.size) {
        return 0;
    }

    uint64_t remaining = (uint64_t)file->file.size - (uint64_t)file->offset;
    uint64_t to_write = (len < remaining) ? len : remaining;
    uint64_t write_total = 0;

    while (write_total < to_write) {
        uint64_t chunk64 = to_write - write_total;
        if (chunk64 > FILE_IO_CHUNK_SIZE) {
            chunk64 = FILE_IO_CHUNK_SIZE;
        }

        uint32_t chunk = (uint32_t)chunk64;
        uint32_t write_offset = file->offset + (uint32_t)write_total;
        if (!fat32_write_at(&file->file,
                            write_offset,
                            buffer + (size_t)write_total,
                            chunk)) {
            return file_fail_i64(__func__, OS_STATUS_IO_ERROR, "fat32_write_failed");
        }

        write_total += (uint64_t)chunk;
    }

    file->offset += (uint32_t)to_write;
    file_cache_invalidate(file);
    return (int64_t)to_write;
}

int64_t syscall_file_seek(int32_t fd, int64_t offset, int32_t whence)
{
    if (fd < 0 || fd >= FILE_MAX_FD || g_files[fd].used == 0) {
        return file_fail_i64(__func__, OS_STATUS_INVALID_ARG, "invalid_fd");
    }
    if (!fd_is_owned_by_current_process(fd)) {
        return file_fail_i64(__func__, OS_STATUS_ACCESS_DENIED, "fd_owner_mismatch");
    }

    kernel_file_t *file = &g_files[fd];
    int64_t base = 0;
    switch (whence) {
        case FILE_SEEK_SET:
            base = 0;
            break;
        case FILE_SEEK_CUR:
            base = (int64_t)file->offset;
            break;
        case FILE_SEEK_END:
            base = (int64_t)file->file.size;
            break;
        default:
            return file_fail_i64(__func__, OS_STATUS_INVALID_ARG, "invalid_whence");
    }

    int64_t next = base + offset;
    if (next < 0 || (uint64_t)next > (uint64_t)file->file.size) {
        return file_fail_i64(__func__, OS_STATUS_INVALID_ARG, "seek_out_of_range");
    }

    file->offset = (uint32_t)next;
    return next;
}

int32_t syscall_file_close(int32_t fd)
{
    if (fd < 0 || fd >= FILE_MAX_FD || g_files[fd].used == 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_fd");
    }
    if (!fd_is_owned_by_current_process(fd)) {
        return file_fail_i32(__func__, OS_STATUS_ACCESS_DENIED, "fd_owner_mismatch");
    }

    memset(&g_files[fd], 0, sizeof(g_files[fd]));
    return 0;
}

int32_t syscall_file_mkdir(const char *path)
{
    if (path == NULL || path[0] == '\0' || process_get_current_pid() < 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_path_or_pid");
    }

    return fat32_mkdir(path) ? 0 : file_fail_i32(__func__, OS_STATUS_IO_ERROR, "fat32_mkdir_failed");
}

int32_t syscall_file_opendir(const char *path)
{
    if (path == NULL || path[0] == '\0' || process_get_current_pid() < 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_path_or_pid");
    }

    int32_t fat_handle = fat32_opendir(path);
    if (fat_handle < 0) {
        return file_fail_i32(__func__, OS_STATUS_NOT_FOUND, "dir_not_found");
    }

    int32_t current_pid = process_get_current_pid();
    for (int32_t i = 0; i < FILE_MAX_DIR_HANDLE; ++i) {
        if (g_dirs[i].used == 0) {
            g_dirs[i].used = 1;
            g_dirs[i].owner_pid = current_pid;
            g_dirs[i].fat32_handle = fat_handle;
            return i;
        }
    }

    (void)fat32_closedir(fat_handle);
    serial_write_string("[OS] [FILE] fn=");
    serial_write_string(__func__);
    serial_write_string(" status=");
    serial_write_status_with_name(OS_STATUS_LIMIT_REACHED);
    serial_write_string(" reason=dir_table_full used=");
    serial_write_uint32(count_used_dir_slots());
    serial_write_string(" limit=");
    serial_write_uint32((uint32_t)FILE_MAX_DIR_HANDLE);
    serial_write_string("\n");
    return (int32_t)OS_STATUS_LIMIT_REACHED;
}

int32_t syscall_file_readdir(int32_t dir_handle, FAT32_DIRENT *out_entry)
{
    if (dir_handle < 0 || dir_handle >= FILE_MAX_DIR_HANDLE || out_entry == NULL ||
        g_dirs[dir_handle].used == 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_dir_handle_or_output");
    }
    if (!dir_is_owned_by_current_process(dir_handle)) {
        return file_fail_i32(__func__, OS_STATUS_ACCESS_DENIED, "dir_owner_mismatch");
    }

    return fat32_readdir(g_dirs[dir_handle].fat32_handle, out_entry);
}

int32_t syscall_file_closedir(int32_t dir_handle)
{
    if (dir_handle < 0 || dir_handle >= FILE_MAX_DIR_HANDLE || g_dirs[dir_handle].used == 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_dir_handle");
    }
    if (!dir_is_owned_by_current_process(dir_handle)) {
        return file_fail_i32(__func__, OS_STATUS_ACCESS_DENIED, "dir_owner_mismatch");
    }

    (void)fat32_closedir(g_dirs[dir_handle].fat32_handle);
    memset(&g_dirs[dir_handle], 0, sizeof(g_dirs[dir_handle]));
    return 0;
}

int32_t syscall_file_unlink(const char *path)
{
    if (path == NULL || path[0] == '\0' || process_get_current_pid() < 0) {
        return file_fail_i32(__func__, OS_STATUS_INVALID_ARG, "invalid_path_or_pid");
    }
    return fat32_unlink(path) ? 0 : file_fail_i32(__func__, OS_STATUS_IO_ERROR, "fat32_unlink_failed");
}

void syscall_file_close_all_for_pid(int32_t pid, uint32_t *closed_fds_out, uint32_t *closed_dirs_out)
{
    if (closed_fds_out != NULL) {
        *closed_fds_out = 0;
    }
    if (closed_dirs_out != NULL) {
        *closed_dirs_out = 0;
    }

    if (pid < 0) {
        return;
    }

    uint32_t closed_fds = 0;
    uint32_t closed_dirs = 0;

    for (int32_t fd = 0; fd < FILE_MAX_FD; ++fd) {
        if (g_files[fd].used != 0 && g_files[fd].owner_pid == pid) {
            memset(&g_files[fd], 0, sizeof(g_files[fd]));
            ++closed_fds;
        }
    }

    for (int32_t i = 0; i < FILE_MAX_DIR_HANDLE; ++i) {
        if (g_dirs[i].used != 0 && g_dirs[i].owner_pid == pid) {
            (void)fat32_closedir(g_dirs[i].fat32_handle);
            memset(&g_dirs[i], 0, sizeof(g_dirs[i]));
            ++closed_dirs;
        }
    }

    if (closed_fds_out != NULL) {
        *closed_fds_out = closed_fds;
    }
    if (closed_dirs_out != NULL) {
        *closed_dirs_out = closed_dirs;
    }
}
