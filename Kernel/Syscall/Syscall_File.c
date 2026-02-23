#include "Syscall_File.h"

#include "../Drivers/FileSystem/FAT32/FAT32_Main.h"
#include "../ProcessManager/ProcessManager.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define FILE_MAX_FD 16
#define FILE_IO_CHUNK_SIZE (64U * 1024U)
#define FILE_SEEK_SET 0
#define FILE_SEEK_CUR 1
#define FILE_SEEK_END 2

typedef struct {
    uint8_t used;
    uint8_t writable;
    int32_t owner_pid;
    FAT32_FILE file;
    uint32_t offset;
} kernel_file_t;

static kernel_file_t g_files[FILE_MAX_FD];

static int fd_is_owned_by_current_process(int32_t fd)
{
    int32_t current_pid = process_get_current_pid();
    if (current_pid < 0) {
        return 0;
    }
    return g_files[fd].owner_pid == current_pid;
}

void syscall_file_init(void) {
    memset(g_files, 0, sizeof(g_files));
}

int32_t syscall_file_open(const char *path, uint64_t flags) {
    FAT32_FILE file;
    int32_t current_pid = process_get_current_pid();

    if (!path || path[0] == '\0' || current_pid < 0) {
        return -1;
    }

    if (!fat32_find_file(path, &file)) {
        return -1;
    }

    for (int32_t fd = 0; fd < FILE_MAX_FD; ++fd) {
        if (!g_files[fd].used) {
            g_files[fd].used = 1;
            g_files[fd].writable = (flags & 1u) ? 1u : 0u;
            g_files[fd].owner_pid = current_pid;
            g_files[fd].file = file;
            g_files[fd].offset = 0;
            return fd;
        }
    }

    return -1;
}

int64_t syscall_file_read(int32_t fd, uint8_t *buffer, uint64_t len) {
    if (fd < 0 || fd >= FILE_MAX_FD || !buffer || !g_files[fd].used ||
        !fd_is_owned_by_current_process(fd)) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    kernel_file_t *f = &g_files[fd];
    uint32_t file_size = f->file.size;

    if (f->offset >= file_size) {
        return 0;
    }

    uint64_t remaining = (uint64_t)file_size - (uint64_t)f->offset;
    uint64_t to_read = len < remaining ? len : remaining;
    uint64_t read_total = 0;

    while (read_total < to_read) {
        uint64_t chunk = to_read - read_total;
        if (chunk > FILE_IO_CHUNK_SIZE) {
            chunk = FILE_IO_CHUNK_SIZE;
        }

        if (!fat32_read_at(&f->file,
                           f->offset + (uint32_t)read_total,
                           buffer + read_total,
                           (uint32_t)chunk)) {
            return -1;
        }

        read_total += chunk;
    }

    f->offset += (uint32_t)to_read;
    return (int64_t)to_read;
}

int64_t syscall_file_write(int32_t fd, const uint8_t *buffer, uint64_t len) {
    if (fd < 0 || fd >= FILE_MAX_FD || !buffer || !g_files[fd].used ||
        !fd_is_owned_by_current_process(fd)) {
        return -1;
    }
    if (!g_files[fd].writable) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    kernel_file_t *f = &g_files[fd];
    uint32_t file_size = f->file.size;

    if (f->offset >= file_size) {
        return 0;
    }

    uint64_t remaining = (uint64_t)file_size - (uint64_t)f->offset;
    uint64_t to_write = len < remaining ? len : remaining;
    uint64_t write_total = 0;

    while (write_total < to_write) {
        uint64_t chunk = to_write - write_total;
        if (chunk > FILE_IO_CHUNK_SIZE) {
            chunk = FILE_IO_CHUNK_SIZE;
        }

        if (!fat32_write_at(&f->file,
                            f->offset + (uint32_t)write_total,
                            buffer + write_total,
                            (uint32_t)chunk)) {
            return -1;
        }

        write_total += chunk;
    }

    f->offset += (uint32_t)to_write;
    return (int64_t)to_write;
}

int64_t syscall_file_seek(int32_t fd, int64_t offset, int32_t whence) {
    if (fd < 0 || fd >= FILE_MAX_FD || !g_files[fd].used ||
        !fd_is_owned_by_current_process(fd)) {
        return -1;
    }

    kernel_file_t *f = &g_files[fd];
    int64_t base = 0;
    switch (whence) {
        case FILE_SEEK_SET:
            base = 0;
            break;
        case FILE_SEEK_CUR:
            base = (int64_t)f->offset;
            break;
        case FILE_SEEK_END:
            base = (int64_t)f->file.size;
            break;
        default:
            return -1;
    }

    int64_t next = base + offset;
    if (next < 0 || (uint64_t)next > (uint64_t)f->file.size) {
        return -1;
    }

    f->offset = (uint32_t)next;
    return next;
}

int32_t syscall_file_close(int32_t fd) {
    if (fd < 0 || fd >= FILE_MAX_FD || !g_files[fd].used ||
        !fd_is_owned_by_current_process(fd)) {
        return -1;
    }

    memset(&g_files[fd], 0, sizeof(g_files[fd]));
    return 0;
}

void syscall_file_close_all_for_pid(int32_t pid)
{
    if (pid < 0) {
        return;
    }

    for (int32_t fd = 0; fd < FILE_MAX_FD; ++fd) {
        if (g_files[fd].used && g_files[fd].owner_pid == pid) {
            memset(&g_files[fd], 0, sizeof(g_files[fd]));
        }
    }
}
