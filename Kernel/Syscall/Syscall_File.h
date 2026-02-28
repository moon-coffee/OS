#pragma once

#include <stdint.h>
#include "../Drivers/FileSystem/FAT32/FAT32_Main.h"

void syscall_file_init(void);
int32_t syscall_file_open(const char *path, uint64_t flags);
int32_t syscall_file_creat(const char *path);
int64_t syscall_file_read(int32_t fd, uint8_t *buffer, uint64_t len);
int64_t syscall_file_write(int32_t fd, const uint8_t *buffer, uint64_t len);
int64_t syscall_file_seek(int32_t fd, int64_t offset, int32_t whence);
int32_t syscall_file_close(int32_t fd);
int32_t syscall_file_mkdir(const char *path);
int32_t syscall_file_opendir(const char *path);
int32_t syscall_file_readdir(int32_t dir_handle, FAT32_DIRENT *out_entry);
int32_t syscall_file_closedir(int32_t dir_handle);
int32_t syscall_file_unlink(const char *path);
void syscall_file_close_all_for_pid(int32_t pid, uint32_t *closed_fds_out, uint32_t *closed_dirs_out);
