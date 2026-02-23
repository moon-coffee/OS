#pragma once

#include <stdint.h>

void syscall_file_init(void);
int32_t syscall_file_open(const char *path, uint64_t flags);
int64_t syscall_file_read(int32_t fd, uint8_t *buffer, uint64_t len);
int64_t syscall_file_write(int32_t fd, const uint8_t *buffer, uint64_t len);
int64_t syscall_file_seek(int32_t fd, int64_t offset, int32_t whence);
int32_t syscall_file_close(int32_t fd);
void syscall_file_close_all_for_pid(int32_t pid);
