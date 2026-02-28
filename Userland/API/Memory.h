#pragma once

#include <stddef.h>
#include <stdint.h>

void *kmalloc(uint32_t size);
void  kfree(void *ptr);
void *mmap(uint64_t length, uint64_t flags);
void *memcpy(void *dst, const void *src, size_t n);
int   memcmp(const void *s1, const void *s2, size_t n);
void *memset(void *ptr, int value, size_t num);

size_t os_strnlen(const char *str, size_t max_len);
int os_strcpy_s(char *dst, size_t dst_size, const char *src);
int os_strcat_s(char *dst, size_t dst_size, const char *src);
