#pragma once
#include <stddef.h>
#include <stdint.h>

#define INPUT_KBD_MOD_SHIFT (1u << 0)
#define INPUT_KBD_MOD_CTRL  (1u << 1)
#define INPUT_KBD_MOD_ALT   (1u << 2)
#define INPUT_KBD_MOD_CAPS  (1u << 3)

typedef struct __attribute__((packed)) {
    uint16_t keycode;
    uint8_t pressed;
    uint8_t ascii;
    uint8_t modifiers;
    uint8_t reserved[3];
} input_keyboard_event_t;

typedef struct __attribute__((packed)) {
    uint16_t x;
    uint16_t y;
    uint8_t buttons;
    int8_t wheel;
    uint8_t reserved[2];
} input_mouse_event_t;

int32_t file_open(const char *path, uint64_t flags);
int64_t file_read(int32_t fd, void *buffer, uint64_t len);
int64_t file_write(int32_t fd, const void *buffer, uint64_t len);
int64_t file_seek(int32_t fd, int64_t offset, int32_t whence);
int32_t file_close(int32_t fd);
void* kmalloc(uint32_t size);
void  kfree(void *ptr);
void* memcpy(void *dst, const void *src, size_t n);
int   memcmp(const void *s1, const void *s2, size_t n);
void *memset(void *ptr, int value, size_t num);
void serial_write_string(const char *str);
void serial_write_uint64(uint64_t value);
void serial_write_uint32(uint32_t value);
void serial_write_uint16(uint16_t value);
int32_t wm_create_window(uint32_t width, uint32_t height);
void    draw_pixel(uint32_t x, uint32_t y, uint32_t color);
void    draw_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
void    draw_present(void);
void process_yield(void);
int32_t input_read_keyboard(input_keyboard_event_t *event_out);
int32_t input_read_mouse(input_mouse_event_t *event_out);
