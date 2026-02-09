#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint64_t base;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
} FRAMEBUFFER;

void framebuffer_init(FRAMEBUFFER* fb);
void framebuffer_clear(uint32_t color);
void framebuffer_put_pixel(uint32_t x, uint32_t y, uint32_t color);