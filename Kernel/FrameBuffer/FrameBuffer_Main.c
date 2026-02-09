#include "FrameBuffer_Main.h"

static FRAMEBUFFER fb;
static volatile uint32_t* fb_addr;
static bool initialized = false;

void framebuffer_init(FRAMEBUFFER* info) {
    fb = *info;

    fb.bpp = 32;

    fb_addr = (volatile uint32_t*)fb.base;
    initialized = true;
}

void framebuffer_put_pixel(uint32_t x, uint32_t y, uint32_t color) {
    if (!initialized) return;
    if (x >= fb.width || y >= fb.height) return;

    uint32_t index = (fb.pitch / 4) * y + x;
    fb_addr[index] = color;
}

void framebuffer_clear(uint32_t color) {
    if (!initialized) return;

    uint32_t pixels_per_line = fb.pitch / 4;
    for (uint32_t y = 0; y < fb.height; y++) {
        for (uint32_t x = 0; x < fb.width; x++) {
            fb_addr[y * pixels_per_line + x] = color;
        }
    }
}