#pragma once

#include <stdint.h>

int32_t wm_create_window(uint32_t width, uint32_t height);
void draw_pixel(uint32_t x, uint32_t y, uint32_t color);
void draw_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
void draw_present(void);
