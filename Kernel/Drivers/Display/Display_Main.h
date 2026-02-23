#pragma once

#include <stdbool.h>
#include <stdint.h>

bool display_init(void);
bool display_is_ready(void);
uint32_t display_width(void);
uint32_t display_height(void);
void display_draw_pixel(uint32_t x, uint32_t y, uint32_t color);
void display_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
void display_present(void);
