#pragma once

#include <stdbool.h>
#include <stdint.h>

bool intel_uhd_init(void);
void intel_uhd_register_driver(void);
bool intel_uhd_is_ready(void);
uint32_t intel_uhd_width(void);
uint32_t intel_uhd_height(void);
void intel_uhd_draw_pixel(uint32_t x, uint32_t y, uint32_t color);
void intel_uhd_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
void intel_uhd_present(void);