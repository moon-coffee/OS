#pragma once

#include <stdint.h>

void window_manager_init(void);
int32_t window_manager_create_window_for_process(int32_t pid, uint32_t width, uint32_t height);
void window_manager_destroy_window_for_process(int32_t pid);
int32_t window_manager_draw_pixel_for_process(int32_t pid, uint32_t x, uint32_t y, uint32_t color);
int32_t window_manager_fill_rect_for_process(int32_t pid,
                                             uint32_t x,
                                             uint32_t y,
                                             uint32_t w,
                                             uint32_t h,
                                             uint32_t color);
int32_t window_manager_present_for_process(int32_t pid);
