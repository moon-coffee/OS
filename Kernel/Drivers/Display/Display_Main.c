#include <stddef.h>

#include "Display_Main.h"
#include "../DriverSelect.h"

static const display_driver_t *g_active_display_driver = NULL;

bool display_init(void) {
    g_active_display_driver = NULL;

    driver_select_register_binary_display_drivers();
    g_active_display_driver = driver_select_pick_display_driver();
    if (!g_active_display_driver) {
        return false;
    }
    return true;
}

bool display_is_ready(void) {
    if (!g_active_display_driver) {
        return false;
    }

    return g_active_display_driver->is_ready();
}

uint32_t display_width(void) {
    if (!display_is_ready()) {
        return 0;
    }

    return g_active_display_driver->width();
}

uint32_t display_height(void) {
    if (!display_is_ready()) {
        return 0;
    }

    return g_active_display_driver->height();
}

void display_draw_pixel(uint32_t x, uint32_t y, uint32_t color) {
    if (!display_is_ready()) {
        return;
    }

    g_active_display_driver->draw_pixel(x, y, color);
}

void display_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    if (!display_is_ready()) {
        return;
    }

    g_active_display_driver->fill_rect(x, y, w, h, color);
}

void display_present(void) {
    if (!display_is_ready()) {
        return;
    }

    g_active_display_driver->present();
}
