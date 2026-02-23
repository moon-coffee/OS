#pragma once

#include <stdbool.h>
#include "Display/Display_Driver.h"

bool driver_select_register_display_driver(const display_driver_t *driver);
void driver_select_set_boot_framebuffer(const display_boot_framebuffer_t *framebuffer);
void driver_select_register_binary_display_drivers(void);
const display_driver_t *driver_select_pick_display_driver(void);
