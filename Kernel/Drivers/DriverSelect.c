#include <stddef.h>
#include <stdint.h>

#include "DriverSelect.h"
#include "DriverBinary.h"
#include "DriverModule.h"
#include "../Serial.h"
#include "Display/ImplusOS_Generic/ImplusOS_Generic.h"

#define MAX_DISPLAY_DRIVERS 8
#define DISPLAY_DRIVER_MODULE_MAX_SIZE (2ULL * 1024ULL * 1024ULL)
#define DISPLAY_DRIVER_MODULE_MAX_IMAGE_SIZE (4ULL * 1024ULL * 1024ULL)

static const display_driver_t *g_display_drivers[MAX_DISPLAY_DRIVERS];
static uint32_t g_display_driver_count = 0;
static int g_display_binary_registered = 0;
static display_boot_framebuffer_t g_boot_framebuffer;

static void log_display_driver_status(const char *severity,
                                      const char *stage,
                                      const char *name)
{
    serial_write_string("[OS] [DRIVER] [");
    serial_write_string(severity);
    serial_write_string("] subsystem=DISPLAY stage=");
    serial_write_string(stage);
    serial_write_string(" driver=");
    serial_write_string(name);
    serial_write_string("\n");
}

bool driver_select_register_display_driver(const display_driver_t *driver) {
    if (!driver || !driver->name || !driver->init || !driver->is_ready ||
        !driver->width || !driver->height || !driver->draw_pixel ||
        !driver->fill_rect || !driver->present) {
        return false;
    }

    for (uint32_t i = 0; i < g_display_driver_count; ++i) {
        if (g_display_drivers[i] == driver) {
            return true;
        }
    }

    if (g_display_driver_count >= MAX_DISPLAY_DRIVERS) {
        log_display_driver_status("NONFATAL", "registry_full", "N/A");
        return false;
    }

    g_display_drivers[g_display_driver_count++] = driver;
    return true;
}

void driver_select_set_boot_framebuffer(const display_boot_framebuffer_t *framebuffer) {
    if (!framebuffer) {
        g_boot_framebuffer.addr = NULL;
        g_boot_framebuffer.size_bytes = 0;
        g_boot_framebuffer.width = 0;
        g_boot_framebuffer.height = 0;
        g_boot_framebuffer.pixels_per_scan_line = 0;
        g_boot_framebuffer.bytes_per_pixel = 0;
        return;
    }

    g_boot_framebuffer = *framebuffer;
}

static void load_display_driver_module(driver_module_id_t module_id,
                                       const char *module_name) {
    uint64_t entry = 0;

    if (!driver_module_manager_load(module_id,
                                    DISPLAY_DRIVER_MODULE_MAX_SIZE,
                                    DISPLAY_DRIVER_MODULE_MAX_IMAGE_SIZE,
                                    &entry)) {
        log_display_driver_status("NONFATAL", "module_load", module_name);
        return;
    }

    display_driver_module_init_t init_fn =
        (display_driver_module_init_t)(uintptr_t)entry;
    const display_driver_t *driver =
        init_fn(driver_module_manager_kernel_api());

    if (!driver) {
        log_display_driver_status("NONFATAL", "module_init", module_name);
        return;
    }

    if (!driver_select_register_display_driver(driver)) {
        log_display_driver_status("NONFATAL", "module_register", module_name);
        return;
    }

    log_display_driver_status("INFO", "module_loaded", module_name);
}

static const display_driver_t g_boot_fb_driver = {
    .name        = "BootFramebuffer",
    .probe       = fb_probe,
    .init        = fb_init,
    .is_ready    = fb_is_ready,
    .width       = fb_width,
    .height      = fb_height,
    .draw_pixel  = fb_draw_pixel,
    .fill_rect   = fb_fill_rect,
    .present     = fb_present,
};

void driver_select_register_binary_display_drivers(void) {
    if (g_display_binary_registered) {
        return;
    }

    g_display_binary_registered = 1;
    driver_select_register_display_driver(&g_boot_fb_driver);
    load_display_driver_module(DRIVER_MODULE_ID_DISPLAY_VIRTIO,
                               "VirtIO_Driver.ELF");
    load_display_driver_module(DRIVER_MODULE_ID_DISPLAY_INTEL_UHD_9TH,
                               "Intel_UHD_Graphics_9TH_Driver.ELF");
    load_display_driver_module(DRIVER_MODULE_ID_DISPLAY_IMPLUS_DISPLAY_GENERIC_DRIVER,
                               "ImplusOS_Generic_Display_Driver.ELF");
}

const display_driver_t *driver_select_pick_display_driver(void) {
    for (uint32_t i = 0; i < g_display_driver_count; ++i) {
        const display_driver_t *driver = g_display_drivers[i];
        if (!driver) {
            continue;
        }

        if (driver->probe && !driver->probe()) {
            continue;
        }

        if (!driver->init()) {
            log_display_driver_status("NONFATAL", "driver_init", driver->name);
            continue;
        }

        log_display_driver_status("INFO", "driver_selected", driver->name);
        return driver;
    }
    log_display_driver_status("FATAL", "driver_select", "none");
    return NULL;
}
