#include "PS2_Input.h"

#include "../DriverBinary.h"
#include "../DriverModule.h"
#include "../../Serial.h"

#include <stdbool.h>
#include <stdint.h>

#define PS2_DRIVER_MAX_FILE_SIZE  (512ULL * 1024ULL)
#define PS2_DRIVER_MAX_IMAGE_SIZE (2ULL * 1024ULL * 1024ULL)

static const ps2_input_driver_t *g_ps2_driver = NULL;
static uint8_t g_ps2_load_attempted = 0;
static uint8_t g_ps2_initialized = 0;

static void log_ps2_driver_status(const char *severity,
                                  const char *stage,
                                  const char *detail)
{
    serial_write_string("[OS] [DRIVER] [");
    serial_write_string(severity);
    serial_write_string("] subsystem=PS2 stage=");
    serial_write_string(stage);
    serial_write_string(" detail=");
    serial_write_string(detail);
    serial_write_string("\n");
}

static bool ensure_ps2_driver_loaded(void)
{
    if (g_ps2_driver != NULL) {
        return true;
    }

    if (g_ps2_load_attempted) {
        return false;
    }
    g_ps2_load_attempted = 1;

    uint64_t entry = 0;
    if (!driver_module_manager_load(DRIVER_MODULE_ID_PS2,
                                    PS2_DRIVER_MAX_FILE_SIZE,
                                    PS2_DRIVER_MAX_IMAGE_SIZE,
                                    &entry)) {
        log_ps2_driver_status("NONFATAL", "module_load", "PS2_Driver.ELF");
        return false;
    }

    ps2_input_driver_module_init_t init_fn =
        (ps2_input_driver_module_init_t)(uintptr_t)entry;
    const ps2_input_driver_t *driver =
        init_fn(driver_module_manager_kernel_api());
    if (driver == NULL ||
        driver->init == NULL ||
        driver->poll == NULL ||
        driver->read_keyboard == NULL ||
        driver->read_mouse == NULL) {
        log_ps2_driver_status("NONFATAL", "module_init", "invalid_api");
        return false;
    }

    g_ps2_driver = driver;
    return true;
}

static bool ensure_ps2_initialized(void)
{
    if (!ensure_ps2_driver_loaded()) {
        return false;
    }
    if (!g_ps2_initialized) {
        if (!g_ps2_driver->init()) {
            log_ps2_driver_status("NONFATAL", "driver_init", "no_ps2_devices");
            return false;
        }
        g_ps2_initialized = 1;
        log_ps2_driver_status("INFO", "driver_init", "ready");
    }
    return true;
}

bool ps2_input_init(void)
{
    return ensure_ps2_initialized();
}

void ps2_input_poll(void)
{
    if (!ensure_ps2_initialized()) {
        return;
    }
    g_ps2_driver->poll();
}

int32_t ps2_input_read_keyboard(ps2_keyboard_event_t *out_event)
{
    if (out_event == NULL) {
        return -1;
    }
    if (!ensure_ps2_initialized()) {
        return 0;
    }
    return g_ps2_driver->read_keyboard(out_event);
}

int32_t ps2_input_read_mouse(ps2_mouse_event_t *out_event)
{
    if (out_event == NULL) {
        return -1;
    }
    if (!ensure_ps2_initialized()) {
        return 0;
    }
    return g_ps2_driver->read_mouse(out_event);
}
