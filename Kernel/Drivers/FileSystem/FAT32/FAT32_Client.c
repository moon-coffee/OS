#include "FAT32_Main.h"

#include "../../DriverBinary.h"
#include "../../DriverModule.h"
#include "../../../Serial.h"

#include <stdbool.h>
#include <stdint.h>

#define FAT32_DRIVER_MAX_FILE_SIZE  (1024ULL * 1024ULL)
#define FAT32_DRIVER_MAX_IMAGE_SIZE (4ULL * 1024ULL * 1024ULL)

static const fat32_driver_t *g_fat32_driver = NULL;
static uint8_t g_fat32_load_attempted = 0;
static uint8_t g_fat32_initialized = 0;

static bool ensure_fat32_driver_loaded(void)
{
    if (g_fat32_driver != NULL) {
        return true;
    }

    if (g_fat32_load_attempted) {
        return false;
    }
    g_fat32_load_attempted = 1;

    uint64_t entry = 0;
    if (!driver_module_manager_load(DRIVER_MODULE_ID_FAT32,
                                    FAT32_DRIVER_MAX_FILE_SIZE,
                                    FAT32_DRIVER_MAX_IMAGE_SIZE,
                                    &entry)) {
        serial_write_string("[OS] [FAT32] Failed to load FAT32 module\n");
        return false;
    }

    fat32_driver_module_init_t init_fn = (fat32_driver_module_init_t)(uintptr_t)entry;
    const fat32_driver_t *driver = init_fn(driver_module_manager_kernel_api());
    if (driver == NULL ||
        driver->init == NULL ||
        driver->find_file == NULL ||
        driver->read_file == NULL ||
        driver->write_file == NULL ||
        driver->read_at == NULL ||
        driver->write_at == NULL ||
        driver->get_file_size == NULL ||
        driver->list_root_files == NULL) {
        serial_write_string("[OS] [FAT32] FAT32 module init failed\n");
        return false;
    }

    g_fat32_driver = driver;
    return true;
}

static bool ensure_fat32_initialized(void)
{
    if (!ensure_fat32_driver_loaded()) {
        return false;
    }
    if (!g_fat32_initialized) {
        if (!g_fat32_driver->init()) {
            return false;
        }
        g_fat32_initialized = 1;
    }
    return true;
}

bool fat32_init(void)
{
    return ensure_fat32_initialized();
}

bool fat32_find_file(const char *filename, FAT32_FILE *file)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->find_file(filename, file);
}

bool fat32_read_file(FAT32_FILE *file, uint8_t *buffer)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->read_file(file, buffer);
}

bool fat32_write_file(FAT32_FILE *file, const uint8_t *buffer)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->write_file(file, buffer);
}

bool fat32_read_at(FAT32_FILE *file, uint32_t offset, uint8_t *buffer, uint32_t size)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->read_at(file, offset, buffer, size);
}

bool fat32_write_at(FAT32_FILE *file, uint32_t offset, const uint8_t *buffer, uint32_t size)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->write_at(file, offset, buffer, size);
}

uint32_t fat32_get_file_size(FAT32_FILE *file)
{
    if (!ensure_fat32_initialized()) {
        return 0;
    }
    return g_fat32_driver->get_file_size(file);
}

void fat32_list_root_files(void)
{
    if (!ensure_fat32_initialized()) {
        return;
    }
    g_fat32_driver->list_root_files();
}
