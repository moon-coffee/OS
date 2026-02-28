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

static void log_fat32_driver_status(const char *severity,
                                    const char *stage,
                                    const char *detail)
{
    serial_write_string("[OS] [DRIVER] [");
    serial_write_string(severity);
    serial_write_string("] subsystem=FAT32 stage=");
    serial_write_string(stage);
    serial_write_string(" detail=");
    serial_write_string(detail);
    serial_write_string("\n");
}

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
        log_fat32_driver_status("FATAL", "module_load", "FAT32_Driver.ELF");
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
        driver->list_root_files == NULL ||
        driver->creat == NULL ||
        driver->mkdir == NULL ||
        driver->opendir == NULL ||
        driver->readdir == NULL ||
        driver->closedir == NULL ||
        driver->unlink == NULL ||
        driver->truncate == NULL ||
        driver->set_case_sensitive_lookup == NULL ||
        driver->get_case_sensitive_lookup == NULL) {
        log_fat32_driver_status("FATAL", "module_init", "invalid_api");
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
            log_fat32_driver_status("FATAL", "driver_init", "init_failed");
            return false;
        }
        g_fat32_initialized = 1;
        log_fat32_driver_status("INFO", "driver_init", "ready");
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

bool fat32_truncate(FAT32_FILE *file, uint32_t new_size)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->truncate(file, new_size);
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

bool fat32_creat(const char *path)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->creat(path);
}

bool fat32_mkdir(const char *path)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->mkdir(path);
}

int32_t fat32_opendir(const char *path)
{
    if (!ensure_fat32_initialized()) {
        return -1;
    }
    return g_fat32_driver->opendir(path);
}

int32_t fat32_readdir(int32_t dir_handle, FAT32_DIRENT *out_entry)
{
    if (!ensure_fat32_initialized()) {
        return -1;
    }
    return g_fat32_driver->readdir(dir_handle, out_entry);
}

int32_t fat32_closedir(int32_t dir_handle)
{
    if (!ensure_fat32_initialized()) {
        return -1;
    }
    return g_fat32_driver->closedir(dir_handle);
}

bool fat32_unlink(const char *path)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->unlink(path);
}

void fat32_set_case_sensitive_lookup(bool enabled)
{
    if (!ensure_fat32_initialized()) {
        return;
    }
    g_fat32_driver->set_case_sensitive_lookup(enabled);
}

bool fat32_get_case_sensitive_lookup(void)
{
    if (!ensure_fat32_initialized()) {
        return false;
    }
    return g_fat32_driver->get_case_sensitive_lookup();
}
