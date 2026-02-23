#include "PCI_Main.h"

#include "../DriverBinary.h"
#include "../DriverModule.h"
#include "../../Serial.h"

#include <stdbool.h>
#include <stdint.h>

#define PCI_DRIVER_MAX_FILE_SIZE  (512ULL * 1024ULL)
#define PCI_DRIVER_MAX_IMAGE_SIZE (2ULL * 1024ULL * 1024ULL)

static const pci_driver_t *g_pci_driver = NULL;
static uint8_t g_pci_load_attempted = 0;

static bool ensure_pci_driver_loaded(void)
{
    if (g_pci_driver != NULL) {
        return true;
    }

    if (g_pci_load_attempted) {
        return false;
    }
    g_pci_load_attempted = 1;

    uint64_t entry = 0;
    if (!driver_module_manager_load(DRIVER_MODULE_ID_PCI,
                                    PCI_DRIVER_MAX_FILE_SIZE,
                                    PCI_DRIVER_MAX_IMAGE_SIZE,
                                    &entry)) {
        serial_write_string("[OS] [PCI] Failed to load PCI module\n");
        return false;
    }

    pci_driver_module_init_t init_fn = (pci_driver_module_init_t)(uintptr_t)entry;
    const pci_driver_t *driver = init_fn(driver_module_manager_kernel_api());
    if (driver == NULL || driver->read_config == NULL || driver->write_config == NULL) {
        serial_write_string("[OS] [PCI] PCI module init failed\n");
        return false;
    }

    g_pci_driver = driver;
    serial_write_string("[OS] [PCI] PCI module ready\n");
    return true;
}

uint32_t pci_read_config(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset)
{
    if (!ensure_pci_driver_loaded()) {
        return 0xFFFFFFFFu;
    }
    return g_pci_driver->read_config(bus, device, func, offset);
}

void pci_write_config(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value)
{
    if (!ensure_pci_driver_loaded()) {
        return;
    }
    g_pci_driver->write_config(bus, device, func, offset, value);
}

void pci_scan_bus(void)
{
    if (!ensure_pci_driver_loaded()) {
        return;
    }
    if (g_pci_driver->scan_bus != NULL) {
        g_pci_driver->scan_bus();
    }
}

int pci_find_device(uint16_t vendor_id, uint16_t device_id, pci_device_t *out_device)
{
    if (out_device == NULL) {
        return 0;
    }
    if (!ensure_pci_driver_loaded()) {
        return 0;
    }
    if (g_pci_driver->find_device == NULL) {
        return 0;
    }
    return g_pci_driver->find_device(vendor_id, device_id, out_device);
}

uint32_t pci_read_bar(uint8_t bus, uint8_t device, uint8_t func, uint8_t bar_index)
{
    if (!ensure_pci_driver_loaded()) {
        return 0;
    }
    if (g_pci_driver->read_bar != NULL) {
        return g_pci_driver->read_bar(bus, device, func, bar_index);
    }
    if (bar_index >= 6u) {
        return 0;
    }
    return g_pci_driver->read_config(bus, device, func, (uint8_t)(0x10u + (bar_index * 4u)));
}
