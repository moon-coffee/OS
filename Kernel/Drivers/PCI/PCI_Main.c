#include "PCI_Main.h"

#include <stdint.h>

#ifdef IMPLUS_DRIVER_MODULE
#include "../DriverBinary.h"
#else
#include "../../IO/IO_Main.h"
#include "../../Serial.h"
#endif

#ifdef IMPLUS_DRIVER_MODULE
static const driver_kernel_api_t *g_driver_api = NULL;

#define outl g_driver_api->outl
#define inl g_driver_api->inl
#define serial_write_char g_driver_api->serial_write_char
#define serial_write_string g_driver_api->serial_write_string
#define serial_write_uint16 g_driver_api->serial_write_uint16
#define serial_write_uint32 g_driver_api->serial_write_uint32
#endif

uint32_t pci_read_config(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset)
{
    uint32_t address = (1u << 31) |
                       ((uint32_t)bus << 16) |
                       ((uint32_t)device << 11) |
                       ((uint32_t)func << 8) |
                       ((uint32_t)offset & 0xFCu);
    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

void pci_write_config(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value)
{
    uint32_t address = (1u << 31) |
                       ((uint32_t)bus << 16) |
                       ((uint32_t)device << 11) |
                       ((uint32_t)func << 8) |
                       ((uint32_t)offset & 0xFCu);
    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

uint32_t pci_read_bar(uint8_t bus, uint8_t device, uint8_t func, uint8_t bar_index)
{
    if (bar_index >= 6u) {
        return 0;
    }
    return pci_read_config(bus, device, func, (uint8_t)(0x10u + (bar_index * 4u)));
}

static void pci_read_bars(pci_device_t *dev)
{
    for (int i = 0; i < 6; i++) {
        dev->bar[i] = pci_read_bar(dev->bus, dev->device, dev->func, (uint8_t)i);
    }
}

int pci_find_device(uint16_t vendor_id, uint16_t device_id, pci_device_t *out_device)
{
    if (out_device == NULL) {
        return 0;
    }

    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t func = 0; func < 8; func++) {
                uint32_t vendor_device = pci_read_config((uint8_t)bus, device, func, 0x00);
                uint16_t cur_vendor = (uint16_t)(vendor_device & 0xFFFFu);
                uint16_t cur_device = (uint16_t)((vendor_device >> 16) & 0xFFFFu);

                if (cur_vendor == 0xFFFFu) {
                    if (func == 0u) {
                        break;
                    }
                    continue;
                }

                if (cur_vendor == vendor_id && cur_device == device_id) {
                    uint32_t class_reg = pci_read_config((uint8_t)bus, device, func, 0x08);
                    out_device->bus = (uint8_t)bus;
                    out_device->device = device;
                    out_device->func = func;
                    out_device->vendor_id = cur_vendor;
                    out_device->device_id = cur_device;
                    out_device->class_code = (uint8_t)((class_reg >> 24) & 0xFFu);
                    out_device->subclass = (uint8_t)((class_reg >> 16) & 0xFFu);
                    out_device->prog_if = (uint8_t)((class_reg >> 8) & 0xFFu);
                    pci_read_bars(out_device);
                    return 1;
                }

                if (func == 0u) {
                    uint32_t header_type = pci_read_config((uint8_t)bus, device, func, 0x0C);
                    if (((header_type >> 16) & 0x80u) == 0u) {
                        break;
                    }
                }
            }
        }
    }

    return 0;
}

void pci_scan_bus(void)
{
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t func = 0; func < 8; func++) {
                uint32_t vendor_device = pci_read_config((uint8_t)bus, device, func, 0x00);
                uint16_t vendor_id = (uint16_t)(vendor_device & 0xFFFFu);
                uint16_t device_id = (uint16_t)((vendor_device >> 16) & 0xFFFFu);

                if (vendor_id == 0xFFFFu) {
                    if (func == 0u) {
                        break;
                    }
                    continue;
                }

                uint32_t class_reg = pci_read_config((uint8_t)bus, device, func, 0x08);
                uint8_t class_code = (uint8_t)((class_reg >> 24) & 0xFFu);
                uint8_t subclass = (uint8_t)((class_reg >> 16) & 0xFFu);
                uint8_t prog_if = (uint8_t)((class_reg >> 8) & 0xFFu);

                pci_device_t dev;
                dev.bus = (uint8_t)bus;
                dev.device = device;
                dev.func = func;
                dev.vendor_id = vendor_id;
                dev.device_id = device_id;
                dev.class_code = class_code;
                dev.subclass = subclass;
                dev.prog_if = prog_if;
                pci_read_bars(&dev);

                serial_write_string("Bus ");
                serial_write_uint32(bus);
                serial_write_string(" Device ");
                serial_write_uint32(device);
                serial_write_string(" Func ");
                serial_write_uint32(func);
                serial_write_char('\n');

                serial_write_string("  VendorID: 0x");
                serial_write_uint16(vendor_id);
                serial_write_string(" DeviceID: 0x");
                serial_write_uint16(device_id);
                serial_write_char('\n');

                serial_write_string("  Class: 0x");
                serial_write_uint32(class_code);
                serial_write_string(" Subclass: 0x");
                serial_write_uint32(subclass);
                serial_write_string(" ProgIF: 0x");
                serial_write_uint32(prog_if);
                serial_write_char('\n');

                for (int i = 0; i < 6; i++) {
                    serial_write_string("  BAR");
                    serial_write_uint32((uint32_t)i);
                    serial_write_string(": 0x");
                    serial_write_uint32(dev.bar[i]);
                    serial_write_char('\n');
                }

                if (func == 0u) {
                    uint32_t header_type = pci_read_config((uint8_t)bus, device, func, 0x0C);
                    if (((header_type >> 16) & 0x80u) == 0u) {
                        break;
                    }
                }
            }
        }
    }
}

#ifdef IMPLUS_DRIVER_MODULE
static const pci_driver_t g_pci_driver = {
    .read_config = pci_read_config,
    .write_config = pci_write_config,
    .scan_bus = pci_scan_bus,
    .find_device = pci_find_device,
    .read_bar = pci_read_bar,
};

#undef outl
#undef inl
#undef serial_write_char
#undef serial_write_string
#undef serial_write_uint16
#undef serial_write_uint32

const pci_driver_t *driver_module_init(const driver_kernel_api_t *api)
{
    if (api == NULL ||
        api->outl == NULL ||
        api->inl == NULL ||
        api->serial_write_char == NULL ||
        api->serial_write_string == NULL ||
        api->serial_write_uint16 == NULL ||
        api->serial_write_uint32 == NULL) {
        return NULL;
    }

    g_driver_api = api;
    return &g_pci_driver;
}
#endif
