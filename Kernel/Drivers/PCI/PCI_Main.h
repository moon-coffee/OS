#ifndef PCI_H
#define PCI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

typedef struct {
    uint8_t bus;
    uint8_t device;
    uint8_t func;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint32_t bar[6];
} pci_device_t;

typedef struct {
    uint32_t (*read_config)(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset);
    void (*write_config)(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value);
    void (*scan_bus)(void);
    int (*find_device)(uint16_t vendor_id, uint16_t device_id, pci_device_t *out_device);
    uint32_t (*read_bar)(uint8_t bus, uint8_t device, uint8_t func, uint8_t bar_index);
} pci_driver_t;

uint32_t pci_read_config(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset);
void pci_write_config(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value);

void pci_scan_bus(void);
int pci_find_device(uint16_t vendor_id, uint16_t device_id, pci_device_t *out_device);

uint32_t pci_read_bar(uint8_t bus, uint8_t device, uint8_t func, uint8_t bar_index);

#ifdef __cplusplus
}
#endif

#endif
