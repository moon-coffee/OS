#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "Display/Display_Driver.h"
#include "PCI/PCI_Main.h"
#include "FileSystem/FAT32/FAT32_Main.h"
#include "PS2/PS2_Input.h"

typedef struct {
    void (*serial_write_char)(char value);
    void (*serial_write_string)(const char *str);
    void (*serial_write_uint16)(uint16_t value);
    void (*serial_write_uint32)(uint32_t value);
    void (*serial_write_uint64)(uint64_t value);

    void *(*kmalloc)(uint32_t size);
    void (*kfree)(void *ptr);

    void *(*dma_alloc)(size_t size, uint64_t *phys_out);
    void (*dma_free)(void *ptr, size_t size);
    uint64_t (*virt_to_phys)(void *virt);

    void *(*memset)(void *s, int c, size_t n);
    void *(*memcpy)(void *dst, const void *src, size_t n);

    uint8_t (*inb)(uint16_t port);
    void (*outb)(uint16_t port, uint8_t value);
    uint32_t (*inl)(uint16_t port);
    void (*outl)(uint16_t port, uint32_t value);

    bool (*disk_read)(uint32_t lba, uint8_t *buffer, uint32_t sector_count);
    bool (*disk_write)(uint32_t lba, const uint8_t *buffer, uint32_t sector_count);

    uint32_t (*pci_read_config)(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset);
    void (*pci_write_config)(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint32_t value);

    void *(*map_mmio_virt)(uint64_t phys_addr);
} driver_kernel_api_t;

typedef const display_driver_t *(*display_driver_module_init_t)(const driver_kernel_api_t *api);
typedef const pci_driver_t *(*pci_driver_module_init_t)(const driver_kernel_api_t *api);
typedef const fat32_driver_t *(*fat32_driver_module_init_t)(const driver_kernel_api_t *api);
typedef const ps2_input_driver_t *(*ps2_input_driver_module_init_t)(const driver_kernel_api_t *api);
