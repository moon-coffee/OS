#include "DriverModule.h"

#include "PCI/PCI_Main.h"
#include "../ELF/ELF_Loader.h"
#include "../IO/IO_Main.h"
#include "../Memory/DMA_Memory.h"
#include "../Memory/Memory_Main.h"
#include "../Memory/Other_Utils.h"
#include "../Paging/Paging_Main.h"
#include "../Serial.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t present;
    uint8_t loaded;
    const void *file_data;
    uint64_t file_size;
    uint64_t entry;
} module_state_t;

static module_state_t g_modules[DRIVER_MODULE_ID_MAX + 1];

static const driver_kernel_api_t g_driver_api = {
    .serial_write_char = serial_write_char,
    .serial_write_string = serial_write_string,
    .serial_write_uint16 = serial_write_uint16,
    .serial_write_uint32 = serial_write_uint32,
    .serial_write_uint64 = serial_write_uint64,
    .kmalloc = kmalloc,
    .kfree = kfree,
    .dma_alloc = dma_alloc,
    .dma_free = dma_free,
    .virt_to_phys = virt_to_phys,
    .memset = memset,
    .memcpy = memcpy,
    .inb = inb,
    .outb = outb,
    .inl = inl,
    .outl = outl,
    .disk_read = disk_read,
    .disk_write = disk_write,
    .pci_read_config = pci_read_config,
    .pci_write_config = pci_write_config,
    .map_mmio_virt = map_mmio_virt,
};

void driver_module_manager_init(const BOOT_INFO *boot_info)
{
    for (uint32_t i = 0; i <= DRIVER_MODULE_ID_MAX; ++i) {
        g_modules[i].present = 0;
        g_modules[i].loaded = 0;
        g_modules[i].file_data = NULL;
        g_modules[i].file_size = 0;
        g_modules[i].entry = 0;
    }

    if (boot_info == NULL) {
        serial_write_string("[OS] [DRIVER] BOOT_INFO missing for module manager\n");
        return;
    }

    for (uint64_t i = 0; i < (uint64_t)boot_info->LoadedFileCount; ++i) {
        const LOADED_FILE *file = &boot_info->LoadedFiles[i];
        driver_module_id_t id = (driver_module_id_t)file->Id;
        if (id == DRIVER_MODULE_ID_INVALID || id > DRIVER_MODULE_ID_MAX) {
            continue;
        }
        if (file->PhysAddr == 0 || file->Size == 0) {
            continue;
        }

        module_state_t *state = &g_modules[id];
        state->present = 1;
        state->file_data = (const void *)(uintptr_t)file->PhysAddr;
        state->file_size = file->Size;
    }
}

const driver_kernel_api_t *driver_module_manager_kernel_api(void)
{
    return &g_driver_api;
}

bool driver_module_manager_load(driver_module_id_t id,
                                uint64_t max_file_size,
                                uint64_t max_image_size,
                                uint64_t *entry_out)
{
    if (entry_out == NULL ||
        id == DRIVER_MODULE_ID_INVALID ||
        id > DRIVER_MODULE_ID_MAX ||
        max_file_size == 0 ||
        max_image_size == 0) {
        return false;
    }

    module_state_t *state = &g_modules[id];
    if (!state->present || state->file_data == NULL || state->file_size == 0) {
        return false;
    }

    if (state->loaded) {
        *entry_out = state->entry;
        return true;
    }

    elf_module_load_policy_t policy = {
        .max_file_size = max_file_size,
        .max_image_size = max_image_size,
        .max_relocation_count = 4096,
    };

    uint64_t entry = 0;
    if (!elf_loader_load_module_from_memory(state->file_data,
                                            state->file_size,
                                            &policy,
                                            &entry)) {
        return false;
    }

    state->loaded = 1;
    state->entry = entry;
    *entry_out = entry;
    return true;
}
