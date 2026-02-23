#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "DriverBinary.h"
#include "DriverModuleIds.h"
#include "../Kernel_Main.h"

void driver_module_manager_init(const BOOT_INFO *boot_info);
const driver_kernel_api_t *driver_module_manager_kernel_api(void);

bool driver_module_manager_load(driver_module_id_t id,
                                uint64_t max_file_size,
                                uint64_t max_image_size,
                                uint64_t *entry_out);
