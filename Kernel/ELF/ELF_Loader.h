#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint64_t max_file_size;
    uint64_t min_vaddr;
    uint64_t max_vaddr;
} elf_load_policy_t;

typedef struct {
    uint64_t max_file_size;
    uint64_t max_image_size;
    uint32_t max_relocation_count;
} elf_module_load_policy_t;

bool elf_loader_path_to_fat83(const char *path, char out_name[12]);
bool elf_loader_load_from_fat83(const char fat_name[12],
                                const elf_load_policy_t *policy,
                                uint64_t *entry_out);
bool elf_loader_load_from_path(const char *path,
                               const elf_load_policy_t *policy,
                               uint64_t *entry_out);
bool elf_loader_load_module_from_memory(const void *file_data,
                                        uint64_t file_size,
                                        const elf_module_load_policy_t *policy,
                                        uint64_t *entry_out);
