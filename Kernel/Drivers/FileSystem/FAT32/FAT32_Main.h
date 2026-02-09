#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

bool disk_read(uint32_t lba, uint8_t *buffer, uint32_t sector_count);
bool disk_write(uint32_t lba, const uint8_t *buffer, uint32_t sector_count);

typedef struct {
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t num_fats;
    uint32_t fat_size_sectors;
    uint32_t root_cluster;
} FAT32_BPB;

typedef struct {
    char name[12];
    uint32_t first_cluster;
    uint32_t size;
} FAT32_FILE;

bool fat32_init(void);
bool fat32_find_file(const char *filename, FAT32_FILE *file);
bool fat32_read_file(FAT32_FILE *file, uint8_t *buffer);
bool fat32_write_file(FAT32_FILE *file, const uint8_t *buffer);
uint32_t fat32_get_file_size(FAT32_FILE *file);
void fat32_list_root_files(void);
