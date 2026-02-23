#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

bool disk_read(uint32_t lba, uint8_t *buffer, uint32_t sector_count);
bool disk_write(uint32_t lba, const uint8_t *buffer, uint32_t sector_count);

#define FAT32_MAX_SECTOR_SIZE        512
#define FAT32_CLUSTER_BUFFER_SIZE    (FAT32_MAX_SECTOR_SIZE * 128)
#define FAT32_PATH_MAX               260

typedef struct {
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t num_fats;
    uint32_t fat_size_sectors;
    uint32_t root_cluster;
    uint32_t total_sectors;
} FAT32_BPB;

typedef struct FAT32_FILE {
    char name[FAT32_PATH_MAX];
    uint32_t first_cluster;
    uint32_t size;
    uint8_t attributes;
} FAT32_FILE;

typedef struct {
    bool (*init)(void);
    bool (*find_file)(const char *filename, FAT32_FILE *file);
    bool (*read_file)(FAT32_FILE *file, uint8_t *buffer);
    bool (*write_file)(FAT32_FILE *file, const uint8_t *buffer);
    bool (*read_at)(FAT32_FILE *file, uint32_t offset, uint8_t *buffer, uint32_t size);
    bool (*write_at)(FAT32_FILE *file, uint32_t offset, const uint8_t *buffer, uint32_t size);
    uint32_t (*get_file_size)(FAT32_FILE *file);
    void (*list_root_files)(void);
} fat32_driver_t;

bool fat32_init(void);
bool fat32_find_file(const char *filename, FAT32_FILE *file);
bool fat32_read_file(FAT32_FILE *file, uint8_t *buffer);
bool fat32_write_file(FAT32_FILE *file, const uint8_t *buffer);
bool fat32_read_at(FAT32_FILE *file, uint32_t offset, uint8_t *buffer, uint32_t size);
bool fat32_write_at(FAT32_FILE *file, uint32_t offset, const uint8_t *buffer, uint32_t size);
uint32_t fat32_get_file_size(FAT32_FILE *file);
void fat32_list_root_files(void);
