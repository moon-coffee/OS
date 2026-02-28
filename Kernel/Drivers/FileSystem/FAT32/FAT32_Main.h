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
    uint32_t dir_entry_sector;
    uint16_t dir_entry_offset;
    uint8_t lfn_entry_count;
    uint8_t reserved0;
} FAT32_FILE;

typedef struct {
    char name[FAT32_PATH_MAX];
    uint32_t first_cluster;
    uint32_t size;
    uint8_t attributes;
} FAT32_DIRENT;

typedef struct {
    bool (*init)(void);
    bool (*find_file)(const char *filename, FAT32_FILE *file);
    bool (*read_file)(FAT32_FILE *file, uint8_t *buffer);
    bool (*write_file)(FAT32_FILE *file, const uint8_t *buffer);
    bool (*read_at)(FAT32_FILE *file, uint32_t offset, uint8_t *buffer, uint32_t size);
    bool (*write_at)(FAT32_FILE *file, uint32_t offset, const uint8_t *buffer, uint32_t size);
    uint32_t (*get_file_size)(FAT32_FILE *file);
    void (*list_root_files)(void);
    bool (*creat)(const char *path);
    bool (*mkdir)(const char *path);
    int32_t (*opendir)(const char *path);
    int32_t (*readdir)(int32_t dir_handle, FAT32_DIRENT *out_entry);
    int32_t (*closedir)(int32_t dir_handle);
    bool (*unlink)(const char *path);
    bool (*truncate)(FAT32_FILE *file, uint32_t new_size);
    void (*set_case_sensitive_lookup)(bool enabled);
    bool (*get_case_sensitive_lookup)(void);
} fat32_driver_t;

bool fat32_init(void);
bool fat32_find_file(const char *filename, FAT32_FILE *file);
bool fat32_read_file(FAT32_FILE *file, uint8_t *buffer);
bool fat32_write_file(FAT32_FILE *file, const uint8_t *buffer);
bool fat32_read_at(FAT32_FILE *file, uint32_t offset, uint8_t *buffer, uint32_t size);
bool fat32_write_at(FAT32_FILE *file, uint32_t offset, const uint8_t *buffer, uint32_t size);
bool fat32_truncate(FAT32_FILE *file, uint32_t new_size);
uint32_t fat32_get_file_size(FAT32_FILE *file);
void fat32_list_root_files(void);
bool fat32_creat(const char *path);
bool fat32_mkdir(const char *path);
int32_t fat32_opendir(const char *path);
int32_t fat32_readdir(int32_t dir_handle, FAT32_DIRENT *out_entry);
int32_t fat32_closedir(int32_t dir_handle);
bool fat32_unlink(const char *path);
void fat32_set_case_sensitive_lookup(bool enabled);
bool fat32_get_case_sensitive_lookup(void);
