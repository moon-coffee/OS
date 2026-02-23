#include "FAT32_Main.h"
#include "../../../Serial.h"
#ifdef IMPLUS_DRIVER_MODULE
#include "../../DriverBinary.h"
#endif
#include <string.h>

#ifdef IMPLUS_DRIVER_MODULE
static const driver_kernel_api_t *g_driver_api = NULL;

#define disk_read g_driver_api->disk_read
#define disk_write g_driver_api->disk_write
#define serial_write_string g_driver_api->serial_write_string
#define memset g_driver_api->memset
#define memcpy g_driver_api->memcpy
#endif

#define FAT32_ATTR_VOLUME_ID 0x08
#define FAT32_ATTR_DIRECTORY 0x10
#define FAT32_ATTR_LFN       0x0F
#define FAT32_DIR_ENTRY_SIZE 32

#define FAT32_MAX_NAME_LEN 260
#define FAT32_LFN_CHARS_PER_ENTRY 13
#define FAT32_MAX_LFN_ORDER ((FAT32_MAX_NAME_LEN + FAT32_LFN_CHARS_PER_ENTRY - 1) / FAT32_LFN_CHARS_PER_ENTRY)

#define FAT32_MIN_SECTOR_SIZE       512
#define FAT32_MAX_SECTORS_PER_CLUSTER 128
#define FAT32_MAX_RESERVED_SECTORS  65535
#define FAT32_MAX_NUM_FATS          2
#define FAT32_MAX_FAT_SIZE_SECTORS  0x10000000UL

static FAT32_BPB bpb;

static uint8_t g_sector_buffer[FAT32_MAX_SECTOR_SIZE];
static uint8_t g_read_buffer[FAT32_CLUSTER_BUFFER_SIZE];

static uint16_t read_u16(const uint8_t *p) {
    if (!p) return 0;
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p) {
    if (!p) return 0;
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static char to_upper_ascii(char c) {
    if (c >= 'a' && c <= 'z') {
        return (char)(c - ('a' - 'A'));
    }
    return c;
}

static bool string_case_equal(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }

    while (*a && *b) {
        if (to_upper_ascii(*a) != to_upper_ascii(*b)) {
            return false;
        }
        ++a;
        ++b;
    }

    return (*a == '\0' && *b == '\0');
}

static void string_copy_limit(char *dst, uint32_t dst_size, const char *src) {
    if (!dst || dst_size == 0) {
        return;
    }

    uint32_t i = 0;
    if (src) {
        while (src[i] != '\0' && i + 1 < dst_size) {
            dst[i] = src[i];
            ++i;
        }
    }

    dst[i] = '\0';
}

static const char *skip_path_separators(const char *path) {
    if (!path) {
        return NULL;
    }

    while (*path == '/' || *path == '\\') {
        ++path;
    }

    return path;
}

static const char *extract_path_component(const char *path,
                                          char *component,
                                          uint32_t component_size,
                                          bool *has_more) {
    if (!path || !component || component_size == 0 || !has_more) {
        return NULL;
    }

    const char *p = skip_path_separators(path);
    uint32_t len = 0;

    while (*p != '\0' && *p != '/' && *p != '\\') {
        if (len + 1 >= component_size) {
            return NULL;
        }
        component[len++] = *p++;
    }

    component[len] = '\0';
    p = skip_path_separators(p);
    *has_more = (*p != '\0');
    return p;
}

static void fat32_short_name_to_string(const uint8_t *entry, char out_name[13]) {
    uint32_t n = 0;

    for (int i = 0; i < 8; ++i) {
        uint8_t ch = entry[i];
        if (ch == ' ') {
            break;
        }
        if (n + 1 < 13) {
            out_name[n++] = (char)ch;
        }
    }

    bool has_ext = false;
    for (int i = 8; i < 11; ++i) {
        if (entry[i] != ' ') {
            has_ext = true;
            break;
        }
    }

    if (has_ext && n + 1 < 13) {
        out_name[n++] = '.';
    }

    if (has_ext) {
        for (int i = 8; i < 11; ++i) {
            uint8_t ch = entry[i];
            if (ch == ' ') {
                break;
            }
            if (n + 1 < 13) {
                out_name[n++] = (char)ch;
            }
        }
    }

    out_name[n] = '\0';
}

static void fat32_lfn_store_char(char *lfn_name,
                                 uint32_t lfn_size,
                                 uint32_t index,
                                 uint16_t value) {
    if (!lfn_name || lfn_size == 0 || index >= lfn_size - 1) {
        return;
    }

    if (value == 0x0000 || value == 0xFFFF) {
        if (lfn_name[index] == '\0') {
            return;
        }
        lfn_name[index] = '\0';
        return;
    }

    if (value < 0x80) {
        lfn_name[index] = (char)value;
    } else {
        lfn_name[index] = '?';
    }
}

static bool fat32_decode_lfn_entry(const uint8_t *entry,
                                   char *lfn_name,
                                   uint32_t lfn_size) {
    uint8_t order = entry[0] & 0x1F;
    if (order == 0 || order > FAT32_MAX_LFN_ORDER) {
        return false;
    }

    uint32_t base = (uint32_t)(order - 1u) * FAT32_LFN_CHARS_PER_ENTRY;
    static const uint8_t offsets[FAT32_LFN_CHARS_PER_ENTRY] = {
        1, 3, 5, 7, 9,
        14, 16, 18, 20, 22, 24,
        28, 30
    };

    for (uint32_t i = 0; i < FAT32_LFN_CHARS_PER_ENTRY; ++i) {
        fat32_lfn_store_char(lfn_name,
                             lfn_size,
                             base + i,
                             read_u16(&entry[offsets[i]]));
    }

    return true;
}

static void fat32_fill_file_from_entry(const uint8_t *entry,
                                       const char *resolved_name,
                                       FAT32_FILE *file) {
    uint16_t high = read_u16(&entry[20]);
    uint16_t low  = read_u16(&entry[26]);
    file->first_cluster = ((uint32_t)high << 16) | low;
    file->size = read_u32(&entry[28]);
    file->attributes = entry[11];
    string_copy_limit(file->name, sizeof(file->name), resolved_name);
}

static uint32_t fat_start_lba(void) {
    return bpb.reserved_sectors;
}

static uint32_t data_start_lba(void) {
    uint32_t fat_area = bpb.num_fats * bpb.fat_size_sectors;
    if (fat_area > 0xFFFFFFFFUL - bpb.reserved_sectors) {
        return 0;
    }
    return bpb.reserved_sectors + fat_area;
}

static uint32_t cluster_to_lba(uint32_t cluster) {
    if (cluster < 2) return 0;
    
    uint32_t data_lba = data_start_lba();
    if (data_lba == 0) return 0;

    uint32_t offset = (uint32_t)(cluster - 2) * bpb.sectors_per_cluster;
    if (offset > 0xFFFFFFFFUL - data_lba) {
        return 0;
    }
    
    return data_lba + offset;
}

static uint32_t fat_get_next_cluster(uint32_t cluster) {
    if (cluster < 2 || cluster >= 0x0FFFFFF8) return 0x0FFFFFFF;

    uint32_t fat_offset = cluster * 4;

    uint32_t sector_offset = fat_offset / bpb.bytes_per_sector;
    if (sector_offset > 0xFFFFFFFFUL - fat_start_lba()) {
        return 0x0FFFFFFF;
    }
    
    uint32_t sector = fat_start_lba() + sector_offset;
    uint32_t offset = fat_offset % bpb.bytes_per_sector;

    if (offset + 4 > bpb.bytes_per_sector) return 0x0FFFFFFF;

    if (!disk_read(sector, g_sector_buffer, 1)) return 0x0FFFFFFF;

    uint32_t val =
        g_sector_buffer[offset] |
        (g_sector_buffer[offset + 1] << 8) |
        (g_sector_buffer[offset + 2] << 16) |
        (g_sector_buffer[offset + 3] << 24);

    return val & 0x0FFFFFFF;
}

static bool __attribute__((unused))
fat_set_next_cluster(uint32_t cluster, uint32_t next) {
    if (cluster < 2 || cluster >= 0x0FFFFFF8) return false;

    uint32_t fat_offset = cluster * 4;
    uint32_t offset = fat_offset % bpb.bytes_per_sector;
    if (offset + 4 > bpb.bytes_per_sector) return false;

    for (uint32_t fat = 0; fat < bpb.num_fats; fat++) {
        uint32_t sector_offset = fat_offset / bpb.bytes_per_sector;
        
        uint32_t fat_lba = fat * bpb.fat_size_sectors;
        if (fat_lba > 0xFFFFFFFFUL - fat_start_lba() ||
            sector_offset > 0xFFFFFFFFUL - (fat_start_lba() + fat_lba)) {
            return false;
        }
        
        uint32_t sector = fat_start_lba() + fat_lba + sector_offset;

        if (!disk_read(sector, g_sector_buffer, 1)) return false;

        g_sector_buffer[offset]     = next & 0xFF;
        g_sector_buffer[offset + 1] = (next >> 8) & 0xFF;
        g_sector_buffer[offset + 2] = (next >> 16) & 0xFF;
        g_sector_buffer[offset + 3] = (g_sector_buffer[offset + 3] & 0xF0) | ((next >> 24) & 0x0F);

        if (!disk_write(sector, g_sector_buffer, 1)) return false;
    }

    return true;
}

static bool fat32_lookup_entry_in_directory(uint32_t dir_cluster,
                                            const char *target_name,
                                            FAT32_FILE *out_file) {
    if (dir_cluster < 2 || !target_name || !out_file || target_name[0] == '\0') {
        return false;
    }

    char lfn_name[FAT32_MAX_NAME_LEN];
    int lfn_valid = 0;

    memset(lfn_name, 0, sizeof(lfn_name));

    uint32_t cluster = dir_cluster;
    uint32_t max_clusters = bpb.fat_size_sectors * bpb.bytes_per_sector / 4;

    for (uint32_t c = 0; c < max_clusters; ++c) {
        uint32_t lba = cluster_to_lba(cluster);
        if (!lba) {
            return false;
        }

        for (uint8_t sec = 0; sec < bpb.sectors_per_cluster; ++sec) {
            if (!disk_read(lba + sec, g_sector_buffer, 1)) {
                return false;
            }

            for (uint32_t i = 0; i < bpb.bytes_per_sector; i += FAT32_DIR_ENTRY_SIZE) {
                const uint8_t *entry = &g_sector_buffer[i];
                uint8_t first = entry[0];

                if (first == 0x00) {
                    return false;
                }
                if (first == 0xE5) {
                    lfn_valid = 0;
                    memset(lfn_name, 0, sizeof(lfn_name));
                    continue;
                }

                uint8_t attr = entry[11];

                if (attr == FAT32_ATTR_LFN) {
                    uint8_t seq = entry[0];
                    uint8_t order = seq & 0x1F;

                    if (order == 0 || order > FAT32_MAX_LFN_ORDER) {
                        lfn_valid = 0;
                        memset(lfn_name, 0, sizeof(lfn_name));
                        continue;
                    }

                    if (seq & 0x40) {
                        memset(lfn_name, 0, sizeof(lfn_name));
                        lfn_valid = 1;
                    }

                    if (!lfn_valid ||
                        !fat32_decode_lfn_entry(entry, lfn_name, sizeof(lfn_name))) {
                        lfn_valid = 0;
                        memset(lfn_name, 0, sizeof(lfn_name));
                    }
                    continue;
                }

                if (attr & FAT32_ATTR_VOLUME_ID) {
                    lfn_valid = 0;
                    memset(lfn_name, 0, sizeof(lfn_name));
                    continue;
                }

                char short_name[13];
                fat32_short_name_to_string(entry, short_name);

                const char *candidate =
                    (lfn_valid && lfn_name[0] != '\0') ? lfn_name : short_name;
                    
                if (string_case_equal(candidate, target_name)) {
                    fat32_fill_file_from_entry(entry, candidate, out_file);
                    return true;
                }

                lfn_valid = 0;
                memset(lfn_name, 0, sizeof(lfn_name));
            }
        }

        uint32_t next = fat_get_next_cluster(cluster);
        if (next < 2 || next >= 0x0FFFFFF8) {
            break;
        }
        cluster = next;
    }

    return false;
}

static bool fat32_lookup_path(const char *path, FAT32_FILE *out_entry) {
    if (!path || !out_entry) {
        return false;
    }

    const char *cursor = skip_path_separators(path);
    if (!cursor || *cursor == '\0') {
        return false;
    }

    uint32_t current_dir_cluster = bpb.root_cluster;
    FAT32_FILE current_entry;
    char component[FAT32_MAX_NAME_LEN];
    bool has_more = false;

    while (1) {
        const char *next = extract_path_component(cursor,
                                                  component,
                                                  sizeof(component),
                                                  &has_more);
        if (!next || component[0] == '\0') {
            return false;
        }

        if (!fat32_lookup_entry_in_directory(current_dir_cluster,
                                             component,
                                             &current_entry)) {
            return false;
        }

        if (!has_more) {
            *out_entry = current_entry;
            return true;
        }

        if ((current_entry.attributes & FAT32_ATTR_DIRECTORY) == 0) {
            return false;
        }

        if (current_entry.first_cluster < 2) {
            return false;
        }

        current_dir_cluster = current_entry.first_cluster;
        cursor = next;
    }
}

static bool fat32_validate_bpb(void) {
    if (bpb.bytes_per_sector < FAT32_MIN_SECTOR_SIZE ||
        bpb.bytes_per_sector > FAT32_MAX_SECTOR_SIZE) {
        serial_write_string("[OS] [FAT32] Invalid sector size\n");
        return false;
    }

    if (bpb.sectors_per_cluster == 0 ||
        bpb.sectors_per_cluster > FAT32_MAX_SECTORS_PER_CLUSTER) {
        serial_write_string("[OS] [FAT32] Invalid sectors per cluster\n");
        return false;
    }

    if (bpb.reserved_sectors == 0 ||
        bpb.reserved_sectors > FAT32_MAX_RESERVED_SECTORS) {
        serial_write_string("[OS] [FAT32] Invalid reserved sectors\n");
        return false;
    }

    if (bpb.num_fats == 0 || bpb.num_fats > FAT32_MAX_NUM_FATS) {
        serial_write_string("[OS] [FAT32] Invalid number of FATs\n");
        return false;
    }

    if (bpb.fat_size_sectors == 0 ||
        bpb.fat_size_sectors > FAT32_MAX_FAT_SIZE_SECTORS) {
        serial_write_string("[OS] [FAT32] Invalid FAT size\n");
        return false;
    }

    if (bpb.num_fats > FAT32_MAX_FAT_SIZE_SECTORS / bpb.fat_size_sectors) {
        serial_write_string("[OS] [FAT32] FAT area overflow\n");
        return false;
    }

    if (bpb.root_cluster < 2) {
        serial_write_string("[OS] [FAT32] Invalid root cluster\n");
        return false;
    }

    uint32_t cluster_size = (uint32_t)bpb.sectors_per_cluster * bpb.bytes_per_sector;
    if (cluster_size == 0 || cluster_size > FAT32_CLUSTER_BUFFER_SIZE) {
        serial_write_string("[OS] [FAT32] Cluster size exceeds buffer\n");
        return false;
    }

    if (data_start_lba() == 0 && bpb.reserved_sectors + bpb.num_fats * bpb.fat_size_sectors > 0) {
        serial_write_string("[OS] [FAT32] Data area calculation overflow\n");
        return false;
    }

    return true;
}

uint32_t fat32_get_file_size(FAT32_FILE *file) {
    if (!file) return 0;
    return file->size;
}

bool fat32_init(void) {
    if (!disk_read(0, g_sector_buffer, 1)) {
        serial_write_string("[OS] [FAT32] Boot sector read failed\n");
        return false;
    }

    bpb.bytes_per_sector    = read_u16(&g_sector_buffer[11]);
    bpb.sectors_per_cluster = g_sector_buffer[13];
    bpb.reserved_sectors    = read_u16(&g_sector_buffer[14]);
    bpb.num_fats            = g_sector_buffer[16];
    bpb.fat_size_sectors    = read_u32(&g_sector_buffer[36]);
    bpb.root_cluster        = read_u32(&g_sector_buffer[44]);
    bpb.total_sectors       = read_u32(&g_sector_buffer[32]);

    if (!fat32_validate_bpb()) {
        return false;
    }
    
    serial_write_string("[OS] [FAT32] Init Success\n");
    return true;
}

bool fat32_find_file(const char *filename, FAT32_FILE *file) {
    if (!filename || !file) {
        return false;
    }

    if (!fat32_lookup_path(filename, file)) {
        return false;
    }

    if (file->attributes & FAT32_ATTR_DIRECTORY) {
        return false;
    }

    return true;
}

void fat32_list_root_files(void) {
    uint32_t cluster = bpb.root_cluster;
    char lfn_name[FAT32_MAX_NAME_LEN];
    int lfn_valid = 0;

    memset(lfn_name, 0, sizeof(lfn_name));

    uint32_t max_clusters = bpb.fat_size_sectors * bpb.bytes_per_sector / 4;

    for (uint32_t c = 0; c < max_clusters; c++) {
        for (uint8_t sec = 0; sec < bpb.sectors_per_cluster; sec++) {
            uint32_t lba = cluster_to_lba(cluster);
            if (!lba) return;
            if (!disk_read(lba + sec, g_sector_buffer, 1)) return;

            for (uint32_t i = 0; i < bpb.bytes_per_sector; i += 32) {
                if (g_sector_buffer[i] == 0x00) return;
                if (g_sector_buffer[i] == 0xE5) {
                    lfn_valid = 0;
                    memset(lfn_name, 0, sizeof(lfn_name));
                    continue;
                }

                uint8_t attr = g_sector_buffer[i + 11];

                if (attr == FAT32_ATTR_LFN) {
                    uint8_t seq = g_sector_buffer[i];
                    uint8_t order = seq & 0x1F;

                    if (order == 0 || order > FAT32_MAX_LFN_ORDER) {
                        lfn_valid = 0;
                        memset(lfn_name, 0, sizeof(lfn_name));
                        continue;
                    }

                    if (seq & 0x40) {
                        memset(lfn_name, 0, sizeof(lfn_name));
                        lfn_valid = 1;
                    }

                    if (!lfn_valid ||
                        !fat32_decode_lfn_entry(&g_sector_buffer[i], lfn_name, sizeof(lfn_name))) {
                        lfn_valid = 0;
                        memset(lfn_name, 0, sizeof(lfn_name));
                    }
                    continue;
                }

                if (attr & FAT32_ATTR_VOLUME_ID) {
                    lfn_valid = 0;
                    memset(lfn_name, 0, sizeof(lfn_name));
                    continue;
                }

                char short_name[13];
                fat32_short_name_to_string(&g_sector_buffer[i], short_name);

                const char *display_name =
                    (lfn_valid && lfn_name[0] != '\0') ? lfn_name : short_name;

                serial_write_string(display_name);
                if (attr & FAT32_ATTR_DIRECTORY) {
                    serial_write_string("/");
                }
                serial_write_string("\n");
                
                lfn_valid = 0;
                memset(lfn_name, 0, sizeof(lfn_name));
            }
        }

        uint32_t next = fat_get_next_cluster(cluster);
        if (next < 2 || next >= 0x0FFFFFF8) break;
        cluster = next;
    }
}

static bool fat32_seek_to_offset(const FAT32_FILE *file,
                                 uint32_t offset,
                                 uint32_t cluster_size,
                                 uint32_t *cluster_out,
                                 uint32_t *offset_in_cluster_out) {
    if (!file || !cluster_out || !offset_in_cluster_out || cluster_size == 0) {
        return false;
    }

    uint32_t cluster = file->first_cluster;
    uint32_t max_clusters = bpb.fat_size_sectors * bpb.bytes_per_sector / 4;
    uint32_t skip_clusters = offset / cluster_size;

    if (skip_clusters > max_clusters) {
        return false;
    }

    for (uint32_t i = 0; i < skip_clusters; ++i) {
        uint32_t next = fat_get_next_cluster(cluster);
        if (next < 2 || next >= 0x0FFFFFF8) {
            return false;
        }
        cluster = next;
    }

    *cluster_out = cluster;
    *offset_in_cluster_out = offset % cluster_size;
    return true;
}

bool fat32_read_at(FAT32_FILE *file, uint32_t offset, uint8_t *buffer, uint32_t size) {
    if (!file || !buffer) {
        return false;
    }
    if (size == 0) {
        return offset <= file->size;
    }
    if (offset > file->size || size > file->size - offset) {
        return false;
    }

    uint32_t cluster_size = (uint32_t)bpb.sectors_per_cluster * bpb.bytes_per_sector;
    if (cluster_size == 0 || cluster_size > FAT32_CLUSTER_BUFFER_SIZE) {
        serial_write_string("[OS] [FAT32] Invalid cluster size\n");
        return false;
    }
    if (file->first_cluster < 2) {
        serial_write_string("[OS] [FAT32] Invalid start cluster\n");
        return false;
    }

    uint32_t cluster = 0;
    uint32_t offset_in_cluster = 0;
    if (!fat32_seek_to_offset(file,
                              offset,
                              cluster_size,
                              &cluster,
                              &offset_in_cluster)) {
        serial_write_string("[OS] [FAT32] Invalid cluster chain\n");
        return false;
    }

    uint32_t bytes_left = size;
    while (bytes_left) {
        uint32_t lba = cluster_to_lba(cluster);
        if (!lba) {
            serial_write_string("[OS] [FAT32] Invalid cluster LBA\n");
            return false;
        }

        if (!disk_read(lba, g_read_buffer, bpb.sectors_per_cluster)) {
            serial_write_string("[OS] [FAT32] Disk read failed\n");
            return false;
        }

        uint32_t bytes_in_cluster = cluster_size - offset_in_cluster;
        uint32_t n_read = bytes_left > bytes_in_cluster ? bytes_in_cluster : bytes_left;
        memcpy(buffer, g_read_buffer + offset_in_cluster, n_read);

        buffer += n_read;
        bytes_left -= n_read;
        offset_in_cluster = 0;

        if (bytes_left) {
            uint32_t next = fat_get_next_cluster(cluster);
            if (next < 2 || next >= 0x0FFFFFF8) {
                serial_write_string("[OS] [FAT32] Cluster chain ended early\n");
                return false;
            }
            cluster = next;
        }
    }

    return true;
}

bool fat32_write_at(FAT32_FILE *file, uint32_t offset, const uint8_t *buffer, uint32_t size) {
    if (!file || !buffer) {
        return false;
    }
    if (size == 0) {
        return offset <= file->size;
    }
    if (offset > file->size || size > file->size - offset) {
        return false;
    }

    uint32_t cluster_size = (uint32_t)bpb.sectors_per_cluster * bpb.bytes_per_sector;
    if (cluster_size == 0 || cluster_size > FAT32_CLUSTER_BUFFER_SIZE) {
        serial_write_string("[OS] [FAT32] Invalid cluster size\n");
        return false;
    }
    if (file->first_cluster < 2) {
        serial_write_string("[OS] [FAT32] Invalid start cluster\n");
        return false;
    }

    uint32_t cluster = 0;
    uint32_t offset_in_cluster = 0;
    if (!fat32_seek_to_offset(file,
                              offset,
                              cluster_size,
                              &cluster,
                              &offset_in_cluster)) {
        serial_write_string("[OS] [FAT32] Invalid cluster chain\n");
        return false;
    }

    uint32_t bytes_left = size;
    while (bytes_left) {
        uint32_t lba = cluster_to_lba(cluster);
        if (!lba) {
            serial_write_string("[OS] [FAT32] Invalid cluster LBA\n");
            return false;
        }

        uint32_t bytes_in_cluster = cluster_size - offset_in_cluster;
        uint32_t n_write = bytes_left > bytes_in_cluster ? bytes_in_cluster : bytes_left;

        if (offset_in_cluster == 0 && n_write == cluster_size) {
            if (!disk_write(lba, buffer, bpb.sectors_per_cluster)) {
                serial_write_string("[OS] [FAT32] Disk write failed\n");
                return false;
            }
        } else {
            if (!disk_read(lba, g_read_buffer, bpb.sectors_per_cluster)) {
                serial_write_string("[OS] [FAT32] Disk read failed\n");
                return false;
            }
            memcpy(g_read_buffer + offset_in_cluster, buffer, n_write);
            if (!disk_write(lba, g_read_buffer, bpb.sectors_per_cluster)) {
                serial_write_string("[OS] [FAT32] Disk write failed\n");
                return false;
            }
        }

        buffer += n_write;
        bytes_left -= n_write;
        offset_in_cluster = 0;

        if (bytes_left) {
            uint32_t next = fat_get_next_cluster(cluster);
            if (next < 2 || next >= 0x0FFFFFF8) {
                serial_write_string("[OS] [FAT32] Cluster chain ended early\n");
                return false;
            }
            cluster = next;
        }
    }

    return true;
}

bool fat32_write_file(FAT32_FILE *file, const uint8_t *buffer) {
    if (!file || !buffer) {
        return false;
    }
    return fat32_write_at(file, 0, buffer, file->size);
}

bool fat32_read_file(FAT32_FILE *file, uint8_t *buffer) {
    if (!file || !buffer) {
        return false;
    }
    return fat32_read_at(file, 0, buffer, file->size);
}

#ifdef IMPLUS_DRIVER_MODULE
static const fat32_driver_t g_fat32_driver = {
    .init = fat32_init,
    .find_file = fat32_find_file,
    .read_file = fat32_read_file,
    .write_file = fat32_write_file,
    .read_at = fat32_read_at,
    .write_at = fat32_write_at,
    .get_file_size = fat32_get_file_size,
    .list_root_files = fat32_list_root_files,
};

#undef disk_read
#undef disk_write
#undef serial_write_string
#undef memset
#undef memcpy

const fat32_driver_t *driver_module_init(const driver_kernel_api_t *api)
{
    if (api == NULL ||
        api->disk_read == NULL ||
        api->disk_write == NULL ||
        api->serial_write_string == NULL ||
        api->memset == NULL ||
        api->memcpy == NULL) {
        return NULL;
    }

    g_driver_api = api;
    return &g_fat32_driver;
}
#endif
