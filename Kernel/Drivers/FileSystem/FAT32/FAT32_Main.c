#include "FAT32_Main.h"
#include "../../../Serial.h"
#include <string.h>

static FAT32_BPB bpb;

static int memcmp_local(const void *a, const void *b, uint32_t n) {
    const uint8_t *p = a;
    const uint8_t *q = b;
    for (uint32_t i = 0; i < n; i++) {
        if (p[i] != q[i])
            return p[i] - q[i];
    }
    return 0;
}

static uint32_t fat_start_lba(void) {
    return bpb.reserved_sectors;
}

static uint32_t data_start_lba(void) {
    return bpb.reserved_sectors + bpb.num_fats * bpb.fat_size_sectors;
}

static uint32_t cluster_to_lba(uint32_t cluster) {
    if (cluster < 2) return 0;
    return data_start_lba() + (cluster - 2) * bpb.sectors_per_cluster;
}

static uint32_t fat_get_next_cluster(uint32_t cluster) {
    if (cluster < 2 || cluster >= 0x0FFFFFF8) return 0x0FFFFFFF;

    uint32_t fat_offset = cluster * 4;
    uint32_t sector = fat_start_lba() + (fat_offset / bpb.bytes_per_sector);
    uint32_t offset = fat_offset % bpb.bytes_per_sector;

    if (offset + 4 > bpb.bytes_per_sector) return 0x0FFFFFFF;

    uint8_t buf[bpb.bytes_per_sector];
    if (!disk_read(sector, buf, 1)) return 0x0FFFFFFF;

    uint32_t val =
        buf[offset] |
        (buf[offset + 1] << 8) |
        (buf[offset + 2] << 16) |
        (buf[offset + 3] << 24);

    return val & 0x0FFFFFFF;
}

static bool __attribute__((unused))
fat_set_next_cluster(uint32_t cluster, uint32_t next) {
    if (cluster < 2 || cluster >= 0x0FFFFFF8) return false;

    uint32_t fat_offset = cluster * 4;
    uint32_t offset = fat_offset % bpb.bytes_per_sector;
    if (offset + 4 > bpb.bytes_per_sector) return false;

    for (uint32_t fat = 0; fat < bpb.num_fats; fat++) {
        uint32_t sector = fat_start_lba() +
                          fat * bpb.fat_size_sectors +
                          (fat_offset / bpb.bytes_per_sector);

        uint8_t buf[bpb.bytes_per_sector];
        if (!disk_read(sector, buf, 1)) return false;

        buf[offset]     = next & 0xFF;
        buf[offset + 1] = (next >> 8) & 0xFF;
        buf[offset + 2] = (next >> 16) & 0xFF;
        buf[offset + 3] = (buf[offset + 3] & 0xF0) | ((next >> 24) & 0x0F);

        if (!disk_write(sector, buf, 1)) return false;
    }

    return true;
}

uint32_t fat32_get_file_size(FAT32_FILE *file) {
    if (!file) return 0;
    return file->size;
}

bool fat32_init(void) {
    uint8_t sector[512];
    if (!disk_read(0, sector, 1)) return false;

    bpb.bytes_per_sector    = *(uint16_t*)&sector[11];
    bpb.sectors_per_cluster = sector[13];
    bpb.reserved_sectors    = *(uint16_t*)&sector[14];
    bpb.num_fats            = sector[16];
    bpb.fat_size_sectors    = *(uint32_t*)&sector[36];
    bpb.root_cluster        = *(uint32_t*)&sector[44];

    if (bpb.bytes_per_sector == 0 || bpb.bytes_per_sector > 4096) return false;
    if (bpb.sectors_per_cluster == 0 || bpb.sectors_per_cluster > 128) return false;
    if (bpb.num_fats == 0 || bpb.num_fats > 2) return false;
    if (bpb.root_cluster < 2) return false;
    serial_write_string("[OS] [FAT32] Init Success\n");
    return true;
}

bool fat32_find_file(const char *filename, FAT32_FILE *file) {
    if (!filename || !file) return false;

    uint32_t cluster = bpb.root_cluster;
    uint8_t buf[bpb.bytes_per_sector];
    uint32_t max_clusters = bpb.fat_size_sectors * bpb.bytes_per_sector / 4;

    for (uint32_t c = 0; c < max_clusters; c++) {
        for (uint8_t sec = 0; sec < bpb.sectors_per_cluster; sec++) {
            uint32_t lba = cluster_to_lba(cluster);
            if (!lba) return false;
            if (!disk_read(lba + sec, buf, 1)) return false;

            for (uint32_t i = 0; i < bpb.bytes_per_sector; i += 32) {
                if (buf[i] == 0x00) return false;
                if (buf[i] == 0xE5) continue;

                uint8_t attr = buf[i + 11];
                if ((attr & 0x0F) == 0x0F) continue;
                if (attr & 0x08) continue;

                if (memcmp_local(filename, &buf[i], 11) == 0) {
                    uint16_t high = *(uint16_t*)&buf[i + 20];
                    uint16_t low  = *(uint16_t*)&buf[i + 26];
                    file->first_cluster = ((uint32_t)high << 16) | low;
                    file->size = *(uint32_t*)&buf[i + 28];
                    memcpy(file->name, &buf[i], 11);
                    file->name[11] = '\0';
                    return true;
                }
            }
        }

        uint32_t next = fat_get_next_cluster(cluster);
        if (next < 2 || next >= 0x0FFFFFF8) break;
        cluster = next;
    }

    return false;
}

void fat32_list_root_files(void) {
    uint32_t cluster = bpb.root_cluster;
    uint8_t buf[bpb.bytes_per_sector];
    char lfn_stack[260];
    memset(lfn_stack, 0, sizeof(lfn_stack));
    uint32_t lfn_count = 0;

    uint32_t max_clusters = bpb.fat_size_sectors * bpb.bytes_per_sector / 4;

    for (uint32_t c = 0; c < max_clusters; c++) {
        for (uint8_t sec = 0; sec < bpb.sectors_per_cluster; sec++) {
            uint32_t lba = cluster_to_lba(cluster);
            if (!lba) return;
            if (!disk_read(lba + sec, buf, 1)) return;

            for (uint32_t i = 0; i < bpb.bytes_per_sector; i += 32) {
                if (buf[i] == 0x00) return;
                if (buf[i] == 0xE5) { lfn_count = 0; continue; }

                uint8_t attr = buf[i + 11];

                if (attr == 0x0F) {
                    uint8_t order = buf[i] & 0x3F;
                    uint32_t pos = (order - 1) * 13;
                    uint32_t k = 0;

                    for (int j = 0; j < 5; j++) {
                        uint16_t c = *(uint16_t*)&buf[i + 1 + j * 2];
                        if (!c || c == 0xFFFF) break;
                        lfn_stack[pos + k++] = (char)c;
                    }
                    for (int j = 0; j < 6; j++) {
                        uint16_t c = *(uint16_t*)&buf[i + 14 + j * 2];
                        if (!c || c == 0xFFFF) break;
                        lfn_stack[pos + k++] = (char)c;
                    }
                    for (int j = 0; j < 2; j++) {
                        uint16_t c = *(uint16_t*)&buf[i + 28 + j * 2];
                        if (!c || c == 0xFFFF) break;
                        lfn_stack[pos + k++] = (char)c;
                    }

                    if (order > lfn_count) lfn_count = order;
                    continue;
                }

                if (attr & 0x08) { lfn_count = 0; continue; }

                if (lfn_count) {
                    lfn_stack[lfn_count * 13] = '\0';
                    serial_write_string(lfn_stack);
                    serial_write_string("\n");
                } else {
                    char name[12];
                    memcpy(name, &buf[i], 11);
                    name[11] = '\0';
                    for (int j = 10; j >= 0; j--) {
                        if (name[j] == ' ') name[j] = '\0';
                        else break;
                    }
                    serial_write_string(name);
                    serial_write_string("\n");
                }

                memset(lfn_stack, 0, sizeof(lfn_stack));
                lfn_count = 0;
            }
        }

        uint32_t next = fat_get_next_cluster(cluster);
        if (next < 2 || next >= 0x0FFFFFF8) break;
        cluster = next;
    }
}

bool fat32_read_file(FAT32_FILE *file, uint8_t *buffer) {
    if (!file || !buffer) return false;

    uint32_t cluster = file->first_cluster;
    uint32_t bytes_left = file->size;
    uint32_t cluster_size = bpb.sectors_per_cluster * bpb.bytes_per_sector;
    uint8_t buf[cluster_size];

    while (bytes_left) {
        serial_write_string("[OS] [FAT32] read loop\n");
        serial_write_string("[OS] [FAT32] cluster\n");
        serial_write_uint32(cluster);
        serial_write_string("[OS] [FAT32] bytes_left\n");
        serial_write_uint32(bytes_left);
        uint32_t lba = cluster_to_lba(cluster);
        if (!lba) return false;
        uint32_t n_read = bytes_left > cluster_size ? cluster_size : bytes_left;
        serial_write_string("[OS] [FAT32] Disk read start\n");
        if (!disk_read(lba, buf, bpb.sectors_per_cluster)) return false;
        serial_write_string("[OS] [FAT32] Disk read success\n");
        serial_write_string("[OS] [FAT32] memcpy start\n");
        memcpy(buffer, buf, n_read);
        serial_write_string("[OS] [FAT32] memcpy done\n");
        buffer += n_read;
        bytes_left -= n_read;

        serial_write_string("[OS] [FAT32] get next cluster\n");
        uint32_t next = fat_get_next_cluster(cluster);
        serial_write_string("[OS] [FAT32] next cluster\n");
        serial_write_uint32(next);
        if (next < 2 || next >= 0x0FFFFFF8) break;
        cluster = next;
    }

    return bytes_left == 0;
}

bool fat32_write_file(FAT32_FILE *file, const uint8_t *buffer) {
    if (!file || !buffer) return false;

    uint32_t cluster = file->first_cluster;
    uint32_t bytes_left = file->size;
    uint8_t buf[bpb.bytes_per_sector];
    uint32_t max_clusters = bpb.fat_size_sectors * bpb.bytes_per_sector / 4;

    for (uint32_t c = 0; c < max_clusters && bytes_left; c++) {
        for (uint8_t sec = 0; sec < bpb.sectors_per_cluster && bytes_left; sec++) {
            uint32_t lba = cluster_to_lba(cluster);
            if (!lba) return false;

            uint32_t n = bytes_left > bpb.bytes_per_sector ?
                         bpb.bytes_per_sector : bytes_left;

            if (n == bpb.bytes_per_sector) {
                if (!disk_write(lba + sec, buffer, 1)) return false;
            } else {
                if (!disk_read(lba + sec, buf, 1)) return false;
                memcpy(buf, buffer, n);
                if (!disk_write(lba + sec, buf, 1)) return false;
            }

            buffer += n;
            bytes_left -= n;
        }

        uint32_t next = fat_get_next_cluster(cluster);
        if (next < 2 || next >= 0x0FFFFFF8) break;
        cluster = next;
    }

    return bytes_left == 0;
}
