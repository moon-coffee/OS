#include <stdint.h>
#include <stdbool.h>
#include "../Serial.h"

#define ATA_DATA     0x1F0
#define ATA_SECCOUNT 0x1F2
#define ATA_LBA0     0x1F3
#define ATA_LBA1     0x1F4
#define ATA_LBA2     0x1F5
#define ATA_HDDEVSEL 0x1F6
#define ATA_COMMAND  0x1F7
#define ATA_STATUS   0x1F7
#define ATA_CONTROL  0x3F6
#define FAT32_START_LBA 2048
#define ATA_CMD_READ    0x20
#define ATA_SR_BSY      0x80
#define ATA_SR_DRQ      0x08
#define ATA_SR_ERR      0x01

void outb(uint16_t port, uint8_t val){
    __asm__ volatile("outb %0,%1" :: "a"(val), "Nd"(port));
}

uint8_t inb(uint16_t port){
    uint8_t val;
    __asm__ volatile("inb %1,%0" : "=a"(val) : "Nd"(port));
    return val;
}

uint16_t inw(uint16_t port){
    uint16_t val;
    __asm__ volatile("inw %1,%0" : "=a"(val) : "Nd"(port));
    return val;
}

static inline void outsw(uint16_t port, const void* addr, int count){
    __asm__ volatile(
        "rep outsw"
        : "+S"(addr), "+c"(count)
        : "d"(port)
        : "memory"
    );
}

static inline void insw(uint16_t port, void* addr, int count){
    __asm__ volatile(
        "rep insw"
        : "+D"(addr), "+c"(count)
        : "d"(port)
        : "memory"
    );
}


bool disk_read(uint32_t lba, uint8_t *buffer, uint32_t sectors){
    if (sectors == 0) return false;

    for (uint32_t s = 0; s < sectors; s++) {
        uint32_t real_lba = FAT32_START_LBA + lba + s;

        outb(ATA_HDDEVSEL, 0xE0 | ((real_lba >> 24) & 0x0F));
        outb(ATA_SECCOUNT, 1);
        outb(ATA_LBA0, real_lba & 0xFF);
        outb(ATA_LBA1, (real_lba >> 8) & 0xFF);
        outb(ATA_LBA2, (real_lba >> 16) & 0xFF);
        outb(ATA_COMMAND, ATA_CMD_READ);

        uint32_t timeout = 10000000;
        while (inb(ATA_STATUS) & ATA_SR_BSY) {
            if (--timeout == 0) {
                serial_write_string("[OS] [IO] Timeout waiting for BSY clear\n");
                return false;
            }
        }

        timeout = 10000000;
        uint8_t status;
        do {
            status = inb(ATA_STATUS);
            if (status & ATA_SR_ERR) {
                serial_write_string("[OS] [IO] Disk error detected\n");
                return false;
            }
            if (--timeout == 0) {
                serial_write_string("[OS] [IO] Timeout waiting for DRQ\n");
                return false;
            }
        } while (!(status & ATA_SR_DRQ));
        
        for (int i = 0; i < 256; i++) {
            ((uint16_t*)buffer)[i] = inw(ATA_DATA);
        }
        buffer += 512;
    }
    return true;
}

bool disk_write(uint32_t lba, const uint8_t *buffer, uint32_t sectors){
    if (sectors == 0) return false;

    for (uint32_t s = 0; s < sectors; s++) {
        uint32_t real_lba = FAT32_START_LBA + lba + s;

        outb(ATA_HDDEVSEL, 0xE0 | ((real_lba >> 24) & 0x0F));
        outb(ATA_SECCOUNT, 1);
        outb(ATA_LBA0, real_lba & 0xFF);
        outb(ATA_LBA1, (real_lba >> 8) & 0xFF);
        outb(ATA_LBA2, (real_lba >> 16) & 0xFF);
        outb(ATA_COMMAND, 0x30);

        uint32_t timeout = 10000000;
        while(inb(ATA_STATUS) & ATA_SR_BSY) {
            if (--timeout == 0) return false;
        }

        timeout = 10000000;
        while(!(inb(ATA_STATUS) & ATA_SR_DRQ)) {
            if (--timeout == 0) return false;
        }

        outsw(ATA_DATA, buffer, 256);
        buffer += 512;
    }
    return true;
}

void outl(uint16_t port, uint32_t val) {
    __asm__ volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}

uint32_t inl(uint16_t port) {
    uint32_t ret;
    __asm__ volatile ("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
