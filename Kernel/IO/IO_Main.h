#pragma once
#include <stdbool.h>
#include <stdint.h>

uint8_t inb(uint16_t port);
void outb(uint16_t port, uint8_t data);
void outl(uint16_t port, uint32_t val);
uint32_t inl(uint16_t port);
bool disk_read(uint32_t lba, uint8_t *buffer, uint32_t sectors);
bool disk_write(uint32_t lba, const uint8_t *buffer, uint32_t sectors);
