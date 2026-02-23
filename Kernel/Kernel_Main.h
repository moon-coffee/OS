#ifndef KERNEL_MAIN_H
#define KERNEL_MAIN_H

#include <stdint.h>
#include <stddef.h>

#include "Drivers/DriverModuleIds.h"

typedef uint64_t UINTN;
typedef uint32_t UINT32;

typedef uint64_t EFI_PHYSICAL_ADDRESS;

#define MAX_LOADED_FILES 8

typedef struct {
    UINT32 Type;
    UINT32 Pad;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct {
    UINT32 Id;
    UINT32 Reserved;
    EFI_PHYSICAL_ADDRESS PhysAddr;
    uint64_t Size;
} LOADED_FILE;

typedef struct {
    EFI_MEMORY_DESCRIPTOR *MemoryMap;
    UINTN MemoryMapSize;
    UINTN MemoryMapDescriptorSize;
    UINT32 MemoryMapDescriptorVersion;

    uint64_t FrameBufferBase;
    UINT32 FrameBufferSize;
    UINT32 HorizontalResolution;
    UINT32 VerticalResolution;
    UINT32 PixelsPerScanLine;

    UINTN LoadedFileCount;
    LOADED_FILE LoadedFiles[MAX_LOADED_FILES];
} BOOT_INFO;

__attribute__((noreturn))
void kernel_main(BOOT_INFO *boot_info);

#endif
