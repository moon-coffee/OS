#include <efi.h>
#include <efilib.h>
#include <stdint.h>

#include "../Kernel/Drivers/DriverModuleIds.h"

#define CHECK(st, msg) \
    if (EFI_ERROR(st)) { Print(L"%s: %r\n", msg, st); return st; }

#define EI_NIDENT 16
#define PT_LOAD   1

typedef uint64_t EFI_PHYSICAL_ADDRESS;

#define MAX_LOADED_FILES 8

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

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    UINT32 Id;
    const CHAR16 *Path;
    BOOLEAN Required;
} PRELOAD_FILE_SPEC;

EFI_STATUS LoadFileToMemory(
    EFI_SYSTEM_TABLE *ST,
    EFI_FILE_PROTOCOL *File,
    VOID **Buffer,
    UINTN *Size
)
{
    EFI_STATUS Status;
    EFI_FILE_INFO *Info;
    UINTN InfoSize = sizeof(EFI_FILE_INFO) + 256;

    Status = uefi_call_wrapper(
        ST->BootServices->AllocatePool,
        3,
        EfiLoaderData,
        InfoSize,
        (VOID**)&Info
    );
    if (EFI_ERROR(Status))
        return Status;

    Status = uefi_call_wrapper(
        File->GetInfo,
        4,
        File,
        &gEfiFileInfoGuid,
        &InfoSize,
        Info
    );
    if (EFI_ERROR(Status))
        return Status;

    *Size = Info->FileSize;

    Status = uefi_call_wrapper(
        ST->BootServices->AllocatePool,
        3,
        EfiLoaderData,
        *Size,
        Buffer
    );
    if (EFI_ERROR(Status))
        return Status;

    Status = uefi_call_wrapper(
        File->Read,
        3,
        File,
        Size,
        *Buffer
    );

    return Status;
}

EFI_STATUS LoadKernelELF(
    EFI_SYSTEM_TABLE *ST,
    VOID *KernelImage,
    UINTN KernelImageSize,
    UINT64 *EntryPoint
)
{
    Elf64_Ehdr *Ehdr = (Elf64_Ehdr*)KernelImage;

    if (Ehdr->e_ident[0] != 0x7F ||
        Ehdr->e_ident[1] != 'E'  ||
        Ehdr->e_ident[2] != 'L'  ||
        Ehdr->e_ident[3] != 'F')
        return EFI_LOAD_ERROR;

    if (Ehdr->e_phoff >= KernelImageSize ||
        Ehdr->e_phoff + (Ehdr->e_phnum * sizeof(Elf64_Phdr)) > KernelImageSize) {
        Print(L"[LOADER] Invalid program header table offset\n");
        return EFI_LOAD_ERROR;
    }

    Elf64_Phdr *Phdrs =
        (Elf64_Phdr*)((UINT8*)KernelImage + Ehdr->e_phoff);

    for (UINTN i = 0; i < Ehdr->e_phnum; i++) {
        Elf64_Phdr *Ph = &Phdrs[i];
        if (Ph->p_type != PT_LOAD)
            continue;

        if (Ph->p_offset >= KernelImageSize) {
            Print(L"[LOADER] Segment %lu: offset out of bounds\n", i);
            return EFI_LOAD_ERROR;
        }

        if (Ph->p_offset + Ph->p_filesz > KernelImageSize) {
            Print(L"[LOADER] Segment %lu: file size exceeds image boundary\n", i);
            return EFI_LOAD_ERROR;
        }

        if (Ph->p_memsz < Ph->p_filesz) {
            Print(L"[LOADER] Segment %lu: memsz < filesz\n", i);
            return EFI_LOAD_ERROR;
        }

        if (Ph->p_filesz > KernelImageSize - Ph->p_offset) {
            Print(L"[LOADER] Segment %lu: arithmetic overflow detected\n", i);
            return EFI_LOAD_ERROR;
        }

        EFI_PHYSICAL_ADDRESS Addr =
            (EFI_PHYSICAL_ADDRESS)Ph->p_paddr;

        UINTN Pages =
            EFI_SIZE_TO_PAGES(Ph->p_memsz);

        EFI_STATUS Status = uefi_call_wrapper(
            ST->BootServices->AllocatePages,
            4,
            AllocateAddress,
            EfiLoaderData,
            Pages,
            &Addr
        );
        if (EFI_ERROR(Status)) {
            Print(L"[LOADER] Failed to allocate pages for segment %lu\n", i);
            return Status;
        }

        CopyMem(
            (VOID*)Ph->p_paddr,
            (UINT8*)KernelImage + Ph->p_offset,
            Ph->p_filesz
        );

        SetMem(
            (VOID*)(Ph->p_paddr + Ph->p_filesz),
            Ph->p_memsz - Ph->p_filesz,
            0
        );

        Print(L"[LOADER] Loaded segment %lu: %lu bytes\n", i, Ph->p_filesz);
    }

    *EntryPoint = Ehdr->e_entry;
    return EFI_SUCCESS;
}

static EFI_STATUS LoadDriverModuleFile(
    EFI_SYSTEM_TABLE *ST,
    EFI_FILE_PROTOCOL *Root,
    const PRELOAD_FILE_SPEC *Spec,
    BOOT_INFO *BootInfo
)
{
    if (ST == NULL || Root == NULL || Spec == NULL || BootInfo == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    EFI_FILE_PROTOCOL *File = NULL;
    EFI_STATUS Status = uefi_call_wrapper(
        Root->Open,
        5,
        Root,
        &File,
        (CHAR16 *)Spec->Path,
        EFI_FILE_MODE_READ,
        0
    );

    if (EFI_ERROR(Status)) {
        if (!Spec->Required) {
            return EFI_SUCCESS;
        }
        Print(L"[LOADER] required module open failed: %s (%r)\n",
              Spec->Path,
              Status);
        return Status;
    }

    VOID *Buffer = NULL;
    UINTN Size = 0;
    Status = LoadFileToMemory(ST, File, &Buffer, &Size);
    uefi_call_wrapper(File->Close, 1, File);
    if (EFI_ERROR(Status)) {
        if (!Spec->Required) {
            return EFI_SUCCESS;
        }
        Print(L"[LOADER] required module read failed: %s (%r)\n",
              Spec->Path,
              Status);
        return Status;
    }

    if (Size == 0) {
        if (!Spec->Required) {
            return EFI_SUCCESS;
        }
        Print(L"[LOADER] required module is empty: %s\n", Spec->Path);
        return EFI_LOAD_ERROR;
    }

    if (BootInfo->LoadedFileCount >= MAX_LOADED_FILES) {
        return EFI_OUT_OF_RESOURCES;
    }

    UINTN idx = BootInfo->LoadedFileCount++;
    BootInfo->LoadedFiles[idx].Id = Spec->Id;
    BootInfo->LoadedFiles[idx].Reserved = 0;
    BootInfo->LoadedFiles[idx].PhysAddr =
        (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer;
    BootInfo->LoadedFiles[idx].Size = (uint64_t)Size;

    Print(L"[LOADER] module loaded: %s (%u bytes)\n", Spec->Path, (UINT32)Size);
    return EFI_SUCCESS;
}

static EFI_STATUS PreloadDriverModules(
    EFI_SYSTEM_TABLE *ST,
    EFI_FILE_PROTOCOL *Root,
    BOOT_INFO *BootInfo
)
{
    static PRELOAD_FILE_SPEC Specs[] = {
        { DRIVER_MODULE_ID_PCI, L"\\Kernel\\Driver\\PCI_Driver.ELF", TRUE },
        { DRIVER_MODULE_ID_FAT32, L"\\Kernel\\Driver\\FAT32_Driver.ELF", TRUE },
        { DRIVER_MODULE_ID_PS2, L"\\Kernel\\Driver\\PS2_Driver.ELF", TRUE },
        { DRIVER_MODULE_ID_DISPLAY_VIRTIO, L"\\Kernel\\Driver\\VirtIO_Driver.ELF", FALSE },
        { DRIVER_MODULE_ID_DISPLAY_INTEL_UHD_9TH, L"\\Kernel\\Driver\\Intel_UHD_Graphics_9TH_Driver.ELF", FALSE },
        { DRIVER_MODULE_ID_DISPLAY_IMPLUS_DISPLAY_GENERIC_DRIVER, L"\\Kernel\\Driver\\ImplusOS_Generic_Display_Driver.ELF", FALSE },
    };

    BootInfo->LoadedFileCount = 0;

    for (UINTN i = 0; i < (sizeof(Specs) / sizeof(Specs[0])); ++i) {
        EFI_STATUS Status = LoadDriverModuleFile(ST, Root, &Specs[i], BootInfo);
        if (EFI_ERROR(Status)) {
            return Status;
        }
    }

    return EFI_SUCCESS;
}

EFI_STATUS ExitBootServicesComplete(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *ST,
    BOOT_INFO *BootInfo
)
{
    EFI_STATUS Status;
    UINTN MapKey;
    UINTN BufferSize;

    while (1) {
        BufferSize = 0;
        Status = uefi_call_wrapper(
            ST->BootServices->GetMemoryMap,
            5,
            &BufferSize,
            NULL,
            &MapKey,
            &BootInfo->MemoryMapDescriptorSize,
            &BootInfo->MemoryMapDescriptorVersion
        );

        if (Status != EFI_BUFFER_TOO_SMALL)
            return Status;

        BufferSize +=
            BootInfo->MemoryMapDescriptorSize * 8;

        Status = uefi_call_wrapper(
            ST->BootServices->AllocatePool,
            3,
            EfiLoaderData,
            BufferSize,
            (VOID**)&BootInfo->MemoryMap
        );
        if (EFI_ERROR(Status))
            return Status;

        Status = uefi_call_wrapper(
            ST->BootServices->GetMemoryMap,
            5,
            &BufferSize,
            BootInfo->MemoryMap,
            &MapKey,
            &BootInfo->MemoryMapDescriptorSize,
            &BootInfo->MemoryMapDescriptorVersion
        );
        if (EFI_ERROR(Status))
            return Status;

        BootInfo->MemoryMapSize = BufferSize;

        Status = uefi_call_wrapper(
            ST->BootServices->ExitBootServices,
            2,
            ImageHandle,
            MapKey
        );

        if (Status == EFI_SUCCESS)
            break;

        uefi_call_wrapper(
            ST->BootServices->FreePool,
            1,
            BootInfo->MemoryMap
        );
    }

    return EFI_SUCCESS;
}

typedef void (*KernelEntryFn)(BOOT_INFO*);

EFI_STATUS EFIAPI efi_main(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *ST
)
{
    InitializeLib(ImageHandle, ST);

    EFI_STATUS Status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *KernelFile;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;

    VOID *KernelBuffer;
    UINTN KernelSize;
    UINT64 KernelEntry;

    BOOT_INFO BootInfo = {0};

    Print(L"[LOADER] start\n");

    Status = uefi_call_wrapper(
        ST->BootServices->HandleProtocol,
        3,
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID**)&LoadedImage
    );
    CHECK(Status, L"LoadedImage");

    Status = uefi_call_wrapper(
        ST->BootServices->HandleProtocol,
        3,
        LoadedImage->DeviceHandle,
        &gEfiSimpleFileSystemProtocolGuid,
        (VOID**)&Fs
    );
    CHECK(Status, L"SimpleFS");

    Status = uefi_call_wrapper(
        Fs->OpenVolume,
        2,
        Fs,
        &Root
    );
    CHECK(Status, L"OpenVolume");

    Status = uefi_call_wrapper(
        ST->BootServices->LocateProtocol,
        3,
        &gEfiGraphicsOutputProtocolGuid,
        NULL,
        (VOID**)&Gop
    );
    CHECK(Status, L"GOP");

    BootInfo.FrameBufferBase =
        Gop->Mode->FrameBufferBase;
    BootInfo.FrameBufferSize =
        (UINT32)Gop->Mode->FrameBufferSize;
    BootInfo.HorizontalResolution =
        Gop->Mode->Info->HorizontalResolution;
    BootInfo.VerticalResolution =
        Gop->Mode->Info->VerticalResolution;
    BootInfo.PixelsPerScanLine =
        Gop->Mode->Info->PixelsPerScanLine;
        
    Status = uefi_call_wrapper(
        Root->Open,
        5,
        Root,
        &KernelFile,
        L"\\Kernel\\Kernel_Main.ELF",
        EFI_FILE_MODE_READ,
        0
    );
    CHECK(Status, L"Open Kernel");

    Status = LoadFileToMemory(
        ST,
        KernelFile,
        &KernelBuffer,
        &KernelSize
    );
    CHECK(Status, L"Read Kernel");
    uefi_call_wrapper(KernelFile->Close, 1, KernelFile);
    
    Status = LoadKernelELF(
        ST,
        KernelBuffer,
        KernelSize,
        &KernelEntry
    );
    CHECK(Status, L"ELF Load");

    Status = PreloadDriverModules(ST, Root, &BootInfo);
    CHECK(Status, L"Preload Drivers");

    Print(L"[LOADER] Jumping to kernel\n");

    Status = ExitBootServicesComplete(
        ImageHandle,
        ST,
        &BootInfo
    );

    if (EFI_ERROR(Status))
        while (1);

    KernelEntryFn Entry =
        (KernelEntryFn)KernelEntry;

    Entry(&BootInfo);

    while (1);
}