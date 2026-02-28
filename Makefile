.PHONY: all run clean image

ARCH := x86_64
CC   ?= x86_64-linux-gnu-gcc
CXX  ?= x86_64-linux-gnu-g++
LD   ?= x86_64-linux-gnu-ld
NASM ?= nasm

BUILD_DIR := Build
IMAGE_DIR := Image
IMAGE     := $(IMAGE_DIR)/disk.iso

OVMF_CODE := /usr/share/OVMF/OVMF_CODE_4M.fd

KERNEL_DIR   := Kernel
USERLAND_DIR := Userland

KERNEL_ELF        := $(BUILD_DIR)/Kernel/Kernel_Main.ELF
BOOTX64_EFI       := $(BUILD_DIR)/Loader/BOOTX64.EFI
USERLAND_INIT_ELF := $(BUILD_DIR)/Userland/Userland.ELF
USERLAND_APP_ELF  := $(BUILD_DIR)/Userland/SystemApps/UserApp.ELF
PCI_DRIVER_ELF    := $(BUILD_DIR)/Kernel/Drivers/PCI_Driver.ELF
FAT32_DRIVER_ELF  := $(BUILD_DIR)/Kernel/Drivers/FAT32_Driver.ELF
PS2_DRIVER_ELF    := $(BUILD_DIR)/Kernel/Drivers/PS2_Driver.ELF
VIRTIO_DRIVER_ELF := $(BUILD_DIR)/Kernel/Drivers/Display/VirtIO_Driver.ELF
INTEL_DRIVER_ELF  := $(BUILD_DIR)/Kernel/Drivers/Display/Intel_UHD_Graphics_9TH_Driver.ELF
GENERIC_DISPLAY_DRIVER_ELF := $(BUILD_DIR)/Kernel/Drivers/Display/ImplusOS_Generic_Display_Driver.ELF

KERNEL_CFLAGS := \
	-IKernel -IThirdParty \
	-ffreestanding -fno-stack-protector -fno-pic -fno-builtin \
	-mno-red-zone -nostdlib -nostartfiles -nodefaultlibs \
	-Wall -Wextra -Wtype-limits -Wconversion -Wsign-conversion -Wshadow \
	-MMD -MP

KERNEL_LDFLAGS := -T Kernel/Kernel_Main.ld -nostdlib --build-id=none

LOADER_CFLAGS := \
	-I/usr/include/efi \
	-I/usr/include/efi/x86_64 \
	-I/usr/include/efi/protocol \
	-ffreestanding -fpic -fshort-wchar -fno-stack-protector \
	-fno-builtin -mno-red-zone \
	-Wall -Wextra -DEFI_FUNCTION_WRAPPER

USERLAND_LDFLAGS     := -T Userland/Userland.ld -nostdlib --build-id=none
USERLAND_APP_LDFLAGS := -T Userland/Application/SystemApps/UserApp.ld -nostdlib --build-id=none
USERLAND_CFLAGS := \
	-ffreestanding -fno-stack-protector -fno-pic -fno-builtin \
	-mno-red-zone -nostdlib -nostartfiles -nodefaultlibs \
	-Wall -Wextra -Wtype-limits -Wconversion -Wsign-conversion -Wshadow \
	-MMD -MP

USERLAND_CXXFLAGS := \
	-ffreestanding -fno-stack-protector -fno-pic -fno-builtin \
	-mno-red-zone -nostdlib -nostartfiles -nodefaultlibs \
	-fno-exceptions -fno-rtti \
	-Wall -Wextra -MMD -MP

DRIVER_MODULE_CFLAGS := \
	-IKernel -IThirdParty \
	-ffreestanding -fno-stack-protector -fPIC -fno-builtin \
	-mno-red-zone -nostdlib -nostartfiles -nodefaultlibs \
	-Wall -Wextra -Wtype-limits -Wconversion -Wsign-conversion -Wshadow \
	-MMD -MP \
	-DIMPLUS_DRIVER_MODULE
DRIVER_MODULE_LDFLAGS := -nostdlib -shared -Wl,--build-id=none -Wl,-Bsymbolic -Wl,-e,driver_module_init

KERNEL_C_SRCS := \
	Kernel/Kernel_Main.c \
	Kernel/Memory/Memory_Main.c \
	Kernel/Memory/Other_Utils.c \
	Kernel/Memory/DMA_Memory.c \
	Kernel/Paging/Paging_Main.c \
	Kernel/SMP/SMP_Main.c \
	Kernel/IDT/IDT_Main.c \
	Kernel/IO/IO_Main.c \
	Kernel/GDT/GDT_Main.c \
	Kernel/ELF/ELF_Loader.c \
	Kernel/Drivers/DriverModule.c \
	Kernel/Drivers/FileSystem/FAT32/FAT32_Client.c \
	Kernel/Drivers/DriverSelect.c \
	Kernel/Drivers/Display/Display_Main.c \
	Kernel/Drivers/Display/ImplusOS_Generic/ImplusOS_Generic.c \
	Kernel/Drivers/PS2/PS2_Client.c \
	Kernel/Drivers/PCI/PCI_Client.c \
	Kernel/ProcessManager/ProcessManager_Create.c \
	Kernel/WindowManager/WindowManager.c \
	Kernel/Syscall/Syscall_Init.c \
	Kernel/Syscall/Syscall_File.c \
	Kernel/Syscall/Syscall_Dispatch.c

KERNEL_ASM_SRCS := \
	Kernel/Paging/Paging.asm \
	Kernel/GDT/GDT.asm \
	Kernel/IDT/IDT.asm \
	Kernel/Syscall/Syscall_Entry.asm

USERLAND_C_SRCS := \
	Userland/Userland.c \
	Userland/Syscalls.c

USERLAND_APP_C_SRCS := \
	Userland/Application/SystemApps/UApp_Main.c \
	Userland/Application/PNG_Decoder/PNG_Decoder.c \
	Userland/Syscalls.c

KERNEL_OBJS       := $(KERNEL_C_SRCS:%.c=$(BUILD_DIR)/%.o) \
                     $(KERNEL_ASM_SRCS:%.asm=$(BUILD_DIR)/%.o)
USERLAND_INIT_OBJS := $(USERLAND_C_SRCS:%.c=$(BUILD_DIR)/%.o)
USERLAND_APP_OBJS  := $(USERLAND_APP_C_SRCS:%.c=$(BUILD_DIR)/%.o)
DRIVER_MODULE_OBJS := \
	$(BUILD_DIR)/Modules/PCI_Module.o \
	$(BUILD_DIR)/Modules/FAT32_Module.o \
	$(BUILD_DIR)/Modules/PS2_Module.o \
	$(BUILD_DIR)/Modules/VirtIO_Module.o \
	$(BUILD_DIR)/Modules/Intel_Module.o \
	$(BUILD_DIR)/Modules/ImplusOS_Generic_Display_Driver.o

all: $(BOOTX64_EFI) \
     $(KERNEL_ELF) \
     $(USERLAND_INIT_ELF) \
     $(USERLAND_APP_ELF) \
     $(PCI_DRIVER_ELF) \
     $(FAT32_DRIVER_ELF) \
     $(PS2_DRIVER_ELF) \
     $(VIRTIO_DRIVER_ELF) \
     $(INTEL_DRIVER_ELF) \
     $(GENERIC_DISPLAY_DRIVER_ELF)

$(BUILD_DIR)/Loader/Loader.o: BootLoader/Loader.c
	mkdir -p $(dir $@)
	$(CC) $(LOADER_CFLAGS) -c $< -o $@

$(BOOTX64_EFI): $(BUILD_DIR)/Loader/Loader.o
	mkdir -p $(dir $@)
	$(LD) -nostdlib -znocombreloc \
		-T /usr/lib/elf_x86_64_efi.lds \
		-shared -Bsymbolic \
		/usr/lib/crt0-efi-x86_64.o \
		$< \
		/usr/lib/libefi.a \
		/usr/lib/libgnuefi.a \
		-o $@.so
	objcopy -j .text -j .sdata -j .data -j .dynamic \
		-j .dynsym -j .rel -j .rela -j .reloc \
		--target=efi-app-x86_64 $@.so $@
	rm -f $@.so

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(KERNEL_CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.asm
	mkdir -p $(dir $@)
	$(NASM) -f elf64 $< -o $@

$(KERNEL_ELF): $(KERNEL_OBJS)
	mkdir -p $(dir $@)
	$(LD) $(KERNEL_LDFLAGS) $^ -o $@

$(BUILD_DIR)/Userland/%.o: Userland/%.c
	mkdir -p $(dir $@)
	$(CC) $(USERLAND_CFLAGS) -c $< -o $@

$(BUILD_DIR)/Userland/%.o: Userland/%.cpp
	mkdir -p $(dir $@)
	$(CXX) $(USERLAND_CXXFLAGS) -c $< -o $@

$(USERLAND_INIT_ELF): $(USERLAND_INIT_OBJS)
	mkdir -p $(dir $@)
	$(LD) $(USERLAND_LDFLAGS) $^ -o $@

$(USERLAND_APP_ELF): $(USERLAND_APP_OBJS)
	mkdir -p $(dir $@)
	$(LD) $(USERLAND_APP_LDFLAGS) $^ -o $@

$(BUILD_DIR)/Modules/PCI_Module.o: Kernel/Drivers/PCI/PCI_Main.c
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/Modules/FAT32_Module.o: Kernel/Drivers/FileSystem/FAT32/FAT32_Main.c
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/Modules/PS2_Module.o: Kernel/Drivers/PS2/PS2_Input.c
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/Modules/VirtIO_Module.o: Kernel/Drivers/Display/VirtIO/VirtIO.c
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/Modules/Intel_Module.o: Kernel/Drivers/Display/Intel_UHD_Graphics_9TH/Intel_UHD_Graphics_9TH.c
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/Modules/ImplusOS_Generic_Display_Driver.o: Kernel/Drivers/Display/ImplusOS_Generic/ImplusOS_Generic.c
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_CFLAGS) -c $< -o $@

$(PCI_DRIVER_ELF): $(BUILD_DIR)/Modules/PCI_Module.o
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_LDFLAGS) $^ -o $@

$(FAT32_DRIVER_ELF): $(BUILD_DIR)/Modules/FAT32_Module.o
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_LDFLAGS) $^ -o $@

$(PS2_DRIVER_ELF): $(BUILD_DIR)/Modules/PS2_Module.o
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_LDFLAGS) $^ -o $@

$(VIRTIO_DRIVER_ELF): $(BUILD_DIR)/Modules/VirtIO_Module.o
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_LDFLAGS) $^ -o $@

$(INTEL_DRIVER_ELF): $(BUILD_DIR)/Modules/Intel_Module.o
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_LDFLAGS) $^ -o $@

$(GENERIC_DISPLAY_DRIVER_ELF): $(BUILD_DIR)/Modules/ImplusOS_Generic_Display_Driver.o
	mkdir -p $(dir $@)
	$(CC) $(DRIVER_MODULE_LDFLAGS) $^ -o $@

image: all
	@mkdir -p $(IMAGE_DIR)
	@dd if=/dev/zero of=$(IMAGE) bs=1M count=128 2>/dev/null
	@parted $(IMAGE) --script mklabel gpt mkpart ESP fat32 1MiB 100% set 1 esp on 2>/dev/null
	@$(MAKE) __mount_image

__mount_image:
	@MOUNT_POINT=$$(mktemp -d); \
	LOOP_DEVICE=$$(sudo losetup -Pf --show $(IMAGE)) || exit 1; \
	trap "sudo losetup -d $$LOOP_DEVICE 2>/dev/null; rmdir $$MOUNT_POINT 2>/dev/null" EXIT; \
	sudo mkfs.fat -F32 $${LOOP_DEVICE}p1 || exit 1; \
	sudo mount $${LOOP_DEVICE}p1 $$MOUNT_POINT || exit 1; \
	sudo mkdir -p $$MOUNT_POINT/EFI/BOOT $$MOUNT_POINT/Kernel/Driver $$MOUNT_POINT/Userland/SystemApps; \
	sudo cp $(BOOTX64_EFI) $$MOUNT_POINT/EFI/BOOT/BOOTX64.EFI; \
	sudo cp $(KERNEL_ELF) $$MOUNT_POINT/Kernel/Kernel_Main.ELF; \
	sudo cp $(USERLAND_INIT_ELF) $$MOUNT_POINT/Userland/Userland.ELF; \
	sudo cp $(USERLAND_APP_ELF) $$MOUNT_POINT/Userland/SystemApps/UserApp.ELF; \
	sudo cp $(PCI_DRIVER_ELF) $(FAT32_DRIVER_ELF) $(PS2_DRIVER_ELF) $(VIRTIO_DRIVER_ELF) $(INTEL_DRIVER_ELF) $(GENERIC_DISPLAY_DRIVER_ELF) $$MOUNT_POINT/Kernel/Driver/; \
	[ -f Kernel/FILE.TXT ] && sudo cp Kernel/FILE.TXT $$MOUNT_POINT/FILE.TXT; \
	[ -f Userland/image.png ] && sudo cp Userland/image.png $$MOUNT_POINT/Userland/image.png; \
	sync; \
	sudo umount $$MOUNT_POINT || exit 1;

ISO_ROOT := $(IMAGE_DIR)/iso_root
ESP_IMG  := $(IMAGE_DIR)/esp.iso

image_esp: all
	@mkdir -p $(ISO_ROOT)/EFI/BOOT $(ISO_ROOT)/Kernel/Driver $(ISO_ROOT)/Userland/SystemApps
	@cp $(BOOTX64_EFI) $(ISO_ROOT)/EFI/BOOT/BOOTX64.EFI
	@cp $(KERNEL_ELF) $(ISO_ROOT)/Kernel/Kernel_Main.ELF
	@cp $(USERLAND_INIT_ELF) $(ISO_ROOT)/Userland/Userland.ELF
	@cp $(USERLAND_APP_ELF) $(ISO_ROOT)/Userland/SystemApps/UserApp.ELF
	@cp $(PCI_DRIVER_ELF) $(FAT32_DRIVER_ELF) $(PS2_DRIVER_ELF) $(VIRTIO_DRIVER_ELF) $(INTEL_DRIVER_ELF) $(GENERIC_DISPLAY_DRIVER_ELF) $(ISO_ROOT)/Kernel/Driver/
	@[ -f Kernel/FILE.TXT ] && cp Kernel/FILE.TXT $(ISO_ROOT)/FILE.TXT || true
	@[ -f Userland/image.png ] && cp Userland/image.png $(ISO_ROOT)/Userland/image.png || true
	@$(MAKE) __create_esp_iso

__create_esp_iso:
	@ESP_MOUNT=$$(mktemp -d); \
	trap "sudo umount $$ESP_MOUNT 2>/dev/null; rmdir $$ESP_MOUNT 2>/dev/null" EXIT; \
	dd if=/dev/zero of=$(ESP_IMG) bs=1M count=64 2>/dev/null; \
	mkfs.fat -F32 $(ESP_IMG) 2>/dev/null; \
	sudo mount $(ESP_IMG) $$ESP_MOUNT || exit 1; \
	sudo mkdir -p $$ESP_MOUNT/EFI/BOOT; \
	sudo cp $(BOOTX64_EFI) $$ESP_MOUNT/EFI/BOOT/BOOTX64.EFI; \
	sync; \
	sudo umount $$ESP_MOUNT || exit 1; \
	xorriso -as mkisofs -R -J -V "MY_OS" -o $(IMAGE) -eltorito-alt-boot -e esp.iso -no-emul-boot $(ISO_ROOT) 2>/dev/null;

run: image
	@qemu-system-x86_64 -m 512M \
  		-drive if=pflash,format=raw,readonly=on,file=${OVMF_CODE} \
  		-drive format=raw,file=${IMAGE} \
  		-serial stdio \
		-vga none \
		-device virtio-gpu
	  	
clean:
	@rm -rf $(BUILD_DIR) $(IMAGE_DIR)

-include $(KERNEL_OBJS:.o=.d)
-include $(USERLAND_INIT_OBJS:.o=.d)
-include $(USERLAND_APP_OBJS:.o=.d)
-include $(DRIVER_MODULE_OBJS:.o=.d)
