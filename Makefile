.PHONY: all run clean image

ARCH := x86_64
CC   ?= x86_64-linux-gnu-gcc
LD   ?= x86_64-linux-gnu-ld
NASM ?= nasm

BUILD_DIR := Build
IMAGE_DIR := Image
IMAGE     := $(IMAGE_DIR)/disk.iso

OVMF_CODE := /usr/share/OVMF/OVMF_CODE_4M.fd

KERNEL_DIR   := Kernel
USERLAND_DIR := Userland

KERNEL_ELF  := $(BUILD_DIR)/Kernel/Kernel_Main.ELF
BOOTX64_EFI := $(BUILD_DIR)/Loader/BOOTX64.EFI
USERLAND_ELF := $(BUILD_DIR)/Userland/Userland.ELF

KERNEL_CFLAGS := \
	-IKernel -IThirdParty \
	-ffreestanding -fno-stack-protector -fno-pic -fno-builtin \
	-mno-red-zone -nostdlib -nostartfiles -nodefaultlibs \
	-Wall -Wextra -MMD -MP

KERNEL_LDFLAGS := -T Kernel/Kernel_Main.ld -nostdlib --build-id=none

LOADER_CFLAGS := \
	-I/usr/include/efi \
	-I/usr/include/efi/x86_64 \
	-I/usr/include/efi/protocol \
	-ffreestanding -fpic -fshort-wchar -fno-stack-protector \
	-fno-builtin -mno-red-zone \
	-Wall -Wextra -DEFI_FUNCTION_WRAPPER

USERLAND_LDFLAGS := -T Userland/Userland.ld -nostdlib --build-id=none

KERNEL_C_SRCS := \
	Kernel/Kernel_Main.c \
	Kernel/Memory/Memory_Main.c \
	Kernel/Memory/Memory_Utils.c \
	Kernel/Memory/Other_Utils.c \
	Kernel/Paging/Paging_Main.c \
	Kernel/IDT/IDT_Main.c \
	Kernel/IO/IO_Main.c \
	Kernel/GDT/GDT_Main.c \
	Kernel/Drivers/FileSystem/FAT32/FAT32_Main.c \
	Kernel/Syscall/Syscall_Init.c \
	Kernel/Syscall/Syscall_Dispatch.c \
	Kernel/FrameBuffer/FrameBuffer_Main.c

KERNEL_ASM_SRCS := \
	Kernel/Paging/Paging.asm \
	Kernel/GDT/GDT.asm \
	Kernel/IDT/IDT.asm \
	Kernel/Syscall/Syscall_Entry.asm

USERLAND_ASM_SRC := Userland/Userland.asm

KERNEL_OBJS := \
	$(KERNEL_C_SRCS:%.c=$(BUILD_DIR)/%.o) \
	$(KERNEL_ASM_SRCS:%.asm=$(BUILD_DIR)/%.o)

LOADER_OBJ := $(BUILD_DIR)/Loader/Loader.o
USERLAND_OBJ := $(BUILD_DIR)/Userland/Userland.o

all: $(BOOTX64_EFI) $(KERNEL_ELF) $(USERLAND_ELF)

$(BUILD_DIR)/Loader/Loader.o: BootLoader/Loader.c
	mkdir -p $(dir $@)
	$(CC) $(LOADER_CFLAGS) -c $< -o $@

$(BOOTX64_EFI): $(LOADER_OBJ)
	mkdir -p $(dir $@)
	$(LD) -nostdlib -znocombreloc \
		-T /usr/lib/elf_x86_64_efi.lds \
		-shared -Bsymbolic \
		/usr/lib/crt0-efi-x86_64.o \
		$< \
		/usr/lib/libefi.a \
		/usr/lib/libgnuefi.a \
		-o $@.so

	objcopy \
		-j .text -j .sdata -j .data -j .dynamic \
		-j .dynsym -j .rel -j .rela -j .reloc \
		--target=efi-app-x86_64 \
		$@.so $@

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

$(USERLAND_OBJ): $(USERLAND_ASM_SRC)
	mkdir -p $(dir $@)
	$(NASM) -f elf64 $< -o $@

$(USERLAND_ELF): $(USERLAND_OBJ)
	mkdir -p $(dir $@)
	$(LD) $(USERLAND_LDFLAGS) $< -o $@

image: all
	mkdir -p $(IMAGE_DIR)
	dd if=/dev/zero of=$(IMAGE) bs=1M count=128
	parted $(IMAGE) --script \
		mklabel gpt \
		mkpart ESP fat32 1MiB 100% \
		set 1 esp on

	sudo losetup -Pf --show $(IMAGE) | while read LOOP; do \
		sudo mkfs.fat -F32 $${LOOP}p1; \
		sudo mount $${LOOP}p1 /mnt; \
		\
		sudo mkdir -p /mnt/EFI/BOOT; \
		sudo cp $(BOOTX64_EFI) /mnt/EFI/BOOT/BOOTX64.EFI; \
		\
		sudo mkdir -p /mnt/Kernel; \
		sudo cp $(KERNEL_ELF) /mnt/Kernel/Kernel_Main.ELF; \
		\
		sudo cp $(USERLAND_ELF) /mnt/URLD.ELF; \
		\
		sudo cp Kernel/FILE.TXT /mnt/FILE.TXT; \
		sync; \
		sudo umount /mnt; \
		sudo losetup -d $$LOOP; \
	done

run: image
	qemu-system-x86_64 \
		-m 512M \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive format=raw,file=$(IMAGE) \
		-serial stdio

clean:
	rm -rf $(BUILD_DIR) $(IMAGE_DIR)

-include $(KERNEL_OBJS:.o=.d)
