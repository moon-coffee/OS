# ImplusOS Repo

## Overview
ImplusOS is a hobby OS tree with a UEFI boot path, a small kernel, and userland samples.

- Build is intended for interactive Linux environments.
- Target host platform is Linux (Ubuntu and similar distributions).

<img width="960" height="540" alt="ImplusOS" src="https://github.com/moon-coffee/ImplusOS/blob/7d2ea7a94544d773c83d8c35323cbd7ac8e2e37d/Docs/Image/ImplusOS.png" />

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Static Badge](https://img.shields.io/badge/Repo-3.6MB-blue)
![Static Badge](https://img.shields.io/badge/Implus-OS-blue)

## Build
1. Install toolchains:
```bash
sudo apt install -y build-essential pkg-config git make cmake
sudo apt install -y gcc-multilib g++-multilib
sudo apt install -y gcc-x86-64-linux-gnu g++-x86-64-linux-gnu
sudo apt install -y nasm
sudo apt install -y binutils
sudo apt install -y gnu-efi
sudo apt install -y parted
sudo apt install -y qemu-system-x86
sudo apt install -y gdb
sudo apt install -y dosfstools
sudo apt install -y xorriso
sudo apt install -y mtools
sudo apt install -y util-linux
```
2. Build and run:
```bash
make
make run
```

## Notes
* This project assumes building in an interactive Linux environment (such as a local terminal).
* You may not be able to build successfully in non-interactive environments (CI/CD, restricted container environments, etc.).

## Current Feature Set
- UEFI bootloader path.
- Process manager and syscall dispatch.
- FAT32 file I/O syscall backend.
- PS/2 keyboard and mouse input path.
- Window manager drawing syscalls.
- PNG decoder user application sample.
- Display drivers: VirtIO GPU, Intel UHD Graphics 9th, generic framebuffer path.

## Current Constraints
- Verified operation is QEMU + OVMF centric.
- Physical hardware operation is not guaranteed.
- USB / network / audio drivers are not yet integrated.

## Error and Status Contract
- Kernel subsystems return `os_status_t` (`Kernel/Common/Status.h`).
- Negative status values are errors.
- Userland wrappers expose `os_errno` with status-to-errno conversion.
- Mapping table: `Docs/Architecture/Status_Codes.md`.

## Documentation
- User guidance:
  - `Docs/ForUsers/ForUsers_English.md`
  - `Docs/ForUsers/ForUsers_Japanese.md`
- Architecture references:
  - `Docs/Architecture/Kernel_Architecture.md`
  - `Docs/Architecture/Kernel_Config_Guide.md`
  - `Docs/Architecture/Status_Codes.md`
- API docs generation:
  - `doxygen Doxyfile`

## License
MIT.
