# ImplusOS | Important Information

## First Things First
- This repository may be deleted or made private in the future.
- Damage to hardware or software is not supported.
- You are responsible for any resulting damage.

## Current Feature Set
- UEFI bootloader path.
- Process manager and syscall dispatch.
- FAT32 file I/O syscall backend.
- PS/2 keyboard and mouse input path.
- Window manager drawing syscalls.
- PNG decoder user application sample.
- Display drivers: VirtIO GPU, Intel UHD Graphics 9th, generic framebuffer path.

## Current Constraints
- Verified operation is centered on QEMU + OVMF.
- Operation on physical hardware is not guaranteed.
- USB / network / audio drivers are not yet integrated.

## Syscall Error Handling
- Kernel APIs return `os_status_t` values.
- Negative return values are failures.
- Userland wrappers keep return values and update `os_errno`.
- Mapping table: `Docs/Architecture/Status_Codes.md`.

## Documentation Map
- Architecture overview: `Docs/Architecture/Kernel_Architecture.md`
- Config guide: `Docs/Architecture/Kernel_Config_Guide.md`
- Status code table: `Docs/Architecture/Status_Codes.md`
- API generation: `doxygen Doxyfile`

## License
- Follow the MIT License.
- No support is provided after distribution.
- You may use, modify, and redistribute under MIT terms.
