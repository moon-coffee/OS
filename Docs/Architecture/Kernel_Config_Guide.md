# Kernel Config Guide

## Purpose
`Kernel/KernelConfig.h` centralizes build-time limits that affect process, file, and window manager capacity.

## Tunables
- `PROCESS_MAX_COUNT_CONFIG` (alias: `OS_CONFIG_PROCESS_MAX_COUNT`)
  - Controls maximum process slots.
  - Impacts process table allocation size and scheduler scan cost.
- `FILE_MAX_FD_CONFIG` (alias: `OS_CONFIG_FILE_MAX_FD`)
  - Controls maximum open file slots in kernel.
- `FILE_MAX_DIR_HANDLE_CONFIG` (alias: `OS_CONFIG_FILE_MAX_DIR_HANDLE`)
  - Controls maximum directory handle slots.
- `WM_MAX_WINDOWS_CONFIG` (alias: `OS_CONFIG_WM_MAX_WINDOWS`)
  - Controls maximum active windows.

## Validation Rules
- Compile-time range checks are enforced in `Kernel/KernelConfig.h`.
- Invalid values fail the build early with `#error`.
- `FILE_MAX_DIR_HANDLE_CONFIG` must be less than or equal to `FILE_MAX_FD_CONFIG`.

## Change Workflow
1. Update the target config macro (or pass it from build flags).
2. Rebuild and verify kernel boot.
3. Run file/window/process stress paths to confirm limits:
   - process creation saturation
   - file open/close saturation
   - window creation saturation

## Operational Notes
- Larger values increase memory footprint (tables are statically sized in several subsystems).
- Keep values close to expected workloads to reduce boot-time memory pressure.
