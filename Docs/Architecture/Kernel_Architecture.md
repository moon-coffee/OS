# ImplusOS Kernel Architecture

## Scope
This document summarizes the current kernel structure for process execution, memory layout, and interrupt/syscall flow.

## Process Model
- Process state is managed by `Kernel/ProcessManager/ProcessManager_Create.c`.
- A process slot owns:
  - register save frame (`saved_rsp`, `saved_user_rsp`)
  - per-process page table (`cr3`)
  - kernel stack and user memory ranges
  - capability mask (`PROCESS_CAP_*`)
- Scheduling is cooperative with explicit yield points (`process_yield`) and syscall exit scheduling.
- Syscall entry/exit context frame format is defined in `Kernel/Syscall/Syscall_Main.h`.

## Memory Model
- Virtual ranges are defined in `Kernel/ProcessManager/ProcessManager.h`:
  - user code: `USER_CODE_BASE` .. `USER_CODE_LIMIT`
  - user heap: `USER_HEAP_BASE` .. `USER_HEAP_LIMIT`
  - user stack: `USER_STACK_BASE` .. `USER_STACK_TOP`
- Guard pages are installed for heap/stack boundaries.
- User buffer validation is enforced in syscall dispatch through:
  - `process_user_buffer_is_valid`
  - `process_user_cstring_length`

## Interrupt and Syscall Flow
- IDT setup: `Kernel/IDT/*`
- Syscall entry stubs: `Kernel/Syscall/Syscall_Entry.asm`
- Syscall dispatch core: `Kernel/Syscall/Syscall_Dispatch.c`
- File syscall backend: `Kernel/Syscall/Syscall_File.c`
- Input polling is integrated in syscall dispatch (`ps2_input_poll`) to keep event queues refreshed.

## Status and Error Policy
- Kernel returns signed `os_status_t` values (`Kernel/Common/Status.h`).
- `0` or positive values indicate success / non-error payloads.
- Negative values indicate errors and map to userland `os_errno`.
- Canonical mapping table: `Docs/Architecture/Status_Codes.md`.
