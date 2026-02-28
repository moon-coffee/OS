# Status Codes and errno Mapping

Kernel subsystems return `os_status_t` from `Kernel/Common/Status.h`.

## Rules
- `status >= 0`: success or non-error payload.
- `status < 0`: failure.
- Userland wrapper (`Userland/Syscalls.c`) keeps syscall return value and also updates `os_errno`.

## Mapping Table

| os_status_t | Symbol | errno |
| --- | --- | --- |
| `0` | `OS_STATUS_OK` | `0` |
| `-22` | `OS_STATUS_INVALID_ARG` | `22` |
| `-2` | `OS_STATUS_NOT_FOUND` | `2` |
| `-13` | `OS_STATUS_ACCESS_DENIED` | `13` |
| `-24` | `OS_STATUS_LIMIT_REACHED` | `24` |
| `-5` | `OS_STATUS_IO_ERROR` | `5` |
| `-14` | `OS_STATUS_FAULT` | `14` |
| `-95` | `OS_STATUS_NOT_SUPPORTED` | `95` |
| `-255` | `OS_STATUS_INTERNAL` | `255` |

## Logging Format
- Syscall layer: `[OS] [SYSCALL] fn=... status=<number> (<symbol>) reason=...`
- File layer: `[OS] [FILE] fn=... status=<number> (<symbol>) reason=...`
