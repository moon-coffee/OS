BITS 64
section .text
global syscall_entry
extern syscall_dispatch

syscall_entry:
    swapgs

    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    ; Syscall ABI -> SysV ABI
    ; rax=num, rdi=arg1, rsi=arg2, rdx=arg3, r10=arg4, r8=arg5, r9=arg6
    mov r11, rdi        ; save arg1
    mov rdi, rax        ; num
    mov rax, rsi        ; save arg2
    mov rsi, r11        ; arg1
    mov r11, rdx        ; save arg3
    mov rdx, rax        ; arg2
    mov rcx, r11        ; arg3
    mov r8,  r10        ; arg4
    ; r9 already arg5
    call syscall_dispatch

    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    swapgs
    sysret

section .note.GNU-stack noalloc noexec nowrite progbits
