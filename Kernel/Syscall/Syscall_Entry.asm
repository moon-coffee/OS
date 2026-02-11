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

    mov r11, rdi
    mov rdi, rax
    mov rax, rsi
    mov rsi, r11
    mov r11, rdx
    mov rdx, rax
    mov rcx, r11
    mov r8,  r10
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
