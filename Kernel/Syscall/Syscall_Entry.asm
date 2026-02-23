BITS 64
section .text
global syscall_entry
extern syscall_dispatch

syscall_entry:
    swapgs
    
    mov [gs:0], rsp
    
    mov rsp, [gs:8]
    
    and rsp, ~0xF
    sub rsp, 8

    ; Saved frame layout (rsp = index 0):
    ; 0:rax 1:rdx 2:rsi 3:rdi 4:r8 5:r9 6:r10 7:r12
    ; 8:r13 9:r14 10:r15 11:rbx 12:rbp 13:rcx 14:r11
    push r11
    push rcx
    push rbp
    push rbx
    push r15
    push r14
    push r13
    push r12
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rdx
    push rax
    
    mov rdi, rsp
    mov rsi, rax
    mov rdx, [rsp + 24]
    mov rcx, [rsp + 16]
    mov r8, [rsp + 8]
    mov r9, [rsp + 48]
    
    call syscall_dispatch
    
    mov rsp, rax
    
    pop rax
    pop rdx
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r12
    pop r13
    pop r14
    pop r15
    pop rbx
    pop rbp
    pop rcx
    pop r11

    mov rsp, [gs:0]
    
    swapgs
    o64 sysret

section .note.GNU-stack noalloc noexec nowrite progbits
