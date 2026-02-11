BITS 64

global load_idt
global isr_default
global isr_page_fault

extern page_fault_handler

SECTION .data

SECTION .text

isr_default:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov al, 0x20
    out 0x20, al

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    iretq

isr_page_fault:
    mov rbx, rsp

    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rdi, [rbx + 0]
    mov rsi, [rbx + 8]
    mov rdx, [rbx + 32]
    mov rax, cr2
    mov rcx, rax

    sub rsp, 8
    call page_fault_handler
    add rsp, 8

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    iretq

load_idt:
    cli
    lidt [rdi]
    sti
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
