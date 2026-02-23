BITS 64

global load_idt
global isr_default
global isr_page_fault
global isr_double_fault
global page_fault_resume_user

extern double_fault_handler
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
    cli

    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, rsp
    mov rcx, cr2

    call page_fault_handler
.pf_hang:
    hlt
    jmp .pf_hang

isr_double_fault:
    cli
    mov rdi, rsp
    call double_fault_handler

page_fault_resume_user:
    mov r10, rsi
    mov r8, rdi

    mov rax, [r8 + 0]
    mov rdx, [r8 + 8]
    mov rsi, [r8 + 16]
    mov rdi, [r8 + 24]
    mov r9,  [r8 + 40]
    mov r12, [r8 + 56]
    mov r13, [r8 + 64]
    mov r14, [r8 + 72]
    mov r15, [r8 + 80]
    mov rbx, [r8 + 88]
    mov rbp, [r8 + 96]
    mov rcx, [r8 + 104]
    mov r11, [r8 + 112]

    mov rsp, r10
    mov r10, [r8 + 48]
    mov r8,  [r8 + 32]
    o64 sysret

load_idt:
    cli
    lidt [rdi]
    sti
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
