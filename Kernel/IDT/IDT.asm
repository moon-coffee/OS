BITS 64

global load_idt
global isr_default
global isr_page_fault
global isr_double_fault
global isr_nmi
global isr_general_protection
global isr_machine_check
global page_fault_resume_user

extern double_fault_handler
extern nmi_handler
extern general_protection_fault_handler
extern machine_check_handler
extern page_fault_handler

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
    mov rdi, [rsp]       ; error_code
    mov rsi, [rsp + 8]   ; rip
    mov rdx, rsp         ; fault stack pointer
    mov rcx, cr2
    mov r8, rbp
    call page_fault_handler
    test eax, eax
    jz .pf_resume
.pf_hang:
    hlt
    jmp .pf_hang
.pf_resume:
    add rsp, 8
    iretq

isr_double_fault:
    cli
    mov rdi, [rsp]       ; error_code
    mov rsi, [rsp + 8]   ; rip
    mov rdx, rsp         ; fault stack pointer
    mov rcx, rbp
    call double_fault_handler
.df_hang:
    hlt
    jmp .df_hang

isr_nmi:
    cli
    mov rdi, [rsp]       ; rip
    mov rsi, rsp         ; fault stack pointer
    mov rdx, rbp
    call nmi_handler
.nmi_hang:
    hlt
    jmp .nmi_hang

isr_general_protection:
    cli
    mov rdi, [rsp]       ; error_code
    mov rsi, [rsp + 8]   ; rip
    mov rdx, rsp         ; fault stack pointer
    mov rcx, rbp
    call general_protection_fault_handler
.gp_hang:
    hlt
    jmp .gp_hang

isr_machine_check:
    cli
    mov rdi, [rsp]       ; rip
    mov rsi, rsp         ; fault stack pointer
    mov rdx, rbp
    call machine_check_handler
.mce_hang:
    hlt
    jmp .mce_hang

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
