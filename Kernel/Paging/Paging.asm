BITS 64
global paging_init_asm

SECTION .bss
align 4096
pml4:
    resq 512
pdpt:
    resq 512
pd:
    resq 512

SECTION .text
paging_init_asm:
    mov rax, pdpt
    or  rax, 0b111
    mov [pml4], rax

    mov rax, pd
    or  rax, 0b111
    mov [pdpt], rax

    mov rax, cr4
    or  rax, 1 << 5
    mov cr4, rax

    xor rcx, rcx
.fill_pd:
    mov rax, rcx
    shl rax, 21
    or  rax, (1 << 7) | 0b111
    mov [pd + rcx*8], rax
    inc rcx
    cmp rcx, 512
    jne .fill_pd

    mov rax, pml4
    mov cr3, rax

    mov rax, cr0
    bts rax, 31
    mov cr0, rax

    ret

section .note.GNU-stack noalloc noexec nowrite progbits
