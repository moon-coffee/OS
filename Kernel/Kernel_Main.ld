OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kernel_main)

SECTIONS
{
    . = 0x00100000;

    _kernel_start = .;
    
    .text :
    {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : {
        *(.rodata*)
    }

    .data ALIGN(4K) : {
        *(.data*)
    }

    .bss ALIGN(4K) : {
        *(COMMON)
        *(.bss*)
    }

    . = ALIGN(16);
    _stack_bottom = .;
    . += 0x8000;
    _stack_top = .;

    _kernel_end = .;
}
