#include "ELF_Loader.h"

#include "../Drivers/FileSystem/FAT32/FAT32_Main.h"
#include "../Memory/Memory_Main.h"
#include "../Memory/Other_Utils.h"
#include "../Serial.h"

#include <stddef.h>
#include <stdint.h>

#define ELF_MAGIC_0 0x7F
#define ELF_MAGIC_1 'E'
#define ELF_MAGIC_2 'L'
#define ELF_MAGIC_3 'F'

#define ET_DYN 3
#define PT_LOAD 1

#define SHT_RELA 4
#define SHN_UNDEF 0

#define R_X86_64_NONE      0
#define R_X86_64_64        1
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8

#define ELF_PAGE_SIZE 4096ULL

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t r_addend;
} Elf64_Rela;

typedef struct {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

static inline uint32_t elf64_r_type(uint64_t info)
{
    return (uint32_t)(info & 0xFFFFFFFFu);
}

static inline uint32_t elf64_r_sym(uint64_t info)
{
    return (uint32_t)(info >> 32);
}

static char to_upper_ascii(char c)
{
    if (c >= 'a' && c <= 'z') {
        return (char)(c - ('a' - 'A'));
    }
    return c;
}

static uint64_t align_down_u64(uint64_t value, uint64_t align)
{
    if (align == 0) {
        return value;
    }
    return value & ~(align - 1u);
}

static uint64_t align_up_u64(uint64_t value, uint64_t align)
{
    if (align == 0) {
        return value;
    }
    return (value + align - 1u) & ~(align - 1u);
}

static bool range_in_file(uint64_t file_size, uint64_t offset, uint64_t size)
{
    if (offset > file_size) {
        return false;
    }
    return size <= (file_size - offset);
}

static bool in_vaddr_range(uint64_t start,
                           uint64_t size,
                           uint64_t min_vaddr,
                           uint64_t max_vaddr)
{
    if (size == 0) {
        return false;
    }
    if (start < min_vaddr) {
        return false;
    }
    if (start >= max_vaddr) {
        return false;
    }
    if (size > (max_vaddr - start)) {
        return false;
    }
    return true;
}

static bool runtime_range_ok(uint64_t image_start,
                             uint64_t image_span,
                             uint64_t addr,
                             uint64_t size)
{
    if (size == 0 || addr < image_start) {
        return false;
    }
    uint64_t offset = addr - image_start;
    if (offset > image_span) {
        return false;
    }
    return size <= (image_span - offset);
}

bool elf_loader_path_to_fat83(const char *path, char out_name[12])
{
    if (!path || !out_name) {
        return false;
    }

    for (int i = 0; i < 11; ++i) {
        out_name[i] = ' ';
    }
    out_name[11] = '\0';

    int name_len = 0;
    int ext_len = 0;
    int in_ext = 0;

    for (const char *p = path; *p; ++p) {
        char c = *p;

        if (c == '/') {
            name_len = 0;
            ext_len = 0;
            in_ext = 0;
            for (int i = 0; i < 11; ++i) {
                out_name[i] = ' ';
            }
            continue;
        }

        if (c == '.') {
            if (in_ext) {
                return false;
            }
            in_ext = 1;
            continue;
        }

        c = to_upper_ascii(c);

        if (!in_ext) {
            if (name_len >= 8) {
                return false;
            }
            out_name[name_len++] = c;
        } else {
            if (ext_len >= 3) {
                return false;
            }
            out_name[8 + ext_len++] = c;
        }
    }

    return name_len > 0;
}

bool elf_loader_load_from_fat83(const char fat_name[12],
                                const elf_load_policy_t *policy,
                                uint64_t *entry_out)
{
    if (!fat_name || !policy || !entry_out) {
        return false;
    }

    FAT32_FILE file;
    if (!fat32_find_file(fat_name, &file)) {
        serial_write_string("[OS] [ELF] file not found\n");
        return false;
    }

    if (file.size == 0 || (uint64_t)file.size > policy->max_file_size) {
        serial_write_string("[OS] [ELF] invalid size\n");
        return false;
    }

    uint8_t *buffer = (uint8_t *)kmalloc(file.size);
    if (!buffer) {
        serial_write_string("[OS] [ELF] out of memory\n");
        return false;
    }

    if (!fat32_read_file(&file, buffer)) {
        serial_write_string("[OS] [ELF] read failed\n");
        kfree(buffer);
        return false;
    }

    if ((uint64_t)file.size < sizeof(Elf64_Ehdr)) {
        serial_write_string("[OS] [ELF] header too small\n");
        kfree(buffer);
        return false;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buffer;
    if (ehdr->e_ident[0] != ELF_MAGIC_0 ||
        ehdr->e_ident[1] != ELF_MAGIC_1 ||
        ehdr->e_ident[2] != ELF_MAGIC_2 ||
        ehdr->e_ident[3] != ELF_MAGIC_3) {
        serial_write_string("[OS] [ELF] invalid magic\n");
        kfree(buffer);
        return false;
    }

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr) || ehdr->e_phnum == 0) {
        serial_write_string("[OS] [ELF] invalid phdr info\n");
        kfree(buffer);
        return false;
    }

    uint64_t phdr_table_bytes =
        (uint64_t)ehdr->e_phnum * (uint64_t)ehdr->e_phentsize;
    if (ehdr->e_phoff > file.size ||
        phdr_table_bytes > ((uint64_t)file.size - ehdr->e_phoff)) {
        serial_write_string("[OS] [ELF] phdr out of range\n");
        kfree(buffer);
        return false;
    }

    Elf64_Phdr *phdrs = (Elf64_Phdr *)(buffer + ehdr->e_phoff);
    int load_segments = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD) {
            continue;
        }

        if (ph->p_memsz < ph->p_filesz) {
            serial_write_string("[OS] [ELF] memsz < filesz\n");
            kfree(buffer);
            return false;
        }

        if (!in_vaddr_range(ph->p_vaddr, ph->p_memsz, policy->min_vaddr, policy->max_vaddr)) {
            serial_write_string("[OS] [ELF] vaddr out of range\n");
            kfree(buffer);
            return false;
        }

        if (!range_in_file(file.size, ph->p_offset, ph->p_filesz)) {
            serial_write_string("[OS] [ELF] segment out of file range\n");
            kfree(buffer);
            return false;
        }

        uint8_t *dst = (uint8_t *)(uintptr_t)ph->p_vaddr;
        uint8_t *src = buffer + ph->p_offset;

        memcpy(dst, src, (size_t)ph->p_filesz);
        for (uint64_t j = ph->p_filesz; j < ph->p_memsz; ++j) {
            dst[j] = 0;
        }

        ++load_segments;
    }

    if (load_segments == 0) {
        serial_write_string("[OS] [ELF] no load segment\n");
        kfree(buffer);
        return false;
    }

    if (ehdr->e_entry < policy->min_vaddr || ehdr->e_entry >= policy->max_vaddr) {
        serial_write_string("[OS] [ELF] entry out of range\n");
        kfree(buffer);
        return false;
    }

    *entry_out = ehdr->e_entry;
    kfree(buffer);
    return true;
}

bool elf_loader_load_from_path(const char *path,
                               const elf_load_policy_t *policy,
                               uint64_t *entry_out)
{
    if (!path || !policy || !entry_out) {
        return false;
    }

    return elf_loader_load_from_fat83(path, policy, entry_out);
}

bool elf_loader_load_module_from_memory(const void *file_data,
                                        uint64_t file_size,
                                        const elf_module_load_policy_t *policy,
                                        uint64_t *entry_out)
{
    if (file_data == NULL || policy == NULL || entry_out == NULL) {
        return false;
    }
    if (file_size == 0 || file_size > policy->max_file_size) {
        return false;
    }
    if (file_size < sizeof(Elf64_Ehdr)) {
        return false;
    }

    const uint8_t *image = (const uint8_t *)file_data;
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)image;

    if (ehdr->e_ident[0] != ELF_MAGIC_0 ||
        ehdr->e_ident[1] != ELF_MAGIC_1 ||
        ehdr->e_ident[2] != ELF_MAGIC_2 ||
        ehdr->e_ident[3] != ELF_MAGIC_3) {
        return false;
    }

    if (ehdr->e_type != ET_DYN) {
        serial_write_string("[OS] [ELF] module must be ET_DYN\n");
        return false;
    }

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr) || ehdr->e_phnum == 0) {
        return false;
    }

    if (!range_in_file(file_size,
                       ehdr->e_phoff,
                       (uint64_t)ehdr->e_phnum * (uint64_t)ehdr->e_phentsize)) {
        return false;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(image + ehdr->e_phoff);

    uint64_t min_vaddr = 0;
    uint64_t max_vaddr = 0;
    uint32_t load_segment_count = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD) {
            continue;
        }

        if (ph->p_memsz < ph->p_filesz) {
            return false;
        }
        if (!range_in_file(file_size, ph->p_offset, ph->p_filesz)) {
            return false;
        }

        uint64_t seg_end = ph->p_vaddr + ph->p_memsz;
        if (seg_end < ph->p_vaddr) {
            return false;
        }

        if (load_segment_count == 0) {
            min_vaddr = ph->p_vaddr;
            max_vaddr = seg_end;
        } else {
            if (ph->p_vaddr < min_vaddr) {
                min_vaddr = ph->p_vaddr;
            }
            if (seg_end > max_vaddr) {
                max_vaddr = seg_end;
            }
        }
        ++load_segment_count;
    }

    if (load_segment_count == 0) {
        return false;
    }

    uint64_t aligned_min = align_down_u64(min_vaddr, ELF_PAGE_SIZE);
    uint64_t aligned_max = align_up_u64(max_vaddr, ELF_PAGE_SIZE);
    if (aligned_max <= aligned_min) {
        return false;
    }

    uint64_t image_span = aligned_max - aligned_min;
    if (image_span == 0 || image_span > policy->max_image_size) {
        return false;
    }

    uint64_t page_count64 = image_span / ELF_PAGE_SIZE;
    if (page_count64 == 0 || page_count64 > UINT32_MAX) {
        return false;
    }
    uint32_t page_count = (uint32_t)page_count64;

    void *load_base_ptr = alloc_contiguous_pages(page_count, 1);
    if (load_base_ptr == NULL) {
        serial_write_string("[OS] [ELF] module memory alloc failed\n");
        return false;
    }

    uint64_t runtime_start = (uint64_t)(uintptr_t)load_base_ptr;
    uint64_t load_bias = runtime_start - aligned_min;
    memset(load_base_ptr, 0, (size_t)image_span);

    bool ok = false;
    bool failed = false;

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) {
            continue;
        }

        uint64_t dst_addr = load_bias + ph->p_vaddr;
        if (!runtime_range_ok(runtime_start, image_span, dst_addr, ph->p_memsz)) {
            failed = true;
            break;
        }

        uint8_t *dst = (uint8_t *)(uintptr_t)dst_addr;
        const uint8_t *src = image + ph->p_offset;
        memcpy(dst, src, (size_t)ph->p_filesz);
        for (uint64_t j = ph->p_filesz; j < ph->p_memsz; ++j) {
            dst[j] = 0;
        }
    }

    if (!failed && ehdr->e_shoff != 0 && ehdr->e_shnum != 0) {
        if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
            failed = true;
        } else if (!range_in_file(file_size,
                                  ehdr->e_shoff,
                                  (uint64_t)ehdr->e_shnum * (uint64_t)ehdr->e_shentsize)) {
            failed = true;
        } else {
            const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(image + ehdr->e_shoff);
            uint32_t relocation_count = 0;

            for (uint16_t sec = 0; sec < ehdr->e_shnum && !failed; ++sec) {
                const Elf64_Shdr *rel_sec = &shdrs[sec];
                if (rel_sec->sh_type != SHT_RELA || rel_sec->sh_size == 0) {
                    continue;
                }

                if (rel_sec->sh_entsize != sizeof(Elf64_Rela) ||
                    (rel_sec->sh_size % rel_sec->sh_entsize) != 0) {
                    failed = true;
                    break;
                }

                if (!range_in_file(file_size, rel_sec->sh_offset, rel_sec->sh_size)) {
                    failed = true;
                    break;
                }

                uint64_t rel_count64 = rel_sec->sh_size / rel_sec->sh_entsize;
                if (rel_count64 > UINT32_MAX) {
                    failed = true;
                    break;
                }
                uint32_t rel_count = (uint32_t)rel_count64;

                relocation_count += rel_count;
                if (relocation_count > policy->max_relocation_count) {
                    serial_write_string("[OS] [ELF] relocation limit exceeded\n");
                    failed = true;
                    break;
                }

                const Elf64_Rela *rels = (const Elf64_Rela *)(image + rel_sec->sh_offset);

                const Elf64_Sym *symbols = NULL;
                uint32_t symbol_count = 0;

                if (rel_sec->sh_link < ehdr->e_shnum) {
                    const Elf64_Shdr *sym_sec = &shdrs[rel_sec->sh_link];
                    if (sym_sec->sh_entsize == sizeof(Elf64_Sym) &&
                        range_in_file(file_size, sym_sec->sh_offset, sym_sec->sh_size)) {
                        symbols = (const Elf64_Sym *)(image + sym_sec->sh_offset);
                        symbol_count = (uint32_t)(sym_sec->sh_size / sym_sec->sh_entsize);
                    }
                }

                for (uint32_t r = 0; r < rel_count; ++r) {
                    const Elf64_Rela *rela = &rels[r];
                    uint64_t where_addr = load_bias + rela->r_offset;
                    if (!runtime_range_ok(runtime_start, image_span, where_addr, sizeof(uint64_t))) {
                        failed = true;
                        break;
                    }

                    uint64_t *where = (uint64_t *)(uintptr_t)where_addr;
                    uint32_t type = elf64_r_type(rela->r_info);

                    if (type == R_X86_64_NONE) {
                        continue;
                    }

                    if (type == R_X86_64_RELATIVE) {
                        *where = load_bias + (uint64_t)rela->r_addend;
                        continue;
                    }

                    if (type == R_X86_64_64 ||
                        type == R_X86_64_GLOB_DAT ||
                        type == R_X86_64_JUMP_SLOT) {
                        uint32_t sym_index = elf64_r_sym(rela->r_info);
                        if (symbols == NULL || sym_index >= symbol_count) {
                            failed = true;
                            break;
                        }

                        const Elf64_Sym *sym = &symbols[sym_index];
                        if (sym->st_shndx == SHN_UNDEF) {
                            failed = true;
                            break;
                        }

                        uint64_t sym_addr = load_bias + sym->st_value;
                        *where = sym_addr + (uint64_t)rela->r_addend;
                        continue;
                    }

                    serial_write_string("[OS] [ELF] unsupported relocation type\n");
                    failed = true;
                    break;
                }
            }
        }
    }

    if (!failed) {
        uint64_t entry = load_bias + ehdr->e_entry;
        if (runtime_range_ok(runtime_start, image_span, entry, 1)) {
            *entry_out = entry;
            ok = true;
        }
    }

    if (!ok) {
        free_contiguous_pages(load_base_ptr, page_count);
    }

    return ok;
}
