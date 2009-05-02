/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifndef GIMLI_ELF_H
#define GIMLI_ELF_H

#ifdef __cplusplus
extern "C" {
#endif

struct gimli_elf_shdr {
  struct gimli_elf_shdr *next;
  char *name;
  char *data;
  int section_no;
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
  struct gimli_elf_ehdr *elf;
};

struct gimli_elf_symbol {
  char *name;
  uint32_t st_name;
  uint8_t  st_info;
  uint8_t  st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
};

struct gimli_elf_ehdr {
  int fd;
  uint8_t ei_class;
  uint16_t
    e_type,
    e_machine;
  uint64_t 
    e_version,
    e_entry, /* entry point for executable */
    e_phoff, /* prog hdr table offset */
    e_shoff, /* section hdr table offset */
    e_flags, /* cpu specific flags */
    e_ehsize,    /* size of this EHDR in bytes */
    e_phentsize, /* size of a prog hdr entry */
    e_phnum,     /* number of prog hdr entries */
    e_shentsize, /* size of a section header entry */
    e_shnum,     /* number of section headers */
    e_shstrndx   /* index of the string table into section header table */
    ;
  struct gimli_elf_shdr *sections;
  struct gimli_elf_ehdr *refelf;
  char *objname;
  uint64_t vaddr;
};

typedef int (*gimli_elf_sym_iter_func)(struct gimli_elf_ehdr *elf,
  struct gimli_elf_symbol *sym, void *arg);

int gimli_elf_enum_symbols(struct gimli_elf_ehdr *elf,
  gimli_elf_sym_iter_func func, void *arg);
struct gimli_elf_ehdr *gimli_elf_open(const char *filename, struct gimli_elf_ehdr *refelf);
struct gimli_elf_shdr *gimli_get_elf_section_by_name(gimli_object_file_t *elf,
  const char *name);
const char *gimli_get_section_data(gimli_object_file_t *elf, int section);

/* for e_type: */
#define GIMLI_ET_NONE 0 /* no file type */
#define GIMLI_ET_REL 1  /* relocatable file */
#define GIMLI_ET_EXEC 2 /* executable */
#define GIMLI_ET_DYN 3  /* shared obj */
#define GIMLI_ET_CORE 4 /* core file */

/* for e_machine: */
#define GIMLI_EM_NONE  0   /* no machine */
#define GIMLI_EM_SPARC 2   /* sparc */
#define GIMLI_EM_386   3   /* i386 */
#define GIMLI_EM_X86_64 62 /* amd x86_64 */

/* e_version: */
#define GIMLI_EV_NONE    0 /* invalid */
#define GIMLI_EV_CURRENT 1 /* current version */

/* e_ident: offsets for specific items */
#define GIMLI_EI_CLASS      4
#define GIMLI_EI_DATA       5
#define GIMLI_EI_VERSION    6
#define GIMLI_EI_OSABI      7
#define GIMLI_EI_ABIVERSION 8
#define GIMLI_EI_ELF_MAGIC "\x7F" "ELF"

/* EI_CLASS: */
#define GIMLI_ELFCLASS32 1 /* 32-bit objects */
#define GIMLI_ELFCLASS64 2 /* 64-bit objects */

/* EI_DATA: */
#define GIMLI_ELFDATA2LSB 1
#define GIMLI_ELFDATA2MSB 2

/* EI_VERSION: must have EV_CURRENT as value */

/* EI_OSABI: */
#define GIMLI_ELFOSABI_LINUX   3
#define GIMLI_ELFOSABI_SOLARIS 6
#define GIMLI_ELFOSABI_FREEBSD 9

#define GIMLI_SHN_UNDEF  0
#define GIMLI_SHN_XINDEX 0xffff

#define GIMLI_SHT_NULL     0
#define GIMLI_SHT_PROGBITS 1
#define GIMLI_SHT_SYMTAB   2
#define GIMLI_SHT_STRTAB   3
#define GIMLI_SHT_DYNAMIC  6
#define GIMLI_SHT_NOBITS   8
#define GIMLI_SHT_DYNSYM   11

#define GIMLI_STB_LOCAL  0
#define GIMLI_STB_GLOBAL 1
#define GIMLI_STB_WEAK   2

#define GIMLI_ELF_BIND(x)  ((x) >> 4)
#define GIMLI_ELF_TYPE(x)  ((x) & 0xf)

#define GIMLI_STT_NOTYPE 0
#define GIMLI_STT_OBJECT 1
#define GIMLI_STT_FUNC   2
#define GIMLI_STT_SECTION 3
#define GIMLI_STT_FILE    4
#define GIMLI_STT_COMMON  5
#define GIMLI_STT_TLS     6

#define GIMLI_PT_NULL 0
#define GIMLI_PT_LOAD 1
#define GIMLI_PT_DYNAMIC 2
#define GIMLI_PT_INTERP 3

#define gimli_object_is_executable(obj)  ((obj)->e_type == GIMLI_ET_EXEC)

#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

