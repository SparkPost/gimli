/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifndef __MACH__
#include "impl.h"

/* on-disk data types */
typedef uint32_t elf32_addr_t;
typedef uint32_t elf32_off_t;
typedef uint16_t elf32_half_t;
typedef uint32_t elf32_word_t;
typedef int32_t  elf32_sword_t;

typedef uint64_t elf64_addr_t;
typedef uint64_t elf64_off_t;
typedef uint16_t elf64_half_t;
typedef uint32_t elf64_word_t;
typedef int32_t  elf64_sword_t;
typedef uint64_t elf64_xword_t;
typedef int64_t  elf64_sxword_t;

struct elf32_ehdr {
  elf32_half_t e_type, e_machine;
  elf32_word_t e_version;
  elf32_addr_t e_entry;
  elf32_off_t  e_phoff, e_shoff;
  elf32_word_t e_flags;
  elf32_half_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};

struct elf64_ehdr {
  elf64_half_t e_type, e_machine;
  elf64_word_t e_version;
  elf64_addr_t e_entry;
  elf64_off_t  e_phoff, e_shoff;
  elf64_word_t e_flags;
  elf64_half_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};

struct elf32_shdr {
  elf32_word_t sh_name, sh_type, sh_flags;
  elf32_addr_t sh_addr;
  elf32_off_t  sh_offset;
  elf32_word_t sh_size, sh_link, sh_info, sh_addralign, sh_entsize;
};
struct elf64_shdr {
  elf64_word_t  sh_name, sh_type;
  elf64_xword_t sh_flags;
  elf64_addr_t  sh_addr;
  elf64_off_t   sh_offset;
  elf64_xword_t sh_size;
  elf64_word_t  sh_link, sh_info;
  elf64_xword_t sh_addralign, sh_entsize;
};

struct elf32_sym {
  elf32_word_t st_name;
  elf32_addr_t st_value;
  elf32_word_t st_size;
  uint8_t st_info, st_other;
  elf32_half_t st_shndx;
};

struct elf64_sym {
  elf64_word_t st_name;
  uint8_t st_info, st_other;
  elf64_half_t st_shndx;
  elf64_addr_t st_value;
  elf64_xword_t st_size;
};

struct elf32_phdr {
  elf32_word_t p_type;
  elf32_off_t p_offset;
  elf32_addr_t p_vaddr, p_paddr;
  elf32_word_t p_filesz, p_memsz, p_flags, p_align;
};

struct elf64_phdr {
  elf64_word_t p_type, p_flags;
  elf64_off_t p_offset;
  elf64_addr_t p_vaddr, p_paddr;
  elf64_xword_t p_filesz, p_memsz, p_align;
};




static uint8_t native_elf_abi =
#ifdef __linux__
  GIMLI_ELFOSABI_LINUX
#elif defined(sun)
  GIMLI_ELFOSABI_SOLARIS
#elif defined(__FreeBSD__)
  GIMLI_ELFOSABI_FREEBSD
#else
# error unsupported OS
#endif
  ;

static uint16_t native_machine =
#ifdef __x86_64__
  GIMLI_EM_X86_64
#elif defined(__sparc__)
  GIMLI_EM_SPARC
#else
  GIMLI_EM_386
#endif
  ;

struct gimli_elf_shdr *gimli_get_section_by_index(
  struct gimli_elf_ehdr *elf, int section)
{
  struct gimli_elf_shdr *s;

  for (s = elf->sections; s; s = s->next) {
    if (s->section_no == section) {
      return s;
    }
  }
  return NULL;
}

struct gimli_elf_shdr *gimli_get_elf_section_by_name(struct gimli_elf_ehdr *elf,
  const char *name)
{
  struct gimli_elf_shdr *s = NULL;

  for (s = elf->sections; s; s = s->next) {
    if (!strcmp(s->name, name)) {
      return s;
    }
  }
  return NULL;
}

const char *gimli_get_section_data(struct gimli_elf_ehdr *elf, int section)
{
  struct gimli_elf_shdr *s;
  int i;

  s = gimli_get_section_by_index(elf, section);

  if (!s->data) {
    s->data = malloc(s->sh_size);
    if (!s->data) return NULL;
    if (lseek(s->elf->fd, s->sh_offset, SEEK_SET) != s->sh_offset) {
      fprintf(stderr, "ELF: failed to seek: %s\n", strerror(errno));
      free(s->data);
      s->data = NULL;
      return NULL;
    }
    if (read(s->elf->fd, s->data, s->sh_size) != s->sh_size) {
      fprintf(stderr, "ELF: failed to read: %s\n", strerror(errno));
      free(s->data);
      s->data = NULL;
      return NULL;
    }
  }
  return s->data;
}

const char *gimli_elf_get_string(struct gimli_elf_ehdr *elf,
  int section, uint64_t off)
{
  const char *d = gimli_get_section_data(elf, section);
  if (d) {
    return d + off;
  }
  return NULL;
}


struct gimli_elf_ehdr *gimli_elf_open(const char *filename)
{
  struct gimli_elf_ehdr *elf = calloc(1, sizeof(*elf));
  unsigned char ident[16];
  int i;
  struct gimli_elf_shdr *last_section = NULL;
  struct gimli_elf_shdr *s;

  elf->fd = open(filename, O_RDONLY);
  if (elf->fd == -1) {
    return 0;
  }

  read(elf->fd, ident, sizeof(ident));

  if (memcmp(ident, GIMLI_EI_ELF_MAGIC, 4)) {
    return 0;
  }

  elf->objname = strdup(filename);

  if (ident[GIMLI_EI_VERSION] != GIMLI_EV_CURRENT) {
    fprintf(stderr, "ELF: %s: unsupported ELF version %d\n", filename,
      ident[GIMLI_EI_VERSION]);
    return 0;
  }
  if (ident[GIMLI_EI_OSABI] && ident[GIMLI_EI_OSABI] != native_elf_abi) {
    fprintf(stderr, "ELF: %s: unsupported OS ABI %d (expected %d)\n",
      filename, ident[GIMLI_EI_OSABI], native_elf_abi);
    return 0;
  }

  /* we only support reading natively encoded ELF objects */
#ifdef __sparc__
  if (ident[GIMLI_EI_DATA] != GIMLI_ELFDATA2MSB) {
    fprintf(stderr, "ELF: %s: expected MSB format on this system\n",
      filename);
    return 0;
  }
#else
  if (ident[GIMLI_EI_DATA] != GIMLI_ELFDATA2LSB) {
    fprintf(stderr, "ELF: %s: expected LSB format on this system\n",
      filename);
    return 0;
  }
#endif

  elf->ei_class = ident[GIMLI_EI_CLASS];

  if (elf->ei_class == GIMLI_ELFCLASS32) {
    struct elf32_ehdr hdr;

    if (read(elf->fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
      fprintf(stderr, "ELF: %s: error reading EHDR: %s\n",
        filename, strerror(errno));
      return 0;
    }
    elf->e_type = hdr.e_type;
    elf->e_machine = hdr.e_machine;
    elf->e_version = hdr.e_version;
    elf->e_entry = hdr.e_entry;
    elf->e_phoff = hdr.e_phoff;
    elf->e_shoff = hdr.e_shoff;
    elf->e_flags = hdr.e_flags;
    elf->e_ehsize = hdr.e_ehsize;
    elf->e_phentsize = hdr.e_phentsize;
    elf->e_phnum = hdr.e_phnum;
    elf->e_shentsize = hdr.e_shentsize;
    elf->e_shnum = hdr.e_shnum;
    elf->e_shstrndx = hdr.e_shstrndx;
  } else {
    struct elf64_ehdr hdr;

    if (read(elf->fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
      fprintf(stderr, "ELF: %s: error reading EHDR: %s\n",
          filename, strerror(errno));
      return 0;
    }
    elf->e_type = hdr.e_type;
    elf->e_machine = hdr.e_machine;
    elf->e_version = hdr.e_version;
    elf->e_entry = hdr.e_entry;
    elf->e_phoff = hdr.e_phoff;
    elf->e_shoff = hdr.e_shoff;
    elf->e_flags = hdr.e_flags;
    elf->e_ehsize = hdr.e_ehsize;
    elf->e_phentsize = hdr.e_phentsize;
    elf->e_phnum = hdr.e_phnum;
    elf->e_shentsize = hdr.e_shentsize;
    elf->e_shnum = hdr.e_shnum;
    elf->e_shstrndx = hdr.e_shstrndx;
  }

  if (elf->e_machine != native_machine) {
    fprintf(stderr, "ELF: %s: expected e_machine=%d, found %d\n",
      filename, native_machine, elf->e_machine);
    return 0;
  }

  if (elf->e_version != GIMLI_EV_CURRENT) {
    fprintf(stderr, "ELF: %s: unsupported ELF version %d\n", filename,
      elf->e_version);
    return 0;
  }

  /* run through the section headers, pulling them in */
  for (i = 0; i < elf->e_shnum; i++) {
    s = calloc(1, sizeof(*s));
    s->section_no = i;
    s->elf = elf;
    off_t target = elf->e_shoff + (i * elf->e_shentsize);

    if (lseek(elf->fd, target, SEEK_SET) != target) {
      fprintf(stderr,
        "ELF: %s: failed to seek for section header %d: offset %d: %s\n",
        filename, i, target, strerror(errno));
      return 0;
    }
    if (elf->ei_class == GIMLI_ELFCLASS32) {
      struct elf32_shdr hdr;

      if (read(elf->fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr,
          "ELF: %s: failed to read section header %d: %s\n",
            filename, i, strerror(errno));
        return 0;
      }

      s->sh_name = hdr.sh_name;
      s->sh_type = hdr.sh_type;
      s->sh_flags = hdr.sh_flags;
      s->sh_addr = hdr.sh_addr;
      s->sh_offset = hdr.sh_offset;
      s->sh_size = hdr.sh_size;
      s->sh_link = hdr.sh_link;
      s->sh_info = hdr.sh_info;
      s->sh_addralign = hdr.sh_addralign;
      s->sh_entsize = hdr.sh_entsize;

    } else {
      struct elf64_shdr hdr;

      if (read(elf->fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr,
          "ELF: %s: failed to read section header %d: %s\n",
            filename, i, strerror(errno));
        return 0;
      }

      s->sh_name = hdr.sh_name;
      s->sh_type = hdr.sh_type;
      s->sh_flags = hdr.sh_flags;
      s->sh_addr = hdr.sh_addr;
      s->sh_offset = hdr.sh_offset;
      s->sh_size = hdr.sh_size;
      s->sh_link = hdr.sh_link;
      s->sh_info = hdr.sh_info;
      s->sh_addralign = hdr.sh_addralign;
      s->sh_entsize = hdr.sh_entsize;
    }

    if (last_section) {
      last_section->next = s;
    } else {
      elf->sections = s;

      /* let's fixup the e_shstrndx here.  If it has the value
       * SHN_XINDEX, then the true value is stashed in the sh_link
       * field of the 0th section (that's us) */
      if (elf->e_shstrndx == GIMLI_SHN_XINDEX) {
        elf->e_shstrndx = s->sh_link;
      }
    }
    last_section = s;
  }
//  printf("e_shstrndx is %d\n", elf->e_shstrndx); 
  /* now make a pass through the sections to find out their names */
  for (s = elf->sections; s; s = s->next) {
    s->name = (char*)gimli_elf_get_string(elf, elf->e_shstrndx, s->sh_name);
//    printf("Section %d has name [%d] %s\n", s->section_no, s->sh_name, s->name);
  }

  /* now we need to locate the LOAD Program Header, and from that
   * we can deduce the base_address */
  for (i = 0; i < elf->e_phnum; i++) {
    struct elf64_phdr hdr;

    lseek(elf->fd, elf->e_phoff + (i * elf->e_phentsize), SEEK_SET);

    if (elf->ei_class == GIMLI_ELFCLASS32) {
      struct elf32_phdr hdr32;

      if (read(elf->fd, &hdr32, sizeof(hdr32)) != sizeof(hdr32)) {
        fprintf(stderr, "ELF: %s: error reading EHDR: %s\n",
            filename, strerror(errno));
        return 0;
      }
      hdr.p_type = hdr32.p_type;
      hdr.p_flags = hdr32.p_flags;
      hdr.p_offset = hdr32.p_offset;
      hdr.p_vaddr = hdr32.p_vaddr;
      hdr.p_paddr = hdr32.p_paddr;
      hdr.p_filesz = hdr32.p_filesz;
      hdr.p_memsz = hdr32.p_align;

    } else {
      if (read(elf->fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        fprintf(stderr, "ELF: %s: error reading EHDR: %s\n",
            filename, strerror(errno));
        return 0;
      }
    }

    if (hdr.p_type == GIMLI_PT_LOAD) {
      elf->vaddr = hdr.p_vaddr;
      break;
    }
  }

  return elf;
}

int gimli_elf_enum_symbols(struct gimli_elf_ehdr *elf,
  gimli_elf_sym_iter_func func, void *arg)
{
  struct gimli_elf_shdr *s;
  int matches = 0;
  const char *symtab = NULL;
  const char *end = NULL;

  /* find the symbol table */
  for (s = elf->sections; s; s = s->next) {
    if (s->sh_type == GIMLI_SHT_SYMTAB || s->sh_type == GIMLI_SHT_DYNSYM) {
      symtab = gimli_get_section_data(elf, s->section_no);
      if (symtab == NULL) {
        continue;
      }
      end = symtab + s->sh_size;

      for (; symtab < end; symtab += s->sh_entsize) {
        struct gimli_elf_symbol sym;

        memset(&sym, 0, sizeof(sym));
        if (elf->ei_class == GIMLI_ELFCLASS32) {
          struct elf32_sym s;

          memcpy(&s, symtab, sizeof(s));
          sym.st_name = s.st_name;
          sym.st_value = s.st_value;
          sym.st_size = s.st_size;
          sym.st_info = s.st_info;
          sym.st_other = s.st_other;
          sym.st_shndx = s.st_shndx;
        } else {
          struct elf64_sym s;

          memcpy(&s, symtab, sizeof(s));
          sym.st_name = s.st_name;
          sym.st_value = s.st_value;
          sym.st_size = s.st_size;
          sym.st_info = s.st_info;
          sym.st_other = s.st_other;
          sym.st_shndx = s.st_shndx;
        }
        if (sym.st_shndx == GIMLI_SHN_UNDEF) {
          continue;
        }
        if (sym.st_shndx == GIMLI_SHN_XINDEX) {
          printf("Got an xindex here\n");
        }

        sym.name = (char*)gimli_elf_get_string(elf,
                s->sh_link, sym.st_name);

        if (sym.name == NULL) {
          continue;
        }

        if (func(elf, &sym, arg)) {
          matches++;
        }
      }
    }
  }


  return matches;
}

#endif
/* vim:ts=2:sw=2:et:
 */

