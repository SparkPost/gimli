/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifndef __MACH__
#include "impl.h"

static int for_each_symbol(struct gimli_elf_ehdr *elf,
  struct gimli_elf_symbol *sym, void *arg)
{
  struct gimli_object_file *f = arg;

#if 0
  /* ignore non-code symbols */
  if (GIMLI_ELF_TYPE(sym->st_info) != GIMLI_STT_FUNC) {
    return 0;
  }
#endif
  sym->st_value += f->base_addr;

  if (sym->st_size && sym->name[0] && !strchr(sym->name, '.') &&
      !strchr(sym->name, '$')) {
    gimli_add_symbol(f, sym->name, (void*)sym->st_value, sym->st_size);
    return 1;
  }
  return 0;
}

int gimli_process_elf(struct gimli_object_file *f)
{
  char altpath[1024];

  if (!f->elf) return 0;

#ifdef __linux
  /* LSB says that debugging versions may be present in /usr/lib/debug,
   * so let's try those first */
  snprintf(altpath, sizeof(altpath)-1, "/usr/lib/debug%s.debug", f->objname);
  f->aux_elf = gimli_elf_open(altpath, f->elf);
#endif

  gimli_elf_enum_symbols(f->elf, for_each_symbol, f);

  if (f->aux_elf) {
    gimli_elf_enum_symbols(f->aux_elf, for_each_symbol, f);
  }

  return 1;
}

#endif

/* vim:ts=2:sw=2:et:
 */

