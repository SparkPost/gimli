/*
 * Copyright (c) 2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

int gimli_read_pointer(gimli_proc_t proc, gimli_addr_t addr, gimli_addr_t *val)
{
  uint64_t p64;
  uint32_t p32;

  *val = 0;
  if (sizeof(void*) == 8) { // FIXME: data model aware
    if (gimli_read_mem(proc, addr, &p64, sizeof(p64)) == sizeof(p64)) {
      *val = p32;
      return 1;
    }
    return 0;
  }
  /* 32-bit target */
  if (gimli_read_mem(proc, addr, &p32, sizeof(p32)) == sizeof(p32)) {
    *val = p32;
    return 1;
  }
  return 0;
}

char *gimli_get_string_symbol(gimli_proc_t proc,
    const char *obj, const char *name)
{
  struct gimli_symbol *sym;

  sym = gimli_sym_lookup(proc, obj, name);
  if (sym) {
    gimli_addr_t addr;

    if (gimli_read_pointer(proc, sym->addr, &addr)) {
      return gimli_read_string(proc, addr);
    }
  }
  return NULL;
}

int gimli_copy_from_symbol(const char *obj, const char *name,
  int deref, void *buf, uint32_t size)
{
  struct gimli_symbol *sym;

  sym = gimli_sym_lookup(the_proc, obj, name);
  if (sym) {
    gimli_addr_t addr = sym->addr;

    while (deref--) {
      if (!gimli_read_pointer(the_proc, addr, &addr)) {
        return 0;
      }
    }

    return gimli_read_mem(the_proc, addr, buf, size) == size;
  }
  return 0;
}



/* vim:ts=2:sw=2:et:
 */

