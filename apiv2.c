/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

/* Implements GIMLI_ANA_API_VERSION <= 2 */

static const struct gimli_proc_stat *gimli_get_proc_stat(void)
{
  return &the_proc->proc_stat;
}

static int v2_get_source_info(void *addr, char *buf,
  int buflen, int *lineno)
{
  uint64_t l;
  int ret = dwarf_determine_source_line_number(the_proc, addr, buf, buflen, &l);
  if (ret) {
    *lineno = (int)l;
  }
  return ret;
}

static char *gimli_get_string_symbol(const char *obj, const char *name)
{
  struct gimli_symbol *sym;

  sym = gimli_sym_lookup(the_proc, obj, name);
  if (sym) {
    void *addr;

    if (gimli_read_mem(the_proc, sym->addr, &addr, sizeof(addr)) == sizeof(addr)) {
      return gimli_read_string(the_proc, addr);
    }
  }
  return NULL;
}

static int gimli_copy_from_symbol(const char *obj, const char *name,
  int deref, void *buf, uint32_t size)
{
  struct gimli_symbol *sym;

  sym = gimli_sym_lookup(the_proc, obj, name);
  if (sym) {
    void *addr = sym->addr;

    while (deref--) {
      if (gimli_read_mem(the_proc, addr, &addr, sizeof(addr)) != sizeof(addr)) {
        return 0;
      }
    }

    return gimli_read_mem(the_proc, addr, buf, size) == size;
  }
  return 0;
}

static struct gimli_symbol *v1_sym_lookup(
    const char *obj, const char *name)
{
  return gimli_sym_lookup(the_proc, obj, name);
}

static const char *v1_pc_sym_name(void *addr,
    char *buf, int buflen)
{
  return gimli_pc_sym_name(the_proc, addr, buf, buflen);
}

static int v1_read_mem(void *src, void *dest, int len)
{
  return gimli_read_mem(the_proc, src, dest, len);
}

static char *v1_read_string(void *src)
{
  return gimli_read_string(the_proc, src);
}

struct gimli_ana_api ana_api = {
  GIMLI_ANA_API_VERSION,
  v1_sym_lookup,
  v1_pc_sym_name,
  v1_read_mem,
  v1_read_string,
  v2_get_source_info,
  gimli_get_parameter,
  gimli_get_string_symbol,
  gimli_copy_from_symbol,
  gimli_get_proc_stat,
};

/* vim:ts=2:sw=2:et:
 */
