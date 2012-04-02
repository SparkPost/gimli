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
      *val = p64;
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

int gimli_module_register_tracer(gimli_tracer_f func, void *arg)
{
  return gimli_hook_register("tracer", func, arg);
}

static gimli_iter_status_t visit_tracer(gimli_hook_f func, void *farg, void *arg)
{
  gimli_proc_t proc = arg;
  gimli_tracer_f tracer = (gimli_tracer_f)func;

  tracer(proc, farg);

  return GIMLI_ITER_CONT;
}

void gimli_module_call_tracers(gimli_proc_t proc)
{
  gimli_hook_visit("tracer", visit_tracer, proc);
}

int gimli_module_register_var_printer(gimli_var_printer_f func, void *arg)
{
  return gimli_hook_register("prettyprinter", (gimli_hook_f)func, arg);
}

struct prettyargs {
  gimli_proc_t proc;
  gimli_stack_frame_t frame;
  const char *varname;
  gimli_type_t t;
  gimli_addr_t addr;
  int depth;
};

static gimli_iter_status_t visit_pretty(gimli_hook_f func, void *farg, void *arg)
{
  struct prettyargs *args = arg;
  gimli_var_printer_f pretty = (gimli_var_printer_f)func;

  return pretty(args->proc, args->frame, args->varname,
      args->t, args->addr, args->depth, farg);
}

gimli_iter_status_t gimli_module_call_var_printer(
    gimli_proc_t proc, gimli_stack_frame_t frame,
    const char *varname, gimli_type_t t,
    gimli_addr_t addr, int depth)
{
  struct prettyargs pargs = { proc, frame, varname, t, addr, depth };

  return gimli_hook_visit("prettyprinter", visit_pretty, &pargs);
}

struct printer_type {
  gimli_var_printer_f func;
  void *arg;
  int ntypes;
};
static gimli_hash_t printer_by_type = NULL;

static gimli_iter_status_t filter_printer_type(gimli_proc_t proc,
    gimli_stack_frame_t frame,
    const char *varname, gimli_type_t t, gimli_addr_t addr,
    int depth, void *arg)
{
  struct printer_type *list;
  const char *decl;

  if (!t) return GIMLI_ITER_CONT;

  decl = gimli_type_declname(t);
  if (gimli_hash_find(printer_by_type, decl, (void**)&list)) {
    return list->func(proc, frame, varname, t, addr, depth, list->arg);
  }

  return GIMLI_ITER_CONT;
}

static void free_printer(void *ptr)
{
  struct printer_type *list = ptr;

  if (--list->ntypes) return;
  free(list);
}

int gimli_module_register_var_printer_for_types(const char *typenames[],
    int ntypes, gimli_var_printer_f func, void *arg)
{
  struct printer_type *list = calloc(1, sizeof(*list));
  int i;

  list->arg = arg;
  list->func = func;
  list->ntypes = ntypes;

  if (!printer_by_type) {
    printer_by_type = gimli_hash_new(free_printer);
    gimli_module_register_var_printer(filter_printer_type, NULL);
  }
  for (i = 0; i < ntypes; i++) {
    gimli_hash_insert(printer_by_type, typenames[i], list);
  }

  return 1;
}

/* vim:ts=2:sw=2:et:
 */

