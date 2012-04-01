/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

static STAILQ_HEAD(modulelist, module_item)
  modules = STAILQ_HEAD_INITIALIZER(modules);

gimli_iter_status_t gimli_visit_modules(gimli_module_visit_f func, void *arg)
{
  struct module_item *mod;
  gimli_iter_status_t status = GIMLI_ITER_CONT;

  STAILQ_FOREACH(mod, &modules, modules) {
    status = func(mod, arg);
    if (status != GIMLI_ITER_CONT) {
      break;
    }
  }
  return status;
}

static int load_module(const char *exename, const char *filename)
{
  void *h;
  struct module_item *mod;
  gimli_module_init_func func;
  int found = 0;

  h = dlopen(filename, RTLD_NOW|RTLD_GLOBAL);
  if (!h) {
    printf("Unable to load library: %s: %s\n", filename, dlerror());
    return 0;
  }

  func = (gimli_module_init_func)dlsym(h, "gimli_ana_init");
  if (func) {
    found++;

    mod = calloc(1, sizeof(*mod));
    mod->ptr.v2 = (*func)(&ana_api);

    if (!mod->ptr.v2) {
      free(mod);
    } else {
      mod->name = strdup(filename);
      mod->exename = strdup(exename);
      mod->api_version = mod->ptr.v2->api_version;
      STAILQ_INSERT_TAIL(&modules, mod, modules);
    }
  }

  /* TODO: v3 load goes here */

  return found;
}

static int load_module_for_file(gimli_mapped_object_t file)
{
  struct gimli_symbol *sym;
  char *name = NULL;
  char buf[1024];
  char buf2[1024];
  void *h;
  int res = 0;

  sym = gimli_sym_lookup(the_proc, file->objname, "gimli_tracer_module_name");
  if (sym) {
    name = gimli_read_string(the_proc, sym->addr);
  }
  if (name == NULL) {
    strcpy(buf, file->objname);
    snprintf(buf2, sizeof(buf2)-1, "gimli_%s", basename(buf));
    name = strdup(buf2);
  }
  strcpy(buf, file->objname);
  snprintf(buf2, sizeof(buf2)-1, "%s/%s", dirname(buf), name);

  if (access(buf2, F_OK) == 0) {
    res = load_module(file->objname, buf);
  } else if (sym) {
    printf("NOTE: module %s declared that its tracing "
        "should be performed by %s, but that module was not found (%s)\n",
        file->objname, buf2, strerror(errno));
  }
  free(name);

  return res;
}

/* perform discovery of tracer module */
static gimli_iter_status_t load_modules_for_file(const char *k, int klen,
    void *item, void *arg)
{
  gimli_mapped_object_t file = item;

  load_module_for_file(file);

  return GIMLI_ITER_CONT;
}


void gimli_load_modules(gimli_proc_t proc)
{
  gimli_hash_iter(the_proc->files, load_modules_for_file, NULL);
}


/* vim:ts=2:sw=2:et:
 */

