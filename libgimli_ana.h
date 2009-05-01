/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifndef LIBGIMLI_ANA_H
#define LIBGIMLI_ANA_H

/* This header defines the interface that a gimli analysis module may
 * consume/provide to provide additional diagnostics during trace generation.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct gimli_symbol {
  /** de-mangled symbol name */
  char *name;
  /** raw, un-mangled symbol name */
  char *rawname;
  void *addr;
  uint32_t size;
  uint32_t ordinality;
  struct gimli_symbol *next;
};

#define GIMLI_ANA_API_VERSION 1

struct gimli_ana_api {
  int api_version;
  /** lookup a symbol based on its raw, un-mangled, name */
  struct gimli_symbol *(*sym_lookup)(const char *obj, const char *name);

  /** compute a readable label for an address */
  const char *(*sym_name)(void *addr, char *buf, int buflen);

  /** read memory from the target process, returns the length that
   * was successfully read */
  int (*read_mem)(void *src, void *dest, int len);

  /** read a NUL terminated string from target process.
   * The caller must free() the memory when it is no longer required */
  char *(*read_string)(void *src);

};

struct gimli_ana_module {
  int api_version;
  void (*perform_trace)(const struct gimli_ana_api *api, const char *object);
};

typedef struct gimli_ana_module *(*gimli_module_init_func)(
  const struct gimli_ana_api *api);
extern struct gimli_ana_module *gimli_ana_init(const struct gimli_ana_api *api);

#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

