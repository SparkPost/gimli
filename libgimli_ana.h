/*
 * Copyright (c) 2009-2010 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
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
  /** resolved address in the target process */
  void *addr;
  /** size of the symbol. Not all systems provide this information
   * for all symbols */
  uint32_t size;
  /** do not use */
  uint32_t ordinality;
  /** do not use */
  struct gimli_symbol *next;
};

#define GIMLI_ANA_API_VERSION 2

struct gimli_proc_stat {
  pid_t pid;
  size_t pr_size;
  size_t pr_rssize;
};

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

/* API Version 2 begins here */

  /** determine the source filename and line number information
   * for a given code address.
   * Returns 1 if the source information is found, 0 otherwise.
   * Populates filebuf and lineno if the source is found. */
  int (*get_source_info)(void *addr, char *buf, int buflen, int *lineno);

  /** Given a context, locate a named parameter and return its
   * C-style datatype name, address and size.  Returns 1 if located.
   * 0 otherwise. */
  int (*get_parameter)(void *context, const char *varname,
    const char **datatype, void **addr, uint64_t *size);

  /** Lookup a symbol, treat it as a char* in the target and
   * return a copy of the NUL-terminated string to which it points.
   * This is logically equivalent to sym_lookup, deref'ing the
   * result, and then read_string'ing the result of that.
   * The caller must free() the return memory when it is no longer
   * required. */
  char *(*get_string_symbol)(const char *obj, const char *name);

  /** Lookup a symbol and copy its target into a caller provided
   * buffer.
   * If deref is non-zero, the symbol value is treated as pointer
   * with that many levels of indirection; this function will
   * de-reference each of those levels to arrive at a final address.
   * SIZE bytes of data will then be read from the final address
   * and copied in the the caller provided buffer.
   * Returns 0 if SIZE could not be read completely, 1 on success */
  int (*copy_from_symbol)(const char *obj, const char *name,
    int deref, void *addr, uint32_t size);

  /* returns process status information for the target process */
  const struct gimli_proc_stat *(*get_proc_status)(void);
};

struct gimli_ana_module {
  int api_version;
  void (*perform_trace)(const struct gimli_ana_api *api, const char *object);
/* API Version 2 begins here */
#define GIMLI_ANA_SUPPRESS 0
#define GIMLI_ANA_CONTINUE 1
  /* inform a module that we're about to trace a thread.
   * The module should return GIMLI_ANA_CONTINUE to allow this to continue,
   * or GIMLI_ANA_SUPPRESS if it should want to suppress that thread from
   * the trace.
   * NFRAMES is the number of stack frames found for this thread.
   * PCADDRS is an array containing the instruction addresses of each
   * frame.
   * CONTEXTS is an array of gimli internal context information that
   * can be passed to the API to interrogate the respective frames.
   */
  int (*on_begin_thread_trace)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int nframes, void **pcaddrs, void **contexts);
  /* called before gimli prints a frame in the trace; allows a module
   * to suppress the frame or not; return either GIMLI_ANA_SUPPRESS or
   * GIMLI_ANA_CONTINUE.
   * FRAMENO gives the ordinal number of the frame (0 being top of stack),
   * PCADDR is the instruction address of that frame, and CONTEXT is the
   * gimli internal context that can be used to interrogate that frame */
  int (*before_print_frame)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int frameno, void *pcaddr, void *context);
  /* called before gimli prints a parameter in the trace; allows a module
   * to suppress the parameter or not; return either GIMLI_ANA_SUPPRESS or
   * GIMLI_ANA_CONTINUE.
   * FRAMENO gives the ordinal number of the frame (0 being top of stack),
   * PCADDR is the instruction address of that frame, and CONTEXT is the
   * gimli internal context that can be used to interrogate that frame.
   * DATATYPE is the textual, C-style, rendition of the data type name.
   * VARNAME is the identifier for the parameter.
   * VARADDR is the address of the parameter in memory. */
  int (*before_print_frame_var)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int frameno, void *pcaddr, void *context,
    const char *datatype, const char *varname,
    void *varaddr, uint64_t varsize);
  /* called after gimli prints a parameter in the trace.
   * FRAMENO gives the ordinal number of the frame (0 being top of stack),
   * PCADDR is the instruction address of that frame, and CONTEXT is the
   * gimli internal context that can be used to interrogate that frame.
   * DATATYPE is the textual, C-style, rendition of the data type name.
   * VARNAME is the identifier for the parameter.
   * VARADDR is the address of the parameter in memory. */
  void (*after_print_frame_var)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int frameno, void *pcaddr, void *context,
    const char *datatype, const char *varname,
    void *varaddr, uint64_t varsize);
  /* called after gimli prints a frame in the trace.
   * FRAMENO gives the ordinal number of the frame (0 being top of stack),
   * PCADDR is the instruction address of that frame, and CONTEXT is the
   * gimli internal context that can be used to interrogate that frame */
  void (*after_print_frame)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int frameno, void *pcaddr, void *context);
  /* inform a module that we're done tracing a thread.
   * NFRAMES is the number of stack frames found for this thread.
   * PCADDRS is an array containing the instruction addresses of each
   * frame.
   * CONTEXTS is an array of gimli internal context information that
   * can be passed to the API to interrogate the respective frames.
   */
  void (*on_end_thread_trace)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int nframes, void **pcaddrs, void **contexts);
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

