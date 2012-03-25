/*
 * Copyright (c) 2009-2012 Message Systems, Inc. All rights reserved
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

#define GIMLI_ANA_API_VERSION 3

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

/* Version 3 APIs start here */

/** hash table utility API */
typedef struct libgimli_hash_table *gimli_hash_t;

typedef enum _gimli_hash_iter_ret {
  GIMLI_HASH_ITER_STOP = 0,
  GIMLI_HASH_ITER_CONT = 1
} gimli_hash_iter_ret;

typedef gimli_hash_iter_ret (*gimli_hash_iter_func_t)(
  const char *k, int klen, void *item, void *arg
);
typedef void (*gimli_hash_free_func_t)(void *item);

gimli_hash_t gimli_hash_new(gimli_hash_free_func_t dtor);
int gimli_hash_size(gimli_hash_t h);
int gimli_hash_iter(gimli_hash_t h, gimli_hash_iter_func_t func, void *arg);
void gimli_hash_destroy(gimli_hash_t h);
void gimli_hash_delete_all(gimli_hash_t h);
int gimli_hash_delete(gimli_hash_t h, const char *k);
int gimli_hash_find(gimli_hash_t h, const char *k, void **item_p);
int gimli_hash_insert(gimli_hash_t h, const char *k, void *item);


/** represents various error states */
typedef enum {
  GIMLI_ERR_OK,
  GIMLI_ERR_BAD_ADDR,
  GIMLI_ERR_NO_PROC,
  GIMLI_ERR_OOM,
  GIMLI_ERR_PERM,
  GIMLI_ERR_CHECK_ERRNO,
  GIMLI_ERR_TIMEOUT,
  GIMLI_ERR_THREAD_DEBUGGER_INIT_FAILED,
} gimli_err_t;

/** represents a pointer on any architecture */
typedef uint64_t gimli_addr_t;

/** opaque type represents a target process, which may be myself */
typedef struct gimli_proc *gimli_proc_t;

/** returns a proc handle to my own process.
 * Caller must gimli_proc_delete() it when it is no longer needed */
gimli_err_t gimli_proc_self(gimli_proc_t *proc);

/** deletes a reference to a proc handle.
 * When the final handle is deleted, the process will be detached
 * (and continued) if it was a remote process.
 */
void gimli_proc_delete(gimli_proc_t proc);

/** adds a reference to a proc handle */
void gimli_proc_addref(gimli_proc_t proc);

/** returns a proc handle to a target process.
 * If successful, the target process will be stopped.
 * Caller must gimli_proc_delete() the handle when it is no longer
 * needed */
gimli_err_t gimli_proc_attach(int pid, gimli_proc_t *proc);

/** Returns the PID of the target process.
 * A PID of 0 is returned if the target process is myself */
int gimli_proc_pid(gimli_proc_t proc);

/** Represents a mapping to the target process address space */
typedef struct gimli_mem_ref *gimli_mem_ref_t;

/** Returns mapping to the target address space.
 * Depending on the system and the target, this may be a live mapping
 * wherein writes to the local area are immediately reflected in the
 * target, or it may be a buffered copy of the data that will not
 * update in the target until gimli_proc_mem_commit() is called.
 * For portability, if you want to ensure that writes take effect,
 * you must always call gimli_proc_mem_commit at the appropriate time.
 * */
gimli_err_t gimli_proc_mem_ref(gimli_proc_t p,
    gimli_addr_t addr, size_t size, gimli_mem_ref_t *ref);

/** For targets that don't support direct mmap of the address space,
 * this function will apply changes in the mapping to the target.
 * Changes are not guaranteed to be applied unless you call this
 * function at the appropriate time */
gimli_err_t gimli_proc_mem_commit(gimli_mem_ref_t ref);

/** Returns base address of a mapping, in the target address space */
gimli_addr_t gimli_mem_ref_target(gimli_mem_ref_t mem);

/** Returns the base address of a mapping in my address space.
 * This is the start of the readable/writable mapped view of
 * the target process */
void *gimli_mem_ref_local(gimli_mem_ref_t mem);

/** Returns the size of the mapping */
size_t gimli_mem_ref_size(gimli_mem_ref_t mem);

/** deletes a reference to a mapping; when the last
 * reference is deleted, the mapping is no longer valid */
void gimli_mem_ref_delete(gimli_mem_ref_t mem);

/** adds a reference to a mapping */
void gimli_mem_ref_addref(gimli_mem_ref_t mem);


#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

