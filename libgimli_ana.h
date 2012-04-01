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

/* forward declarations */
struct libgimli_hash_table;
struct gimli_proc;
struct gimli_mem_ref;
struct gimli_type;
struct gimli_type_collection;
struct gimli_thread_state;
struct gimli_stack_frame;
struct gimli_stack_trace;
struct gimli_variable;

/** a container of type information */
typedef struct gimli_type_collection *gimli_type_collection_t;
/** represents type information */
typedef struct gimli_type *gimli_type_t;
/** a hash table */
typedef struct libgimli_hash_table *gimli_hash_t;
/** opaque type represents a target process, which may be myself */
typedef struct gimli_proc *gimli_proc_t;
/** Represents a mapping to the target process address space */
typedef struct gimli_mem_ref *gimli_mem_ref_t;
/** Represents a thread in a target process */
typedef struct gimli_thread_state *gimli_thread_t;
/** Represents a stack trace */
typedef struct gimli_stack_trace *gimli_stack_trace_t;
/** Represents a stack frame in a stack trace */
typedef struct gimli_stack_frame *gimli_stack_frame_t;
/** Represents a variable */
typedef struct gimli_variable *gimli_var_t;
/** represents a pointer on any architecture */
typedef uint64_t gimli_addr_t;

struct gimli_symbol {
  /** de-mangled symbol name */
  const char *name;
  /** raw, un-mangled symbol name */
  const char *rawname;
  /** resolved address in the target process */
  gimli_addr_t addr;
  /** size of the symbol. Not all systems provide this information
   * for all symbols */
  uint32_t size;
};

#define GIMLI_ANA_API_VERSION 2

/* {{{ Deprecated V1 and V2 Gimli APIs enclosed in this block */

struct gimli_proc_stat {
  pid_t pid;
  size_t pr_size;
  size_t pr_rssize;
};

struct gimli_ana_api {
  int api_version;
  /** lookup a symbol based on its raw, un-mangled, name.
   * @deprecated use gimli_sym_lookup() instead.
   * */
  struct gimli_symbol *(*sym_lookup)(const char *obj, const char *name);

  /** compute a readable label for an address.
   * @deprecated use gimli_data_sym_name() or gimli_pc_sym_name() instead.
   * */
  const char *(*sym_name)(void *addr, char *buf, int buflen);

  /** read memory from the target process, returns the length that
   * was successfully read.
   * @deprecated use gimli_read_mem() or gimli_proc_mem_ref()
   * */
  int (*read_mem)(void *src, void *dest, int len);

  /** read a NUL terminated string from target process.
   * The caller must free() the memory when it is no longer required.
   * @deprecated use gimli_read_string()
   * */
  char *(*read_string)(void *src);

/* API Version 2 begins here */

  /** determine the source filename and line number information
   * for a given code address.
   * Returns 1 if the source information is found, 0 otherwise.
   * Populates filebuf and lineno if the source is found.
   * @deprecated use gimli_determine_source_line_number()
   * */
  int (*get_source_info)(void *addr, char *buf, int buflen, int *lineno);

  /** Given a context, locate a named parameter and return its
   * C-style datatype name, address and size.  Returns 1 if located.
   * 0 otherwise.
   * context is a gimli_stack_frame_t.
   * @deprecated use gimli_stack_frame_resolve_var()
   * */
  int (*get_parameter)(void *context, const char *varname,
    const char **datatype, void **addr, uint64_t *size);

  /** Lookup a symbol, treat it as a char* in the target and
   * return a copy of the NUL-terminated string to which it points.
   * This is logically equivalent to sym_lookup, deref'ing the
   * result, and then read_string'ing the result of that.
   * The caller must free() the return memory when it is no longer
   * required.
   * @deprecated use gimli_get_string_symbol()
   * */
  char *(*get_string_symbol)(const char *obj, const char *name);

  /** Lookup a symbol and copy its target into a caller provided
   * buffer.
   * If deref is non-zero, the symbol value is treated as pointer
   * with that many levels of indirection; this function will
   * de-reference each of those levels to arrive at a final address.
   * SIZE bytes of data will then be read from the final address
   * and copied in the the caller provided buffer.
   * Returns 0 if SIZE could not be read completely, 1 on success.
   * @deprecated use gimli_copy_from_symbol()
   * */
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
   * PCADDR is the instruction address of that frame, and CONTEXT is a
   * gimli_stack_frame_t that can be used to interrogate that frame.
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
   * gimli_stack_frame_t that can be used to interrogate that frame.
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
   * gimli_stack_frame_t that can be used to interrogate that frame */
  void (*after_print_frame)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int frameno, void *pcaddr, void *context);
  /* inform a module that we're done tracing a thread.
   * NFRAMES is the number of stack frames found for this thread.
   * PCADDRS is an array containing the instruction addresses of each
   * frame.
   * CONTEXTS is an array of gimli_stack_frame_t that
   * can be passed to the API to interrogate the respective frames.
   */
  void (*on_end_thread_trace)(
    const struct gimli_ana_api *api, const char *object, int tid,
    int nframes, void **pcaddrs, void **contexts);
};

typedef struct gimli_ana_module *(*gimli_module_init_func)(
  const struct gimli_ana_api *api);
extern struct gimli_ana_module *gimli_ana_init(const struct gimli_ana_api *api);

/* }}} end of deprecated V1 and V2 APIs */

/* Version 3 APIs start here */

/** hash table utility API */

typedef enum {
  /** done iterating */
  GIMLI_ITER_STOP = 0,
  /** keep going */
  GIMLI_ITER_CONT = 1,
  /** like stop, but implies error */
  GIMLI_ITER_ERR = 2,
} gimli_iter_status_t;

typedef gimli_iter_status_t (*gimli_hash_iter_func_t)(
  const char *k, int klen, void *item, void *arg
);
typedef void (*gimli_hash_free_func_t)(void *item);

#define GIMLI_HASH_INITIAL_SIZE (1<<7)
/** duplicate keys when added.  If not set, caller is responsible
 * for ensuring that the key pointer used remains valid for the
 * lifetime of the item in hash */
#define GIMLI_HASH_DUP_KEYS   1
/** keys are treated as pointer values instead of strings */
#define GIMLI_HASH_PTR_KEYS   2
/** keys are treated as uint64_t values instead of strings */
#define GIMLI_HASH_U64_KEYS   4

gimli_hash_t gimli_hash_new_size(gimli_hash_free_func_t dtor, uint32_t flags, size_t size);
gimli_hash_t gimli_hash_new(gimli_hash_free_func_t dtor);
int gimli_hash_size(gimli_hash_t h);
int gimli_hash_iter(gimli_hash_t h, gimli_hash_iter_func_t func, void *arg);
void gimli_hash_destroy(gimli_hash_t h);
void gimli_hash_delete_all(gimli_hash_t h, int downsize);
int gimli_hash_delete(gimli_hash_t h, const char *k);
int gimli_hash_find(gimli_hash_t h, const char *k, void **item_p);
int gimli_hash_insert(gimli_hash_t h, const char *k, void *item);

int gimli_hash_delete_u64(gimli_hash_t h, uint64_t k);
int gimli_hash_find_u64(gimli_hash_t h, uint64_t k, void **item_p);
int gimli_hash_insert_u64(gimli_hash_t h, uint64_t k, void *item);

int gimli_hash_delete_ptr(gimli_hash_t h, void * k);
int gimli_hash_find_ptr(gimli_hash_t h, void * k, void **item_p);
int gimli_hash_insert_ptr(gimli_hash_t h, void * k, void *item);


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

typedef gimli_iter_status_t gimli_proc_visit_thread_f(
    gimli_proc_t proc,
    gimli_thread_t thread,
    void *arg);

/** visit each of the threads associated with a proc */
gimli_iter_status_t gimli_proc_visit_threads(
    gimli_proc_t proc,
    gimli_proc_visit_thread_f func,
    void *arg);

/** Obtain a stack trace from a thread */
gimli_stack_trace_t gimli_thread_stack_trace(gimli_thread_t thr, int max_frames);

void gimli_stack_trace_addref(gimli_stack_trace_t trace);
void gimli_stack_trace_delete(gimli_stack_trace_t trace);

int gimli_stack_trace_num_frames(gimli_stack_trace_t trace);



/** visit each frame of a stack trace */
typedef gimli_iter_status_t gimli_stack_trace_visit_f(
      gimli_proc_t proc,
      gimli_thread_t thread,
      gimli_stack_frame_t frame,
      void *arg);

gimli_iter_status_t gimli_stack_trace_visit(
    gimli_stack_trace_t trace,
    gimli_stack_trace_visit_f func,
    void *arg);

gimli_addr_t gimli_stack_frame_pcaddr(gimli_stack_frame_t frame);
int gimli_stack_frame_number(gimli_stack_frame_t frame);

int gimli_stack_frame_resolve_var(gimli_stack_frame_t frame,
    int filter,
    const char *varname, gimli_type_t *datatype, gimli_addr_t *addr
    );

/** visit each variable in a frame of a stack trace */
typedef gimli_iter_status_t gimli_stack_frame_visit_f(
    gimli_stack_frame_t frame,
    gimli_var_t var,
    void *arg);

#define GIMLI_WANT_PARAMS  0x1
#define GIMLI_WANT_LOCALS  0x2
#define GIMLI_WANT_ALL     (GIMLI_WANT_PARAMS|GIMLI_WANT_LOCALS)

gimli_iter_status_t gimli_stack_frame_visit_vars(
    gimli_stack_frame_t frame,
    int filter,
    gimli_stack_frame_visit_f func,
    void *arg);

/** Given ADDR and a type definition, print out the contents of
 * ADDR interpreted as that type, using VARNAME as the hypothetical
 * name of the variable */
int gimli_print_addr_as_type(gimli_proc_t proc, const char *varname,
    gimli_type_t t, gimli_addr_t addr);

const char *gimli_data_sym_name(gimli_proc_t proc,
    gimli_addr_t addr, char *buf, int buflen);
const char *gimli_pc_sym_name(gimli_proc_t proc,
    gimli_addr_t addr, char *buf, int buflen);
struct gimli_symbol *gimli_sym_lookup(gimli_proc_t proc,
    const char *obj, const char *name);

int gimli_determine_source_line_number(gimli_proc_t proc,
  gimli_addr_t pc, char *src, int srclen,
  uint64_t *lineno);

/* {{{ Reading and writing memory */

/** Read memory from SRC address in the target and copy it into the
 * buffer DEST whose length is LEN.
 * Returns the number of bytes that were successfully read from the
 * target */
int gimli_read_mem(gimli_proc_t proc, gimli_addr_t src, void *dest, int len);

/** Write memory to DEST address in the target by copying it from the
 * buffer SRC whose length is LEN.
 * Returns the number of bytes that were successfully written to the
 * target */
int gimli_write_mem(gimli_proc_t proc, gimli_addr_t dest, const void *src, int len);

/** Given the address of a pointer in the target, de-reference it
 * and return the result.
 * This automatically handles differences in pointer size between
 * gimli and the target process */
int gimli_read_pointer(gimli_proc_t proc, gimli_addr_t addr, gimli_addr_t *val);

/** read a NUL terminated string from target process.
 * The caller must free() the memory when it is no longer required.  */
char *gimli_read_string(gimli_proc_t proc, gimli_addr_t addr);

/** Lookup a symbol, treat it as a char* in the target and return a copy of the
 * NUL-terminated string to which it points.
 * This is logically equivalent to
 * sym_lookup, deref'ing the result, and then read_string'ing the result of
 * that.  The caller must free() the returned memory when it is no longer
 * required. */
char *gimli_get_string_symbol(gimli_proc_t proc,
    const char *obj, const char *name);

/** Lookup a symbol and copy its target into a caller provided buffer.
 * If deref is non-zero, the symbol value is treated as pointer with that
 * many levels of indirection; this function will de-reference each of those
 * levels to arrive at a final address.  SIZE bytes of data will then be read
 * from the final address and copied in the the caller provided buffer.
 * Returns 0 if SIZE could not be read completely, 1 on success */
int gimli_copy_from_symbol(const char *obj, const char *name,
  int deref, void *buf, uint32_t size);

/** Returns mapping to the target address space.
 * Writes will be buffered and will not reflect in the target
 * until gimli_proc_mem_commit() is called.
 *
 * NOTE! always verify the length of the mapping, as it may be
 * shorter than you requested, especially if a portion of the
 * range is invalid.
 * */
gimli_err_t gimli_proc_mem_ref(gimli_proc_t p,
    gimli_addr_t addr, size_t size, gimli_mem_ref_t *ref);

/** apply changes in the mapping to the target.
 * Changes are not guaranteed to be applied unless you call this
 * function at the appropriate time */
gimli_err_t gimli_proc_mem_commit(gimli_mem_ref_t ref);

/** Returns base address of a mapping, in the target address space */
gimli_addr_t gimli_mem_ref_target(gimli_mem_ref_t mem);

/** Returns the base address of a mapping in my address space.
 * This is the start of the readable/writable view of
 * the target process */
void *gimli_mem_ref_local(gimli_mem_ref_t mem);

/** Returns the size of the mapping */
size_t gimli_mem_ref_size(gimli_mem_ref_t mem);

/** deletes a reference to a mapping; when the last
 * reference is deleted, the mapping is no longer valid */
void gimli_mem_ref_delete(gimli_mem_ref_t mem);

/** adds a reference to a mapping */
void gimli_mem_ref_addref(gimli_mem_ref_t mem);

/* }}} */

/* {{{ --- types */

gimli_type_t gimli_find_type_by_name(gimli_proc_t proc,
    const char *objname,
    const char *tname);

gimli_type_t gimli_find_type_by_addr(gimli_proc_t proc,
    gimli_addr_t addr);

/** create a new empty type collection object */
gimli_type_collection_t gimli_type_collection_new(void);

/** add a reference to a type collection */
void gimli_type_collection_addref(gimli_type_collection_t col);

/** deletes a reference to a type collection */
void gimli_type_collection_delete(gimli_type_collection_t col);

/** lookup a type by name */
gimli_type_t gimli_type_collection_find_type(
    gimli_type_collection_t col, const char *name);

/** lookup a function by name */
gimli_type_t gimli_type_collection_find_function(
    gimli_type_collection_t col, const char *name);

/** callback function for visiting types in a collection */
typedef gimli_iter_status_t gimli_type_collection_visit_f(
    /** collection being walked */
    gimli_type_collection_t col,
    /** type being visited */
    gimli_type_t t,
    /** caller provided closure */
    void *arg);

/** visit each type in the collection */
gimli_iter_status_t gimli_type_collection_visit(
    gimli_type_collection_t col,
    gimli_type_collection_visit_f func, void *arg);

/** returns the name of the variable or member for this type */
const char *gimli_type_name(gimli_type_t t);

/** returns the C-style type name for this type */
const char *gimli_type_declname(gimli_type_t t);

/** returns the number of bits required
 * to hold an instance of this type */
size_t gimli_type_size(gimli_type_t t);

/** returns the "kind" of the type */
int gimli_type_kind(gimli_type_t t);

#define GIMLI_K_INTEGER  1
#define GIMLI_K_FLOAT    2
#define GIMLI_K_POINTER  3
#define GIMLI_K_ARRAY    4
#define GIMLI_K_FUNCTION 5
#define GIMLI_K_STRUCT   6
#define GIMLI_K_UNION    7
#define GIMLI_K_ENUM     8
#define GIMLI_K_TYPEDEF  9
#define GIMLI_K_VOLATILE 10
#define GIMLI_K_CONST    11
#define GIMLI_K_RESTRICT 12

/** integer is signed (otherwise unsigned) */
#define GIMLI_INT_SIGNED 0x1
/** character display format */
#define GIMLI_INT_CHAR   0x2
/** boolean display format */
#define GIMLI_INT_BOOL   0x4
/** varargs display format */
#define GIMLI_INT_VARARGS 0x8

#define GIMLI_FP_SINGLE 1
#define GIMLI_FP_DOUBLE 2
#define GIMLI_FP_COMPLEX 3
#define GIMLI_FP_IMAGINARY 4
#define GIMLI_FP_LONG_DOUBLE 5

/** generic encoding information */
struct gimli_type_encoding {
  /** GIMLI_INT_XXX for integer types,
   * GIMLI_FP_XXX for floating point */
  uint32_t format;
  /** offset of value in bits */
  uint32_t offset;
  /** size of storage in bits */
  uint32_t bits;
};

/** returns the encoding information for
 * the type */
void gimli_type_encoding(gimli_type_t t,
    struct gimli_type_encoding *enc);

/** create an instance of an integer type */
gimli_type_t gimli_type_new_integer(gimli_type_collection_t col,
    const char *name, const struct gimli_type_encoding *enc);

/** create an instance of a float type */
gimli_type_t gimli_type_new_float(gimli_type_collection_t col,
    const char *name, const struct gimli_type_encoding *enc);

/** follow a type graph, skipping aliasing nodes (typedef, volatile, const,
 * restrict) until we reach a base type */
gimli_type_t gimli_type_resolve(gimli_type_t t);

/** create a new volatile type */
gimli_type_t gimli_type_new_volatile(gimli_type_collection_t col,
    gimli_type_t t);

/** create a new "restrict" type */
gimli_type_t gimli_type_new_restrict(gimli_type_collection_t col,
    gimli_type_t t);

/** create a new "const" type */
gimli_type_t gimli_type_new_const(gimli_type_collection_t col,
    gimli_type_t t);

/** create a new pointer type */
gimli_type_t gimli_type_new_pointer(gimli_type_collection_t col,
    gimli_type_t target);

/** return the target of a pointer type */
gimli_type_t gimli_type_follow_pointer(gimli_type_t t);

/** create a new "typedef" type */
gimli_type_t gimli_type_new_typedef(gimli_type_collection_t col,
    gimli_type_t target, const char *name);

/** information about struct/union members */
struct gimli_type_membinfo {
  /** type of member */
  gimli_type_t type;
  /** offset in bits */
  uint64_t offset;
  /** size in bits */
  uint64_t size;
};

/** returns information about a type member */
int gimli_type_membinfo(gimli_type_t t,
    /** name of the member */
    const char *name,
    struct gimli_type_membinfo *info);

typedef gimli_iter_status_t gimli_type_member_visit_f(
    const char *name,
    struct gimli_type_membinfo *info,
    void *arg
    );

/** visit each member of a structure or union type */
gimli_iter_status_t gimli_type_member_visit(
    gimli_type_t t,
    gimli_type_member_visit_f func,
    void *arg
    );

/** create an instance of a structure type */
gimli_type_t gimli_type_new_struct(gimli_type_collection_t col,
    const char *name);

/** create an instance of a union type */
gimli_type_t gimli_type_new_union(gimli_type_collection_t col,
    const char *name);

/** add a new member to a structure type.
 * Note that you can set the encoding on membertype
 * to control the offset and size of the member */
int gimli_type_add_member(gimli_type_t t,
    const char *name,
    gimli_type_t membertype,
    /* if 0, size and offset are computed from membertype,
     * otherwise, specify size and offset in bits */
    uint64_t size,
    uint64_t offset
    );

/** add a new "enum" type */
gimli_type_t gimli_type_new_enum(gimli_type_collection_t col,
    const char *name, const struct gimli_type_encoding *enc);

/** add an enum value */
int gimli_type_enum_add(gimli_type_t t, const char *name,
    int value);

/** resolve an enum value to a label */
const char *gimli_type_enum_resolve(gimli_type_t t, int value);


/** information about arrays */
struct gimli_type_arinfo {
  /** type of array elements */
  gimli_type_t contents;
  /** size of the array */
  uint32_t nelems;
};

/** returns array information */
int gimli_type_arinfo(gimli_type_t t,
    struct gimli_type_arinfo *info);

/** create a new array type */
gimli_type_t gimli_type_new_array(gimli_type_collection_t col,
    const struct gimli_type_arinfo *info);

/** information about functions */
struct gimli_type_funcinfo {
  /** return type */
  gimli_type_t rettype;
  /** number of arguments */
  uint32_t nargs;
  /** flags */
  uint32_t flags;
/** if set in flags, the function is variadic */
#define GIMLI_FUNC_VARARG 0x1
};

/** returns function information */
int gimli_type_funcinfo(gimli_type_t t,
    struct gimli_type_funcinfo *info);

gimli_type_t gimli_type_new_function(gimli_type_collection_t col,
    const char *name,
    uint32_t flags,
    gimli_type_t rettype);

int gimli_type_function_add_parameter(gimli_type_t func,
    const char *name, gimli_type_t arg);


/** callback function for recursively visiting a
 * type */
typedef gimli_iter_status_t gimli_type_visit_f(
    /** name of member */
    const char *name,
    /** type being visited */
    gimli_type_t t,
    /** offset in bits */
    uint64_t offset,
    /** depth of recursion */
    int depth,
    /** caller provided closure */
    void *arg);

/** recursively visit a type */
gimli_iter_status_t gimli_type_visit(gimli_type_t t,
    gimli_type_visit_f func,
    void *arg);

/* }}} */

#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

