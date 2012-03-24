/*
 * Copyright (c) 2008-2011 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#ifndef IMPL_H
#define IMPL_H

#ifdef __linux__
# define _GNU_SOURCE 1
#endif
#ifdef __MACH__
/* in what looks like an honest omission, signal.h only requests 64-bit
 * ucontext structures on ppc platforms, so let's poke these defines to
 * force them to appear */
# define __need_mcontext64_t
# define __need_ucontext64_t
#endif

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <inttypes.h>
#include "gimli_config.h"
#include <pthread.h>
#include <libgen.h>
#ifdef sun
#define _STRUCTURED_PROC 1
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/frame.h>
#endif
#ifdef __FreeBSD__
#include <sys/procfs.h>
#endif

#ifdef __MACH__
#include <stdbool.h>
#include <mach/boolean.h>
#include <mach_debug/mach_debug.h>
#include <mach/mach_traps.h>
#include <mach/vm_map.h>
#include <mach/thread_status.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>
#include <mach-o/fat.h>
#include <mach-o/dyld_images.h>
#endif
#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/ptrace.h>
#endif
#if defined(sun) || defined(__FreeBSD__)
#include <proc_service.h>
#include <rtld_db.h>
#endif
#if defined(sun) || defined(__linux__) || defined(__FreeBSD__)
#include <thread_db.h>
#endif
#include <stdarg.h>
#include <dlfcn.h>
#ifdef __MACH__
#include "gimli_macho.h"
#else
#include "gimli_elf.h"
#endif
#include "libgimli.h"
#include "libgimli_ana.h"

#ifdef __cplusplus
extern "C" {
#endif

struct gimli_dwarf_reg_column {
  int rule; /* DW_RULE_XXX */
  uint64_t value; /* operand */
  const uint8_t *ops;
};

#define GIMLI_MAX_DWARF_REGS 42
#define GIMLI_DWARF_CFA_REG GIMLI_MAX_DWARF_REGS-2
#define GIMLI_DWARF_CFA_OFF GIMLI_MAX_DWARF_REGS-1
struct gimli_dwarf_unwind_state {
  struct gimli_dwarf_reg_column cols[GIMLI_MAX_DWARF_REGS];
};


typedef struct libgimli_hash_table *gimli_hash_t;

struct gimli_heartbeat {
  int state;
  int ticks;
};

struct gimli_thread_state {
  void *pc; /* pc in frame 0 */
  void *fp; /* frame pointer */
  void *sp; /* stack pointer */
  int lwpid;
#if defined(__linux__)
  struct user_regs_struct regs;
#elif defined(sun)
  prgregset_t regs;
  lwpstatus_t lwpst; 
#elif defined(__FreeBSD__)
  gregset_t regs;
#elif defined(__MACH__) && defined(__x86_64__)
  x86_thread_state64_t regs;
#elif defined(__MACH__)
  x86_thread_state32_t regs;
#endif
};
struct gimli_unwind_cursor {
  struct gimli_thread_state st;
  struct gimli_dwarf_unwind_state dw;
  /* if a signal frame, the signal that triggered it */
  siginfo_t si;
  int frameno;
  int tid;
  int dwarffail;
};

struct dw_secinfo {
  int idx;
  int size;
  char *data, *end;
  char *cur;
};

struct gimli_line_info {
  char *filename;
  uint64_t lineno;
  void *addr;
  void *end;
};

#ifdef __MACH__
typedef struct gimli_macho_object gimli_object_file_t;
#else
typedef struct gimli_elf_ehdr gimli_object_file_t;
#endif

struct gimli_section_data {
  char *name;
  uint8_t *data;
  uint64_t size;
  uint64_t offset;
  uint64_t addr;
  gimli_object_file_t *container;
};

struct gimli_section_data *gimli_get_section_by_name(
  gimli_object_file_t *elf, const char *name);

struct gimli_object_file {
  char *objname;
  struct gimli_object_file *next;
  int fd;
  /* primary object for the mapped module */
  gimli_object_file_t *elf;
  /* alternate object containing aux debug info */
  gimli_object_file_t *aux_elf;

  gimli_hash_t symbols; /* symname => gimli_symbol */
  struct gimli_symbol **symtab;
  struct gimli_symbol *symroot;
  uint64_t symcount;

  uint64_t base_addr;

  struct gimli_line_info *lines;
  uint64_t linecount;

  gimli_hash_t dies; /* offset-string => gimli_dwarf_die */
  struct gimli_dwarf_die *first_die;
  struct gimli_ana_module *tracer_module;

  gimli_hash_t sections; /* sectname => gimli_section_data */
};

struct gimli_object_mapping {
  struct gimli_object_mapping *next;
  void *base;
  unsigned long len;
  unsigned long offset;
  struct gimli_object_file *objfile;
  struct dw_fde *fdes;
  unsigned int num_fdes;
  struct dw_die_arange *arange;
  unsigned int num_arange;
};

extern int debug, quiet, detach, watchdog_interval, watchdog_start_interval,
  watchdog_stop_interval, do_setsid, respawn_frequency, trace_interval;
extern int run_only_once;
extern int immortal_child;
extern int run_as_uid, run_as_gid;
extern char *glider_path, *trace_dir, *gimli_progname, *pidfile, *arg0;
extern char *log_file;
extern int gimli_nthreads;
extern int max_frames;
extern struct gimli_thread_state *gimli_threads;
extern struct gimli_object_file *gimli_files;
extern struct gimli_object_mapping *gimli_mappings;

extern void logprint(const char *fmt, ...);

struct gimli_object_mapping *gimli_add_mapping(
  const char *objname, void *base, unsigned long len,
  unsigned long offset);
struct gimli_object_mapping *gimli_mapping_for_addr(void *addr);

struct gimli_object_file *gimli_add_object(
  const char *objname, void *base);
struct gimli_symbol *gimli_add_symbol(struct gimli_object_file *f,
  const char *name, void *addr, uint32_t size);
struct gimli_object_file *gimli_find_object(
  const char *objname);

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

#if SIZEOF_VOIDP == 8
# define PTRFMT "0x%016llx"
# define PTRFMT_T uint64_t
#else
# define PTRFMT "0x%08lx"
# define PTRFMT_T uint32_t
#endif 

int gimli_process_elf(struct gimli_object_file *f);
int gimli_process_dwarf(struct gimli_object_file *f);
int gimli_unwind_next(struct gimli_unwind_cursor *cur);
int gimli_dwarf_unwind_next(struct gimli_unwind_cursor *cur);
int gimli_dwarf_regs_to_thread(struct gimli_unwind_cursor *cur);
int gimli_thread_regs_to_dwarf(struct gimli_unwind_cursor *cur);
void *gimli_reg_addr(struct gimli_unwind_cursor *cur, int col);
int dwarf_determine_source_line_number(void *pc, char *src, int srclen,
  uint64_t *lineno);

char **gimli_init_proctitle(int argc, char **argv);
void gimli_set_proctitle(const char *fmt, ...);
void gimli_set_proctitlev(const char *fmt, va_list ap);

extern struct gimli_ana_api ana_api;

int process_args(int *argc, char **argv[]);

int gimli_demangle(const char *mangled, char *out, int out_size);

int gimli_attach(int pid);
int gimli_detach(void);

const char *gimli_pc_sym_name(void *addr, char *buf, int buflen);
int gimli_read_mem(void *src, void *dest, int len);
struct gimli_symbol *gimli_sym_lookup(const char *obj, const char *name);
char *gimli_read_string(void *addr);
int gimli_get_parameter(void *context, const char *varname,
  const char **datatype, void **addr, uint64_t *size);
extern struct gimli_symbol *find_symbol_for_addr(struct gimli_object_file *f,
  void *addr);
struct gimli_dwarf_attr *gimli_dwarf_die_get_attr(
  struct gimli_dwarf_die *die, uint64_t attrcode);

#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

