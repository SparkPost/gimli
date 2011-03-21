#ifndef LDB_OBJS_H
#define LDB_OBJS_H

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "gimli_dwarf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LDB_MAX_FRAMES 256

/* represents a thread */
struct ldb_thread {
  int tid;
  int nframes;
  struct gimli_thread_state *st;
  struct gimli_unwind_cursor frames[LDB_MAX_FRAMES];
  void *pcaddrs[LDB_MAX_FRAMES];
  void *contexts[LDB_MAX_FRAMES];
};
#define LDB_THREAD "ldb.thread"

/* iterator/accessor for threads */
struct ldb_threads {
  int nthr;
};
#define LDB_THREADS "ldb.threads"

/* represents a frame */
struct ldb_frame {
  int thread_ref;
  struct ldb_thread *thr;
  int nframe;
  struct gimli_unwind_cursor frame;
};
#define LDB_FRAME "ldb.frame"

/* iterator/accessor for frames */
struct ldb_frames {
  int thread_ref;
  struct ldb_thread *thr;
  int nframe;
};
#define LDB_FRAMES "ldb.frames"

/* iterator/access for variables in a frame */
struct ldb_vars {
  struct gimli_unwind_cursor cur;
  struct gimli_dwarf_die *die;
  struct gimli_dwarf_die *iter;
  uint64_t frame_base;
  uint64_t comp_unit_base;
  struct gimli_object_mapping *m;
};
#define LDB_VARS "ldb.vars"

/* represents a variable in the target */
struct ldb_var {
  struct gimli_unwind_cursor cur;
  struct gimli_dwarf_die *die;
  uint64_t frame_base;
  uint64_t comp_unit_base;
  struct gimli_object_mapping *m;
  int is_stack;
  struct gimli_dwarf_attr *type;
  struct gimli_dwarf_attr *name;
  uint64_t location;
};
#define LDB_VAR "ldb.var"

/* represents the value of a variable in the target.
 * This is basically a thin layer over an ldb_var. */
struct ldb_value {
  struct ldb_var var;
  struct gimli_dwarf_die *iter, *td;
  struct gimli_dwarf_attr *type;
  /* for bitfields */
  int mask, shift;
};
#define LDB_VALUE "ldb.value"

void ldb_register(lua_State *L);


#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

