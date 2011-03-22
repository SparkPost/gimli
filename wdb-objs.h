#ifndef WDB_OBJS_H
#define WDB_OBJS_H

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "gimli_dwarf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WDB_MAX_FRAMES 256

/* represents a thread */
struct wdb_thread {
  int tid;
  int nframes;
  struct gimli_thread_state *st;
  struct gimli_unwind_cursor frames[WDB_MAX_FRAMES];
  void *pcaddrs[WDB_MAX_FRAMES];
  void *contexts[WDB_MAX_FRAMES];
};
#define WDB_THREAD "wdb.thread"

/* iterator/accessor for threads */
struct wdb_threads {
  int nthr;
};
#define WDB_THREADS "wdb.threads"

/* represents a frame */
struct wdb_frame {
  int thread_ref;
  struct wdb_thread *thr;
  int nframe;
  struct gimli_unwind_cursor frame;
};
#define WDB_FRAME "wdb.frame"

/* iterator/accessor for frames */
struct wdb_frames {
  int thread_ref;
  struct wdb_thread *thr;
  int nframe;
};
#define WDB_FRAMES "wdb.frames"

/* iterator/access for variables in a frame */
struct wdb_vars {
  struct gimli_unwind_cursor cur;
  struct gimli_dwarf_die *die;
  struct gimli_dwarf_die *iter;
  uint64_t frame_base;
  uint64_t comp_unit_base;
  struct gimli_object_mapping *m;
};
#define WDB_VARS "wdb.vars"

/* represents a variable in the target */
struct wdb_var {
  struct gimli_unwind_cursor cur;
  struct gimli_dwarf_die *die;
  uint64_t frame_base;
  uint64_t comp_unit_base;
  struct gimli_object_mapping *m;
  int is_stack;
  struct gimli_dwarf_attr *type;
  struct gimli_dwarf_attr *name;
  uint64_t location;

  struct gimli_dwarf_die *iter, *td;
  /* for bitfields */
  int mask, shift;
};
#define WDB_VAR "wdb.var"

#if 0
/* represents the value of a variable in the target.
 * This is basically a thin layer over an wdb_var. */
struct wdb_value {
  struct wdb_var var;
  struct gimli_dwarf_die *iter, *td;
  struct gimli_dwarf_attr *type;
  /* for bitfields */
  int mask, shift;
};
#define WDB_VALUE "wdb.value"
#endif

void wdb_register(lua_State *L);


#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

