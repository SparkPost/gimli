#ifndef LDB_OBJS_H
#define LDB_OBJS_H

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

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

void ldb_register(lua_State *L);


#ifdef __cplusplus
}
#endif

#endif

/* vim:ts=2:sw=2:et:
 */

