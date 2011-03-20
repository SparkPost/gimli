/*
 * Copyright (c) 2011 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */

#include "impl.h"
#include "ldb-objs.h"

#define LDB_META "ldb.meta"

static int ldb_attach(lua_State *L)
{
  int pid = luaL_checkint(L, 1);

  if (!tracer_attach(pid)) {
    luaL_error(L, "unable to attach to pid %d", pid);
  }

  return 0;
}

/* to call, an instance of ldb_thread must be on top of the stack;
 * it will be popped */
static struct ldb_frame *make_frame(lua_State *L,
  int nframe)
{
  struct ldb_thread *thr = luaL_checkudata(L, -1, LDB_THREAD);
  int ref;
  struct ldb_frame *f;

  /* pop thr, make a ref to it */
  ref = luaL_ref(L, LUA_REGISTRYINDEX);
  f = lua_newuserdata(L, sizeof(*f));
  f->thread_ref = ref;
  f->thr = thr;
  f->nframe = nframe;
  luaL_getmetatable(L, LDB_FRAME);
  lua_setmetatable(L, -2);

  if (nframe < 0 || nframe >= thr->nframes) {
    luaL_error(L, "frame %d is outside range 0-%d", nframe, thr->nframes - 1);
  }
  f->frame = thr->frames[nframe];
  gimli_is_signal_frame(&f->frame);

  return f;
}

static int ldb_frame_gc(lua_State *L)
{
  struct ldb_frame *f = luaL_checkudata(L, -1, LDB_FRAME);

  luaL_unref(L, LUA_REGISTRYINDEX, f->thread_ref);
  f->thread_ref = LUA_NOREF;
  f->thr = NULL;

  return 0;
}

static int ldb_frame_tostring(lua_State *L)
{
  struct ldb_frame *f = luaL_checkudata(L, -1, LDB_FRAME);

  if (f->thr) {
    lua_pushfstring(L, "frame #%d of LWP %d", f->nframe, f->thr->st->lwpid);
  } else {
    lua_pushfstring(L, "frame #%d (finalized)", f->nframe);
  }

  return 1;
}

static int ldb_frame_from_frame(lua_State *L, int up)
{
  struct ldb_frame *f = luaL_checkudata(L, -1, LDB_FRAME);
  int nframe = f->nframe + up;
  
  if (nframe < 0 || nframe >= f->thr->nframes) {
    lua_pushnil(L);
    return 1;
  }

  lua_rawgeti(L, LUA_REGISTRYINDEX, f->thread_ref);
  make_frame(L, nframe);
  return 1;
}

static int ldb_frame_index(lua_State *L)
{
  struct ldb_frame *f = luaL_checkudata(L, 1, LDB_FRAME);
  const char *what = luaL_checkstring(L, 2);

  if (!strcmp(what, "up")) {
    lua_pop(L, 1);
    return ldb_frame_from_frame(L, 1);
  }
  if (!strcmp(what, "down")) {
    lua_pop(L, 1);
    return ldb_frame_from_frame(L, -1);
  }
  if (!strcmp(what, "pc")) {
    char pcbuf[30];
    snprintf(pcbuf, sizeof(pcbuf), PTRFMT, (PTRFMT_T)f->frame.st.pc);
    lua_pushstring(L, pcbuf);
    return 1;
  }
  /* fall back to other methods in the metatable */
  lua_getmetatable(L, 1);
  lua_pushvalue(L, 2);
  lua_gettable(L, -2);
  return 0;
}

static const luaL_Reg ldb_frame_funcs[] = {
  {"__gc", ldb_frame_gc},
  {"__tostring", ldb_frame_tostring},
  {"__index", ldb_frame_index},
  {NULL, NULL}
};

static int ldb_frames_gc(lua_State *L)
{
  struct ldb_frames *f = luaL_checkudata(L, 1, LDB_FRAMES);

  luaL_unref(L, LUA_REGISTRYINDEX, f->thread_ref);
  f->thread_ref = LUA_NOREF;
  f->thr = NULL;

  return 0;
}

static int ldb_frames_index(lua_State *L)
{
  struct ldb_frames *f = luaL_checkudata(L, 1, LDB_FRAMES);
  int nframe = luaL_checkint(L, 2);

  /* push thread on to stack for make_frame */
  lua_rawgeti(L, LUA_REGISTRYINDEX, f->thread_ref);
  make_frame(L, nframe);
  return 1;
}

static int ldb_frames_iter(lua_State *L)
{
  struct ldb_frames *f = luaL_checkudata(L, 1, LDB_FRAMES);

  if (f->nframe >= f->thr->nframes) {
    lua_pushnil(L);
    f->nframe = 0;
    return 1;
  }

  /* push thread on to stack for make_frame */
  lua_rawgeti(L, LUA_REGISTRYINDEX, f->thread_ref);
  make_frame(L, f->nframe++);
  return 1;
}

static const luaL_Reg ldb_frames_funcs[] = {
  {"__gc", ldb_frames_gc},
  {"__index", ldb_frames_index},
  {"__call", ldb_frames_iter},
  {NULL, NULL}
};

static int ldb_thread_tostring(lua_State *L)
{
  struct ldb_thread *thr = luaL_checkudata(L, 1, LDB_THREAD);
  lua_pushfstring(L, "thread:tid=%d:LWP=%d:frames=%d",
    thr->tid, thr->st->lwpid, thr->nframes);
  return 1;
}

static int ldb_thread_frames(lua_State *L)
{
  struct ldb_thread *thr = luaL_checkudata(L, 1, LDB_THREAD);
  struct ldb_frames *frames;
  int ref;

  /* pop off the name "frames" */
  lua_pop(L, 1);


  frames = lua_newuserdata(L, sizeof(*frames));
  luaL_getmetatable(L, LDB_FRAMES);
  lua_setmetatable(L, -2);
  frames->thr = thr;
  /* make a ref to thr */
  lua_pushvalue(L, 1);
  frames->thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  frames->nframe = 0;

  return 1;
}

static int ldb_thread_index(lua_State *L)
{
  struct ldb_thread *f = luaL_checkudata(L, 1, LDB_THREAD);
  const char *what = luaL_checkstring(L, 2);

  if (!strcmp(what, "frames")) {
    return ldb_thread_frames(L);
  }
  luaL_error(L, "no such property frame.%s", what);
  return 0;
}

static const luaL_Reg ldb_thread_funcs[] = {
  {"__tostring", ldb_thread_tostring},
  {"__index", ldb_thread_index},
  {NULL, NULL},
};

static void make_thread(lua_State *L, int i)
{
  struct ldb_thread *thr;
  int nf;

  if (i < 0 || i >= gimli_nthreads) {
    luaL_error(L, "invalid thread index %d (range is 0-%d)",
        i, gimli_nthreads-1);
  }

  thr = lua_newuserdata(L, sizeof(*thr));
  luaL_getmetatable(L, LDB_THREAD);
  lua_setmetatable(L, -2);

  thr->tid = i;
  thr->st = &gimli_threads[i];
  thr->nframes = gimli_stack_trace(i, thr->frames, LDB_MAX_FRAMES);
  for (nf = 0; nf < thr->nframes; nf++) {
    thr->pcaddrs[nf] = thr->frames[nf].st.pc;
    thr->contexts[nf] = &thr->frames[nf];
  }
}

static int ldb_threads_index(lua_State *L)
{
  int nthr = luaL_checkint(L, 2);

  make_thread(L, nthr);
  return 1;
}

static int ldb_threads_iter(lua_State *L)
{
  struct ldb_threads *thr = luaL_checkudata(L, 1, LDB_THREADS);

  if (thr->nthr >= gimli_nthreads) {
    lua_pushnil(L);
    thr->nthr = 0;
    return 1;
  }

  make_thread(L, thr->nthr++);
  return 1;
}

static const luaL_Reg ldb_threads_funcs[] = {
  {"__index", ldb_threads_index},
  {"__call", ldb_threads_iter},
  {NULL, NULL}
};

static int ldb_index(lua_State *L)
{
  const char *what = luaL_checkstring(L, 2);

  if (!strcmp(what, "threads")) {
    struct ldb_threads *t = lua_newuserdata(L, sizeof(*t));

    t->nthr = 0;
    luaL_getmetatable(L, LDB_THREADS);
    lua_setmetatable(L, -2);
    return 1;
  }

  /* fall back to other methods in the metatable */
  lua_getmetatable(L, 1);
  lua_pushvalue(L, 2);
  lua_gettable(L, -2);
  return 1;
}

static const luaL_Reg ldb_funcs[] = {
  {"attach", ldb_attach},
  {"__index", ldb_index},
  {NULL, NULL},
};

static void newmeta(lua_State *L, const char *id, const struct luaL_Reg *funcs)
{
  luaL_newmetatable(L, id);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index"); /* mt.__index = mt */
  luaL_register(L, NULL, funcs);
}

void ldb_register(lua_State *L)
{
  newmeta(L, LDB_META, ldb_funcs);
  lua_createtable(L, 0, 0);
  luaL_getmetatable(L, LDB_META);
  lua_setmetatable(L, -2);
  lua_setglobal(L, "ldb");

  newmeta(L, LDB_THREADS, ldb_threads_funcs);
  newmeta(L, LDB_THREAD, ldb_thread_funcs);
  newmeta(L, LDB_FRAMES, ldb_frames_funcs);
  newmeta(L, LDB_FRAME, ldb_frame_funcs);
}


/* vim:ts=2:sw=2:et:
 */

