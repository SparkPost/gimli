/*
 * Copyright (c) 2011 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */

#include "impl.h"
#include "wdb-objs.h"

#define WDB_META "wdb.meta"

static int wdb_attach(lua_State *L)
{
  int pid = luaL_checkint(L, 1);

  if (!tracer_attach(pid)) {
    luaL_error(L, "unable to attach to pid %d", pid);
  }

  return 0;
}

static void wdb_push_address(lua_State *L, uint64_t addr)
{
  char pcbuf[30];

  snprintf(pcbuf, sizeof(pcbuf), PTRFMT, (PTRFMT_T)addr);
  lua_pushstring(L, pcbuf);
}

/* resolve a value down to the significant portion of its type.
 * This modifies the value struct so that this doesn't have to be
 * repeated again for the same value */
static void resolve_value(lua_State *L, struct wdb_var *var)
{
  struct gimli_dwarf_die *td;
  struct gimli_dwarf_attr *type;

  if (var->td) {
    /* already resolved */
    return;
  }
  type = var->type;

  while (type) {
    td = gimli_dwarf_get_die(var->m->objfile, type->code);
    if (!td) {
      return;
    }
    var->td = td;
    var->type = type;

    switch (td->tag) {
      case DW_TAG_typedef:
      case DW_TAG_const_type:
      case DW_TAG_volatile_type:
      case DW_TAG_shared_type:
      case DW_TAG_restrict_type:
        type = gimli_dwarf_die_get_attr(td, DW_AT_type);
        break;
      default:
        type = NULL;
    }
  }

}

/* resolve a value to an integer numeric */
static int resolve_numeric(lua_State *L, struct wdb_var *var,
  uintmax_t *n, int *is_signed)
{
  uint64_t ate, size;
  uint64_t u64;
  uint32_t u32;
  uint16_t u16;
  uint8_t u8;

  *is_signed = 0;

  switch (var->td->tag) {
    case DW_TAG_base_type:
    case DW_TAG_enumeration_type:
      if (!gimli_dwarf_die_get_uint64_t_attr(var->td, DW_AT_encoding, &ate)) {
        ate = DW_ATE_signed;
      }
      gimli_dwarf_die_get_uint64_t_attr(var->td, DW_AT_byte_size, &size);
      switch (ate) {
        case DW_ATE_signed:
        case DW_ATE_signed_char:
          *is_signed = 1;
          /* fall through */
        case DW_ATE_unsigned:
        case DW_ATE_unsigned_char:
          switch (size) {
            case 8:
              gimli_dwarf_read_value((void*)var->location,
                var->is_stack, &u64, size);
              *n = (uintmax_t)u64;
              break;
            case 4:
              gimli_dwarf_read_value((void*)var->location,
                var->is_stack, &u32, size);
              *n = (uintmax_t)u32;
              break;
            case 2:
              gimli_dwarf_read_value((void*)var->location,
                var->is_stack, &u16, size);
              *n = (uintmax_t)u16;
              break;
            case 1:
              gimli_dwarf_read_value((void*)var->location,
                var->is_stack, &u8, size);
              *n = (uintmax_t)u16;
              break;
            default:
              luaL_error(L, "invalid byte size %d", size);
          }
          if (var->mask) {
            *n >>= var->shift;
            *n &= var->mask;
          }
          return 1;
      }
  }
  printf("\nresolve_value: td->tag=%llu\n", var->td->tag);
  /* not numeric */
  return 0;
}

static int make_child_value(lua_State *L,
  struct wdb_var *var, struct gimli_dwarf_die *kid)
{
  int is_stack;
  struct gimli_dwarf_attr *loc;
  uint64_t root;
  int mask, shift;
  uint64_t u64;
  struct wdb_var *member;

  loc = gimli_dwarf_die_get_attr(kid, DW_AT_data_member_location);
  is_stack = 1;
  root = (uint64_t)(intptr_t)var->location;

  if (loc) {
    if (loc->form != DW_FORM_block) {
      fprintf(stderr, "unhandled loc->form %lld for struct member",
          loc->form);
      return 0;
    }
    if (!dw_eval_expr(&var->cur, loc->ptr, loc->code, 0,
          &root, &root, &is_stack)) {
      return 0;
    }
  } /* else: occupies start of element */

  if (gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_bit_size, &u64)) {
    /* it's a bit field */
    uint64_t size = u64;
    uint64_t off;

    if (!gimli_dwarf_die_get_uint64_t_attr(kid,
          DW_AT_bit_offset, &off)) {
      off = 1;
    }
    gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_byte_size, &u64);

    /* offset is number of bits from MSB for that storage type.
     * Let's flip that around so that it is the offset from the
     * LSB */
    off = ((u64 * 8) - 1) - off;
    mask = (1 << size) - 1;
    shift = off - (size - 1);

  } else {
    mask = 0;
    shift = 0;
  }
  member = lua_newuserdata(L, sizeof(*member));
  memcpy(member, var, sizeof(*var));
  luaL_getmetatable(L, WDB_VAR);
  lua_setmetatable(L, -2);

  /* update to reflect this member */
  member->name = gimli_dwarf_die_get_attr(kid, DW_AT_name);
  member->type = gimli_dwarf_die_get_attr(kid, DW_AT_type);
  member->is_stack = is_stack;
  member->location = root;
  member->die = kid;
  member->mask = mask;
  member->shift = shift;
  member->iter = NULL;
  member->td = NULL;

  return 1;
}

static int wdb_var_index(lua_State *L)
{
  struct wdb_var *var = luaL_checkudata(L, 1, WDB_VAR);

  resolve_value(L, var);
  switch (var->td->tag) {
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
    {
      struct gimli_dwarf_die *kid;
      struct gimli_dwarf_attr *mname;
      const char *what = luaL_checkstring(L, 2);

      /* find matching child element */
      for (kid = var->td->kids; kid; kid = kid->next) {
        if (kid->tag != DW_TAG_member) continue;

        mname = gimli_dwarf_die_get_attr(kid, DW_AT_name);
        if (!mname) continue;
        if (strcmp(mname->ptr, what)) continue;
        break;
      }
      if (!kid) {
        luaL_error(L, "no such element %s", what);
      }
      if (!make_child_value(L, var, kid)) {
        lua_pushnil(L);
      }
      return 1;
    }
    case DW_TAG_array_type:
      luaL_error(L, "FIXME: implement array access");
      break;
    default:
      luaL_error(L, "attempt to index a non-structured type");
  }
  return 0;
}

static int wdb_var_iter(lua_State *L)
{
  struct wdb_var *var = luaL_checkudata(L, 1, WDB_VAR);

  if (!var->iter) {
    resolve_value(L, var);
    switch (var->td->tag) {
      case DW_TAG_structure_type:
      case DW_TAG_union_type:
        var->iter = var->td->kids;
        break;
      default:
        lua_pushnil(L);
        return 1;
    }
  } else {
    var->iter = var->iter->next;
  }

  while (var->iter) {
    struct gimli_dwarf_attr *mname;

    if (var->iter->tag != DW_TAG_member) {
      var->iter = var->iter->next;
      continue;
    }
    mname = gimli_dwarf_die_get_attr(var->iter, DW_AT_name);
    if (mname) {
      lua_pushstring(L, mname->ptr);
    } else {
      lua_pushnil(L);
    }
    if (!make_child_value(L, var, var->iter)) {
      lua_pushnil(L);
    }
    return 2;
  }

  lua_pushnil(L);
  return 1;
}

static int wdb_var_tostring(lua_State *L)
{
  struct wdb_var *var = luaL_checkudata(L, 1, WDB_VAR);
  uintmax_t num;
  int is_signed;

  resolve_value(L, var);

  if (resolve_numeric(L, var, &num, &is_signed)) {
    char nbuf[32];

    if (is_signed) {
      snprintf(nbuf, sizeof(nbuf), "%ji", num);
    } else {
      snprintf(nbuf, sizeof(nbuf), "%ju", num);
    }

    lua_pushstring(L, nbuf);
    return 1;
  }

  // TODO
  lua_pushfstring(L, "not numeric");

  return 1;
}

static const luaL_Reg wdb_var_funcs[] = {
  {"__index", wdb_var_index},
  {"__call", wdb_var_iter},
  {"__tostring", wdb_var_tostring},
  {NULL, NULL}
};

static int wdb_var_ctype(lua_State *L)
{
  struct wdb_var *v = luaL_checkudata(L, 1, WDB_VAR);
  /* the "C" type name */
  lua_pushstring(L, gimli_dwarf_resolve_type_name(v->m->objfile, v->type));
  return 1;
}

static int wdb_var_tag(lua_State *L)
{
  struct wdb_var *v = luaL_checkudata(L, 1, WDB_VAR);

  /* var.tag => the dwarf type tag, as a string */
  struct gimli_dwarf_die *td;

  td = gimli_dwarf_get_die(v->m->objfile, v->type->code);
  if (!td) {
    lua_pushnil(L);
    return 1;
  }
  /* {{{ switch on td->tag, return string rep. */
  switch (td->tag) {
    case DW_TAG_base_type:
      lua_pushstring(L, "base");
      return 1;
    case DW_TAG_typedef:
      lua_pushstring(L, "typedef");
      return 1;
    case DW_TAG_enumeration_type:
      lua_pushstring(L, "enum");
      return 1;
    case DW_TAG_structure_type:
      lua_pushstring(L, "struct");
      return 1;
    case DW_TAG_union_type:
      lua_pushstring(L, "union");
      return 1;
    case DW_TAG_pointer_type:
      lua_pushstring(L, "pointer");
      return 1;
    case DW_TAG_subroutine_type:
      lua_pushstring(L, "subroutine");
      return 1;
    case DW_TAG_const_type:
      lua_pushstring(L, "const");
      return 1;
    case DW_TAG_array_type:
      lua_pushstring(L, "array");
      return 1;
    case DW_TAG_class_type:
      lua_pushstring(L, "class");
      return 1;
    case DW_TAG_reference_type:
      lua_pushstring(L, "reference");
      return 1;
    case DW_TAG_string_type:
      lua_pushstring(L, "string");
      return 1;
    case DW_TAG_ptr_to_member_type:
      lua_pushstring(L, "ptr_to_member");
      return 1;
    case DW_TAG_set_type:
      lua_pushstring(L, "set");
      return 1;
    case DW_TAG_subrange_type:
      lua_pushstring(L, "subrange");
      return 1;
    case DW_TAG_file_type:
      lua_pushstring(L, "file");
      return 1;
    case DW_TAG_packed_type:
      lua_pushstring(L, "packed");
      return 1;
    case DW_TAG_template_type_parameter:
      lua_pushstring(L, "template_type");
      return 1;
    case DW_TAG_thrown_type:
      lua_pushstring(L, "thrown");
      return 1;
    case DW_TAG_volatile_type:
      lua_pushstring(L, "volatile");
      return 1;
    case DW_TAG_restrict_type:
      lua_pushstring(L, "restrict");
      return 1;
    case DW_TAG_interface_type:
      lua_pushstring(L, "interface");
      return 1;
    case DW_TAG_unspecified_type:
      lua_pushstring(L, "unspecified");
      return 1;
    case DW_TAG_shared_type:
      lua_pushstring(L, "shared");
      return 1;
    default:
      /* Shouldn't happen */
      lua_pushfstring(L, "tag=%llx", td->tag);
      return 1;
  }
  /* }}} */
  return 1;
}

static int wdb_var_name(lua_State *L)
{
  struct wdb_var *v = luaL_checkudata(L, 1, WDB_VAR);

  /* var.typename => the dwarf type name, as a string */
  struct gimli_dwarf_die *td;

  td = gimli_dwarf_get_die(v->m->objfile, v->type->code);
  if (!td) {
    lua_pushnil(L);
  } else {
    struct gimli_dwarf_attr *name = gimli_dwarf_die_get_attr(td, DW_AT_name);

    if (name) {
      lua_pushstring(L, name->ptr);
    } else {
      lua_pushnil(L);
    }
  }
  return 1;
}

static int wdb_var_deref(lua_State *L)
{
  struct wdb_var *v = luaL_checkudata(L, 1, WDB_VAR);

  /* var.deref => if a pointer, follow the pointer to the next level var */
  struct gimli_dwarf_die *td;
  struct wdb_var *deref;
  struct gimli_dwarf_attr *type;
  uint64_t u64, size;
  uint32_t u32;

  td = gimli_dwarf_get_die(v->m->objfile, v->type->code);
  if (!td) {
    lua_pushnil(L);
    return 1;
  }
  if (td->tag != DW_TAG_pointer_type) {
    luaL_error(L, "Attempt to dereference a non-pointer");
  }
  type = gimli_dwarf_die_get_attr(td, DW_AT_type);
  if (!type) {
    // TODO: allow this by returning a var (with an address) that
    // can be cast to another type (make other accessors safe)
    luaL_error(L, "Attempt to dereference a void pointer");
  }

  deref = lua_newuserdata(L, sizeof(*v));
  memset(deref, 0, sizeof(*deref));
  luaL_getmetatable(L, WDB_VAR);
  lua_setmetatable(L, -2);
  memcpy(deref, v, sizeof(*v));

  deref->type = type;
  gimli_dwarf_die_get_uint64_t_attr(td, DW_AT_byte_size, &size);
  if (size == 4) {
    gimli_dwarf_read_value((void*)v->location, v->is_stack, &u32, size);
    deref->location = (intptr_t)u32;
  } else {
    gimli_dwarf_read_value((void*)v->location, v->is_stack, &u64, size);
    deref->location = (intptr_t)u64;
  }
  return 1;
}

static int wdb_var_addr(lua_State *L)
{
  struct wdb_var *v = luaL_checkudata(L, 1, WDB_VAR);

  /* var.addr => the address of this instance in the target */
  wdb_push_address(L, v->location);
  return 1;
}

/* make a variable instance from a die */
static void make_var(lua_State *L, struct wdb_vars *vars,
  struct gimli_dwarf_die *die)
{
  struct wdb_var *v = lua_newuserdata(L, sizeof(*v));
  struct gimli_dwarf_attr *location;

  memset(v, 0, sizeof(*v));
  luaL_getmetatable(L, WDB_VAR);
  lua_setmetatable(L, -2);

  v->cur = vars->cur;
  v->die = die;
  v->frame_base = vars->frame_base;
  v->comp_unit_base = vars->comp_unit_base;
  v->m = vars->m;

  location = gimli_dwarf_die_get_attr(die, DW_AT_location);
  v->name = gimli_dwarf_die_get_attr(die, DW_AT_name);
  v->type = gimli_dwarf_die_get_attr(die, DW_AT_type);
  v->location = 0;
  v->is_stack = 0;

  if (location) {
    switch (location->form) {
      case DW_FORM_block:
        if (!dw_eval_expr(&v->cur, (uint8_t*)location->ptr, location->code,
              v->frame_base, &v->location, NULL, &v->is_stack)) {
          v->location = 0;
        }
        break;
      case DW_FORM_data8:
        if (!dw_calc_location(&v->cur, v->comp_unit_base, v->m,
              location->code, &v->location, NULL, &v->is_stack)) {
          v->location = 0;
        }
        break;
      default:
        printf("Unhandled location form %llx\n", location->form);
    }
  }
}


static int wdb_vars_index(lua_State *L)
{
  struct wdb_vars *vars = luaL_checkudata(L, 1, WDB_VARS);
  const char *what = luaL_checkstring(L, 2);
  struct gimli_dwarf_die *die;

  if (!vars->die) {
    lua_pushnil(L);
    return 1;
  }

  /* can we find a matching entry? */
  for (die = vars->die->kids; die; die = die->next) {
    struct gimli_dwarf_attr *name;

    name = gimli_dwarf_die_get_attr(die, DW_AT_name);
    if (!strcmp(name->ptr, what)) {

      /* found it */
      make_var(L, vars, die);
      return 1;
    }
  }

  lua_pushnil(L);
  return 1;
}

/* iterates the parameters in a frame.
 * This generator returns (name, isparam, var)
 */
static int wdb_vars_iter(lua_State *L)
{
  struct wdb_vars *vars = luaL_checkudata(L, 1, WDB_VARS);

  if (vars->iter) {
    struct gimli_dwarf_attr *name;

    name = gimli_dwarf_die_get_attr(vars->iter, DW_AT_name);
    if (name) {
      lua_pushstring(L, name->ptr);
    } else {
      lua_pushnil(L);
    }
    /* TODO: look at all possible types here; do we want to restrict iter
     * by type? have a frame.params vs frame.locals instead?
     */
    lua_pushboolean(L, vars->iter->tag == DW_TAG_formal_parameter);
    make_var(L, vars, vars->iter);

    /* advance ready for next iteration */
    vars->iter = vars->iter->next;
    return 3;
  }

  lua_pushnil(L);
  return 1;
}

static const luaL_Reg wdb_vars_funcs[] = {
  {"__index", wdb_vars_index},
  {"__call", wdb_vars_iter},
  {NULL, NULL}
};

static void make_vars(lua_State *L, struct wdb_frame *f)
{
  struct wdb_vars *vars = lua_newuserdata(L, sizeof(*vars));
  struct gimli_dwarf_attr *frame_base_attr;
  int tmp;

  memset(vars, 0, sizeof(*vars));
  vars->cur = f->frame;

  vars->die = gimli_dwarf_get_die_for_pc(&vars->cur);
  vars->m = gimli_mapping_for_addr(vars->cur.st.pc);
  vars->iter = NULL;

  if (vars->die) {
    vars->iter = vars->die->kids;

    if (vars->die->parent->tag == DW_TAG_compile_unit) {
      gimli_dwarf_die_get_uint64_t_attr(vars->die->parent,
          DW_AT_low_pc, &vars->comp_unit_base);
    }

    frame_base_attr = gimli_dwarf_die_get_attr(vars->die,
      DW_AT_frame_base);

    if (frame_base_attr) {
      switch (frame_base_attr->form) {
        case DW_FORM_block:
          dw_eval_expr(&vars->cur, (uint8_t*)frame_base_attr->ptr,
              frame_base_attr->code,
              0, &vars->frame_base, NULL, &tmp);
          break;
        case DW_FORM_data8:
          dw_calc_location(&vars->cur, vars->comp_unit_base, vars->m,
              frame_base_attr->code, &vars->frame_base, NULL,
              &tmp);
          break;
        default:
          printf("Unhandled frame base form %llx\n",
              frame_base_attr->form);
      }
    }
  }

  luaL_getmetatable(L, WDB_VARS);
  lua_setmetatable(L, -2);
}

/* to call, an instance of wdb_thread must be on top of the stack;
 * it will be popped */
static struct wdb_frame *make_frame(lua_State *L,
  int nframe)
{
  struct wdb_thread *thr = luaL_checkudata(L, -1, WDB_THREAD);
  int ref;
  struct wdb_frame *f;

  /* pop thr, make a ref to it */
  ref = luaL_ref(L, LUA_REGISTRYINDEX);
  f = lua_newuserdata(L, sizeof(*f));
  memset(f, 0, sizeof(*f));
  f->thread_ref = ref;
  f->thr = thr;
  f->nframe = nframe;
  luaL_getmetatable(L, WDB_FRAME);
  lua_setmetatable(L, -2);

  if (nframe < 0 || nframe >= thr->nframes) {
    luaL_error(L, "frame %d is outside range 0-%d", nframe, thr->nframes - 1);
  }
  f->frame = thr->frames[nframe];

  return f;
}

static int wdb_frame_gc(lua_State *L)
{
  struct wdb_frame *f = luaL_checkudata(L, -1, WDB_FRAME);

  luaL_unref(L, LUA_REGISTRYINDEX, f->thread_ref);
  f->thread_ref = LUA_NOREF;
  f->thr = NULL;

  return 0;
}

static int wdb_frame_tostring(lua_State *L)
{
  struct wdb_frame *f = luaL_checkudata(L, -1, WDB_FRAME);

  if (f->thr) {
    lua_pushfstring(L, "frame #%d of LWP %d", f->nframe, f->thr->st->lwpid);
  } else {
    lua_pushfstring(L, "frame #%d (finalized)", f->nframe);
  }

  return 1;
}

static int wdb_frame_from_frame(lua_State *L, int up)
{
  struct wdb_frame *f = luaL_checkudata(L, -1, WDB_FRAME);
  int nframe = f->nframe + up;

  if (nframe < 0 || nframe >= f->thr->nframes) {
    lua_pushnil(L);
    return 1;
  }

  lua_rawgeti(L, LUA_REGISTRYINDEX, f->thread_ref);
  make_frame(L, nframe);
  return 1;
}

static int wdb_frame_index(lua_State *L)
{
  struct wdb_frame *f = luaL_checkudata(L, 1, WDB_FRAME);
  const char *what = luaL_checkstring(L, 2);

  if (!strcmp(what, "up")) {
    lua_pop(L, 1);
    return wdb_frame_from_frame(L, 1);
  }
  if (!strcmp(what, "down")) {
    lua_pop(L, 1);
    return wdb_frame_from_frame(L, -1);
  }
  if (!strcmp(what, "pc")) {
    wdb_push_address(L, (uintptr_t)f->frame.st.pc);
    return 1;
  }
  if (!strcmp(what, "is_signal")) {
    lua_pushboolean(L, gimli_is_signal_frame(&f->frame));
    return 1;
  }
  if (!strcmp(what, "signo")) {
    lua_pushinteger(L, f->frame.si.si_signo);
    return 1;
  }
  if (!strcmp(what, "signame")) {
    const char *signame = strsignal(f->frame.si.si_signo);

    if (signame) {
      lua_pushstring(L, signame);
    } else {
      lua_pushnil(L);
    }
    return 1;
  }
  if (!strcmp(what, "label")) {
    char filebuf[1024];
    lua_pushstring(L, gimli_pc_sym_name(
      f->frame.st.pc, filebuf, sizeof(filebuf)));
    return 1;
  }
  if (!strcmp(what, "vars")) {
    make_vars(L, f);
    return 1;
  }
  if (!strcmp(what, "file") || !strcmp(what, "line")) {
    char filebuf[1024];
    uint64_t lineno;

    if (dwarf_determine_source_line_number(f->frame.st.pc,
          filebuf, sizeof(filebuf), &lineno)) {
      if (!strcmp(what, "file")) {
        lua_pushstring(L, filebuf);
      } else {
        lua_pushinteger(L, lineno);
      }
    } else {
      lua_pushnil(L);
    }
    return 1;
  }
  /* fall back to other methods in the metatable */
  lua_getmetatable(L, 1);
  lua_pushvalue(L, 2);
  lua_gettable(L, -2);
  return 0;
}

static const luaL_Reg wdb_frame_funcs[] = {
  {"__gc", wdb_frame_gc},
  {"__tostring", wdb_frame_tostring},
  {"__index", wdb_frame_index},
  {NULL, NULL}
};

static int wdb_frames_gc(lua_State *L)
{
  struct wdb_frames *f = luaL_checkudata(L, 1, WDB_FRAMES);

  luaL_unref(L, LUA_REGISTRYINDEX, f->thread_ref);
  f->thread_ref = LUA_NOREF;
  f->thr = NULL;

  return 0;
}

static int wdb_frames_index(lua_State *L)
{
  struct wdb_frames *f = luaL_checkudata(L, 1, WDB_FRAMES);
  int nframe = luaL_checkint(L, 2);

  /* push thread on to stack for make_frame */
  lua_rawgeti(L, LUA_REGISTRYINDEX, f->thread_ref);
  make_frame(L, nframe);
  return 1;
}

static int wdb_frames_iter(lua_State *L)
{
  struct wdb_frames *f = luaL_checkudata(L, 1, WDB_FRAMES);

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

static const luaL_Reg wdb_frames_funcs[] = {
  {"__gc", wdb_frames_gc},
  {"__index", wdb_frames_index},
  {"__call", wdb_frames_iter},
  {NULL, NULL}
};

static int wdb_thread_tostring(lua_State *L)
{
  struct wdb_thread *thr = luaL_checkudata(L, 1, WDB_THREAD);
  lua_pushfstring(L, "thread:tid=%d:LWP=%d:frames=%d",
    thr->tid, thr->st->lwpid, thr->nframes);
  return 1;
}

static int wdb_thread_frames(lua_State *L)
{
  struct wdb_thread *thr = luaL_checkudata(L, 1, WDB_THREAD);
  struct wdb_frames *frames;
  int ref;

  /* pop off the name "frames" */
  lua_pop(L, 1);


  frames = lua_newuserdata(L, sizeof(*frames));
  memset(frames, 0, sizeof(*frames));
  luaL_getmetatable(L, WDB_FRAMES);
  lua_setmetatable(L, -2);
  frames->thr = thr;
  /* make a ref to thr */
  lua_pushvalue(L, 1);
  frames->thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  frames->nframe = 0;

  return 1;
}

static int wdb_thread_index(lua_State *L)
{
  struct wdb_thread *f = luaL_checkudata(L, 1, WDB_THREAD);
  const char *what = luaL_checkstring(L, 2);

  if (!strcmp(what, "frames")) {
    return wdb_thread_frames(L);
  }
  luaL_error(L, "no such property frame.%s", what);
  return 0;
}

static const luaL_Reg wdb_thread_funcs[] = {
  {"__tostring", wdb_thread_tostring},
  {"__index", wdb_thread_index},
  {NULL, NULL},
};

static void make_thread(lua_State *L, int i)
{
  struct wdb_thread *thr;
  int nf;

  if (i < 0 || i >= gimli_nthreads) {
    luaL_error(L, "invalid thread index %d (range is 0-%d)",
        i, gimli_nthreads-1);
  }

  thr = lua_newuserdata(L, sizeof(*thr));
  memset(thr, 0, sizeof(*thr));
  luaL_getmetatable(L, WDB_THREAD);
  lua_setmetatable(L, -2);

  thr->tid = i;
  thr->st = &gimli_threads[i];
  thr->nframes = gimli_stack_trace(i, thr->frames, WDB_MAX_FRAMES);
  for (nf = 0; nf < thr->nframes; nf++) {
    thr->pcaddrs[nf] = thr->frames[nf].st.pc;
    thr->contexts[nf] = &thr->frames[nf];
  }
}

static int wdb_threads_index(lua_State *L)
{
  int nthr = luaL_checkint(L, 2);

  make_thread(L, nthr);
  return 1;
}

static int wdb_threads_iter(lua_State *L)
{
  struct wdb_threads *thr = luaL_checkudata(L, 1, WDB_THREADS);

  if (thr->nthr >= gimli_nthreads) {
    lua_pushnil(L);
    thr->nthr = 0;
    return 1;
  }

  make_thread(L, thr->nthr++);
  return 1;
}

static const luaL_Reg wdb_threads_funcs[] = {
  {"__index", wdb_threads_index},
  {"__call", wdb_threads_iter},
  {NULL, NULL}
};

static int wdb_index(lua_State *L)
{
  const char *what = luaL_checkstring(L, 2);

  if (!strcmp(what, "threads")) {
    struct wdb_threads *t = lua_newuserdata(L, sizeof(*t));

    memset(t, 0, sizeof(*t));
    t->nthr = 0;
    luaL_getmetatable(L, WDB_THREADS);
    lua_setmetatable(L, -2);
    return 1;
  }

  /* fall back to other methods in the metatable */
  lua_getmetatable(L, 1);
  lua_pushvalue(L, 2);
  lua_gettable(L, -2);
  return 1;
}

static const luaL_Reg wdb_funcs[] = {
  {"attach", wdb_attach},
  {"type_tag", wdb_var_tag},
  {"type_c", wdb_var_ctype},
  {"type_name", wdb_var_name},
  {"addr", wdb_var_addr},
  {"deref", wdb_var_deref},
  {"__index", wdb_index},
  {NULL, NULL},
};

static void newmeta(lua_State *L, const char *id, const struct luaL_Reg *funcs)
{
  luaL_newmetatable(L, id);
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index"); /* mt.__index = mt */
  luaL_register(L, NULL, funcs);
}

void wdb_register(lua_State *L)
{
  newmeta(L, WDB_META, wdb_funcs);
  lua_createtable(L, 0, 0);
  luaL_getmetatable(L, WDB_META);
  lua_setmetatable(L, -2);
  lua_setglobal(L, "ldb");

  newmeta(L, WDB_THREADS, wdb_threads_funcs);
  newmeta(L, WDB_THREAD, wdb_thread_funcs);
  newmeta(L, WDB_FRAMES, wdb_frames_funcs);
  newmeta(L, WDB_FRAME, wdb_frame_funcs);
  newmeta(L, WDB_VARS, wdb_vars_funcs);
  newmeta(L, WDB_VAR, wdb_var_funcs);
}


/* vim:ts=2:sw=2:et:
 */

