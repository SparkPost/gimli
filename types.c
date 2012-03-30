/*
 * Copyright (c) 2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/* (Portions derived from ctf_types.c and ctf_decl.c)
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include "impl.h"

struct gimli_type_collection {
  int refcnt;
  /* hash of name => gimli_type_t, allows us
   * to both lookup by name and detect collisions */
  gimli_hash_t type_by_name;
  /* hash of name => function type */
  gimli_hash_t func_by_name;

  /* list of all type objects allocated against us */
  STAILQ_HEAD(typelist, gimli_type) typelist;
};

struct gimli_type {
  STAILQ_ENTRY(gimli_type) typelist;

  int kind;
  char *name;
  char *declname;
  struct gimli_type_encoding enc;
  gimli_type_t target;

  struct gimli_type_arinfo arinfo;

  struct {
    char *name;
    union {
      struct gimli_type_membinfo info;
      int value;
    } u;
  } *members;
  int num_members;
};

/* Some definitions for canonicalizing type names */
/*
 * CTF Declaration Stack
 *
 * In order to implement ctf_type_name(), we must convert a type graph back
 * into a C type declaration.  Unfortunately, a type graph represents a storage
 * class ordering of the type whereas a type declaration must obey the C rules
 * for operator precedence, and the two orderings are frequently in conflict.
 * For example, consider these CTF type graphs and their C declarations:
 *
 * CTF_K_POINTER -> CTF_K_FUNCTION -> CTF_K_INTEGER  : int (*)()
 * CTF_K_POINTER -> CTF_K_ARRAY -> CTF_K_INTEGER     : int (*)[]
 *
 * In each case, parentheses are used to raise operator * to higher lexical
 * precedence, so the string form of the C declaration cannot be constructed by
 * walking the type graph links and forming the string from left to right.
 *
 * The functions in this file build a set of stacks from the type graph nodes
 * corresponding to the C operator precedence levels in the appropriate order.
 * The code in ctf_type_name() can then iterate over the levels and nodes in
 * lexical precedence order and construct the final C declaration string.
 */

typedef enum {
  PREC_BASE,
  PREC_POINTER,
  PREC_ARRAY,
  PREC_FUNCTION,
  PREC_MAX
} decl_prec_t;

typedef struct decl_node {
  /* linkage */
  TAILQ_ENTRY(decl_node) list;
  /* type */
  gimli_type_t type;
  /* type dimension if array */
  unsigned int n;
} *decl_node_t;

typedef struct decl {
  /* declaration node stacks */
  TAILQ_HEAD(nodes, decl_node) nodes[PREC_MAX];
  /* storage order of decls */
  int order[PREC_MAX];
  /* qualifier precision */
  decl_prec_t qualp;
  /* ordered precision */
  decl_prec_t ordp;
  /* buffer for output */
  char *buf;
  /* buffer location */
  char *ptr;
  /* buffer limit */
  char *end;
  /* space required */
  size_t len;
} *decl_t;

static void decl_init(decl_t cd, char *buf, size_t len)
{
  int i;

  memset(cd, 0, sizeof(*cd));

  for (i = PREC_BASE; i < PREC_MAX; i++) {
    cd->order[i] = PREC_BASE - 1;
    TAILQ_INIT(&cd->nodes[i]);
  }
  cd->qualp = PREC_BASE;
  cd->ordp = PREC_BASE;
  cd->buf = buf;
  cd->ptr = buf;
  cd->end = buf + len;
}

static void decl_fini(decl_t cd)
{
  decl_node_t cdp, ndp;
  int i;

  for (i = PREC_BASE; i < PREC_MAX; i++) {
    TAILQ_FOREACH_SAFE(cdp, &cd->nodes[i], list, ndp) {
      free(cdp);
    }
  }
}

static void decl_push(decl_t cd, gimli_type_t type)
{
  decl_node_t cdp;
  decl_prec_t prec;
  int n = 1;
  int is_qual = 0;

  switch (type->kind) {
    case GIMLI_K_ARRAY:
      decl_push(cd, type->arinfo.contents);
      n = type->arinfo.nelems;
      prec = PREC_ARRAY;
      break;

    case GIMLI_K_TYPEDEF:
      if (type->name[0] == '\0') {
        decl_push(cd, type->target);
        return;
      }
      prec = PREC_BASE;
      break;

    case GIMLI_K_FUNCTION:
      decl_push(cd, type->target);
      prec = PREC_FUNCTION;
      break;

    case GIMLI_K_POINTER:
      decl_push(cd, type->target);
      prec = PREC_POINTER;
      break;

    case GIMLI_K_VOLATILE:
    case GIMLI_K_CONST:
    case GIMLI_K_RESTRICT:
      decl_push(cd, type->target);
      prec = cd->qualp;
      is_qual++;
      break;

    default:
      prec = PREC_BASE;
  }

  cdp = calloc(1, sizeof(*cdp));
  cdp->type = type;
  cdp->n = n;

  if (TAILQ_FIRST(&cd->nodes[prec]) == NULL) {
    cd->order[prec] = cd->ordp++;
  }

  /* reset qualp to the highest precedence level that we've seen
   * so far that can be qualified (BASE or POINTER) */
  if (prec > cd->qualp && prec < PREC_ARRAY) {
    cd->qualp = prec;
  }

  /* C array declarators are ordered inside-out, so prepend them.
   * Also by convention qualifiers of base types precede the type
   * specified (e.g.: const int vs int const) even though the two
   * forms are equivalent */
  if (type->kind == GIMLI_K_ARRAY || (is_qual && prec == PREC_BASE)) {
    TAILQ_INSERT_HEAD(&cd->nodes[prec], cdp, list);
  } else {
    TAILQ_INSERT_TAIL(&cd->nodes[prec], cdp, list);
  }
}

static void decl_sprintf(decl_t cd, const char *fmt, ...)
{
  size_t len = (size_t)(cd->end - cd->ptr);
  va_list ap;
  size_t n;

  va_start(ap, fmt);
  n = vsnprintf(cd->ptr, len, fmt, ap);
  va_end(ap);

  cd->ptr += n < len ? n : len;
  cd->len += n;
}

/* print a string name for a type into buf.
 * Return the actual number of bytes (not including \0) needed to
 * format the name.
 */
static ssize_t decl_lname(gimli_type_t type, char *buf, size_t len)
{
  struct decl cd;
  decl_node_t cdp;
  decl_prec_t prec, lp, rp;
  int ptr, arr;
  int k;

  decl_init(&cd, buf, len);
  decl_push(&cd, type);

  ptr = cd.order[PREC_POINTER] > PREC_POINTER;
  arr = cd.order[PREC_ARRAY] > PREC_ARRAY;

  rp = arr ? PREC_ARRAY : ptr ? PREC_POINTER : -1;
  lp = ptr ? PREC_POINTER : arr ? PREC_ARRAY : -1;

  /* avoid leading whitespace (see below) */
  k = GIMLI_K_POINTER;

  for (prec = PREC_BASE; prec < PREC_MAX; prec++) {
    TAILQ_FOREACH(cdp, &cd.nodes[prec], list) {

      if (k != GIMLI_K_POINTER && k != GIMLI_K_ARRAY) {
        decl_sprintf(&cd, " ");
      }

      if (lp == prec) {
        decl_sprintf(&cd, "(");
        lp = -1;
      }

      switch (cdp->type->kind) {
        case GIMLI_K_INTEGER:
        case GIMLI_K_FLOAT:
        case GIMLI_K_TYPEDEF:
          decl_sprintf(&cd, "%s", cdp->type->name);
          break;
        case GIMLI_K_POINTER:
          decl_sprintf(&cd, "*");
          break;
        case GIMLI_K_ARRAY:
          decl_sprintf(&cd, "[%u]", cdp->n);
          break;
        case GIMLI_K_FUNCTION:
          decl_sprintf(&cd, "()");
          break;
        case GIMLI_K_STRUCT:
//        case GIMLI_K_FORWARD:
          decl_sprintf(&cd, "struct %s", cdp->type->name);
          break;
        case GIMLI_K_UNION:
          decl_sprintf(&cd, "union %s", cdp->type->name);
          break;
        case GIMLI_K_ENUM:
          decl_sprintf(&cd, "enum %s", cdp->type->name);
          break;
        case GIMLI_K_VOLATILE:
          decl_sprintf(&cd, "volatile");
          break;
        case GIMLI_K_CONST:
          decl_sprintf(&cd, "const");
          break;
        case GIMLI_K_RESTRICT:
          decl_sprintf(&cd, "restrict");
          break;
      }
      k = cdp->type->kind;
    }

    if (rp == prec) {
      decl_sprintf(&cd, ")");
    }
  }
  decl_fini(&cd);
  return cd.len;
}

gimli_type_collection_t gimli_type_collection_new(void)
{
  gimli_type_collection_t col = calloc(1, sizeof(*col));

  if (!col) return NULL;

  col->refcnt = 1;
  STAILQ_INIT(&col->typelist);
  col->type_by_name = gimli_hash_new(NULL);
  col->func_by_name = gimli_hash_new(NULL);

  return col;
}

void gimli_type_collection_addref(gimli_type_collection_t col)
{
  col->refcnt++;
}

static void delete_type(gimli_type_t t)
{
  free(t->name);
  free(t->declname);
  free(t);
}

static gimli_iter_status_t type_rvisit(gimli_type_t t,
    gimli_type_visit_f func,
    void *arg, const char *name, uint64_t offset, int depth)
{
  gimli_iter_status_t status;
  int i;

  status = func(name, t, offset, depth, arg);

  if (status != GIMLI_ITER_CONT) {
    return status;
  }

  if (t->kind != GIMLI_K_STRUCT && t->kind != GIMLI_K_UNION) {
    return GIMLI_ITER_CONT;
  }

  for (i = 0; i < t->num_members; i++) {
    status = type_rvisit(t->members[i].u.info.type, func, arg,
        t->members[i].name, offset + t->members[i].u.info.offset, depth + 1);
    if (status != GIMLI_ITER_CONT) {
      return status;
    }
  }
  return GIMLI_ITER_CONT;
}

gimli_iter_status_t gimli_type_visit(gimli_type_t t,
    gimli_type_visit_f func,
    void *arg)
{
  return type_rvisit(t, func, arg, "", 0, 0);
}

gimli_iter_status_t gimli_type_member_visit(
    gimli_type_t t,
    gimli_type_member_visit_f func,
    void *arg
    )
{
  gimli_iter_status_t status = GIMLI_ITER_CONT;
  int i;

  if (t->kind != GIMLI_K_STRUCT && t->kind != GIMLI_K_UNION) {
    return GIMLI_ITER_ERR;
  }

  for (i = 0; i < t->num_members; i++) {
    status = func(t->members[i].name, &t->members[i].u.info, arg);
    if (status != GIMLI_ITER_CONT) {
      break;
    }
  }
  return status;
}

void gimli_type_collection_delete(gimli_type_collection_t col)
{
  if (--col->refcnt) return;

  gimli_hash_destroy(col->type_by_name);
  gimli_hash_destroy(col->func_by_name);

  while (!STAILQ_EMPTY(&col->typelist)) {
    gimli_type_t t = STAILQ_FIRST(&col->typelist);

    STAILQ_REMOVE_HEAD(&col->typelist, typelist);

    delete_type(t);
  }
}

gimli_iter_status_t gimli_type_collection_visit(gimli_type_collection_t col,
    gimli_type_collection_visit_f func, void *arg)
{
  gimli_type_t t, tmp;
  gimli_iter_status_t status;

  STAILQ_FOREACH_SAFE(t, &col->typelist, typelist, tmp) {
    status = func(col, t, arg);
    if (status != GIMLI_ITER_CONT) {
      break;
    }
  }
  return status;
}

gimli_type_t gimli_type_collection_find_type(
    gimli_type_collection_t col,
    const char *name)
{
  gimli_type_t t;

  if (gimli_hash_find(col->type_by_name, name,
        (void**)&t)) {
    return t;
  }
  return NULL;
}

gimli_type_t gimli_type_collection_find_function(
    gimli_type_collection_t col,
    const char *name)
{
  gimli_type_t t;

  if (gimli_hash_find(col->func_by_name, name,
        (void**)&t)) {
    return t;
  }
  return NULL;
}

const char *gimli_type_name(gimli_type_t t)
{
  return t->name;
}

const char *gimli_type_declname(gimli_type_t t)
{
  char buf[256];
  ssize_t size;

  if (t->declname) return t->declname;
  size = decl_lname(t, buf, sizeof(buf));
  if (size > sizeof(buf) - 1) {
    t->declname = malloc(size + 1);
    decl_lname(t, t->declname, size + 1);
  } else {
    t->declname = strdup(buf);
  }

  return t->declname;
}

size_t gimli_type_size(gimli_type_t t)
{
  size_t s;

  t = gimli_type_resolve(t);

  s = t->enc.bits;

  if (s == 0) {
    printf("gimli_type_size: kind=%d name=%s has 0 size!\n",
        t->kind, t->name);
  }
  return s;
}

int gimli_type_kind(gimli_type_t t)
{
  return t->kind;
}

void gimli_type_encoding(gimli_type_t t,
    struct gimli_type_encoding *enc)
{
  memcpy(enc, &t->enc, sizeof(t->enc));
}

static gimli_type_t new_type(gimli_type_collection_t col,
    int kind, const char *name,
    const struct gimli_type_encoding *enc)
{
  gimli_type_t t;

  if (name) {
    switch (kind) {
      case GIMLI_K_FUNCTION:
        if (gimli_hash_find(col->func_by_name, name, (void**)&t)) {
          return t;
        }
        break;
      default:
        if (gimli_hash_find(col->type_by_name, name, (void**)&t)) {
          return t;
        }
        break;
    }
  }

  t = calloc(1, sizeof(*t));
  if (!t) return NULL;

  STAILQ_INSERT_TAIL(&col->typelist, t, typelist);

  t->kind = kind;
  if (enc) {
    memcpy(&t->enc, enc, sizeof(t->enc));
  }

  if (name) {
    t->name = strdup(name);
    if (!t->name) {
      return NULL;
    }
    switch (kind) {
      case GIMLI_K_FUNCTION:
        gimli_hash_insert(col->func_by_name, name, t);
        break;
      default:
        gimli_hash_insert(col->type_by_name, name, t);
        break;
    }
  } else {
    t->name = strdup("<anon>");
  }

  return t;
}

gimli_type_t gimli_type_new_array(gimli_type_collection_t col,
    const struct gimli_type_arinfo *info)
{
  gimli_type_t t = new_type(col, GIMLI_K_ARRAY, NULL, NULL);

  memcpy(&t->arinfo, info, sizeof(*info));

  t->enc.bits = t->arinfo.nelems * gimli_type_size(t->arinfo.contents);

  return t;
}

gimli_type_t gimli_type_new_integer(gimli_type_collection_t col,
    const char *name, const struct gimli_type_encoding *enc)
{
  return new_type(col, GIMLI_K_INTEGER, name, enc);
}

gimli_type_t gimli_type_new_float(gimli_type_collection_t col,
    const char *name, const struct gimli_type_encoding *enc)
{
  return new_type(col, GIMLI_K_FLOAT, name, enc);
}

gimli_type_t gimli_type_resolve(gimli_type_t t)
{
  /* simple cycle detection */
  gimli_type_t prev = t, orig = t;

  do {
    switch (t->kind) {
      case GIMLI_K_TYPEDEF:
      case GIMLI_K_VOLATILE:
      case GIMLI_K_CONST:
      case GIMLI_K_RESTRICT:
        if (t->target == t || t->target == prev ||
            t->target == orig) {
          fprintf(stderr, "type cycle detected for %p\n",
              t);
          return NULL;
        }
        prev = t;
        t = t->target;
        break;
      default:
        return t;
    }
  } while (t);
  return NULL;
}

static gimli_type_t new_alias(gimli_type_collection_t col,
    int kind, gimli_type_t target)
{
  struct gimli_type_encoding enc;
  gimli_type_t t;

  memset(&enc, 0, sizeof(enc));
  if (kind == GIMLI_K_POINTER) {
    enc.bits = sizeof(void*);
  }
  t = new_type(col, kind, NULL, &enc);

  if (!t) return NULL;
  t->target = target;

  return t;
}

gimli_type_t gimli_type_new_struct(gimli_type_collection_t col, const char *name)
{
  return new_type(col, GIMLI_K_STRUCT, name, NULL);
}

gimli_type_t gimli_type_new_union(gimli_type_collection_t col, const char *name)
{
  return new_type(col, GIMLI_K_UNION, name, NULL);
}

gimli_type_t gimli_type_new_typedef(gimli_type_collection_t col,
    gimli_type_t target, const char *name)
{
  gimli_type_t t = new_type(col, GIMLI_K_TYPEDEF, name, NULL);
  if (t) t->target = target;
  return t;
}

gimli_type_t gimli_type_new_volatile(gimli_type_collection_t col,
    gimli_type_t target)
{
  return new_alias(col, GIMLI_K_VOLATILE, target);
}

gimli_type_t gimli_type_new_restrict(gimli_type_collection_t col,
    gimli_type_t target)
{
  return new_alias(col, GIMLI_K_RESTRICT, target);
}

gimli_type_t gimli_type_new_const(gimli_type_collection_t col,
    gimli_type_t target)
{
  return new_alias(col, GIMLI_K_CONST, target);
}

gimli_type_t gimli_type_new_pointer(gimli_type_collection_t col,
    gimli_type_t target)
{
  return new_alias(col, GIMLI_K_POINTER, target);
}

gimli_type_t gimli_type_follow_pointer(gimli_type_t t)
{
  return t->target;
}

gimli_type_t gimli_type_new_enum(gimli_type_collection_t col,
    const char *name, const struct gimli_type_encoding *enc)
{
  return new_type(col, GIMLI_K_ENUM, name, enc);
}

int gimli_type_enum_add(gimli_type_t t, const char *name, int value)
{
  int n;

  if (t->kind != GIMLI_K_ENUM) {
    return -1;
  }

  t->members = realloc(t->members, (t->num_members + 1) * sizeof(*t->members));
  n = t->num_members++;
  t->members[n].name = strdup(name);
  t->members[n].u.value = value;

  return n;
}

const char *gimli_type_enum_resolve(gimli_type_t t, int value)
{
  int i;

  if (t->kind != GIMLI_K_ENUM) {
    return NULL;
  }

  for (i = 0; i < t->num_members; i++) {
    if (t->members[i].u.value == value) {
      return t->members[i].name;
    }
  }
  return NULL;
}

int gimli_type_membinfo(gimli_type_t t,
    const char *name,
    struct gimli_type_membinfo *info)
{
  int i;

  if (!t->members) return 0;

  for (i = 0; i < t->num_members; i++) {
    if (!strcmp(t->members[i].name, name)) {
      memcpy(info, &t->members[i].u.info, sizeof(*info));
      return 1;
    }
  }
  return 0;
}

int gimli_type_add_member(gimli_type_t t,
    const char *name,
    gimli_type_t membertype,
    uint64_t size,
    uint64_t offset)
{
  int n, i;
  uint64_t biggest;

  switch (t->kind) {
    case GIMLI_K_STRUCT:
    case GIMLI_K_UNION:
      break;
    default:
      return -1;
  }

  t->members = realloc(t->members, (t->num_members + 1) * sizeof(*t->members));
  n = t->num_members++;
  if (size) {
    t->members[n].u.info.size = size;
    t->members[n].u.info.offset = offset;
  } else {
    /* calculate something reasonable.
     * TODO: verify alignment! */
    t->members[n].u.info.offset = 0;
    if (n > 0) {
      t->members[n].u.info.offset =
          t->members[n - 1].u.info.offset
          + gimli_type_size(t->members[n - 1].u.info.type);
    }
    t->members[n].u.info.size = gimli_type_size(membertype);
  }

  t->members[n].name = strdup(name);
  t->members[n].u.info.type = membertype;

  /* re-compute overall size */
  t->enc.bits = 0;
  biggest = 0;
  for (i = 0; i < t->num_members; i++) {
    size = t->members[i].u.info.offset + gimli_type_size(t->members[i].u.info.type);
    if (size > biggest) {
      biggest = size;
    }
  }
  t->enc.bits = biggest;

  return n;
}

/* vim:ts=2:sw=2:et:
 */

