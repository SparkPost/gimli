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
/* (Portions derived from ctf_types.c)
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
  size_t size;
  struct gimli_type_encoding enc;
  gimli_type_t target;

  struct {
    char *name;
    struct gimli_type_membinfo info;
  } *members;
  int num_members;
};

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
  if (t) return t->declname;
  return NULL;
}

size_t gimli_type_size(gimli_type_t t)
{
  return t->size;
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
  gimli_type_t t = calloc(1, sizeof(*t));

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
  }

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
  gimli_type_t t = new_type(col, kind, NULL, NULL);

  if (!t) return NULL;
  t->target = target;

  return t;
}

gimli_type_t gimli_type_new_struct(gimli_type_collection_t col, const char *name)
{
  return new_type(col, GIMLI_K_STRUCT, name, NULL);
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

int gimli_type_membinfo(gimli_type_t t,
    const char *name,
    struct gimli_type_membinfo *info)
{
  int i;

  if (!t->members) return 0;

  for (i = 0; i < t->num_members; i++) {
    if (!strcmp(t->members[i].name, name)) {
      memcpy(info, &t->members[i].info, sizeof(*info));
      return 1;
    }
  }
  return 0;
}

int gimli_type_add_member(gimli_type_t t,
    const char *name,
    gimli_type_t membertype)
{
  int n;

  switch (t->kind) {
    case GIMLI_K_STRUCT:
    case GIMLI_K_UNION:
      break;
    default:
      return -1;
  }

  t->members = realloc(t->members, (t->num_members + 1) * sizeof(*t->members));
  n = t->num_members++;
  t->members[n].name = strdup(name);
  t->members[n].info.type = membertype;

  /* FIXME: t->mbmers[n].info.offset */

  return n;
}

/* vim:ts=2:sw=2:et:
 */

