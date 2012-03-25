/*
 * Copyright (c) 2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */

#include "impl.h"

/** deletes a reference to a proc handle.
 * When the final handle is deleted, the process will be detached
 * (and continued) if it was a remote process.
 */
void gimli_proc_delete(gimli_proc_t proc)
{
  if (--proc->refcnt) return;

  gimli_detach(proc);

  free(proc);
}

/** adds a reference to a proc handle */
void gimli_proc_addref(gimli_proc_t proc)
{
  proc->refcnt++;
}

/** returns a proc handle to a target process.
 * If successful, the target process will be stopped.
 * Caller must gimli_proc_delete() the handle when it is no longer
 * needed */
gimli_err_t gimli_proc_attach(int pid, gimli_proc_t *proc)
{
  gimli_proc_t p = calloc(1, sizeof(*p));
  gimli_err_t err;

  if (!p) {
    *proc = NULL;
    return GIMLI_ERR_OOM;
  }

  *proc = p;
  p->refcnt = 1;
  p->proc_mem = -1;
  p->pid = pid;
  STAILQ_INIT(&p->threads);
  p->files = gimli_hash_new(NULL);

  err = gimli_attach(p);

  if (err != GIMLI_ERR_OK) {
    int sav = errno;

    gimli_proc_delete(p);
    *proc = NULL;

    errno = sav;
  }

  return err;
}

/** Returns the PID of the target process.
 * A PID of 0 is returned if the target process is myself */
int gimli_proc_pid(gimli_proc_t proc)
{
  return proc->pid;
}

/** Returns mapping to the target address space */
gimli_err_t gimli_proc_mem_ref(gimli_proc_t p,
    gimli_addr_t addr, size_t size, gimli_mem_ref_t *refp)
{
  gimli_mem_ref_t ref;

  /* TODO: maintain a cache of page sized mappings for efficiency */

  *refp = NULL;
  ref = calloc(1, sizeof(*ref));
  if (ref == NULL) {
    return GIMLI_ERR_OOM;
  }

  ref->refcnt = 1;
  ref->target = addr;
  ref->size = size;
  ref->proc = p;
  gimli_proc_addref(p);

  if (p->proc_mem_supports_mmap == -1) {
    /* TODO: try mmap, as that would be ideal.
     * Linux 2.6 doesn't support this.
     * When we try this for Solaris and FreeBSD, we need to remember
     * that mmap wants things page aligned and with page offsets, so
     * we'll need to rebase addr against the page size and then provide
     * an offset relative to the page, recording the offset in the
     * map that we're going to return.  We'll also need to record
     * the actual mmap size that we produced.
     * Another way to deal with this is to make the page aligned mapping
     * the relative of this one, and keep the "complex" adjustments
     * as part of the ->relative handling. */

    /* our "probing" determined that we don't do mmap */
    p->proc_mem_supports_mmap = 0;
  }

  if (!p->proc_mem_supports_mmap) {
    /* Poor-mans approach, which is to allocate a buffer and copy
     * data into it */
    int actual;

    ref->base = malloc(size);
    if (!ref->base) {
      gimli_mem_ref_delete(ref);
      return GIMLI_ERR_OOM;
    }
    ref->map_type = gimli_mem_ref_is_malloc;
    actual = gimli_read_mem(p, (void*)(intptr_t)ref->target, ref->base, ref->size);
    if (actual == 0) {
      gimli_mem_ref_delete(ref);
      return GIMLI_ERR_BAD_ADDR;
    }
    /* may not have obtained full size */
    ref->size = actual;
  }

  *refp = ref;
  return GIMLI_ERR_OK;
}

gimli_err_t gimli_proc_mem_commit(gimli_mem_ref_t ref)
{
  gimli_mem_ref_t p;

  /* find out whether we need to do any work */
  for (p = ref; p; p = p->relative) {
    if (p->map_type == gimli_mem_ref_is_mmap) {
      return GIMLI_ERR_OK;
    }
    if (p->map_type == gimli_mem_ref_is_malloc) {
      break;
    }
  }

  /* store it back to the target */
  return gimli_write_mem(ref->proc, (void*)ref->target, ref->base, ref->size) == ref->size;
}

/** Returns base address of a mapping, in the target address space */
gimli_addr_t gimli_mem_ref_target(gimli_mem_ref_t mem)
{
  return mem->target;
}

/** Returns the base address of a mapping in my address space.
 * This is the start of the readable/writable mapped view of
 * the target process */
void *gimli_mem_ref_local(gimli_mem_ref_t mem)
{
  return mem->base + mem->offset;
}

/** Returns the size of the mapping */
size_t gimli_mem_ref_size(gimli_mem_ref_t mem)
{
  return mem->size;
}

/** deletes a reference to a mapping; when the last
 * reference is deleted, the mapping is no longer valid */
void gimli_mem_ref_delete(gimli_mem_ref_t mem)
{
  if (--mem->refcnt) return;

  if (mem->proc) {
    gimli_proc_delete(mem->proc);
    mem->proc = NULL;
  }
  if (mem->relative) {
    gimli_mem_ref_delete(mem->relative);
    mem->relative = NULL;
  }

  switch (mem->map_type) {
    case gimli_mem_ref_is_malloc:
      free(mem->base);
      mem->base = NULL;
  }

  free(mem);
}

/** adds a reference to a mapping */
void gimli_mem_ref_addref(gimli_mem_ref_t mem)
{
  mem->refcnt++;
}


/* vim:ts=2:sw=2:et:
 */

