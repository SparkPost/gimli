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


  ref = calloc(1, sizeof(*ref));
  if (ref == NULL) {
    *refp = NULL;
    return GIMLI_ERR_OOM;
  }

  ref->target = addr;
  ref->size = size;
  ref->proc = p;
  gimli_proc_addref(p);

  *refp = ref;
  return GIMLI_ERR_OK;
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
  return mem->base;
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

  free(mem);
}

/** adds a reference to a mapping */
void gimli_mem_ref_addref(gimli_mem_ref_t mem)
{
  mem->refcnt++;
}


/* vim:ts=2:sw=2:et:
 */

