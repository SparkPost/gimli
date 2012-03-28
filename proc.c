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

static void populate_proc_stat(gimli_proc_t proc)
{
  int fd, ret;
  char buffer[1024];

#ifdef __linux__
  /* see proc(5) for details on statm */
  snprintf(buffer, sizeof(buffer), "/proc/%d/statm", proc->pid);
  fd = open(buffer, O_RDONLY);
  if (fd >= 0) {
    ret = read(fd, buffer, sizeof(buffer));
    if (ret > 0) {
      unsigned long a, b;

      buffer[ret] = '\0';
      /* want first two fields */
      if (sscanf(buffer, "%lu %lu", &a, &b) == 2) {
        proc->proc_stat.pr_size = a * PAGE_SIZE;
        proc->proc_stat.pr_rssize = b * PAGE_SIZE;
      }
    }
    close(fd);
  }
#elif defined(sun)
  psinfo_t info;

  snprintf(buffer, sizeof(buffer), "/proc/%d/psinfo", proc->pid);
  fd = open(buffer, O_RDONLY);
  if (fd >= 0) {
    ret = read(fd, &info, sizeof(info));
    if (ret == sizeof(info)) {
      proc->proc_stat.pr_size = info.pr_size * 1024;
      proc->proc_stat.pr_rssize = info.pr_rssize * 1024;
    }
    close(fd);
  }
#endif
  proc->proc_stat.pid = proc->pid;
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
  } else {
    populate_proc_stat(p);
  }

  return err;
}

/** Returns the PID of the target process.
 * A PID of 0 is returned if the target process is myself */
int gimli_proc_pid(gimli_proc_t proc)
{
  return proc->pid;
}

gimli_iter_status_t gimli_proc_visit_threads(
    gimli_proc_t proc,
    gimli_proc_visit_thread_f func,
    void *arg)
{
  gimli_thread_t thr, tmp;
  gimli_iter_status_t status = GIMLI_ITER_CONT;

  STAILQ_FOREACH_SAFE(thr, &proc->threads, threadlist, tmp) {
    thr->proc = proc;
    status = func(proc, thr, arg);
    if (status != GIMLI_ITER_CONT) {
      break;
    }
  }
  return status;
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

struct gimli_thread_state *gimli_proc_thread_by_lwpid(gimli_proc_t proc, int lwpid, int create)
{
  struct gimli_thread_state *thr;

  STAILQ_FOREACH(thr, &proc->threads, threadlist) {
    if (thr->lwpid == lwpid) {
      return thr;
    }
  }

  if (create) {
    thr = calloc(1, sizeof(*thr));
    thr->lwpid = lwpid;

    STAILQ_INSERT_TAIL(&proc->threads, thr, threadlist);
    return thr;
  }

  return NULL;
}

char *gimli_read_string(gimli_proc_t proc, void *addr)
{
  gimli_mem_ref_t ref;
  gimli_err_t err;
  char *buf, *end;
  int totlen = 0, len, i;
  void *cursor;
#define STRING_AT_ONCE 1024

  /* try to efficiently find a string in the target */
  if (proc->pid == 0) {
    /* easy case is when it's local */
    return strdup((char*)addr);
  }

  /* map in a block at a time and look for the terminator */
  cursor = addr;
  err = gimli_proc_mem_ref(proc, (gimli_addr_t)addr, STRING_AT_ONCE, &ref);
  if (err != GIMLI_ERR_OK) {
    return NULL;
  }

  while (1) {
    buf = gimli_mem_ref_local(ref);
    len = gimli_mem_ref_size(ref);
    cursor += len;
    totlen += len;
    end = memchr(buf, '\0', len);

    if (end) {
      len = end - buf;

      /* now we know our total length */
      if (cursor == addr) {
        /* can simply dup it out of the ref */
        buf = strdup(buf);
        gimli_mem_ref_delete(ref);
        return buf;
      }
      /* re-request a ref with the desired length */
      gimli_mem_ref_delete(ref);
      err = gimli_proc_mem_ref(proc, (gimli_addr_t)addr, totlen + 1, &ref);
      if (err != GIMLI_ERR_OK) {
        return NULL;
      }
      buf = gimli_mem_ref_local(ref);
      buf = strdup(buf);
      gimli_mem_ref_delete(ref);
      return buf;
    }

    /* didn't find the terminator; get the next chunk and examine */
    gimli_mem_ref_delete(ref);
    err = gimli_proc_mem_ref(proc, (gimli_addr_t)cursor, STRING_AT_ONCE, &ref);
  } while (err != GIMLI_ERR_OK);
  return NULL;
}


/* vim:ts=2:sw=2:et:
 */

