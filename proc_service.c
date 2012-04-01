/*
 * Copyright (c) 2009-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */

/* This implements the Solaris proc_service interface.
 * This is also implemented on Linux and FreeBSD, which borrowed the interface
 * to aid in porting debuggers.
 *
 * The idea is that we provide stubs for talking to the target process and
 * resolving symbols, and the debugger libraries will tell us things about the
 * maps and threads in the target process.
 *
 * The libraries rely on us defining an opaque type named ps_prochandle to
 * represent the process handle.  impl.h defines ps_prochandle to gimli_proc,
 * so we treat ps_prochandle parameters as gimli_proc parameters throughout.
 */

#ifdef __linux__
#define _GNU_SOURCE 1
#endif

#include "impl.h"

#ifdef __linux__
/* Linux doesn't provide all the types that are needed */
typedef enum {
  PS_OK,     /* Success */
  PS_ERR,    /* Generic error */
  PS_BADPID, /* Bad process handle */
  PS_BADLID, /* Bad LWP id */
  PS_BADADDR,/* Bad addres */
  PS_NOSYM,  /* Symbol not found */
  PS_NOFREGS,/* FPU regs not available */
} ps_err_e;
#endif
#ifdef sun
static int get_lwp_status(int pid, lwpid_t lwpid, lwpstatus_t *st);
#endif

void gimli_user_regs_to_thread(prgregset_t *ur,
  struct gimli_thread_state *thr)
{
  memcpy(&thr->regs, ur, sizeof(*ur));

#ifdef sun
  thr->fp = (void*)thr->regs[R_FP];
  thr->pc = (void*)thr->regs[R_PC];
  thr->sp = (void*)thr->regs[R_SP];
#elif defined(__linux__)
# ifdef __x86_64__
  thr->pc = (void*)thr->regs.rip;
  thr->sp = (void*)thr->regs.rsp;
  thr->fp = (void*)thr->regs.rsp;
# else
  thr->pc = (void*)thr->regs.eip;
  thr->sp = (void*)thr->regs.esp;
  thr->fp = (void*)thr->regs.ebp;
# endif
#elif defined(__FreeBSD__)
#ifdef __x86_64__
  thr->pc = (void*)thr->regs.r_rip;
  thr->sp = (void*)thr->regs.r_rsp;
  thr->fp = (void*)thr->regs.r_rbp;
#else
# error consult machine/reg.h; probably just want ur->r_eip etc.
  thr->pc = (void*)thr->regs.eip;
  thr->sp = (void*)thr->regs.esp;
  thr->fp = (void*)thr->regs.ebp;
#endif
#endif
}


static int enum_threads1(const td_thrhandle_t *thr, void *pp)
{
  gimli_proc_t proc = pp;
  struct gimli_thread_state *th;
  prgregset_t ur;
  int te;
  td_thrinfo_t info;

  te = td_thr_get_info(thr, &info);
  if (TD_OK != te) {
    fprintf(stderr, "enum_threads: can't get thread info!\n");
    return 0;
  }

  if (info.ti_state == TD_THR_UNKNOWN || info.ti_state == TD_THR_ZOMBIE) {
    return 0;
  }

#if defined(__linux__)
  if (info.ti_lid != proc->pid) {
    /* need to explicitly attach to this process too.
     * We would use td_thr_dbsuspend() but this is just a stub
     * in glibc */
    int status;
    int tries = 10;

    if (gimli_ptrace(PTRACE_ATTACH, info.ti_lid, NULL, NULL)) {
      fprintf(stderr, "enum_threads: failed to attach to thread %d %s\n",
        info.ti_lid, strerror(errno));
      return 0;
    }
  }
#endif

  /* get it tracked */
  gimli_proc_thread_by_lwpid(proc, info.ti_lid, 1);

  return 0;
}

static int enum_threads2(const td_thrhandle_t *thr, void *pp)
{
  gimli_proc_t proc = pp;
  struct gimli_thread_state *th;
  prgregset_t ur;
  int te;
  td_thrinfo_t info;

  te = td_thr_get_info(thr, &info);

  if (TD_OK != te) {
    fprintf(stderr, "enum_threads: can't get thread info!\n");
    return 0;
  }

  if (info.ti_state == TD_THR_UNKNOWN || info.ti_state == TD_THR_ZOMBIE) {
    return 0;
  }

  th = gimli_proc_thread_by_lwpid(proc, info.ti_lid, 0);
  if (!th) {
    /* assuming that this is Linux and we failed to attach to the
     * thread; ignore this one */
    return 0;
  }

  te = td_thr_getgregs(thr, ur);
  th->valid = 0;

  if (TD_OK != te) {
    fprintf(stderr, "getgregs: %d\n", te);
    return 0;
  }
  gimli_user_regs_to_thread(&ur, th);
#ifdef sun
  get_lwp_status(proc->pid, info.ti_lid, &th->lwpst);
#endif
  th->valid = 1;
  return 0;
}

static int resume_threads(const td_thrhandle_t *thr, void *pp)
{
#ifdef __linux__
  gimli_proc_t proc = pp;
  struct gimli_thread_state *th;
  prgregset_t ur;
  int te;
  td_thrinfo_t info;

  te = td_thr_get_info(thr, &info);
  if (TD_OK != te) {
    fprintf(stderr, "resume_threads: can't get thread info!\n");
    return 0;
  }

  if (info.ti_state == TD_THR_UNKNOWN || info.ti_state == TD_THR_ZOMBIE) {
    return 0;
  }

  if (info.ti_lid != proc->pid && 
      gimli_ptrace(PTRACE_DETACH, info.ti_lid, NULL, (void*)SIGCONT)) {
    fprintf(stderr, "resume_threads: failed to detach from thread %d %s\n",
        info.ti_lid, strerror(errno));
  }

#else
  td_thr_dbresume(thr);
#endif
  return 0;
}

void gimli_proc_service_destroy(gimli_proc_t proc)
{
  if (proc->ta) {
    td_ta_thr_iter(proc->ta, resume_threads, proc, TD_THR_ANY_STATE,
      TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

    td_ta_delete(proc->ta);
    proc->ta = NULL;
  }
  if (proc->proc_mem >= -1) {
    close(proc->proc_mem);
    proc->proc_mem = -1;
  }
}

#ifdef sun
/* Note that FreeBSD has a similar interface, but it provides no apparent
 * value over the ptrace facility that we use as a base, requires more
 * stub implementation and more conditional code, so we actively
 * choose not to use it. */
static int collect_map(const rd_loadobj_t *obj, void *pp)
{
  gimli_proc_t proc = pp;
  char *name;

  name = gimli_read_string(proc, (void*)obj->rl_nameaddr);
  gimli_add_mapping(proc, name, (void*)obj->rl_base, obj->rl_bend - obj->rl_base, 0);
  free(name);

  return 1;
}

static void read_rtld_maps(gimli_proc_t proc)
{
  rd_agent_t *agt;

  agt = rd_new(proc);
  rd_loadobj_iter(agt, collect_map, proc);
  rd_reset(agt);
}
#endif

gimli_err_t gimli_proc_service_init(gimli_proc_t proc)
{
  int i, done = 0, tries = 20;
  td_err_e te;

#ifdef sun
  read_rtld_maps(proc);
#endif

  te = td_init();
  if (te != TD_OK) {
    fprintf(stderr, "td_init failed: %d\n", te);
    return GIMLI_ERR_THREAD_DEBUGGER_INIT_FAILED;
  }
  te = td_ta_new(proc, &proc->ta);
  if (te != TD_OK && te != TD_NOLIBTHREAD) {
    fprintf(stderr, "td_ta_new failed: %d\n", te);
    return GIMLI_ERR_THREAD_DEBUGGER_INIT_FAILED;
  }
  if (proc->ta) {
    int nthreads;
    struct gimli_thread_state *thr;

    /* we're going to make two passes over the set of threads; the first pass
     * is to assess the threads and request that they stop.
     *
     * The second pass occurs after we're sure that they stopped so that we can
     * sample their data fully.  This is needed because the thread state
     * management is asynchronous and is not guaranteed to complete on our
     * timeframe (observed on Linux) */

    td_ta_thr_iter(proc->ta, enum_threads1, proc, TD_THR_ANY_STATE,
      TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

    nthreads = 0;
    STAILQ_FOREACH(thr, &proc->threads, threadlist) {
      nthreads++;
    }

    do {
      done = 0;

      td_ta_thr_iter(proc->ta, enum_threads2, proc, TD_THR_ANY_STATE,
        TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

      STAILQ_FOREACH(thr, &proc->threads, threadlist) {
        if (thr->valid) done++;
      }

      if (done >= nthreads) {
        break;
      }

      sleep(1);
    } while (tries--);

  } else {
    gimli_proc_thread_by_lwpid(proc, proc->pid, 1);
  }

  return GIMLI_ERR_OK;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, const prfpregset_t *fpregset)
{
  return PS_ERR;
}

ps_err_e ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid, const prgregset_t gregset)
{
  return PS_ERR;
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, prfpregset_t *fpregset)
{
  return PS_ERR;
}

pid_t ps_getpid(struct ps_prochandle *ph)
{
  return ph->pid;
}

#ifndef sun
ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph, const char *obj,
  const char *name, psaddr_t *symaddr)
{
  struct gimli_symbol *sym = gimli_sym_lookup(ph, obj, name);
  if (sym) {
    *symaddr = (psaddr_t)sym->addr;
    return PS_OK;
  }
  return PS_NOSYM;
}
#endif

#ifdef sun
ps_err_e ps_pglobal_sym(struct ps_prochandle *h,
	const char *object_name, const char *sym_name, ps_sym_t *sym)
{
  return PS_NOSYM;
}
#endif

#ifndef __FreeBSD__
int gimli_write_mem(gimli_proc_t proc, gimli_addr_t ptr, const void *buf, int len)
{
  int ret = pwrite(proc->proc_mem, buf, len, ptr);
  if (ret < 0) ret = 0;
  return ret;
}

int gimli_read_mem(gimli_proc_t proc, gimli_addr_t src, void *dest, int len)
{
  int ret = pread(proc->proc_mem, dest, len, src);
  if (ret < 0) ret = 0;
  return ret;
}
#endif

ps_err_e ps_pread(struct ps_prochandle *h,
			psaddr_t addr, void *buf, size_t size)
{
  return gimli_read_mem(h, (gimli_addr_t)addr, buf, size)
    == size ? PS_OK : PS_BADADDR;
}

ps_err_e ps_pdread(struct ps_prochandle *h, psaddr_t addr,
  void *buf, size_t size)
{
  return gimli_read_mem(h, (gimli_addr_t)addr, buf, size)
    == size ? PS_OK : PS_BADADDR;
}

ps_err_e ps_pwrite(struct ps_prochandle *h,
			psaddr_t addr, const void *buf, size_t size)
{
  return gimli_write_mem(h, (gimli_addr_t)addr, buf, size)
    == size ? PS_OK : PS_BADADDR;
}

ps_err_e ps_pdwrite(struct ps_prochandle *h, psaddr_t addr,
  const void *buf, size_t size)
{
  return gimli_write_mem(h, (gimli_addr_t)addr, buf, size)
    == size ? PS_OK : PS_BADADDR;
}

#ifdef __linux__
ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid, prgregset_t gregset)
{
  if (0 == gimli_ptrace(PTRACE_GETREGS, lwpid, NULL, gregset)) {
    return PS_OK;
  }
  return PS_ERR;
}
#endif

#ifdef sun
static int get_lwp_status(int pid, lwpid_t lwpid, lwpstatus_t *st)
{
  char path[1024];
  int fd;
  int ret;

  snprintf(path, sizeof(path)-1, "/proc/%d/lwp/%d/lwpstatus", pid, lwpid);

  fd = open(path, O_RDONLY);
  if (fd >= 0) {
    ret = read(fd, st, sizeof(*st));
    if (ret == sizeof(*st)) {
      close(fd);
      return 1;
    }
    fprintf(stderr, "unable to read status for LWP %d: %s\n",
      lwpid, strerror(errno));
    close(fd);
  } else {
    fprintf(stderr, "unable to read status for LWP %d: %s %s\n",
      lwpid, path, strerror(errno));
  }
  return 0;
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid,
      prgregset_t gregset)
{
  lwpstatus_t st;

  if (get_lwp_status(ph->pid, lwpid, &st)) {
    memcpy(gregset, &st.pr_reg, sizeof(st.pr_reg));
    return PS_OK;
  }
  return PS_ERR;
}


ps_err_e ps_pauxv(struct ps_prochandle *h, const auxv_t **auxv)
{
  *auxv = h->tdep.auxv;
  return PS_OK;
}

ps_err_e ps_pdmodel(struct ps_prochandle *h, int *data_model)
{
  *data_model = h->tdep.status.pr_dmodel;
  return PS_OK;
}
#endif

void ps_plog(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}



/* vim:ts=2:sw=2:et:
 */

