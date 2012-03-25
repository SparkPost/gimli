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
#ifndef sun
typedef gimli_addr_t paddr_t;
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


static int enum_threads(const td_thrhandle_t *thr, void *pp)
{
  gimli_proc_t proc = pp;
  struct gimli_thread_state *th;
  prgregset_t ur;
  int te;
  td_thrinfo_t info;

#ifdef __FreeBSD__
  proc->threads = realloc(proc->threads,
      (proc->nthreads + 1) * sizeof(*proc->threads));
  proc->cur_enum_thread = &proc->threads[proc->nthreads++];
#endif
  th = proc->cur_enum_thread;

  te = td_thr_get_info(thr, &info);
  if (TD_OK != te) {
    fprintf(stderr, "enum_threads: can't get thread info!\n");
    return 0;
  }

  if (info.ti_state == TD_THR_UNKNOWN || info.ti_state == TD_THR_ZOMBIE) {
    return 0;
  }

#ifdef __linux__
  if (info.ti_lid != proc->pid) {
    /* need to explicitly attach to this process too */
    int status;
    int tries = 10;

    if (gimli_ptrace(PTRACE_ATTACH, info.ti_lid, NULL, NULL)) {
      fprintf(stderr, "enum_threads: failed to attach to thread %d %s\n",
        info.ti_lid, strerror(errno));
      return 0;
    }

    proc->tdep.pids_to_detach[proc->tdep.num_pids++] = info.ti_lid;
  }
#endif

  te = td_thr_getgregs(thr, ur);
  if (TD_OK != te) {
    fprintf(stderr, "getgregs: %d\n", te);
    return 0;
  }

  gimli_user_regs_to_thread(&ur, th);
#ifdef sun
  get_lwp_status(proc->pid, info.ti_lid, &proc->cur_enum_thread->lwpst);
#endif

  proc->cur_enum_thread->lwpid = info.ti_lid;
  proc->cur_enum_thread++;
  return 0;
}

void gimli_proc_service_destroy(gimli_proc_t proc)
{
  if (proc->ta) {
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
 * value over the ptrace facility that we use as a base */
static int collect_map(const rd_loadobj_t *obj, void *pp)
{
  gimli_proc_t proc = pp;
  char *name;

  name = gimli_read_string((void*)obj->rl_nameaddr);
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
  int i, done = 0;
  td_err_e te;

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
#ifdef __FreeBSD__
    /* no td_ta_get_nthreads on FreeBSD, so we realloc as
     * we enumerate the threads */
    td_ta_thr_iter(proc->ta, enum_threads, proc, TD_THR_ANY_STATE,
      TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
#else
    te = td_ta_get_nthreads(proc->ta, &proc->nthreads);
    if (te == TD_OK) {
      proc->threads = calloc(proc->nthreads, sizeof(*proc->threads));
      proc->cur_enum_thread = proc->threads;
      td_ta_thr_iter(proc->ta, enum_threads, proc, TD_THR_ANY_STATE,
        TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
#ifdef __linux__
      proc->tdep.pids_to_detach = calloc(proc->nthreads, sizeof(int));
#endif
    } else {
      fprintf(stderr, "td_ta_get_nthreads failed: %d\n", te);
    }
#endif

  } else {
    proc->threads = calloc(1, sizeof(*proc->threads));
    proc->threads->lwpid = proc->pid;
    proc->nthreads = 1;

  }

#if 0
  while (done < proc->nthreads) {
    for (i = 0; i < proc->nthreads; i++) {
      struct gimli_thread_state *thr = &proc->threads[i];

      if (ptrace(PTRACE_GETREGS, thr->lwpid, NULL, &ur) == 0) {
        gimli_user_regs_to_thread(&ur, thr);
        done++;
      }
    }
    if (done >= proc->nthreads) {
      break;
    }
    sleep(1);
    done = 0;
  }
#endif
#ifdef sun
  read_rtld_maps(proc);
#endif

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

#ifdef sun
ps_err_e ps_pglobal_sym(struct ps_prochandle *h,
	const char *object_name, const char *sym_name, ps_sym_t *sym)
{
  return PS_NOSYM;
}
#endif

#ifndef __FreeBSD__
int gimli_write_mem(gimli_proc_t proc, void *ptr, const void *buf, int len)
{
  int ret = pwrite(proc->proc_mem, buf, len, (intptr_t)ptr);
  if (ret < 0) ret = 0;
  return ret;
}

int gimli_read_mem(gimli_proc_t proc, void *src, void *dest, int len)
{
  int ret = pread(proc->proc_mem, dest, len, (intptr_t)src);
  if (ret < 0) ret = 0;
  return ret;
}
#endif

ps_err_e ps_pread(struct ps_prochandle *h,
			psaddr_t addr, void *buf, size_t size)
{
  return gimli_read_mem(h, (void*)addr, buf, size) == size ? PS_OK : PS_BADADDR;
}

ps_err_e ps_pdread(struct ps_prochandle *h, paddr_t addr,
  void *buf, size_t size)
{
  return gimli_read_mem(h, (void*)addr, buf, size) == size ? PS_OK : PS_BADADDR;
}

ps_err_e ps_pwrite(struct ps_prochandle *h,
			psaddr_t addr, const void *buf, size_t size)
{
  return gimli_write_mem(h, (void*)addr, buf, size) == size ? PS_OK : PS_BADADDR;
}

ps_err_e ps_pdwrite(struct ps_prochandle *h, paddr_t addr,
  void *buf, size_t size)
{
  return gimli_write_mem(h, (void*)addr, buf, size) == size ? PS_OK : PS_BADADDR;
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

