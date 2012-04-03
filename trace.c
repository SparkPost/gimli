/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

int debug = 0;
int max_frames = 256;
gimli_proc_t the_proc = NULL;

gimli_stack_trace_t gimli_thread_stack_trace(gimli_thread_t thr, int max_frames)
{
  gimli_stack_trace_t trace = calloc(1, sizeof(*trace));
  struct gimli_unwind_cursor cur;
  gimli_stack_frame_t frame;
  struct {
    const char *name;
    int before;
    struct gimli_symbol *sym;
  } stopsyms[] = {
    { "main", 0 },
#ifdef __linux__
    { "start_thread", 1 },
#endif
#ifdef sun
    { "_thr_setup", 1 },
    { "_lwp_start", 1 },
#endif
#ifdef __MACH__
    { "_main", 0 },
    { "__pthread_work_internal_init", 1 },
#endif
  };
  int i;
  int stop;

  if (!trace) return NULL;

  trace->refcnt = 1;
  trace->thr = thr;
  STAILQ_INIT(&trace->frames);

  memset(&cur, 0, sizeof(cur));
  cur.proc = thr->proc;

  if (!gimli_init_unwind(&cur, thr)) {
    free(trace);
    return NULL;
  }

  for (i = 0; i < sizeof(stopsyms)/sizeof(stopsyms[0]); i++) {
    stopsyms[i].sym = gimli_sym_lookup(thr->proc, NULL, stopsyms[i].name);
#if 0
    printf("Looking up %s %" PRIx64 "-%" PRIx64 "\n",
        stopsyms[i].name, stopsyms[i].sym->addr,
        stopsyms[i].sym->addr + stopsyms[i].sym->size);
#endif
  }

  do {
    stop = 0;

    for (i = 0; i < sizeof(stopsyms)/sizeof(stopsyms[0]); i++) {
      if (!stopsyms[i].before || !stopsyms[i].sym) continue;
      if ((gimli_addr_t)cur.st.pc >= stopsyms[i].sym->addr &&
          (gimli_addr_t)cur.st.pc <= stopsyms[i].sym->addr + stopsyms[i].sym->size) {
        stop = 1;
        break;
      }
    }
    if (stop) {
      break;
    }

    frame = calloc(1, sizeof(*frame));

    STAILQ_INIT(&frame->vars);
    cur.frameno = trace->num_frames++;
    cur.tid = thr->lwpid;

    frame->cur = cur;
    STAILQ_INSERT_TAIL(&trace->frames, frame, frames);

    for (i = 0; i < sizeof(stopsyms)/sizeof(stopsyms[0]); i++) {
      if (stopsyms[i].before || !stopsyms[i].sym) continue;
      if ((gimli_addr_t)cur.st.pc >= stopsyms[i].sym->addr &&
          (gimli_addr_t)cur.st.pc <= stopsyms[i].sym->addr + stopsyms[i].sym->size) {
        stop = 1;
        break;
      }
    }
    if (stop) {
      break;
    }

  } while (trace->num_frames < max_frames &&
      cur.st.pc && gimli_unwind_next(&cur) && cur.st.pc);

  return trace;
}

int gimli_stack_trace_num_frames(gimli_stack_trace_t trace)
{
  return trace->num_frames;
}

void gimli_stack_trace_addref(gimli_stack_trace_t trace)
{
  trace->refcnt++;
}

void gimli_stack_trace_delete(gimli_stack_trace_t trace)
{
  gimli_stack_frame_t frame;

  if (--trace->refcnt) return;

  while (STAILQ_FIRST(&trace->frames)) {
    gimli_var_t var;

    frame = STAILQ_FIRST(&trace->frames);
    STAILQ_REMOVE_HEAD(&trace->frames, frames);

    while (STAILQ_FIRST(&frame->vars)) {
      var = STAILQ_FIRST(&frame->vars);
      STAILQ_REMOVE_HEAD(&frame->vars, vars);

      // FIXME: release type?
      free(var);
    }
    free(frame);
  }

  free(trace);
}

gimli_iter_status_t gimli_stack_trace_visit(
    gimli_stack_trace_t trace,
    gimli_stack_trace_visit_f func,
    void *arg)
{
  gimli_stack_frame_t frame;
  gimli_iter_status_t status = GIMLI_ITER_CONT;

  STAILQ_FOREACH(frame, &trace->frames, frames) {
    status = func(trace->thr->proc, trace->thr, frame, arg);
    if (status != GIMLI_ITER_CONT) {
      break;
    }
  }
  return status;
}

int gimli_render_siginfo(gimli_proc_t proc, siginfo_t *si, char *buf, size_t bufsize)
{
  char *source = "";
  int use_fault_addr = 0;
  int use_pid = 0;
  char *signame;
  char pidbuf[64];
  char namebuf[1024];
  char addrbuf[1024];

  signame = strsignal(si->si_signo);
  if (!signame) signame = "Unknown signal";

  if (si->si_code > 0) {
    /* kernel generated; si_code has additional information */
    switch (si->si_signo) {
      case SIGILL:
        use_fault_addr = 1;
        switch (si->si_code) {
          case ILL_ILLOPC: source = "illegal opcode"; break;
          case ILL_ILLOPN: source = "illegal operand"; break;
          case ILL_ILLADR: source = "illegal addressing mode"; break;
          case ILL_ILLTRP: source = "illegal trap"; break;
          case ILL_PRVOPC: source = "privileged opcode"; break;
          case ILL_PRVREG: source = "privileged register"; break;
          case ILL_COPROC: source = "co-processor error"; break;
          case ILL_BADSTK: source = "internal stack error"; break;
        }
        break;
      case SIGFPE:
        use_fault_addr = 1;
        switch (si->si_code) {
          case FPE_INTDIV: source = "integer divide by zero"; break;
          case FPE_INTOVF: source = "integer overflow"; break;
          case FPE_FLTDIV: source = "floating point divide by zero"; break;
          case FPE_FLTOVF: source = "floating point overflow"; break;
          case FPE_FLTUND: source = "floating point underflow"; break;
          case FPE_FLTRES: source = "floating point inexact result"; break;
          case FPE_FLTINV: source = "floating point invalid operation"; break;
          case FPE_FLTSUB: source = "subscript out of range"; break;
        }
        break;
      case SIGSEGV:
        use_fault_addr = 1;
        switch (si->si_code) {
          case SEGV_MAPERR: source = "address not mapped to object"; break;
          case SEGV_ACCERR: source = "invalid permissions for mapped object"; break;
        }
        break;
      case SIGBUS:
        use_fault_addr = 1;
        switch (si->si_code) {
          case BUS_ADRALN: source = "invalid address alignment"; break;
          case BUS_ADRERR: source = "non-existent physical address"; break;
          case BUS_OBJERR: source = "object specific hardware error"; break;
        }
        break;
      case SIGTRAP:
        switch (si->si_code) {
          case TRAP_BRKPT: source = "process breakpoint"; break;
          case TRAP_TRACE: source = "process trace trap"; break;
        }
        break;
      case SIGCHLD:
        use_pid = 1;
        switch (si->si_code) {
          case CLD_EXITED: source = "child has exited"; break;
          case CLD_KILLED: source = "child was killed"; break;
          case CLD_DUMPED: source = "child terminated abnormally"; break;
          case CLD_TRAPPED: source = "traced child has trapped"; break;
          case CLD_STOPPED: source = "child has stopped"; break;
          case CLD_CONTINUED: source = "stopped child has continued"; break;
        }
        break;
#ifdef SIGPOLL
      case SIGPOLL:
        switch (si->si_code) {
          case POLL_IN: source = "data input available"; break;
          case POLL_OUT: source = "output buffers available"; break;
          case POLL_MSG: source = "input message available"; break;
          case POLL_ERR: source = "I/O error"; break;
          case POLL_PRI: source = "high priority input available"; break;
          case POLL_HUP: source = "device disconnected"; break;
        }
        break;
#endif

    }
  } else {
    use_pid = 1;
    switch (si->si_code) {
#ifdef SI_NOINFO
      case SI_NOINFO:
        /* explicitly have no info */
        use_pid = 0;
        break;
#endif
      case SI_USER:    source = "userspace"; break;
#ifdef SI_LWP
      case SI_LWP:     source = "_lwp_kill"; break;
#endif
      case SI_QUEUE:   source = "sigqueue"; break;
      case SI_TIMER:   source = "timer";   break;
      case SI_ASYNCIO: source = "asyncio"; break;
      case SI_MESGQ:   source = "mesgq"; break;
#ifdef SI_KERNEL
      case SI_KERNEL:  source = "kernel"; break;
#endif
#ifdef SI_SIGIO
      case SI_SIGIO:   source = "sigio"; break;
#endif
#ifdef SI_TKILL
      case SI_TKILL:   source = "tkill"; break;
#endif
#ifdef SI_RCTL
      case SI_RCTL: source = "resource-control"; break;
#endif
    }
  }

  pidbuf[0] = '\0';
  addrbuf[0] = '\0';
  if (use_pid) {
    snprintf(pidbuf, sizeof(pidbuf), " pid=%d", si->si_pid);
  }
  if (use_fault_addr) {
    const char *name;

    name = gimli_pc_sym_name(proc, (gimli_addr_t)si->si_addr,
        namebuf, sizeof(namebuf));
    if (name && strlen(name)) {
      snprintf(addrbuf, sizeof(addrbuf), " (%s)", name);
    } else {
      snprintf(addrbuf, sizeof(addrbuf), " (" PTRFMT ")", (intptr_t)si->si_addr);
    }
  }

  return snprintf(buf, bufsize, "Signal %d: %s. %s%s%s",
      si->si_signo, signame, source,
      pidbuf, addrbuf);
}

gimli_addr_t gimli_stack_frame_pcaddr(gimli_stack_frame_t frame)
{
  return (gimli_addr_t)frame->cur.st.pc;
}

int gimli_stack_frame_number(gimli_stack_frame_t frame)
{
  return frame->cur.frameno;
}

gimli_iter_status_t gimli_stack_frame_visit_vars(
    gimli_stack_frame_t frame,
    int filter,
    gimli_stack_frame_visit_f func,
    void *arg)
{
  gimli_var_t var;
  gimli_iter_status_t status = GIMLI_ITER_CONT;

  gimli_dwarf_load_frame_var_info(frame);

  /* iterate */
  STAILQ_FOREACH(var, &frame->vars, vars) {
    if ((var->is_param & filter) == 0) continue;

    status = func(frame, var, arg);
  }

  return status;
}

int gimli_stack_frame_resolve_var(gimli_stack_frame_t frame,
    int filter,
    const char *varname, gimli_type_t *datatype, gimli_addr_t *addr
    )
{
  gimli_var_t var;
  gimli_iter_status_t status = GIMLI_ITER_CONT;

  gimli_dwarf_load_frame_var_info(frame);

  /* iterate */
  STAILQ_FOREACH(var, &frame->vars, vars) {
    if (!var->varname) continue;
    if ((var->is_param & filter) == 0) continue;
    if (strcmp(varname, var->varname)) continue;

    /* got a match */
    *datatype = var->type;
    *addr = var->addr;
    return 1;
  }
  return 0;
}

static void detachatexit(void)
{
  if (the_proc) {
    gimli_proc_delete(the_proc);
    the_proc = NULL;
  }
}

int tracer_attach(int pid)
{
  atexit(detachatexit);
  if (gimli_proc_attach(pid, &the_proc) == GIMLI_ERR_OK) {
    return 1;
  }
  return 0;
}

/* vim:ts=2:sw=2:et:
 */

