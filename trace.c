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
  do {
    frame = calloc(1, sizeof(*frame));

    STAILQ_INIT(&frame->vars);
    cur.frameno = trace->num_frames++;
    cur.tid = thr->lwpid;

    frame->cur = cur;
    STAILQ_INSERT_TAIL(&trace->frames, frame, frames);

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
    frame = STAILQ_FIRST(&trace->frames);
    STAILQ_REMOVE_HEAD(&trace->frames, frames);
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

    name = gimli_pc_sym_name(proc, si->si_addr, namebuf, sizeof(namebuf));
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

struct var_data {
  int is_param, depth;
  gimli_var_t var;
  gimli_addr_t addr;
  gimli_mem_ref_t mem;
  uint64_t offset;
  char *ptr;
};

static const char indentstr[] =
"                                                                    ";
static int print_var(struct var_data *data, gimli_type_t t, const char *varname);

static gimli_iter_status_t print_member(const char *name,
    gimli_type_t t, uint64_t offset, void *arg)
{
  struct var_data *data = arg;

  data->offset += offset;
  print_var(data, t, name);
  data->offset -= offset;

  return GIMLI_ITER_CONT;
}

static int print_var(struct var_data *data, gimli_type_t t, const char *varname)
{
  int indent = 4 * (data->depth + 1);

  if (indent > sizeof(indentstr) - 1) {
    indent = sizeof(indentstr) - 1;
  }
  printf("%.*s%s %s <offsetbits:%" PRIu64 ">",
      indent, indentstr,
      gimli_type_declname(t),
      varname,
      data->offset);

  t = gimli_type_resolve(t);

  switch (gimli_type_kind(t)) {
    case GIMLI_K_STRUCT:
    case GIMLI_K_UNION:
      printf(" {\n");
      data->depth++;
      gimli_type_member_visit(t, print_member, data);
      data->depth--;
      printf("%.*s}\n", indent, indentstr);
      break;
    default:
      printf("\n");
  }

  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t show_var(
    gimli_stack_frame_t frame,
    gimli_var_t var,
    void *arg)
{
  struct var_data *data = arg;

  data->var = var;
  data->is_param = var->is_param;
  data->addr = var->addr;

  if (var->type) {
    print_var(data, var->type, var->varname);
  } else {
    printf("%s %s @ " PTRFMT ": t=%p is_param=%d\n",
        var->type ? gimli_type_declname(var->type) : "?",
        var->varname, var->addr,
        var->type, var->is_param);
  }
  return GIMLI_ITER_CONT;
}

void gimli_render_frame(int tid, int nframe, gimli_stack_frame_t frame)
{
  const char *name;
  char namebuf[1024];
  char filebuf[1024];
  uint64_t lineno;
  struct gimli_unwind_cursor cur = frame->cur;
  struct var_data data;

  if (gimli_is_signal_frame(&cur)) {
    if (cur.si.si_signo) {
      gimli_render_siginfo(cur.proc, &cur.si, namebuf, sizeof(namebuf));
      printf("#%-2d %s\n", nframe, namebuf);
    } else {
      printf("#%-2d signal handler\n", nframe);
    }
  } else {
    name = gimli_pc_sym_name(cur.proc, cur.st.pc, namebuf, sizeof(namebuf));
    printf("#%-2d " PTRFMT " %s", nframe, (PTRFMT_T)cur.st.pc, name);
    if (dwarf_determine_source_line_number(cur.proc, cur.st.pc,
          filebuf, sizeof(filebuf), &lineno)) {
      printf(" (%s:%" PRId64 ")", filebuf, lineno);
    }
    printf("\n");

    memset(&data, 0, sizeof(data));
    gimli_stack_frame_visit_vars(frame, GIMLI_WANT_ALL, show_var, &data);
//    gimli_show_param_info(&cur);
  }
}

static void detachatexit(void)
{
  if (the_proc) {
    gimli_proc_delete(the_proc);
    the_proc = NULL;
  }
}

static gimli_iter_status_t process_file(const char *k, int klen,
    void *item, void *arg)
{
  gimli_mapped_object_t file = item;

  gimli_process_dwarf(file);

  return GIMLI_ITER_CONT;
}

int tracer_attach(int pid)
{
  atexit(detachatexit);
  if (gimli_proc_attach(pid, &the_proc) == GIMLI_ERR_OK) {
    gimli_mapped_object_t file;

    gimli_hash_iter(the_proc->files, process_file, NULL);
    return 1;
  }
  return 0;
}

/* vim:ts=2:sw=2:et:
 */

