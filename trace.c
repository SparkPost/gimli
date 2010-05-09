/*
 * Copyright (c) 2007-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#include "impl.h"

int debug = 0;
int gimli_nthreads = 0;
static int max_frames = 256;
struct gimli_thread_state *gimli_threads = NULL;
struct gimli_object_file *gimli_files = NULL;
struct gimli_object_mapping *gimli_mappings = NULL;

struct gimli_ana_api ana_api = {
  GIMLI_ANA_API_VERSION,
  gimli_sym_lookup,
  gimli_pc_sym_name,
  gimli_read_mem,
  gimli_read_string
};

char *gimli_read_string(void *addr)
{
  int len;
  char c;
  char *buf;

  len = 0;
  while (gimli_read_mem(addr + len, &c, 1) == 1) {
    if (c == '\0') {
      break;
    }
    len++;
  }

  if (len) {
    buf = malloc(len+1);
    gimli_read_mem(addr, buf, len);
    buf[len] = '\0';
    return buf;
  }
  return NULL;
}

/* lower is better.
 * We weight underscores at the start heavier than
 * those later on.
 */
static int calc_readability(const char *name)
{
  int start = 1;
  int value = 0; 
  while (*name) {
    if (*name == '_') {
      if (start) {
        value += 2;
      } else {
        value++;
      }
    } else {
      start = 0;
    }
    name++;
  }
  return value;
}

struct gimli_symbol *find_symbol_for_addr(struct gimli_object_file *f,
  void *addr)
{
  struct gimli_symbol *csym, *best;
  int i, n, upper, lower;

  n = f->symcount;
  lower = 0;
  upper = n - 1;

  while (lower <= upper) {
    i = lower + ((upper - lower)/2);
    csym = f->symtab[i];

    if (csym->addr <= addr &&
#ifndef __MACH__
        csym->addr + csym->size >= addr
#else
        /* we have no size info from the nlist symbols */
        ((i + 1 > upper) || (f->symtab[i+1]->addr > addr))
#endif
        ) {
      /* we're in the right region, but there may be multiple
       * symbols that map here; try to find the one with the
       * most readable name */
      int bu, cu;

      while (i && f->symtab[i-1]->addr == csym->addr) {
        i--;
      }

      bu = calc_readability(csym->name);

      while (i < n && f->symtab[i]->addr == csym->addr) {
        cu = calc_readability(f->symtab[i]->name);
        if (cu < bu) {
          bu = cu;
          csym = f->symtab[i];
        }
        i++;
      }
      return csym;
    } else if (csym->addr > addr) {
      upper = i - 1;
    } else {
      lower = i + 1;
    }
  }
  if (lower < 0) lower = 0;
  if (upper < lower) upper = lower + 1;
  for (i = lower; i < upper; i++) {
    if (i < 0 || i >= n) continue;
    if (addr >= f->symtab[i]->addr) {
      return f->symtab[i];
    }
  }
  return NULL;
}

struct gimli_object_mapping *gimli_mapping_for_addr(void *addr)
{
  struct gimli_object_mapping *m;
  for (m = gimli_mappings; m; m = m->next) {
    if (addr >= m->base && addr <= m->base + m->len) {
      return m;
    }
  }
  return NULL;
}

const char *gimli_pc_sym_name(void *addr, char *buf, int buflen)
{
  struct gimli_object_mapping *m;
  struct gimli_symbol *s;

  m = gimli_mapping_for_addr(addr);
  if (m) {
    s = find_symbol_for_addr(m->objfile, addr);
    if (s) {
      if (addr == s->addr) {
        snprintf(buf, buflen-1, "%s`%s", m->objfile->objname, s->name);
      } else {
        snprintf(buf, buflen-1, "%s`%s+%x",
            m->objfile->objname, s->name, addr - s->addr);
      }
    } else {
      snprintf(buf, buflen-1, "%s`%p", m->objfile->objname, addr);
    }
    return buf;
  }
  return "";
}

void gimli_render_frame(int tid, int nframe, struct gimli_unwind_cursor *frame)
{
  const char *name;
  char namebuf[1024];
  char filebuf[1024];
  uint64_t lineno;
  struct gimli_unwind_cursor cur = *frame;

  if (gimli_is_signal_frame(&cur)) {
    if (cur.si.si_signo) {
      char *source = "";
      int use_fault_addr = 0;
      int use_pid = 0;
      char *signame;

      signame = strsignal(cur.si.si_signo);
      if (!signame) signame = "Unknown signal";

      if (cur.si.si_code > 0) {
        /* kernel generated; si_code has additional information */
        switch (cur.si.si_signo) {
          case SIGILL:
            use_fault_addr = 1;
            switch (cur.si.si_code) {
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
            switch (cur.si.si_code) {
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
            switch (cur.si.si_code) {
              case SEGV_MAPERR: source = "address not mapped to object"; break;
              case SEGV_ACCERR: source = "invalid permissions for mapped object"; break;
            }
            break;
          case SIGBUS:
            use_fault_addr = 1;
            switch (cur.si.si_code) {
              case BUS_ADRALN: source = "invalid address alignment"; break;
              case BUS_ADRERR: source = "non-existent physical address"; break;
              case BUS_OBJERR: source = "object specific hardware error"; break;
            }
            break;
          case SIGTRAP:
            switch (cur.si.si_code) {
              case TRAP_BRKPT: source = "process breakpoint"; break;
              case TRAP_TRACE: source = "process trace trap"; break;
            }
            break;
          case SIGCHLD:
            use_pid = 1;
            switch (cur.si.si_code) {
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
            switch (cur.si.si_code) {
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
        switch (cur.si.si_code) {
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
      printf("#%-2d Signal %d: %s. %s",
          nframe, cur.si.si_signo, signame, source);

      if (use_pid) {
        printf(" pid=%d", cur.si.si_pid);
      }

      if (use_fault_addr) {
        name = gimli_pc_sym_name(cur.si.si_addr, namebuf, sizeof(namebuf));
        if (name && strlen(name)) {
          printf(" (%s)", name);
        } else {
          printf(" (" PTRFMT ")", cur.si.si_addr);
        }
      }
      printf("\n");

    } else {
      printf("#%-2d signal handler\n", nframe);
    }
  } else {
    name = gimli_pc_sym_name(cur.st.pc, namebuf, sizeof(namebuf));
    printf("#%-2d " PTRFMT " %s", nframe, cur.st.pc, name);
    if (dwarf_determine_source_line_number(cur.st.pc,
          filebuf, sizeof(filebuf), &lineno)) {
      printf(" (%s:%lld)", filebuf, lineno);
    }
    printf("\n");
    gimli_show_param_info(&cur);
  }
}

int gimli_stack_trace(int tid, struct gimli_unwind_cursor *frames, int nframes)
{
  struct gimli_thread_state *thr = &gimli_threads[tid];
  struct gimli_unwind_cursor cur;
  int i;

  memset(&cur, 0, sizeof(cur));
  if (gimli_init_unwind(&cur, thr)) {
    int frame = 0;
    do {
      cur.frameno = frame;
      cur.tid = tid;
      frames[frame++] = cur;
    } while (cur.st.pc && gimli_unwind_next(&cur) && cur.st.pc);
    return frame;
  }
  return 0;
}

void trace_process(int pid)
{
  if (gimli_attach(pid)) {
    int i;
    struct gimli_object_file *file;
    struct gimli_unwind_cursor *frames;
    void **pcaddrs;
    void **contexts;

    frames = calloc(max_frames, sizeof(*frames));
    if (!frames) {
      fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
      goto out;
    }
    pcaddrs = calloc(max_frames, sizeof(*pcaddrs));
    if (!pcaddrs) {
      fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
      goto out;
    }
    contexts = calloc(max_frames, sizeof(*contexts));
    if (!contexts) {
      fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
      goto out;
    }

    for (file = gimli_files; file; file = file->next) {
      /* perform discovery of tracer module */
      struct gimli_symbol *sym;
      char *name = NULL;
      char buf[1024];
      char buf2[1024];
      void *h;

      sym = gimli_sym_lookup(file->objname, "gimli_tracer_module_name");
      if (sym) {
        name = gimli_read_string(sym->addr);
      }
      if (name == NULL) {
        strcpy(buf, file->objname);
        snprintf(buf2, sizeof(buf2)-1, "gimli_%s", basename(buf));
        name = strdup(buf2);
      }
      strcpy(buf, file->objname);
      snprintf(buf2, sizeof(buf2)-1, "%s/%s", dirname(buf), name);

      if (access(buf2, F_OK) == 0) {
        h = dlopen(buf2, RTLD_NOW|RTLD_GLOBAL);
        if (h) {
          gimli_module_init_func func = (gimli_module_init_func)
            dlsym(h, "gimli_ana_init");
          if (func) {
            file->tracer_module = (*func)(&ana_api); 
          }
        } else {
          printf("Unable to load library: %s: %s\n", buf2, dlerror());
        }
      } else if (sym) {
        printf("NOTE: module %s declared that its tracing should be performed by %s, but that module was not found (%s)\n",
            file->objname, buf2, strerror(errno));
      }

      gimli_process_dwarf(file);
      gimli_bake_symtab(file);
    }

    for (i = 0; i < gimli_nthreads; i++) {
      int nframes = gimli_stack_trace(i, frames, max_frames);
      int suppress = 0;
      int nf;

      for (nf = 0; nf < nframes; nf++) {
        pcaddrs[nf] = frames[nf].st.pc;
        contexts[nf] = &frames[nf];
      }

      for (file = gimli_files; file; file = file->next) {
        if (file->tracer_module &&
            file->tracer_module->api_version >= 2 &&
            file->tracer_module->on_begin_thread_trace) {
          if (file->tracer_module->on_begin_thread_trace(&ana_api,
              file->objname, i, nframes, pcaddrs, contexts)
              == GIMLI_ANA_SUPPRESS) {
            suppress = 1;
            break;
          }
        }
      }

      if (!suppress) {
        struct gimli_thread_state *thr = &gimli_threads[i];

        printf("\nThread %d (LWP %d)\n", i, thr->lwpid);
        for (nf = 0; nf < nframes; nf++) {
          suppress = 0;
          for (file = gimli_files; file; file = file->next) {
            if (file->tracer_module &&
                file->tracer_module->api_version >= 2 &&
                file->tracer_module->before_print_frame) {
              if (file->tracer_module->before_print_frame(&ana_api,
                  file->objname, i, nf, pcaddrs[nf], contexts[nf])
                  == GIMLI_ANA_SUPPRESS) {
                suppress = 1;
                break;
              }
            }
          }
          if (!suppress) {
            gimli_render_frame(i, nf, frames + nf);

            for (file = gimli_files; file; file = file->next) {
              if (file->tracer_module &&
                  file->tracer_module->api_version >= 2 &&
                  file->tracer_module->after_print_frame) {
                file->tracer_module->after_print_frame(&ana_api,
                      file->objname, i, nf, pcaddrs[nf], contexts[nf]);
              }
            }
          }
        }
        for (file = gimli_files; file; file = file->next) {
          if (file->tracer_module &&
              file->tracer_module->api_version >= 2 &&
              file->tracer_module->on_end_thread_trace) {
            file->tracer_module->on_end_thread_trace(&ana_api,
                file->objname, i, nframes, pcaddrs, contexts);
          }
        }
      }
    }

    printf("\n");

    for (file = gimli_files; file; file = file->next) {
      if (file->tracer_module == NULL) continue;

      if (file->tracer_module->perform_trace) {
        file->tracer_module->perform_trace(&ana_api, file->objname);
      }
    }

  }
out:
  gimli_detach();
}

struct gimli_object_mapping *gimli_add_mapping(
  const char *objname, void *base, unsigned long len,
  unsigned long offset)
{
  struct gimli_object_mapping *m = calloc(1, sizeof(*m));

  m->next = gimli_mappings;
  m->base = base;
  m->len = len;
  if (debug) {
    fprintf(stderr, "MAP: %p - %p %s\n", (void*)m->base,
      (void*)(m->base + m->len),  objname);
  }
  m->offset = offset;
  m->objfile = gimli_find_object(objname);
  if (!m->objfile) {
    m->objfile = gimli_add_object(objname, base);
  }
  gimli_mappings = m;
  return m;
}

struct gimli_object_file *gimli_find_object(
  const char *objname)
{
  struct gimli_object_file *f;

  for (f = gimli_files; f; f = f->next) {
    if (!strcmp(f->objname, objname)) {
      return f;
    }
  }
  return NULL;
}

struct gimli_symbol *gimli_add_symbol(struct gimli_object_file *f,
  const char *name, void *addr, uint32_t size)
{
  struct gimli_symbol *s;
  char buf[1024];
 
  s = calloc(1, sizeof(*s));

  s->rawname = strdup(name);
  s->name = s->rawname;

  if (gimli_demangle(s->rawname, buf, sizeof(buf))) {
    s->name = strdup(buf);
  }

  s->addr = addr;
  s->size = size;
  s->ordinality = f->symcount++;
  s->next = f->symroot;
  f->symroot = s;

  if (debug && 0) {
    printf("add symbol: %s`%s = %p (%d)\n",
      f->objname, s->name, s->addr, s->size);
  }

  /* this may fail due to duplicate names */
  gimli_hash_insert(f->symbols, s->rawname, s);
  return s;
}

static gimli_hash_iter_ret populate_symtab(
  const char *k, int klen, void *item, void *arg)
{
  struct gimli_object_file *f = arg;
  struct gimli_symbol *s = item;

  f->symtab[s->ordinality] = s;
  return GIMLI_HASH_ITER_CONT;
}

static int sort_syms_by_addr_asc(const void *A, const void *B)
{
  struct gimli_symbol *a = *(struct gimli_symbol**)A;
  struct gimli_symbol *b = *(struct gimli_symbol**)B;

  if (a->addr == b->addr) {
    return a->ordinality - b->ordinality;
  }
  return a->addr - b->addr;
}

int gimli_bake_symtab(struct gimli_object_file *f)
{
  int i;
  struct gimli_symbol *s;

  f->symtab = calloc(f->symcount, sizeof(struct gimli_symbol*));
  for (s = f->symroot; s; s = s->next) {
    f->symtab[s->ordinality] = s;
  }

  qsort(f->symtab, f->symcount, sizeof(struct gimli_symbol*),
    sort_syms_by_addr_asc);
}

struct gimli_object_file *gimli_add_object(
  const char *objname, void *base)
{
  struct gimli_object_file *f = gimli_find_object(objname);
  struct gimli_symbol *sym;
  char *name = NULL;
  if (f) return f;

  f = calloc(1, sizeof(*f));
  f->objname = strdup(objname);
  f->next = gimli_files;
  f->symbols = gimli_hash_new(NULL);
  f->sections = gimli_hash_new(NULL);
  gimli_files = f;

#ifndef __MACH__
  f->elf = gimli_elf_open(f->objname);
  if (f->elf) {
    f->elf->gobject = f;
    /* need to determine the base address offset for this object */
    f->base_addr = (intptr_t)base - f->elf->vaddr;
    if (debug) {
      printf("ELF: %s %d base=%p vaddr=%p base_addr=%p\n",
        f->objname, f->elf->e_type, base, f->elf->vaddr, f->base_addr);
    }

    gimli_process_elf(f);
  }
#endif

  return f;
}

struct gimli_symbol *gimli_sym_lookup(const char *obj, const char *name)
{
  struct gimli_object_file *f;
  struct gimli_symbol *sym = NULL;

  f = gimli_find_object(obj);
  if (!f) {
    char buf[1024];
    
    /* we may have just been given the basename of the object, in which
     * case, we need to run through the list and match on basenames */
    for (f = gimli_files; f; f = f->next) {
      strcpy(buf, f->objname);
      if (!strcmp(basename(buf), obj)) {
        break;
      }
    }
    if (!f) {
      /* so maybe we were given the basename it refers to a symlink
       * that we need to resolve... */
      for (f = gimli_files; f; f = f->next) {
        char dir[1024];
        int len;

        strcpy(dir, f->objname);
        snprintf(buf, sizeof(buf)-1, "%s/%s", dirname(dir), obj);
        if (realpath(buf, dir)) {
          if (!strcmp(dir, f->objname)) {
            break;
          }
        }
      }
    }
    if (!f) {
      return NULL;
    }
  }

  if (!gimli_hash_find(f->symbols, name, (void**)&sym)) {
    sym = NULL;
  }
  if (debug) {
    printf("sym_lookup: %s`%s => %p\n", obj, name, sym ? sym->addr : 0);
  }
  return sym;
}


int main(int argc, char *argv[])
{
  int pid;
  int c;

  while (1) {
    c = getopt(argc, argv, "d");
    if (c == -1) {
      break;
    }
    switch (c) {
      /* -d option enables copious dwarf debugging */
      case 'd':
        debug = 1;
        break;
      default:
        fprintf(stderr, "invalid option %c\n", c);
        return 1;
    }
  }

  if (getenv("GIMLI_DWARF_DEBUG")) {
    debug = 1;
  }

  if (optind < argc) {
    pid = atoi(argv[optind]);
    trace_process(pid);
    return 0;
  }
  fprintf(stderr, "usage: %s <pid>\n", argv[0]);
  return 1;
}

/* vim:ts=2:sw=2:et:
 */

