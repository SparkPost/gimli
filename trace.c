/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

int debug = 0;
int max_frames = 256;
gimli_proc_t the_proc = NULL;

static struct gimli_proc_stat proc_stat = { 0, };

static const struct gimli_proc_stat *gimli_get_proc_stat(void)
{
  return &proc_stat;
}

static int gimli_get_source_info(void *addr, char *buf,
  int buflen, int *lineno)
{
  uint64_t l;
  int ret = dwarf_determine_source_line_number(the_proc, addr, buf, buflen, &l);
  if (ret) {
    *lineno = (int)l;
  }
  return ret;
}

static char *gimli_get_string_symbol(gimli_proc_t proc, const char *obj, const char *name)
{
  struct gimli_symbol *sym;

  sym = gimli_sym_lookup(proc, obj, name);
  if (sym) {
    void *addr;

    if (gimli_read_mem(proc, sym->addr, &addr, sizeof(addr)) == sizeof(addr)) {
      return gimli_read_string(proc, addr);
    }
  }
  return NULL;
}

static int gimli_copy_from_symbol(const char *obj, const char *name,
  int deref, void *buf, uint32_t size)
{
  struct gimli_symbol *sym;

  sym = gimli_sym_lookup(the_proc, obj, name);
  if (sym) {
    void *addr = sym->addr;

    while (deref--) {
      if (gimli_read_mem(the_proc, addr, &addr, sizeof(addr)) != sizeof(addr)) {
        return 0;
      }
    }

    return gimli_read_mem(the_proc, addr, buf, size) == size;
  }
  return 0;
}

struct gimli_ana_api ana_api = {
  GIMLI_ANA_API_VERSION,
  gimli_sym_lookup,
  gimli_pc_sym_name,
  gimli_read_mem,
  gimli_read_string,
  gimli_get_source_info,
  gimli_get_parameter,
  gimli_get_string_symbol,
  gimli_copy_from_symbol,
  gimli_get_proc_stat,
};

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
  err = gimli_proc_mem_ref(proc, addr, STRING_AT_ONCE, &ref);
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
      err = gimli_proc_mem_ref(proc, addr, totlen + 1, &ref);
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
    err = gimli_proc_mem_ref(proc, cursor, STRING_AT_ONCE, &ref);
  } while (err != GIMLI_ERR_OK);
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

struct gimli_object_mapping *gimli_mapping_for_addr(gimli_proc_t proc, void *addr)
{
  struct gimli_object_mapping *m;
  for (m = proc->mappings; m; m = m->next) {
    if (addr >= m->base && addr <= m->base + m->len) {
      return m;
    }
  }
  return NULL;
}

const char *gimli_pc_sym_name(gimli_proc_t proc, void *addr, char *buf, int buflen)
{
  struct gimli_object_mapping *m;
  struct gimli_symbol *s;

  m = gimli_mapping_for_addr(proc, addr);
  if (m) {
    s = find_symbol_for_addr(m->objfile, addr);
    if (s) {
      if (addr == s->addr) {
        snprintf(buf, buflen-1, "%s`%s", m->objfile->objname, s->name);
      } else {
        snprintf(buf, buflen-1, "%s`%s+%lx",
            m->objfile->objname, s->name, (uintmax_t)(addr - s->addr));
      }
    } else {
      snprintf(buf, buflen-1, "%s`%p", m->objfile->objname, addr);
    }
    return buf;
  }
  return "";
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
      snprintf(addrbuf, sizeof(addrbuf), " (" PTRFMT ")", si->si_addr);
    }
  }

  return snprintf(buf, bufsize, "Signal %d: %s. %s%s%s",
      si->si_signo, signame, source,
      pidbuf, addrbuf);
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
      printf(" (%s:%lld)", filebuf, lineno);
    }
    printf("\n");
    gimli_show_param_info(&cur);
  }
}

int gimli_stack_trace(gimli_proc_t proc, int tid, struct gimli_unwind_cursor *frames, int nframes)
{
  struct gimli_thread_state *thr = &proc->threads[tid];
  struct gimli_unwind_cursor cur;
  int i;

  memset(&cur, 0, sizeof(cur));
  cur.proc = the_proc;
  if (gimli_init_unwind(&cur, thr)) {
    int frame = 0;
    do {
      cur.frameno = frame;
      cur.tid = tid;
      frames[frame++] = cur;
    } while (frame < nframes &&
        cur.st.pc && gimli_unwind_next(&cur) && cur.st.pc);
    return frame;
  }
  return 0;
}

static void populate_proc_stat(int pid)
{
  int fd, ret;
  char buffer[1024];

#ifdef __linux__
  /* see proc(5) for details on statm */
  snprintf(buffer, sizeof(buffer), "/proc/%d/statm", pid);
  fd = open(buffer, O_RDONLY);
  if (fd >= 0) {
    ret = read(fd, buffer, sizeof(buffer));
    if (ret > 0) {
      unsigned long a, b;

      buffer[ret] = '\0';
      /* want first two fields */
      if (sscanf(buffer, "%lu %lu", &a, &b) == 2) {
        proc_stat.pr_size = a * PAGE_SIZE;
        proc_stat.pr_rssize = b * PAGE_SIZE;
      }
    }
    close(fd);
  }
#elif defined(sun)
  psinfo_t info;

  snprintf(buffer, sizeof(buffer), "/proc/%d/psinfo", pid);
  fd = open(buffer, O_RDONLY);
  if (fd >= 0) {
    ret = read(fd, &info, sizeof(info));
    if (ret == sizeof(info)) {
      proc_stat.pr_size = info.pr_size * 1024;
      proc_stat.pr_rssize = info.pr_rssize * 1024;
    }
    close(fd);
  }
#endif
  proc_stat.pid = pid;
}

struct gimli_object_mapping *gimli_add_mapping(
  gimli_proc_t proc,
  const char *objname, void *base, unsigned long len,
  unsigned long offset)
{
  struct gimli_object_mapping *m = calloc(1, sizeof(*m));

  m->next = proc->mappings;
  m->proc = proc; // FIXME: refcnt
  m->base = base;
  m->len = len;
  if (debug) {
    fprintf(stderr, "MAP: %p - %p %s\n", (void*)m->base,
      (void*)(m->base + m->len),  objname);
  }
  m->offset = offset;
  m->objfile = gimli_find_object(proc, objname);
  if (!m->objfile) {
    m->objfile = gimli_add_object(proc, objname, base);
  }
  proc->mappings = m;
  return m;
}

struct gimli_object_file *gimli_find_object(
  gimli_proc_t proc,
  const char *objname)
{
  struct gimli_object_file *f;

  if (objname == NULL) {
    return proc->first_file;
  }

  for (f = proc->files; f; f = f->next) {
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
  gimli_proc_t proc,
  const char *objname, void *base)
{
  struct gimli_object_file *f = gimli_find_object(proc, objname);
  struct gimli_symbol *sym;
  char *name = NULL;
  if (f) return f;

  f = calloc(1, sizeof(*f));
  f->objname = strdup(objname);
  f->next = proc->files;
  f->symbols = gimli_hash_new(NULL);
  f->sections = gimli_hash_new(NULL);
  proc->files = f;

  if (proc->first_file == NULL) {
    proc->first_file = f;
  }

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

struct gimli_symbol *gimli_sym_lookup(gimli_proc_t proc, const char *obj, const char *name)
{
  struct gimli_object_file *f;
  struct gimli_symbol *sym = NULL;

  /* if obj is NULL, we're looking for it anywhere we can find it */
  if (obj == NULL) {
    for (f = proc->files; f; f = f->next) {
      if (!gimli_hash_find(f->symbols, name, (void**)&sym)) {
        sym = NULL;
      }
      if (debug) {
        printf("sym_lookup: %s`%s => %p\n", obj, name, sym ? sym->addr : 0);
      }
      return sym;
    }
    return NULL;
  }

  f = gimli_find_object(proc, obj);
  if (!f) {
    char buf[1024];

    /* we may have just been given the basename of the object, in which
     * case, we need to run through the list and match on basenames */
    for (f = proc->files; f; f = f->next) {
      strcpy(buf, f->objname);
      if (!strcmp(basename(buf), obj)) {
        break;
      }
    }
    if (!f) {
      /* so maybe we were given the basename it refers to a symlink
       * that we need to resolve... */
      for (f = proc->files; f; f = f->next) {
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
    struct gimli_object_file *file;
    populate_proc_stat(pid);

    for (file = the_proc->files; file; file = file->next) {
      gimli_process_dwarf(file);
      gimli_bake_symtab(file);
    }
    return 1;
  }
  return 0;
}

/* vim:ts=2:sw=2:et:
 */

