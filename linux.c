/*
 * Copyright (c) 2007-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#ifdef __linux__
#define _GNU_SOURCE 1
#include "impl.h"

/* frustratingly, linux has a kernel ucontext and a userspace ucontext.
 * To handle signal frames correctly, we need to reference the kernel
 * layout that gets pushed onto the stack */
#ifdef __x86_64__
struct gimli_kernel_sigcontext { /* from asm/sigcontext.h */
  unsigned long r8, r9, r10, r11, r12, r13, r14, r15,
    di, si, bp, bx, dx, ax, cx, sp, ip, flags;
  unsigned short cs, gs, fs, __pad0;
  unsigned long err, trapno, oldmask, cr2;
  void *fpstate;
  unsigned long reserved1[8];
};

struct gimli_kernel_ucontext { /* from asm/ucontext.h */
	unsigned long	  uc_flags;
	struct gimli_kernel_ucontext  *uc_link;
	stack_t		  uc_stack;
	struct gimli_kernel_sigcontext uc_mcontext;
  /* should be a sigset_t here, but through observation, it appears
   * to not really be here... even though I can see the kernel code
   * pushing it at this location... very fishy */
  void *pad;
//	sigset_t	  uc_sigmask;	// appears to not factor into frame
};

struct gimli_kernel_rt_sigframe {
//  char *pretcode;
  struct gimli_kernel_ucontext uc;
  struct siginfo si;
};

#endif

/* this is the linux proc_service style interface.
 * thread_db library routines require that we export these functions
 */

typedef enum {
  PS_OK,     /* Success */
  PS_ERR,    /* Generic error */
  PS_BADPID, /* Bad process handle */
  PS_BADLID, /* Bad LWP id */
  PS_BADADDR,/* Bad addres */
  PS_NOSYM,  /* Symbol not found */
  PS_NOFREGS,/* FPU regs not available */
} ps_err_e;

typedef unsigned long paddr_t;

/* we store this in proc->tdep */
struct ps_prochandle {
  /** points back up to the containing proc */
  gimli_proc_t proc;
  /** thread agent for thread debugging API */
  td_thragent_t *ta;
  /** the pid of each attached thread */
  int *pids_to_detach;
  int num_pids;
  struct gimli_thread_state *cur_enum_thread;
  /** for efficient memory accesses, this is a descriptior
   * for /proc/pid/mem. */
  int proc_mem;
  /** whether mmap works on proc_mem */
  int proc_mem_supports_mmap;
};

static void user_regs_to_thread(struct user_regs_struct *ur,
  struct gimli_thread_state *thr)
{
  memcpy(&thr->regs, ur, sizeof(*ur));
#ifdef __x86_64__
  thr->pc = (void*)ur->rip;
  thr->sp = (void*)ur->rsp;
  thr->fp = (void*)ur->rsp;
#else
  thr->pc = (void*)ur->eip;
  thr->sp = (void*)ur->esp;
  thr->fp = (void*)ur->ebp;
#endif
}

long gimli_ptrace(int cmd, int pid, void *addr, void *data)
{
  int tries = 5;
  long ret;

  errno = 0;
  ret = ptrace(cmd, pid, addr, data);

  if (ret == 0) return 0;

  if (cmd == PTRACE_GETREGS) {
    if (ret == -1) {
      sleep(1);
      while (tries && (ret = ptrace(cmd, pid, addr, data)) == -1) {
        if (errno == ESRCH) {
          if (--tries) {
            sleep(1);
            continue;
          }
        }
        return ret;
      }
      if (ret == 0) {
        return 0;
      }
    }
  }
  return ret;
}

int gimli_read_mem(gimli_proc_t proc, void *src, void *dest, int len)
{
  struct ps_prochandle *tdep = proc->tdep;

  return pread(tdep->proc_mem, dest, len, (intptr_t)src);
#if 0
  long word;
  unsigned char *destptr = (unsigned char *)dest;
  unsigned char *srcptr = (unsigned char*)src;

  do {
    int x = sizeof(word);
    int got;

    word = gimli_ptrace(PTRACE_PEEKDATA, proc->pid, srcptr, NULL);
    if (errno) {
      fprintf(stdout, "readmem: unable to read %d bytes at %p: %s\n",
          x, src, strerror(errno));
      return 0;
    }

    got = x > len ? len : x;
    memcpy(destptr, &word, got);
    destptr += got;
    srcptr += got;
    len -= got;
    nread += got;

  } while (len > 0);
  return nread;
#endif
}


static int enum_threads(const td_thrhandle_t *thr, void *pp)
{
  gimli_proc_t proc = pp;
  struct ps_prochandle *tdep = proc->tdep;
  struct gimli_thread_state *th = tdep->cur_enum_thread;
  struct user_regs_struct ur;
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

  if (info.ti_lid != proc->pid) {
    /* need to explicitly attach to this process too */
    int status;
    int tries = 10;

    if (gimli_ptrace(PTRACE_ATTACH, info.ti_lid, NULL, NULL)) {
      fprintf(stderr, "enum_threads: failed to attach to thread %d %s\n",
        info.ti_lid, strerror(errno));
      return 0;
    }

    tdep->pids_to_detach[tdep->num_pids++] = info.ti_lid;
  }

  tdep->cur_enum_thread->lwpid = info.ti_lid;
  tdep->cur_enum_thread++;
  return 0;
}

static void read_maps(gimli_proc_t proc)
{
  char maps[1024];
  char line[1024];
  FILE *fp;

  snprintf(maps, sizeof(maps)-1, "/proc/%d/maps", proc->pid);
  fp = fopen(maps, "r");
  if (!fp) {
    fprintf(stderr, "read_maps: fopen(%s) %s\n",
      maps, strerror(errno));
    return;
  }

  while (fgets(line, sizeof(line)-1, fp)) {
    int i;
    char *tok = line;

    i = strlen(line);
    while (i > 0 && isspace(line[i-1])) {
      line[i-1] = '\0';
      i--;
    }

    while (!isspace(*tok)) {
      tok++;
    }

    *tok = '\0';
    tok++;

    for (i = 0; i < 4; i++) {
      while (isspace(*tok)) tok++;
      while (!isspace(*tok)) tok++;
      while (isspace(*tok)) tok++;
    }
    if (tok && *tok) {
      unsigned long long v;
      void *base;
      unsigned long len;
      char *objname = tok;

      if (*tok != '/') continue;

      base = (void*)(intptr_t)strtoull(line, &tok, 16);
      v = strtoull(tok + 1, NULL, 16);
      len = v - (intptr_t)base;
      gimli_add_mapping(proc, objname, base, len, 0);
    }
  }
  fclose(fp);
}

int gimli_init_unwind(struct gimli_unwind_cursor *cur,
  struct gimli_thread_state *st)
{
  memcpy(&cur->st, st, sizeof(*st));
  return 1;
}

void *gimli_reg_addr(struct gimli_unwind_cursor *cur, int col)
{
  /* See http://wikis.sun.com/display/SunStudio/Dwarf+Register+Numbering */
  switch (col) {
#ifdef __x86_64__
    case 0: return &cur->st.regs.rax;
    case 1: return &cur->st.regs.rdx;
    case 2: return &cur->st.regs.rcx;
    case 3: return &cur->st.regs.rbx;
    case 4: return &cur->st.regs.rsi;
    case 5: return &cur->st.regs.rdi;
    case 6: return &cur->st.regs.rbp;
    case 7: return &cur->st.regs.rsp;
    case 8: return &cur->st.regs.r8;
    case 9: return &cur->st.regs.r9;
    case 10: return &cur->st.regs.r10;
    case 11: return &cur->st.regs.r11;
    case 12: return &cur->st.regs.r12;
    case 13: return &cur->st.regs.r13;
    case 14: return &cur->st.regs.r14;
    case 15: return &cur->st.regs.r15;
    case 16: return &cur->st.regs.rip; /* return address */
#elif defined(__i386__)
    case 0: return &cur->st.regs.eax;
    case 1: return &cur->st.regs.ecx;
    case 2: return &cur->st.regs.edx;
    case 3: return &cur->st.regs.ebx;
    case 4: return &cur->st.regs.esp;
    case 5: return &cur->st.regs.ebp;
    case 6: return &cur->st.regs.esi;
    case 7: return &cur->st.regs.edi;
    case 8: return &cur->st.regs.eip; /* return address */
#else
# error code me
#endif
    default: return 0;
  }
}

static void hexdump(gimli_proc_t proc, void *addr, int p, int n)
{
  uint32_t data[4];
  int i, j;
  int x;
  struct gimli_symbol *sym;
  char buf[16];

  addr = (char*)addr - (p * sizeof(data));

  for (i = 0; i < n; i++) {
    x = gimli_read_mem(proc, addr, data, sizeof(data));
    printf("%p:   ", addr);
    for (j = 0; j < 4; j++) {
      void *a = (void*)(intptr_t)data[j];
      struct gimli_object_mapping *m = gimli_mapping_for_addr(proc, a);
      if (m) {
        sym = find_symbol_for_addr(m->objfile, a);
      } else {
        sym = NULL;
      }
      if (sym) {
        printf(" %12.*s", 12 , sym->name);
      } else {
        printf("     %08x", data[j]);
      }
    }
    printf("\n");

    addr += sizeof(data);
  }
}

int gimli_is_signal_frame(struct gimli_unwind_cursor *cur)
{
  /* these magic numbers correspond to the machine code instructions
   * used for the sigreturn handling in glibc */
#ifdef __x86_64__
  uint64_t a, b;
  if (gimli_read_mem(cur->proc, cur->st.pc, &a, sizeof(a)) == sizeof(a) &&
      gimli_read_mem(cur->proc, cur->st.pc + sizeof(a), &b, sizeof(b)) == sizeof(b)) {
    if ((a == 0x0f0000000fc0c748) && ((b & 0xff) == 5)) {
      void *siptr;
      int signo;

      /* this only really works for SA_SIGINFO handlers.
       * to make it work for non-SA_SIGINFO handlers, we'd need
       * to down down one level and look at the args passed to the
       * signal handler itself. */

      if (gimli_read_mem(cur->proc, cur->st.fp + sizeof(struct gimli_kernel_ucontext),
          &cur->si, sizeof(cur->si)) != sizeof(cur->si)) {
        /* can't tell the user anything useful */
        memset(&cur->si, 0, sizeof(cur->si));
      }
      return 1;
    }
  }
#elif defined(__i386__)
  uint32_t a, b;
  if (gimli_read_mem(cur->proc, cur->st.pc, &a, sizeof(a)) == sizeof(a) &&
      gimli_read_mem(cur->proc, cur->st.pc + sizeof(a), &b, sizeof(b)) == sizeof(b)) {
    /* pull out the signal number */

    if (a == 0x0077b858 && b == 0x80cd0000) {
      /* no SA_SIGINFO */
      memset(&cur->si, 0, sizeof(cur->si));
//      printf("data around fp=%p\n", cur->st.fp);
//      hexdump(cur->st.fp, 20, 40);

      /* see below for derivation of the magic number; the signal
       * number preceeds the frame, and that's what we're reading in here */
      if (gimli_read_mem(cur->proc, cur->st.fp /* - 760 no dwarf!? */,
          &cur->si.si_signo, sizeof(cur->si.si_signo))
          != sizeof(cur->si.si_signo)) {
        printf("failed to read sigframe\n");
        return 0;
      }

      return 1;
    }
    if (a == 0x0000adb8 && b == 0x9080cd00) {
      /* has SA_SIGINFO */
      struct {
        int signo;
        struct siginfo *siptr;
        struct gimli_kernel_ucontext *ucptr;
        /*
        struct siginfo si;
        struct ucontext uc;
        char retcode[8];
         fp state */
      } frame;

#if 0
      printf("data around fp=%p\n", cur->st.fp);
      hexdump(cur->st.fp, 20, 40);
      printf("data around sp=%p\n", cur->st.sp);
      hexdump(cur->st.sp, 20);
#endif

      /* maybe its because its 3am, but...
       * If DWARF unwinding failed us, the magic number to find
       * the frame is this:
      if (gimli_read_mem(cur->st.fp - 920,
          &frame, sizeof(frame)) != sizeof(frame)) {
        printf("failed to read rt_sigframe\n");
        return 0;
      }
      */
      /* if DWARF worked out, fp points right at the frame(!) */
      if (gimli_read_mem(cur->proc, cur->st.fp,
          &frame, sizeof(frame)) != sizeof(frame)) {
        printf("failed to read rt_sigframe\n");
        return 0;
      }

      if (gimli_read_mem(cur->proc, frame.siptr, &cur->si, sizeof(cur->si))
          != sizeof(cur->si)) {
        printf("failed to read siginfo\n");
        return 0;
      }
      return 1;
    }
  }
#endif
  return 0;
}

int gimli_unwind_next(struct gimli_unwind_cursor *cur)
{
  /* generic x86 backtrace */
  struct x86_frame {
    struct x86_frame *next;
    void *retpc;
  } frame;
  struct gimli_unwind_cursor c;

  c = *cur;
  if (gimli_is_signal_frame(cur)) {
    /* extract the next step from the data in the trampoline */

#ifdef __x86_64__
    struct gimli_kernel_ucontext uc;

    if (gimli_read_mem(cur->proc, cur->st.fp, &uc, sizeof(uc)) != sizeof(uc)) {
      return 0;
    }
    cur->st.regs.r8 = uc.uc_mcontext.r8;
    cur->st.regs.r9 = uc.uc_mcontext.r9;
    cur->st.regs.r10 = uc.uc_mcontext.r10;
    cur->st.regs.r11 = uc.uc_mcontext.r11;
    cur->st.regs.r12 = uc.uc_mcontext.r12;
    cur->st.regs.r13 = uc.uc_mcontext.r13;
    cur->st.regs.r14 = uc.uc_mcontext.r14;
    cur->st.regs.r15 = uc.uc_mcontext.r15;
    cur->st.regs.rdi = uc.uc_mcontext.di;
    cur->st.regs.rsi = uc.uc_mcontext.si;
    cur->st.regs.rbp = uc.uc_mcontext.bp;
    cur->st.regs.rbx = uc.uc_mcontext.bx;
    cur->st.regs.rdx = uc.uc_mcontext.dx;
    cur->st.regs.rax = uc.uc_mcontext.ax;
    cur->st.regs.rcx = uc.uc_mcontext.cx;
    cur->st.regs.rsp = uc.uc_mcontext.sp;
    cur->st.regs.rip = uc.uc_mcontext.ip;

    cur->st.fp = (void*)cur->st.regs.rsp;
    cur->st.pc = (void*)cur->st.regs.rip;
    cur->st.sp = (void*)cur->st.regs.rsp;

    return 1;
#else
    uint32_t a;
    
    /* determine whether we have siginfo or not (see gimli_is_signal_frame
     * for more on this) */
    gimli_read_mem(cur->proc, cur->st.pc, &a, sizeof(a));
    if (a == 0x0077b858) {
      /* no SA_SIGINFO */
      char *ptr;
      struct sigcontext sc;

      /* Now we need to update our regs based on the sigcontext.
       * The kernel pushes the following bits onto the stack:
       *
       * struct sigcontext sc;
       * struct _fpstate unused;
       * long extramask[_NSIG / 32];
       * char retcode[8];
       * the actual fp state comes here
       *
       * this frame structure is approx 720 bytes without taking the
       * real fp state into account.
       *
       * I've observed that the magic offset to the sc is fp - 756 bytes.
       * It feels wrong to have deduced the offset in this way.
       */
      ptr = cur->st.fp;
      ptr += 4;
      /* ptr -= 756; non dwarf */
      if (gimli_read_mem(cur->proc, ptr, &sc, sizeof(sc)) != sizeof(sc)) {
        printf("failed to read sigcontext\n");
        return 0;
      }

      cur->st.regs.edi = sc.edi;
      cur->st.regs.esi = sc.esi;
      cur->st.regs.ebp = sc.ebp;
      cur->st.regs.esp = sc.esp;
      cur->st.regs.ebx = sc.ebx;
      cur->st.regs.edx = sc.edx;
      cur->st.regs.ecx = sc.ecx;
      cur->st.regs.eax = sc.eax;
      cur->st.regs.eip = sc.eip;

      cur->st.fp = (void*)cur->st.regs.ebp;
      cur->st.sp = (void*)cur->st.regs.esp;
      cur->st.pc = (void*)cur->st.regs.eip;
      return 1;

    } else {
      /* has SA_SIGINFO */
      struct {
        int signo;
        struct siginfo *si;
        struct gimli_kernel_ucontext *uc;
      } frame;
      struct ucontext uc;

      if (gimli_read_mem(cur->proc, cur->st.fp /* - 920 non-dwarf !? */,
          &frame, sizeof(frame)) != sizeof(frame)) {
        printf("failed to read rt_sigframe\n");
        return 0;
      }
      if (gimli_read_mem(cur->proc, frame.uc, &uc, sizeof(uc))
          != sizeof(uc)) {
        printf("failed to read ucontext\n");
        return 0;
      }

      cur->st.regs.edi = uc.uc_mcontext.gregs[REG_EDI];
      cur->st.regs.esi = uc.uc_mcontext.gregs[REG_ESI];
      cur->st.regs.ebp = uc.uc_mcontext.gregs[REG_EBP];
      cur->st.regs.esp = uc.uc_mcontext.gregs[REG_ESP];
      cur->st.regs.ebx = uc.uc_mcontext.gregs[REG_EBX];
      cur->st.regs.edx = uc.uc_mcontext.gregs[REG_EDX];
      cur->st.regs.ecx = uc.uc_mcontext.gregs[REG_ECX];
      cur->st.regs.eax = uc.uc_mcontext.gregs[REG_EAX];
      cur->st.regs.eip = uc.uc_mcontext.gregs[REG_EIP];

      cur->st.fp = (void*)cur->st.regs.ebp;
      cur->st.sp = (void*)cur->st.regs.esp;
      cur->st.pc = (void*)cur->st.regs.eip;

      return 1;
    }
#endif
  }

  /* sanity check that dwarf made progress relative to the starting pc */
  if (gimli_dwarf_unwind_next(cur) && cur->st.pc && cur->st.pc != c.st.pc) {
//    printf("dwarf unwound to fp=%p sp=%p pc=%p\n", cur->st.fp, cur->st.sp, cur->st.pc);
#if defined(__x86_64__)
    cur->st.regs.rsp = (intptr_t)cur->st.fp;
//    cur->st.regs.rip = (intptr_t)cur->st.pc;
#endif
    return 1;
  }

//printf("dwarf unwind didn't succeed, doing it the hard way\n");
//printf("fp=%p sp=%p pc=%p\n", c.st.fp, c.st.sp, c.st.pc);

  if (c.st.fp) {
    if (gimli_read_mem(cur->proc, c.st.fp, &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }
//    printf("read frame: fp=%p pc=%p\n", frame.next, frame.retpc);
    /* If we don't appear to be making progress, or we end up in page 0,
     * then assume we're done */
    if (c.st.fp == frame.next || frame.next == 0 || frame.retpc < 1024) {
      return 0;
    }
    cur->st.fp = frame.next;
    cur->st.pc = frame.retpc;
    if (cur->st.pc > 0 && !gimli_is_signal_frame(cur)) {
      cur->st.pc--;
    }
#ifdef __i386__
    cur->st.regs.ebp = (intptr_t)cur->st.fp;
#endif
    return 1;
  }

  return 0;
}

static child_stopped = 0;

static void child_handler(int signo)
{
  int p;
  int status;

  child_stopped = 1;

  p = waitpid(-1, &status, WNOHANG);
}

gimli_err_t gimli_attach(gimli_proc_t proc)
{
  long ret;
  int status;
  td_err_e te;
  struct user_regs_struct ur;
  int i;
  int done = 0;
  struct ps_prochandle *tdep;
  char name[1024];

  tdep = calloc(1, sizeof(*tdep));
  if (!tdep) {
    return GIMLI_ERR_OOM;
  }
  tdep->proc = proc;
  proc->tdep = tdep;

  signal(SIGCHLD, child_handler);
  
  ret = gimli_ptrace(PTRACE_ATTACH, proc->pid, NULL, NULL);
  if (ret != 0) {
    int err = errno;

    fprintf(stderr, "PTRACE_ATTACH: failed: %s\n",
      strerror(err));

    errno = err;

    switch (err) {
      case ESRCH:
        return GIMLI_ERR_NO_PROC;
      case EPERM:
        return GIMLI_ERR_PERM;
      default:
        return GIMLI_ERR_CHECK_ERRNO;
    }
    return 0;
  }

  status = 0;
  for (i = 0; i < 60; i++) {
    if (child_stopped) {
      break;
    }

    if (waitpid(proc->pid, &status, WNOHANG) == proc->pid) {
      child_stopped = 1;
      break;
    }

    fprintf(stderr, "waiting for pid %d to stop\n", proc->pid);
    sleep(1);
  }
  signal(SIGCHLD, SIG_DFL);
  if (!child_stopped) {
    fprintf(stderr, "child didn't stop in 60 seconds\n");
    return GIMLI_ERR_TIMEOUT;
  }

  snprintf(name, sizeof(name), "/proc/%d/mem", proc->pid);
  tdep->proc_mem = open(name, O_RDWR);
  tdep->proc_mem_supports_mmap = -1; /* don't know yet */
  if (tdep->proc_mem == -1) {
    fprintf(stderr, "failed to open %s: %s\n", name, strerror(errno));
    return GIMLI_ERR_CHECK_ERRNO;
  }

  read_maps(proc);

  te = td_init();
  if (te != TD_OK) {
    fprintf(stderr, "td_init failed: %d\n", te);
    return GIMLI_ERR_THREAD_DEBUGGER_INIT_FAILED;
  }
  te = td_ta_new(tdep, &tdep->ta);
  if (te != TD_OK && te != TD_NOLIBTHREAD) {
    fprintf(stderr, "td_ta_new failed: %d\n", te);
    return GIMLI_ERR_THREAD_DEBUGGER_INIT_FAILED;
  }
  if (tdep->ta) {
    te = td_ta_get_nthreads(tdep->ta, &proc->nthreads);
    if (te == TD_OK) {
      proc->threads = calloc(proc->nthreads, sizeof(*proc->threads));
      tdep->cur_enum_thread = proc->threads;
      td_ta_thr_iter(tdep->ta, enum_threads, proc, TD_THR_ANY_STATE,
        TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
      tdep->pids_to_detach = calloc(proc->nthreads, sizeof(int));
    } else {
      fprintf(stderr, "td_ta_get_nthreads failed: %d\n", te);
    }

  } else {
    proc->threads = calloc(1, sizeof(*proc->threads));
    proc->threads->lwpid = proc->pid;
    proc->nthreads = 1;
  }

  while (done < proc->nthreads) {
    for (i = 0; i < proc->nthreads; i++) {
      struct gimli_thread_state *thr = &proc->threads[i];

      if (ptrace(PTRACE_GETREGS, thr->lwpid, NULL, &ur) == 0) {
        user_regs_to_thread(&ur, thr);
        done++;
      }
    }
    if (done >= proc->nthreads) {
      break;
    }
    sleep(1);
    done = 0;
  }
  return GIMLI_ERR_OK;
}

gimli_err_t gimli_detach(gimli_proc_t proc)
{
  long ret;
  struct ps_prochandle *tdep = proc->tdep;
  int i;

  ptrace(PTRACE_DETACH, proc->pid, NULL, SIGCONT);
  for (i = 0; i < tdep->num_pids; i++) {
    ret = ptrace(PTRACE_DETACH, tdep->pids_to_detach[i], NULL, SIGCONT);
  }

  // FIXME: free all bits from tdep properly
  free(tdep);

  return 0;
}

ps_err_e ps_pdwrite(struct ps_prochandle *ph, paddr_t addr,
  void *buf, size_t size)
{
  return PS_ERR;
}

ps_err_e ps_pdread(struct ps_prochandle *ph, paddr_t addr,
  void *buf, size_t size)
{
  if (gimli_read_mem(ph->proc, (void*)addr, buf, size) != size) {
    return PS_ERR;
  }
  return PS_OK;
}

ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph, const char *obj,
  const char *name, paddr_t *symaddr)
{
  struct gimli_symbol *sym = gimli_sym_lookup(ph->proc, obj, name);
  if (sym) {
    *symaddr = (paddr_t)sym->addr;
    return PS_OK;
  }
  return PS_NOSYM;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, void *fpregset)
{
  return PS_ERR;
}

ps_err_e ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid, void *gregset)
{
  return PS_ERR;
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid, void *fpregset)
{
  return PS_ERR;
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid, void *gregset)
{
  if (0 == gimli_ptrace(PTRACE_GETREGS, lwpid, NULL, gregset)) {
    return PS_OK;
  }
  return PS_ERR;
}

pid_t ps_getpid(struct ps_prochandle *ph)
{
  return ph->proc->pid;
}

#endif



/* vim:ts=2:sw=2:et:
 */

