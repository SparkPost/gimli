/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#ifdef sun
#include "impl.h"

/* this is the solaris proc_service style interface.
 * libc_db library routines require that we export these functions.
 * This is something of a pain, as the Solaris interface is a bit
 * tricksy.  There does exist a libproc that implements a lot of these
 * functions, but it is officially not a supported API.
 */

struct ps_prochandle {
  pid_t pid;
  int ctl_fd;    /* handle on /proc/pid/control */
  int as_fd;     /* handle on /proc/pid/as */
  int status_fd; /* handle on /proc/pid/status */
  pstatus_t status;
  struct ps_prochandle *next;
};

static struct ps_prochandle targetph = {
  -1, -1, -1, -1,
  NULL
};
static td_thragent_t *ta = NULL;
static struct gimli_thread_state *cur_enum_thread = NULL;

ps_err_e ps_pcontinue(struct ps_prochandle *ph)
{
  return PS_OK;
}

ps_err_e ps_lcontinue(struct ps_prochandle *ph, lwpid_t lwpid)
{
  return PS_OK;
}

ps_err_e ps_pdread(struct ps_prochandle *ph, psaddr_t addr,
         void *buf, size_t size)
{
  if (ph->as_fd >= 0) {
    ssize_t ret = pread(ph->as_fd, buf, size, addr);
    if (ret == size) {
      return PS_OK;
    }
  }
  return PS_ERR;
}

ps_err_e ps_pdwrite(struct ps_prochandle *ph, psaddr_t addr,
         const void *buf, size_t size)
{
  return PS_ERR;
}

ps_err_e ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
{
  return PS_OK;
}

ps_err_e ps_pstop(struct ps_prochandle *ph)
{
  return PS_OK;
}

ps_err_e ps_lsetregs(struct ps_prochandle *ph, lwpid_t lwpid,
         const prgregset_t gregset)
{
  return PS_ERR;
}

ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph,
      const char *object_name, const char *sym_name, psaddr_t *sym_addr)
{
  struct gimli_symbol *sym = gimli_sym_lookup(object_name, sym_name);
  if (sym) {
    *sym_addr = (psaddr_t)sym->addr;
    return PS_OK;
  }
  return PS_NOSYM;
}

ps_err_e ps_lgetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
      prfpregset_t *fpregset)
{
  return PS_ERR;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle *ph, lwpid_t lwpid,
      const prfpregset_t *fpregset)
{
  return PS_ERR;
}

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

static void user_regs_to_thread(prgregset_t ur,
  struct gimli_thread_state *thr)
{
  memcpy(&thr->regs, ur, sizeof(*ur));
  thr->fp = (void*)ur[R_FP];
  thr->pc = (void*)ur[R_PC];
  thr->sp = (void*)ur[R_SP];
}

static int enum_threads(const td_thrhandle_t *thr, void *unused)
{
  struct gimli_thread_state *th = cur_enum_thread;
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

  te = td_thr_getgregs(thr, ur);
  if (TD_OK != te) {
    fprintf(stderr, "getgregs: %d\n", te);
    return 0;
  }

  user_regs_to_thread(ur, th);
  get_lwp_status(targetph.pid, info.ti_lid, &cur_enum_thread->lwpst);

  cur_enum_thread->lwpid = info.ti_lid;
  cur_enum_thread++;
  return 0;
}

static void read_maps(void)
{
  char filename[1024];
  prmap_t *maps, *m, *end;
  struct stat sb;
  int fd;
  int n;

  snprintf(filename, sizeof(filename)-1, "/proc/%d/map", targetph.pid);
  fd = open(filename, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "open(%s): %s\n", filename, strerror(errno));
    return;
  }
  if (fstat(fd, &sb) != 0) {
    fprintf(stderr, "fstat %s: %s\n", filename, strerror(errno));
    close(fd);
    return;
  }
  maps = malloc(sb.st_size);
  if (maps == NULL) {
    fprintf(stderr, "malloc(%d) for maps: %s\n", sb.st_size, strerror(errno));
    close(fd);
    return;
  }
  n = pread(fd, maps, sb.st_size, 0);
  if (n != sb.st_size) {
    fprintf(stderr, "pread for maps: %s\n", strerror(errno));
    close(fd);
    free(maps);
    return;
  }
  close(fd);
  end = maps + (sb.st_size / sizeof(*m));

  for (m = maps; m < end; m++) {
    /* the mapname is the name of a symlink in /proc/pid/path;
     * we need to resolve that link and add the mapping */
    char target[2048];
    ssize_t ret;

    snprintf(filename, sizeof(filename)-1, "/proc/%d/path/%s",
      targetph.pid, m->pr_mapname);
    ret = readlink(filename, target, sizeof(target));
    if (ret > 0) {
      target[ret] = '\0';
      gimli_add_mapping(target, (void*)m->pr_vaddr, m->pr_size, m->pr_offset);
    }
  }
  
  free(maps);
}

int gimli_attach(int pid)
{
  td_err_e te;
  char path[1024];
  long ctl[3];
  int ret;

  targetph.pid = pid;

  snprintf(path, sizeof(path)-1, "/proc/%d/as", pid);
  targetph.as_fd = open(path, O_RDONLY|O_EXCL);
  if (targetph.as_fd == -1) {
    fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
    goto err;
  }
  
  snprintf(path, sizeof(path)-1, "/proc/%d/status", pid);
  targetph.status_fd = open(path, O_RDONLY);
  if (targetph.status_fd == -1) {
    fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
    goto err;
  }
  snprintf(path, sizeof(path)-1, "/proc/%d/ctl", pid);
  targetph.ctl_fd = open(path, O_WRONLY);
  if (targetph.ctl_fd == -1) {
    fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
    goto err;
  }
 
  /* now ask the process the stop */
  ctl[0] = PCDSTOP;
  ctl[1] = PCTWSTOP;
  ctl[2] = 2000; /* 2 second timeout */
  ret = write(targetph.ctl_fd, ctl, sizeof(ctl));

  if (ret != sizeof(ctl)) {
    fprintf(stderr, "Unable to stop pid %d: %s\n", pid, strerror(errno));
    goto err;
  }

  ret = pread(targetph.status_fd, &targetph.status, sizeof(targetph.status), 0);
  if (ret != sizeof(targetph.status)) {
    if (errno == EOVERFLOW) {
      fprintf(stderr, "This binary was built to work with 32-bit processes; the target is 64-bit\n");
      goto err;
    }
    fprintf(stderr, "Error reading proc status: %s\n", strerror(errno));
    goto err;
  }
#ifdef _LP64
  if (targetph.status.pr_dmodel == PR_MODEL_ILP32) {
    fprintf(stderr, "This binary was built to work with 64-bit processes; the target is 32-bit\n");
    goto err;
  }
#else
  if (targetph.status.pr_dmodel == PR_MODEL_LP64) {
    fprintf(stderr, "This binary was built to work with 32-bit processes; the target is 64-bit\n");
    goto err;
  }
#endif

  read_maps();

  te = td_init();
  if (te != TD_OK) {
    fprintf(stderr, "td_init failed: %d\n", te);
    goto err;
  }
  te = td_ta_new(&targetph, &ta);
  if (te != TD_OK && te != TD_NOLIBTHREAD) {
    fprintf(stderr, "td_ta_new failed: %d\n", te);
    goto err;
  }
  if (ta) {
    te = td_ta_get_nthreads(ta, &gimli_nthreads);
    if (te == TD_OK) {
      gimli_threads = calloc(gimli_nthreads, sizeof(*gimli_threads));
      cur_enum_thread = gimli_threads;
      td_ta_thr_iter(ta, enum_threads, NULL, TD_THR_ANY_STATE,
        TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
    } else {
      fprintf(stderr, "td_ta_get_nthreads failed: %d\n", te);
    }
  } else {
    gimli_threads = calloc(1, sizeof(*gimli_threads));
    user_regs_to_thread(targetph.status.pr_lwp.pr_reg, &gimli_threads[0]);
    gimli_threads->lwpst = targetph.status.pr_lwp;
    gimli_nthreads = 1;
    gimli_threads->lwpid = pid;
  }

  return 1;

err:

  return 0;
}

int gimli_detach(void)
{
  if (targetph.ctl_fd >= 0) {
    /* don't leave the process stopped */
    long ctl[2] = { PCRUN, 0 };

    write(targetph.ctl_fd, ctl, sizeof(ctl));
  }
  
  if (targetph.as_fd >= 0) {
    close(targetph.as_fd);
    targetph.as_fd = -1;
  }
  if (targetph.status_fd >= 0) {
    close(targetph.status_fd);
    targetph.status_fd = -1;
  }
  if (targetph.ctl_fd >= 0) {
    close(targetph.ctl_fd);
    targetph.ctl_fd = -1;
  }

  return 0;
}

int gimli_init_unwind(struct gimli_unwind_cursor *cur,
  struct gimli_thread_state *st)
{
  memcpy(&cur->st, st, sizeof(*st));
  return 1;
}

int gimli_unwind_next(struct gimli_unwind_cursor *cur)
{
  struct {
    void *fp;
    void *pc;
  } frame;
  struct gimli_unwind_cursor c;
  
  if (gimli_is_signal_frame(cur)) {
    ucontext_t uc;

    if (gimli_read_mem((void*)cur->st.lwpst.pr_oldcontext, &uc, sizeof(uc)) !=
        sizeof(uc)) {
      fprintf(stderr, "unable to read old context\n");
      return 0;
    }
    /* update to next in chain */
    cur->st.lwpst.pr_oldcontext = (intptr_t)uc.uc_link;
    /* copy out register set */
    memcpy(cur->st.regs, uc.uc_mcontext.gregs, sizeof(cur->st.regs));
    /* update local copy */
    cur->st.fp = (void*)cur->st.regs[R_FP];
    cur->st.pc = (void*)cur->st.regs[R_PC];
    cur->st.sp = (void*)cur->st.regs[R_SP];
    return 1;
  }

  c = *cur;
  if (gimli_dwarf_unwind_next(cur) && cur->st.pc) {
    return 1;
  }
  if (debug) {
    fprintf(stderr, "dwarf unwind unsuccessful\n");
  }

  if (c.st.fp) {
    if (gimli_read_mem(c.st.fp, &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }

    if (c.st.fp == frame.fp) {
      return 0;
    }
    cur->st.fp = frame.fp;
    cur->st.pc = frame.pc;
    if (cur->st.pc > 0 && !gimli_is_signal_frame(cur)) {
      cur->st.pc--;
    }
    cur->st.regs[R_FP] = (intptr_t)cur->st.fp;

    if (cur->st.pc == 0 && cur->st.lwpst.pr_oldcontext) {
      /* well, gimli_is_signal_frame is supposed to detect a signal
       * frame before we fall off the end of it, but I can't seem
       * to get the numbers to match up on i386, so here's something
       * of a kludge around it.  If we fall off the end, and the
       * lwpstatus indicates that there is a prior context, assume
       * that we're unwinding to that context.
       * To do this, we force in a -1 instruction pointer, which coincides
       * with the non-dwarf aware way of detecting a signal frame */
      cur->st.pc = (void*)-1;
    }
    return 1;
  }
  return 0;
}

void *gimli_reg_addr(struct gimli_unwind_cursor *cur, int col)
{
  /* See http://wikis.sun.com/display/SunStudio/Dwarf+Register+Numbering */
  switch (col) {
#ifdef __i386
    case 0: return &cur->st.regs[EAX];
    case 1: return &cur->st.regs[ECX];
    case 2: return &cur->st.regs[EDX];
    case 3: return &cur->st.regs[EBX];
    case 4: return &cur->st.regs[UESP];
    case 5: return &cur->st.regs[EBP];
    case 6: return &cur->st.regs[ESI];
    case 7: return &cur->st.regs[EDI];
    case 8: return &cur->st.regs[EIP]; /* return address */
#elif defined(__x86_64__)
    case 0: return &cur->st.regs[REG_RAX];
    case 1: return &cur->st.regs[REG_RDX];
    case 2: return &cur->st.regs[REG_RCX];
    case 3: return &cur->st.regs[REG_RBX];
    case 4: return &cur->st.regs[REG_RSI];
    case 5: return &cur->st.regs[REG_RDI];
    case 6: return &cur->st.regs[REG_RBP];
    case 7: return &cur->st.regs[REG_RSP];
    case 8: return &cur->st.regs[REG_R8];
    case 9: return &cur->st.regs[REG_R9];
    case 10: return &cur->st.regs[REG_R10];
    case 11: return &cur->st.regs[REG_R11];
    case 12: return &cur->st.regs[REG_R12];
    case 13: return &cur->st.regs[REG_R13];
    case 14: return &cur->st.regs[REG_R14];
    case 15: return &cur->st.regs[REG_R15];
    case 16: return &cur->st.regs[REG_RIP]; /* return address */
#else
#error no yet coded
#endif
  }
  return 0;
}

int gimli_read_mem(void *src, void *dest, int len)
{
  if (targetph.as_fd >= 0) {
    ssize_t ret = pread(targetph.as_fd, dest, len, (intptr_t)src);
    return ret;
  }
  return -1;
}

/* http://src.opensolaris.org/source/xref/onnv/onnv-gate/usr/src/lib/libproc/common/Pstack.c#82
 * has detailed discussion on signal frames.
 */
int gimli_is_signal_frame(struct gimli_unwind_cursor *cur)
{
#ifdef __x86_64__
  if (((intptr_t)cur->st.fp + (4 * sizeof(greg_t)) ==
      cur->st.lwpst.pr_oldcontext) ||
      (cur->st.pc == (void*)-1 && cur->st.lwpst.pr_oldcontext != 0)) {
    struct {
      int signo;
      siginfo_t *siptr;
    } frame;

    gimli_read_mem((char*)cur->st.lwpst.pr_oldcontext - sizeof(frame),
      &frame, sizeof(frame));

    if (frame.siptr) {
      gimli_read_mem(frame.siptr, &cur->si, sizeof(cur->si));
    } else {
      memset(&cur->si, 0, sizeof(cur->si));
      cur->si.si_signo = frame.signo;
      cur->si.si_code = SI_NOINFO;
    }
    return 1;
  }
#elif defined(__i386)
  if (((intptr_t)cur->st.fp + sizeof(struct frame) +
      (3 * sizeof(greg_t)) == cur->st.lwpst.pr_oldcontext) ||
      (cur->st.pc == (void*)-1 && cur->st.lwpst.pr_oldcontext != 0)) {
    struct {
      int signo;
      siginfo_t *siptr;
      ucontext_t *ucptr;
    } frame;

    gimli_read_mem((char*)cur->st.lwpst.pr_oldcontext - sizeof(frame),
      &frame, sizeof(frame));

    if (frame.siptr) {
      gimli_read_mem(frame.siptr, &cur->si, sizeof(cur->si));
    } else {
      memset(&cur->si, 0, sizeof(cur->si));
      cur->si.si_signo = frame.signo;
      cur->si.si_code = SI_NOINFO;
    }
    return 1;
  }
#elif defined(__sparc__)
  if (cur->st.fp + sizeof(struct frame)
      == cur->st.lwpst.pr_oldcontext) {
    /* TODO: implement for sparc */
    return 1;
  }
#endif
  if (cur->st.pc == (void*)-1) {
    return 1;
  }
  return 0;
}

#endif

/* vim:ts=2:sw=2:et:
 */

