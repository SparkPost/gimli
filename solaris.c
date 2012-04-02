/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#ifdef sun
#include "impl.h"

/* this is the solaris proc_service style interface.
 * libc_db library routines require that we export these functions.
 * This is something of a pain, as the Solaris interface is a bit
 * tricksy.  There does exist a libproc that implements a lot of these
 * functions, but it is officially not a supported API.
 */

#define PR_OBJ_EVERY ((const char*)-1) /* search everything */

ps_err_e ps_pcontinue(struct ps_prochandle *ph)
{
  return PS_OK;
}

ps_err_e ps_lcontinue(struct ps_prochandle *ph, lwpid_t lwpid)
{
  return PS_OK;
}

ps_err_e ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
{
  return PS_OK;
}

ps_err_e ps_pstop(struct ps_prochandle *ph)
{
  return PS_OK;
}

#ifdef __sparc__
ps_err_e ps_lsetxregs(struct ps_prochandle *ph, lwpid_t lid,
         caddr_t xregset)
{
  return PS_ERR;
}

ps_err_e ps_lgetxregs(struct ps_prochandle *ph, lwpid_t lid,
         caddr_t xregset)
{
  char path[1024];
  int fd;
  int ret;

  snprintf(path, sizeof(path)-1, "/proc/%d/lwp/%d/xregs", ph->pid, lid);

  fd = open(path, O_RDONLY);
  if (fd >= 0) {
    ret = read(fd, xregset, sizeof(prxregset_t));
    if (ret == sizeof(prxregset_t)) {
      close(fd);
      return PS_OK;
    }
    fprintf(stderr, "unable to read xregs for LWP %d: %s\n",
      lid, strerror(errno));
    close(fd);
  } else {
    fprintf(stderr, "unable to read xregs for LWP %d: %s %s\n",
      lid, path, strerror(errno));
  }
  return PS_BADLID;
}

ps_err_e ps_lgetxregsize(struct ps_prochandle *ph, lwpid_t lid,
    int *xregsize)
{
  char path[1024];
  struct stat st;

  snprintf(path, sizeof(path)-1, "/proc/%d/lwp/%d/xregs", ph->pid, lid);
  if (stat(path, &st) == 0) {
    *xregsize = (int)st.st_size;
    return PS_OK;
  }
  return PS_BADLID;
}
#endif

ps_err_e ps_pglobal_lookup(struct ps_prochandle *ph,
      const char *object_name, const char *sym_name, psaddr_t *sym_addr)
{
  struct gimli_symbol *sym;

  if (object_name == PS_OBJ_EXEC) {
    object_name = ph->first_file->objname;
  } else if (object_name == PS_OBJ_LDSO) {
    long base = 0;
    auxv_t *av;
    struct gimli_object_mapping *m = NULL;

    object_name = NULL;
    for (av = ph->tdep.auxv; av->a_type != AT_NULL; av++) {
      if (av->a_type == AT_BASE) {
        base = av->a_un.a_val;
        m = gimli_mapping_for_addr(ph, base);
        object_name = m->objfile->objname;
        break;
      }
    }

  } else if (object_name == PR_OBJ_EVERY) {
    object_name = NULL;
  }

  sym = gimli_sym_lookup(ph, object_name, sym_name);
  if (sym) {
    *sym_addr = (psaddr_t)sym->addr;
    return PS_OK;
  }
  return PS_NOSYM;
}

static void show_regs(prgregset_t regs)
{
#if 0
  int i;
  for (i = 0; i < NPRGREG ; i++) {
    printf("reg: %d: %p\n", i, regs[i]);
  }
#endif
}

static int read_auxv(gimli_proc_t proc)
{
  int fd, n;
  char path[1024];
  struct stat st;

  snprintf(path, sizeof(path), "/proc/%d/auxv", proc->pid);
  fd = open(path, O_RDONLY);
  if (fd == -1) {
    return 0;
  }
  if (fstat(fd, &st) == 0 && st.st_size >= sizeof(auxv_t)) {
    proc->tdep.auxv = malloc(st.st_size + sizeof(auxv_t));

    n = read(fd, proc->tdep.auxv, st.st_size);
    n /= sizeof(auxv_t);
    if (n >= 1) {
      proc->tdep.auxv[n].a_type = AT_NULL;
      proc->tdep.auxv[n].a_un.a_val = 0L;
      proc->tdep.naux = n;
    }
  }
  close(fd);
}

static void read_maps(gimli_proc_t proc)
{
  char filename[1024];
  prmap_t *maps, *m, *end;
  struct stat sb;
  int fd;
  int n;

  snprintf(filename, sizeof(filename)-1, "/proc/%d/map", proc->pid);
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
    fprintf(stderr, "malloc(%" PRIu64 ") for maps: %s\n", (uint64_t)sb.st_size, strerror(errno));
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
      proc->pid, m->pr_mapname);
    ret = readlink(filename, target, sizeof(target));
    if (ret > 0) {
      target[ret] = '\0';
      gimli_add_mapping(proc, target, m->pr_vaddr, m->pr_size, m->pr_offset);
    }
  }

  free(maps);
}

gimli_err_t gimli_attach(gimli_proc_t proc)
{
  td_err_e te;
  char path[1024];
  long ctl[3];
  int ret;
  gimli_err_t err;

  snprintf(path, sizeof(path)-1, "/proc/%d/as", proc->pid);
  proc->proc_mem = open(path, O_RDONLY|O_EXCL);
  if (proc->proc_mem == -1) {
    fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
    goto err;
  }

  snprintf(path, sizeof(path)-1, "/proc/%d/status", proc->pid);
  proc->tdep.status_fd = open(path, O_RDONLY);
  if (proc->tdep.status_fd == -1) {
    fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
    goto err;
  }
  snprintf(path, sizeof(path)-1, "/proc/%d/ctl", proc->pid);
  proc->tdep.ctl_fd = open(path, O_WRONLY);
  if (proc->tdep.ctl_fd == -1) {
    fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
    goto err;
  }

  /* now ask the process the stop */
  ctl[0] = PCDSTOP;
  ctl[1] = PCTWSTOP;
  ctl[2] = 2000; /* 2 second timeout */
  ret = write(proc->tdep.ctl_fd, ctl, sizeof(ctl));

  if (ret != sizeof(ctl)) {
    fprintf(stderr, "Unable to stop pid %d: %s\n", proc->pid, strerror(errno));
    goto err;
  }

  ret = pread(proc->tdep.status_fd, &proc->tdep.status, sizeof(proc->tdep.status), 0);
  if (ret != sizeof(proc->tdep.status)) {
    if (errno == EOVERFLOW) {
      fprintf(stderr, "This binary was built to work with 32-bit processes; the target is 64-bit\n");
      goto err;
    }
    fprintf(stderr, "Error reading proc status: %s\n", strerror(errno));
    goto err;
  }
#ifdef _LP64
  if (proc->tdep.status.pr_dmodel == PR_MODEL_ILP32) {
    fprintf(stderr, "This binary was built to work with 64-bit processes; the target is 32-bit\n");
    goto err;
  }
#else
  if (proc->tdep.status.pr_dmodel == PR_MODEL_LP64) {
    fprintf(stderr, "This binary was built to work with 32-bit processes; the target is 64-bit\n");
    goto err;
  }
#endif

  read_auxv(proc);
  read_maps(proc);

  err = gimli_proc_service_init(proc);

  if (err != GIMLI_ERR_OK) {
    return err;
  }

  if (!proc->ta) {
    struct gimli_thread_state *thr = gimli_proc_thread_by_lwpid(proc, proc->pid, 1);

    gimli_user_regs_to_thread(&proc->tdep.status.pr_lwp.pr_reg, thr);
    thr->lwpst = proc->tdep.status.pr_lwp;
  }

  return GIMLI_ERR_OK;

err:

  return GIMLI_ERR_CHECK_ERRNO;
}

gimli_err_t gimli_detach(gimli_proc_t proc)
{
  gimli_proc_service_destroy(proc);

  if (proc->tdep.ctl_fd >= 0) {
    /* don't leave the process stopped */
    long ctl[2] = { PCRUN, 0 };

    write(proc->tdep.ctl_fd, ctl, sizeof(ctl));
  }

  if (proc->tdep.status_fd >= 0) {
    close(proc->tdep.status_fd);
    proc->tdep.status_fd = -1;
  }
  if (proc->tdep.ctl_fd >= 0) {
    close(proc->tdep.ctl_fd);
    proc->tdep.ctl_fd = -1;
  }

  return 0;
}

int gimli_init_unwind(struct gimli_unwind_cursor *cur,
  struct gimli_thread_state *st)
{
  memcpy(&cur->st, st, sizeof(*st));
  return 1;
}

#ifdef __sparc__
static int read_gwindow(struct gimli_unwind_cursor *cur)
{
  char path[1024];
  int fd, n, rv = 0;
  struct stat64 st;
  gwindows_t gwin;

  snprintf(path, sizeof(path), "/proc/%d/lwp/%d/gwindows",
    cur->proc->pid, cur->st.lwpid);

  if (stat64(path, &st) == -1 || st.st_size == 0) {
    return 0;
  }

  fd = open(path, O_RDONLY);
  if (fd == -1) {
    return 0;
  }

  /* zero out gwin, as we may get a partial read */
  memset(&gwin, 0, sizeof(gwin));
  n = read(fd, &gwin, sizeof(gwin));
  if (n > 0) {
    int i;

    for (i = 0; i < gwin.wbcnt; i++) {
      if (gwin.spbuf[i] == cur->st.fp) {
        /* we found the frame we wanted */
        memcpy(&cur->st.regs[R_L0], &gwin.wbuf[i], sizeof(struct rwindow));
        rv = 1;
        break;
      }
    }
  }
  close(fd);

  return rv;
}
#endif

int gimli_unwind_next(struct gimli_unwind_cursor *cur)
{
  struct frame frame;
  struct gimli_unwind_cursor c;

  if (gimli_is_signal_frame(cur)) {
    ucontext_t uc;

    if (gimli_read_mem(cur->proc, cur->st.lwpst.pr_oldcontext,
          &uc, sizeof(uc)) != sizeof(uc)) {
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
    /* registers are all good for dwarf */
    cur->dwarffail = 0;
    return 1;
  }

  c = *cur;
#if 0
  /* disabling dwarf unwinding on Solaris for the time being;
   * it doesn't appear to be accurately, or perhaps, we're not
   * correctly supporting some aspects of it on this system.
   * Solaris does build with frame pointers though (thanks dtrace!)
   * and they're reliable enough that we're not losing out */
  if (gimli_dwarf_unwind_next(cur) && cur->st.pc && cur->st.pc != c.st.pc) {
    fprintf(stderr, "dwarf WIN! %p\n", cur->st.pc);
    cur->st.regs[R_FP] = (intptr_t)cur->st.fp;
    cur->st.regs[R_SP] = (intptr_t)cur->st.sp;
    cur->st.regs[R_PC] = (intptr_t)cur->st.pc;
    return 1;
  }
  if (debug || 1) {
    fprintf(stderr, "dwarf unwind unsuccessful\n");
  }
#endif

  if (c.st.fp) {
    *cur = c;

#ifndef __sparc__
    if (gimli_read_mem(cur->proc, (gimli_addr_t)c.st.fp,
          &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }

    if (c.st.fp == (void*)frame.fr_savfp) {
      return 0;
    }
    cur->st.fp = (void*)frame.fr_savfp;
    cur->st.pc = (void*)frame.fr_savpc;

    if (cur->st.pc > 0 && !gimli_is_signal_frame(cur)) {
      cur->st.pc--;
    }
    cur->st.regs[R_FP] = (intptr_t)cur->st.fp;
    cur->st.regs[R_SP] = (intptr_t)cur->st.fp;
    cur->st.regs[R_PC] = (intptr_t)cur->st.pc;
    cur->st.sp = cur->st.regs[R_SP];
#else
    cur->st.regs[R_PC] = cur->st.regs[R_I7];
    cur->st.regs[R_nPC] = cur->st.regs[R_PC] + 4;
    memcpy(&cur->st.regs[R_O0], &cur->st.regs[R_I0], 8 * sizeof(prgreg_t));
    show_regs(cur->st.regs);
    if (cur->st.regs[R_FP] == 0) {
      return 0;
    }

    if (gimli_read_mem(cur->proc, (cur->st.regs[R_FP] + STACK_BIAS),
        &cur->st.regs[R_L0],
        sizeof(struct rwindow)) != sizeof(struct rwindow)) {
      /* try to fill this data in via gwindow information */
      if (!read_gwindow(cur)) {
        fprintf(stderr, "unable to read rwindow @ " PTRFMT ", and no gwindow\n",
          cur->st.regs[R_FP]);
      }
    }
    cur->st.fp = (void*)cur->st.regs[R_FP];
    cur->st.pc = (void*)cur->st.regs[R_PC];
    cur->st.sp = (void*)cur->st.regs[R_SP];
    cur->dwarffail = 0;
#endif

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
#elif defined(__sparc__)
    case 0: return &cur->st.regs[R_G0];
    case 1: return &cur->st.regs[R_G1];
    case 2: return &cur->st.regs[R_G2];
    case 3: return &cur->st.regs[R_G3];
    case 4: return &cur->st.regs[R_G4];
    case 5: return &cur->st.regs[R_G5];
    case 6: return &cur->st.regs[R_G6];
    case 7: return &cur->st.regs[R_G7];

    case 8: return &cur->st.regs[R_O0];
    case 9: return &cur->st.regs[R_O1];
    case 10: return &cur->st.regs[R_O2];
    case 11: return &cur->st.regs[R_O3];
    case 12: return &cur->st.regs[R_O4];
    case 13: return &cur->st.regs[R_O5];
    case 14: return &cur->st.regs[R_O6];
    case 15: return &cur->st.regs[R_O7];

    case 16: return &cur->st.regs[R_L0];
    case 17: return &cur->st.regs[R_L1];
    case 18: return &cur->st.regs[R_L2];
    case 19: return &cur->st.regs[R_L3];
    case 20: return &cur->st.regs[R_L4];
    case 21: return &cur->st.regs[R_L5];
    case 22: return &cur->st.regs[R_L6];
    case 23: return &cur->st.regs[R_L7];

    case 24: return &cur->st.regs[R_I0];
    case 25: return &cur->st.regs[R_I1];
    case 26: return &cur->st.regs[R_I2];
    case 27: return &cur->st.regs[R_I3];
    case 28: return &cur->st.regs[R_I4];
    case 29: return &cur->st.regs[R_I5];
    case 30: return &cur->st.regs[R_I6];
    case 31: return &cur->st.regs[R_I7];

#else
#error no yet coded
#endif
  }
  return 0;
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

    gimli_read_mem(cur->proc, (gimli_addr_t)((char*)cur->st.lwpst.pr_oldcontext - sizeof(frame)),
      &frame, sizeof(frame));

    if (frame.siptr) {
      gimli_read_mem(cur->proc, (gimli_addr_t)frame.siptr, &cur->si, sizeof(cur->si));
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

    gimli_read_mem(cur->proc, (char*)cur->st.lwpst.pr_oldcontext - sizeof(frame),
      &frame, sizeof(frame));

    if (!frame.siptr || gimli_read_mem(cur->proc, frame.siptr,
          &cur->si, sizeof(cur->si)) != sizeof(cur->si)) {
      memset(&cur->si, 0, sizeof(cur->si));
      cur->si.si_signo = frame.signo;
      cur->si.si_code = SI_NOINFO;
    }
    return 1;
  }
#elif defined(__sparc__)
  if (cur->st.fp + sizeof(struct frame)
      == (void*)cur->st.lwpst.pr_oldcontext) {
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

