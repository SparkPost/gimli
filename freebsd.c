/*
 * Copyright (c) 2011 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#ifdef __FreeBSD__
#include "impl.h"

int gimli_read_mem(gimli_proc_t proc, void *src, void *dest, int len)
{
  struct ptrace_io_desc id;

  memset(&id, 0, sizeof(id));
  id.piod_op = PIOD_READ_D;
  id.piod_offs = src;
  id.piod_addr = dest;
  id.piod_len = len;

  if (ptrace(PT_IO, proc->pid, (caddr_t)&id, 0) == 0) {
    return id.piod_len;
  }
  fprintf(stdout, "readmem: unable to read %d bytes at %p: %s\n",
    len, src, strerror(errno));
  return 0;
}

int gimli_write_mem(gimli_proc_t proc, void *target, const void *buf, int len)
{
  struct ptrace_io_desc id;

  memset(&id, 0, sizeof(id));
  id.piod_op = PIOD_WRITE_D;
  id.piod_offs = target;
  id.piod_addr = (void*)buf;
  id.piod_len = len;

  if (ptrace(PT_IO, proc->pid, (caddr_t)&id, 0) == 0) {
    return id.piod_len;
  }
  fprintf(stdout, "writemem: unable to read %d bytes at %p: %s\n",
    len, target, strerror(errno));
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
  /* generic x86 backtrace */
  struct x86_frame {
    struct x86_frame *next;
    void *retpc;
  } frame;
  struct gimli_unwind_cursor c;

  c = *cur;

  if (gimli_dwarf_unwind_next(cur)) {
//    printf("dwarf unwound to fp=%p sp=%p pc=%p\n", cur->st.fp, cur->st.sp, cur->st.pc);
#if defined(__x86_64__)
    cur->st.regs.r_rbp = (intptr_t)cur->st.fp;
#elif defined(__i386__)
    cur->st.regs.ebp = (intptr_t)cur->st.fp;
#endif
    return 1;
  }
//printf("dwarf unwind didn't succeed, doing it the hard way\n");
//printf("fp=%p sp=%p pc=%p\n", c.st.fp, c.st.sp, c.st.pc);

  if (c.st.fp) {
    if (gimli_read_mem(cur->proc, c.st.fp, &frame, sizeof(frame)) != sizeof(frame)) {
      memset(&frame, 0, sizeof(frame));
    }
 //   printf("read frame: fp=%p pc=%p\n", frame.next, frame.retpc);
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
#elif defined(__x86_64__)
    cur->st.regs.r_rbp = (intptr_t)cur->st.fp;
#endif
    return 1;
  }

  return 0;
}

/*
[Switching to Thread 800e041c0 (LWP 100084)]
0x0000000800b751ac in nanosleep () from /lib/libc.so.7
(gdb) bt
#0  0x0000000800b751ac in nanosleep () from /lib/libc.so.7
#1  0x0000000800ae2e18 in sleep () from /lib/libc.so.7
#2  0x00000008007533d8 in sleep () from /lib/libthr.so.3
#3  0x0000000000400ba0 in handler (signo=11, si=0x7fffffffe5d0,
    v=0x7fffffffe260) at wedgie.c:51
#4  <signal handler called>
#5  0x0000000000400bfe in mr_wedge (data=0x7fffffffe730, port=8080)
    at wedgie.c:61
#6  0x0000000000400c52 in func_one (data=0x7fffffffe730, w_t=32,
    string=0x400f2e "hello", w_e=wee_two, data_not_pointer=
      {one = 42, two = 0x400f24 "forty-two", bit1 = 1, bit2 = 0, moo = 13}, u=
        {one = 1, two = 0x200000001 <Error reading address 0x200000001: Bad address>, s = {inner = 1, inner2 = 2}, tv = {tv_sec = 8589934593, tv_usec = 0}})
    at wedgie.c:69
#7  0x0000000000400cfe in func_two () at wedgie.c:83
#8  0x0000000000400dc0 in main (argc=1, argv=0x7fffffffe7f8) at wedgie.c:105
*/

void *gimli_reg_addr(struct gimli_unwind_cursor *cur, int col)
{
  /* See http://wikis.sun.com/display/SunStudio/Dwarf+Register+Numbering */
  switch (col) {
#ifdef __i386
# error code me; look in /usr/include/machine/reg.h for names
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
    case 0: return &cur->st.regs.r_rax;
    case 1: return &cur->st.regs.r_rdx;
    case 2: return &cur->st.regs.r_rcx;
    case 3: return &cur->st.regs.r_rbx;
    case 4: return &cur->st.regs.r_rsi;
    case 5: return &cur->st.regs.r_rdi;
    case 6: return &cur->st.regs.r_rbp;
    case 7: return &cur->st.regs.r_rsp;
    case 8: return &cur->st.regs.r_r8;
    case 9: return &cur->st.regs.r_r9;
    case 10: return &cur->st.regs.r_r10;
    case 11: return &cur->st.regs.r_r11;
    case 12: return &cur->st.regs.r_r12;
    case 13: return &cur->st.regs.r_r13;
    case 14: return &cur->st.regs.r_r14;
    case 15: return &cur->st.regs.r_r15;
    case 16: return &cur->st.regs.r_rip; /* return address */
#else
#error no yet coded
#endif
  }
  return 0;
}

#if 0
static int enum_threads(const td_thrhandle_t *thr, void *unused)
{
  struct gimli_thread_state *th;
  prgregset_t ur;
  int te;
  td_thrinfo_t info;

  gimli_threads = realloc(gimli_threads,
      (gimli_nthreads + 1) * sizeof(*gimli_threads));
  th = &gimli_threads[gimli_nthreads];
  gimli_nthreads++;

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

  th->lwpid = info.ti_lid;
  return 0;
}
#endif

static void read_maps(gimli_proc_t proc)
{
  struct ptrace_vm_entry map;
  char path[1024];

  memset(&map, 0, sizeof(map));
  map.pve_path = path;
  map.pve_pathlen = sizeof(path);

  while (ptrace(PT_VM_ENTRY, proc->pid, (caddr_t)&map, 0) == 0) {
    gimli_add_mapping(proc, map.pve_path, (void*)map.pve_start,
      map.pve_end, map.pve_offset);

    /* reset for next iteration */
    map.pve_pathlen = sizeof(path);
  }
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
  int i;
  int done = 0;
  gimli_err_t err;

  signal(SIGCHLD, child_handler);

  ret = ptrace(PT_ATTACH, proc->pid, NULL, 0);
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

  read_maps(proc);

  err = gimli_proc_service_init(proc);

  if (err != GIMLI_ERR_OK) {
    return err;
  }

  /* if target is not multi-threaded, pick out its regs */
  if (!proc->ta) {
    struct reg ur;

    if (ptrace(PT_GETREGS, proc->pid, (caddr_t)&ur, 0) == 0) {
      gimli_user_regs_to_thread(&ur, proc->threads);
    }
  }

  return GIMLI_ERR_OK;


#if 0
  read_maps();

  te = td_init();
  if (te != TD_OK) {
    fprintf(stderr, "td_init failed: %d\n", te);
    return 0;
  }
  te = td_ta_new(&targetph, &ta);
  if (te != TD_OK && te != TD_NOLIBTHREAD) {
    fprintf(stderr, "td_ta_new failed: %d\n", te);
    return 0;
  }

  if (ta) {
    gimli_nthreads = 0;
    gimli_threads = NULL;

//fprintf(stderr, "ta=%p, enum threads\n", ta);
    td_ta_thr_iter(ta, enum_threads, NULL, TD_THR_ANY_STATE,
      TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);

  } else {
    prgregset_t ur;

    gimli_threads = calloc(1, sizeof(*gimli_threads));
    gimli_threads->lwpid = pid;
    gimli_nthreads = 1;
//fprintf(stderr, "no ta, 1 thread\n");

    if (ptrace(PT_GETREGS, pid, (caddr_t)&ur, 0) == 0) {
      user_regs_to_thread(ur, gimli_threads);
    }
  }

  return 1;
#endif
}

static int resume_threads(const td_thrhandle_t *thr, void *unused)
{
  td_thr_dbresume(thr);
  return 0;
}

gimli_err_t gimli_detach(gimli_proc_t proc)
{
  if (proc->ta) {
    td_ta_thr_iter(proc->ta, resume_threads, NULL, TD_THR_ANY_STATE,
      TD_THR_LOWEST_PRIORITY, TD_SIGNO_MASK, TD_THR_ANY_USER_FLAGS);
  }

  gimli_proc_service_destroy(proc);

  ptrace(PT_DETACH, proc->pid, NULL, 0);

  return GIMLI_ERR_OK;
}

int gimli_is_signal_frame(struct gimli_unwind_cursor *cur)
{
  if (cur->st.pc == (void*)-1) {
    return 1;
  }
  return 0;
}

ps_err_e ps_lstop(struct ps_prochandle *ph, lwpid_t lwpid)
{
  if (ptrace(PT_SUSPEND, lwpid, 0, 0) == 0) {
    return PS_OK;
  }
  return PS_ERR;
}

ps_err_e ps_lcontinue(struct ps_prochandle *ph, lwpid_t lwpid)
{
  if (ptrace(PT_RESUME, lwpid, 0, 0) == 0) {
    return PS_OK;
  }
  return PS_ERR;
}

ps_err_e ps_linfo(struct ps_prochandle *ph, lwpid_t lwpid, void *info)
{
  if (ptrace(PT_LWPINFO, lwpid, info, sizeof(struct ptrace_lwpinfo)) == 0) {
    return PS_OK;
  }
  return PS_ERR;
}

ps_err_e ps_lgetregs(struct ps_prochandle *ph, lwpid_t lwpid,
      prgregset_t gregset)
{
  td_thrhandle_t thr;

  printf("%s lwpid=%d\n", __FUNCTION__, lwpid);

  if (ph->ta) {
    td_err_e te;

    te = td_ta_map_lwp2thr(ph->ta, lwpid, &thr);
    if (te != TD_OK) {
      fprintf(stderr, "map lwp2thr returned %d\n", te);
      return PS_ERR;
    }
    te = td_thr_getgregs(&thr, gregset);
    if (te == TD_OK) {
      return PS_OK;
    }
      fprintf(stderr, "getgregs returned %d\n", te);
    return PS_ERR;
  }
  return PS_ERR;
}

#endif

/* vim:ts=2:sw=2:et:
 */

