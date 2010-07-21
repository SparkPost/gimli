/*
 * Copyright (c) 2008-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

static gimli_shutdown_func_t shutdown_func = NULL;
static volatile struct gimli_heartbeat *hb = NULL;

/* this apparently redundant function is present to help ensure that
 * the stack trace we generate points the reader to this general area
 * of code.  On Solaris, having kill(2) in the call stack appears to
 * mess with the initial unwind, omitting this function from the trace.
 * Putting the kills into their own function, distinct from the main
 * gimli_signal_handler, means that gimli_signal_handler will show up.
 */
static void request_trace(void)
{
#ifdef sun
  /* on Solaris, it seems STOP'ing yourself somehow prevents one's
   * parent from getting a SIGCHLD, so we trigger one explicitly
   * first */
  kill(getppid(), SIGCHLD);
#endif
  /* go to sleep; parent gets notified that we stopped and initiates
   * a trace; it will resume us once tracing is complete */
  kill(getpid(), SIGSTOP);
}

static void gimli_signal_handler(int signo, siginfo_t *si, void *unused)
{
  /* reset signal to default, which is to cause termination */
  signal(signo, SIG_DFL);

  request_trace();

  /* if we get here, it is because the trace completed and SIGCONT'd
   * us as part of its detach */

  /* invoke an application supplied shutdown handler */
  if (shutdown_func) {
    shutdown_func(signo, si);
  }
  gimli_heartbeat_set(hb, GIMLI_HB_STOPPING);

  /* and now we want to exit, preserving the original exit status.
   * we do this by killing ourselves with the original signal.
   * Since we reset the signal handler above, this will cause
   * our exit status to be reflected correctly up to the parent,
   * and it will respawn us */
  fprintf(stderr, "gimli: exiting due to signal %d\n", signo);
  kill(getpid(), signo); 
}

volatile struct gimli_heartbeat *gimli_heartbeat_attach(void)
{
  char *idstr;
  int fd;

  if (hb) {
    return hb;
  }

  idstr = getenv("GIMLI_HB_FD");
  if (idstr) {
    fd = atoi(idstr);
  } else {
    fprintf(stderr, "gimli: GIMLI_HB_FD is not set\n");
    return NULL;
  }

  /* this is the file descriptor we need to use to access the
   * heartbeat segment */
  hb = mmap(NULL, sizeof(*hb), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

  if (hb == (struct gimli_heartbeat*)-1) {
    fprintf(stderr, "gimli: can't map %s: %s\n", idstr, strerror(errno));
    hb = NULL;
    close(fd);
    return NULL;
  }

  close(fd);
  hb->state = GIMLI_HB_STARTING;
  gimli_establish_signal_handlers();
  return hb;
}

void gimli_establish_signal_handlers(void)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = gimli_signal_handler;
  /* we request SIGINFO even though we don't use it here;
   * turning it on allows the tracer to perform deeper
   * introspection when it attaches */
  sa.sa_flags = SA_SIGINFO;

  sigaction(SIGSEGV, &sa, NULL);
//  signal(SIGSEGV, gimli_signal_handler);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
}

void gimli_heartbeat_set(volatile struct gimli_heartbeat *hb, int state)
{
  hb->state = state;
  hb->ticks++;
}

void gimli_set_shutdown_func(gimli_shutdown_func_t func)
{
  shutdown_func = func;
}

/* vim:ts=2:sw=2:et:
 */

