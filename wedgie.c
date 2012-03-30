/*
 * Copyright (c) 2008-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "libgimli.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <sys/time.h>
  
volatile struct gimli_heartbeat *hb;

typedef int wedgie_t;
enum wedgie_enum {
  wee_one,
  wee_two
};

struct wedgie_data {
  int one;
  char *two;
  unsigned bit1:1;
  unsigned bit2:1;
  signed moo:5;
  double aftermoo;
};

char global_string[] = "global!";

union wedgie_union {
  int one;
  char *two;
  struct {
    int inner;
    int inner2;
  } s;
  struct timeval tv;
};

int global_int = 360;

static void handler(int signo, siginfo_t *si, void *v)
{
  char buf[1024];

  printf("pid: %d signal handler invoked signo=%d si=%p v=%p\n", getpid(), signo, si, v);
  printf("top of stack %p\n", &signo);
  snprintf(buf, sizeof(buf)-1, "./glider %d", getpid());
//  snprintf(buf, sizeof(buf)-1, "gdb .libs/wedgie %d", getpid());

//  snprintf(buf, sizeof(buf)-1, "/opt/msys/gimli/bin/glider %d", getpid());
//  snprintf(buf, sizeof(buf)-1, "gstack %d", getpid());
  sleep(86400);
  system(buf);
  printf("exiting wedgie\n");
  exit(1);
}

static void mr_wedge(struct wedgie_data *data, int port)
{
  char *sptr = global_string;
  int *iptr = &global_int;

  printf("printing global string via local var %s, iptr = %p\n", sptr, iptr);

  fprintf(stderr, "taking a nap in func %p\n", mr_wedge);
  fflush(stderr);
  sleep(2);
  *(long*)42 = 42;
  sleep(10);
  printf("done sleeping\n");
}

static void func_one(struct wedgie_data *data, wedgie_t w_t, const char *string,
  enum wedgie_enum w_e, struct wedgie_data data_not_pointer
#ifndef __sparc__
  /* gcc emits code that causes %sp to end up NULL on call if we include
   * this union parameter on the stack */
  , union wedgie_union u
#endif
)
{
  printf("calling mr_wedge\n"); fflush(stdout);
  mr_wedge(data, 8080);
  printf("done wedging\n");
}

static void func_two(void)
{
  union wedgie_union u;
  struct wedgie_data d = { 42, "forty-two" };
  char multidim[4][8][16] = {0};
  short otherdim[3][6];

  printf("initialize some data\n"); fflush(stdout);
  u.one = 1;
  u.s.inner2 = 2;
  d.bit1 = 1;
  d.bit2 = 0;
  d.moo = 13;
  d.aftermoo = 4.5;

  printf("call func_one\n"); fflush(stdout);
  func_one(&d, 32, "hello", wee_two, d
#ifndef __sparc__
    , u
#endif
  );
  printf("func_one called\n");
}

static void* idle_thread(void *arg)
{
  for (;;) {
    sleep(10);
    printf("idle thread is idle\n");
  }
  return NULL;
}

int main(int argc, char *argv[])
{
  pthread_mutex_t m;
  pthread_t thr;

  pthread_mutex_init(&m, NULL);
  if ((hb = gimli_heartbeat_attach())) {
    fprintf(stderr, "heartbeat activated\n");
    gimli_heartbeat_set(hb, GIMLI_HB_RUNNING);
  } else {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS, &sa, NULL);
#endif
//    signal(SIGSEGV, handler);
  }

  pthread_create(&thr, NULL, idle_thread, NULL);

  fprintf(stderr, "calling func_two\n");
  fflush(stderr);
  func_two();
  fprintf(stderr, "wedgie is done\n");
  return 0;
}

/* vim:ts=2:sw=2:et:
 */

