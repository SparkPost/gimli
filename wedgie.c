/*
 * Copyright (c) 2008-2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#include "libgimli.h"
#include <stdio.h>
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
};

union wedgie_union {
  int one;
  char *two;
  struct {
    int inner;
    int inner2;
  } s;
  struct timeval tv;
};

static void handler(int signo, struct siginfo *si, void *v)
{
  char buf[1024];
  printf("pid: %d signal handler invoked signo=%d si=%p v=%p\n", getpid(), signo, si, v);
  printf("top of stack %p\n", &signo);
  snprintf(buf, sizeof(buf)-1, "valgrind --tool=memcheck ./gimli_coroner %d", getpid());
//  snprintf(buf, sizeof(buf)-1, "gstack %d", getpid());
//  system(buf);
  sleep(50);
  printf("exiting wedgie\n");
  exit(1);
}

static void mr_wedge(struct wedgie_data *data, int port)
{
  fprintf(stderr, "taking a nap\n");
  sleep(2);
  *(long*)42 = 42;
  sleep(10);
  printf("done sleeping\n");
}

static void func_one(struct wedgie_data *data, wedgie_t w_t, const char *string,
  enum wedgie_enum w_e, struct wedgie_data data_not_pointer, union wedgie_union u)
{
  mr_wedge(data, 8080);
  printf("done wedging\n");
}

static void func_two(void)
{
  struct wedgie_data d = { 42, "forty-two" };
  union wedgie_union u;
  u.one = 1;
  u.s.inner2 = 2;
  d.bit1 = 1;
  d.bit2 = 0;
  d.moo = 13;

  func_one(&d, 32, "hello", wee_two, d, u);
  printf("func_one called\n");
}

int main(int argc, char *argv[])
{
  pthread_mutex_t m;
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
//    signal(SIGSEGV, handler);
  }
  func_two();
  fprintf(stderr, "wedgie is done\n");
  return 0;
}

/* vim:ts=2:sw=2:et:
 */

