/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

/* SysV style ps title changing */

static char *title = NULL;
static size_t title_size = 0;
char *gimli_progname = "";
extern char **child_argv;
#ifndef __linux__
extern char **environ;
#endif

char **gimli_init_proctitle(int argc, char **argv)
{
  char *end = NULL;
  int i;
  char **new_vec;
  char buf[1024];

  /* walk over the args; find the end. This assumes contiguous strings */
  end = argv[0] + strlen(argv[0]);
  for (i = 1; i < argc; i++) {
    end = argv[i] + strlen(argv[i]);
  }
  if (end + 1 == environ[0]) {
    /* if the environment is contiguous with the args, use that space too */
    for (i = 0; environ[i] != NULL; i++) {
      if (end + 1 == environ[i]) {
        end = environ[i] + strlen(environ[i]);
      }
    }
    new_vec = malloc((i + 1) * sizeof(char*));
    for (i = 0; environ[i] != NULL; i++) {
      new_vec[i] = strdup(environ[i]);
    }
    new_vec[i] = NULL;
    environ = new_vec;
  }

  title = argv[0];
  title_size = end - title;

  new_vec = malloc((argc + 1) * sizeof(char*));
  for (i = 0; i < argc; i++) {
    new_vec[i] = strdup(argv[i]);
  }
  new_vec[i] = NULL;
  argv = new_vec;
  strcpy(buf, argv[0]);
  gimli_progname = strdup(basename(buf));

  return argv;
}

void gimli_set_proctitle(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  gimli_set_proctitlev(fmt, ap);
  va_end(ap);
}

void gimli_set_proctitlev(const char *fmt, va_list ap)
{
  int len;
  size_t size = title_size;
  char *start = title;

  if (fmt[0] == '-') {
    /* omit the gimli_progname */
    fmt++;
  } else {
    snprintf(title, title_size, "%s: ", child_argv ? child_argv[0] : gimli_progname);
    start += strlen(title);
    size -= strlen(title);
  }

  vsnprintf(start, size, fmt, ap);

  len = strlen(title);
  memset(title + len, '\0', title_size - len);
  if (debug) {
    logprint("%s\n", title);
  }
}



/* vim:ts=2:sw=2:et:
 */

