/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */

#include "impl.h"

static char *config_file = NULL;

static struct option {
  const char *optname;
  const char *envname;
  enum {
    OPT_INTEGER,
    OPT_STRING
  } opttype;
  void *valptr;
} options[] = {
  { "watchdog-interval", "GIMLI_WATCHDOG_INTERVAL",
    OPT_INTEGER, &watchdog_interval },
  { "watchdog-start-interval", "GIMLI_WATCHDOG_START_INTERVAL",
    OPT_INTEGER, &watchdog_start_interval },
  { "watchdog-stop-interval", "GIMLI_WATCHDOG_STOP_INTERVAL",
    OPT_INTEGER, &watchdog_stop_interval },
  { "debug", "GIMLI_DEBUG", OPT_INTEGER, &debug },
  { "detach", "GIMLI_DETACH", OPT_INTEGER, &detach },
  { "setsid", "GIMLI_SETSID", OPT_INTEGER, &do_setsid },
  { "respawn-frequency", "GIMLI_RESPAWN_FREQUENCY",
    OPT_INTEGER, &respawn_frequency },
  { "config-file", "GIMLI_CONFIG_FILE", OPT_STRING, &config_file },
  { NULL }
};

static int apply_option(struct option *opt, const char *value)
{
  int *intptr;
  char **strptr;

  switch (opt->opttype) {
    case OPT_INTEGER:
      intptr = (int*)opt->valptr;
      if (strlen(value)) {
        char *end;
        long v;
        
        errno = 0;
        v = strtol(value, &end, 0);
        if (errno) {
          return 0;
        }
        if (end != value + strlen(value)) {
          return 0;
        }
        *intptr = (int)v;
        return 1;
      } else {
        /* being used as a toggle */
        *intptr = !(*intptr);
        return 1;
      }
      break;

    case OPT_STRING:
      strptr = (char**)opt->valptr;
      *strptr = strdup(value);
      return 1;
  }
  return 0;
}

static int do_cmd_line(int argc, char *argv[], const char *only_me)
{
  int i, j;

  for (i = 1; i < argc; i++) {
    char *name;
    char *val;
    int invalid;

    if (argv[i][0] != '-') {
      break;
    }
    name = argv[i] + 1;
    while (*name == '-') {
      name++;
    }
    val = strchr(name, '=');
    if (val) {
      name = strdup(name);
      val = strchr(name, '=');
      *val = '\0';
      val++;
    } else {
      /* next parameter has value (or it's being used as a toggle).
       * We use argc - 1, because we'd like:
       * monitor --debug ./procname
       * to work as "expected"; you're required to have a process
       * to run, and if your args consume all parameters, then its
       * an invalid command line.
       */
      if (i + 1 < argc - 1 && argv[i+1][0] != '-') {
        val = argv[i+1];
        i++;
      } else {
        /* toggle */
        val = "";
      }
    }
    if (only_me && strcmp(only_me, name)) {
      continue;
    }
    invalid = 1;
    for (j = 0; options[j].optname; j++) {
      if (!strcmp(options[j].optname, name)) {
        if (!apply_option(&options[j], val)) {
          fprintf(stderr, "Invalid value %s for option %s\n",
            val, name);
          return 0;
        }
        invalid = 0;
        break;
      }
    }
    if (invalid) {
      fprintf(stderr, "Unknown option %s\n", name);
      return 0;
    }
  }

  if (i == argc) {
    fprintf(stderr, "Missing required process to run\n");
    return 0;
  }

  return i;
}

static int do_env(const char *only_me)
{
  int i;

  for (i = 0; options[i].optname; i++) {
    char *v;
    
    if (only_me && strcmp(options[i].envname, only_me)) {
      continue;
    }

    v = getenv(options[i].envname);
    if (v) {
      if (!apply_option(&options[i], v)) {
        fprintf(stderr, "Invalid value %s for option %s\n",
          v, options[i].envname);
        return 0;
      }
    }
  }
  return 1;
}

static int do_config_file(void)
{
  FILE *fp;
  char buf[1024];
  char *line;
  char *value;
  int lineno = 0;
  int i;
  int invalid;

  if (!config_file) return 1;

  fp = fopen(config_file, "r");
  if (!fp) {
    fprintf(stderr, "Unable to open config file %s for read: %s\n",
      config_file, strerror(errno));
    return 0;
  }

  while (fgets(buf, sizeof(buf), fp)) {
    line = buf;
    lineno++;
    while (isspace(*line)) {
      line++;
    }
    if (*line == '#') {
      continue;
    }
    value = line + strlen(line) - 1;
    while (value > line && isspace(*value)) {
      *value = '\0';
      value--;
    }

    value = line;
    while (*value && !isspace(*value)) {
      value++;
    }
    if (*value) {
      *value = '\0';
      value++;
      while (isspace(*value)) {
        value++;
      }
      if (*value != '=') {
        fprintf(stderr,
          "Expected line of the form: option = value, got '%s %s' in %s:%d\n",
          line, value, config_file, lineno);
        return 0;
      }
      value++;
      while (isspace(*value)) {
        value++;
      }
    }
    if (!strlen(line)) {
      continue;
    }
    invalid = 1;
    for (i = 0; options[i].optname; i++) {
      if (!strcmp(options[i].optname, line)) {
        if (!apply_option(&options[i], value)) {
          fprintf(stderr, "Invalid value %s for option %s\n",
            value, line);
          return 0;
        }
        invalid = 0;
        break;
      }
    }
    if (invalid) {
      fprintf(stderr, "Unknown option %s at %s:%d\n",
        line, config_file, lineno);
      return 0;
    }
  }
  fclose(fp);

  return 1;
}

/* pull out the bits we need from argv, and tweak it to point
 * at the argv for running the child */
int process_args(int *argcptr, char **argvptr[])
{
  int argc = *argcptr;
  char **argv = *argvptr;
  int i;

  /* step 0: determine the config file path */
  if (!do_env("GIMLI_CONFIG_FILE")) {
    return 0;
  }
  if (!do_cmd_line(argc, argv, "config-file")) {
    return 0;
  }

  /* step 1: read configuration file */
  if (!do_config_file()) {
    return 0;
  }

  /* step 2: read environment */
  if (!do_env(NULL)) {
    return 0;
  }

  /* step 3: use command line args; these trump everything */
  i = do_cmd_line(argc, argv, NULL);
  if (!i) {
    return 0;
  }

  /* when we get here, i is the index of the first non-argument parameter,
   * which is the argv[0] for the child */
  *argcptr = argc - i;
  *argvptr = argv + i;
  return 1;
}

/* vim:ts=2:sw=2:et:
 */
