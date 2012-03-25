/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

/* perform discovery of tracer module */
static gimli_hash_iter_ret load_modules_for_file(const char *k, int klen,
    void *item, void *arg)
{
  gimli_mapped_object_t file = item;

  struct gimli_symbol *sym;
  char *name = NULL;
  char buf[1024];
  char buf2[1024];
  void *h;

  sym = gimli_sym_lookup(the_proc, file->objname, "gimli_tracer_module_name");
  if (sym) {
    name = gimli_read_string(the_proc, sym->addr);
  }
  if (name == NULL) {
    strcpy(buf, file->objname);
    snprintf(buf2, sizeof(buf2)-1, "gimli_%s", basename(buf));
    name = strdup(buf2);
  }
  strcpy(buf, file->objname);
  snprintf(buf2, sizeof(buf2)-1, "%s/%s", dirname(buf), name);

  if (access(buf2, F_OK) == 0) {
    h = dlopen(buf2, RTLD_NOW|RTLD_GLOBAL);
    if (h) {
      gimli_module_init_func func = (gimli_module_init_func)
        dlsym(h, "gimli_ana_init");
      if (func) {
        file->tracer_module = (*func)(&ana_api);
      }
    } else {
      printf("Unable to load library: %s: %s\n", buf2, dlerror());
    }
  } else if (sym) {
    printf("NOTE: module %s declared that its tracing should be performed by %s, but that module was not found (%s)\n",
        file->objname, buf2, strerror(errno));
  }

  return GIMLI_HASH_ITER_CONT;
}

void trace_process(int pid)
{
  if (tracer_attach(pid)) {
    int i;
    struct gimli_object_file *file;
    struct gimli_unwind_cursor *frames;
    void **pcaddrs;
    void **contexts;
    struct gimli_thread_state *thr;

    frames = calloc(max_frames, sizeof(*frames));
    if (!frames) {
      fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
      goto out;
    }
    pcaddrs = calloc(max_frames, sizeof(*pcaddrs));
    if (!pcaddrs) {
      fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
      goto out;
    }
    contexts = calloc(max_frames, sizeof(*contexts));
    if (!contexts) {
      fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
      goto out;
    }
    gimli_hash_iter(the_proc->files, load_modules_for_file, NULL);

    i = -1;
    STAILQ_FOREACH(thr, &the_proc->threads, threadlist) {
      int nframes = gimli_stack_trace(the_proc, thr, frames, max_frames);
      int suppress = 0;
      int nf;

      i++;

      for (nf = 0; nf < nframes; nf++) {
        pcaddrs[nf] = frames[nf].st.pc;
        contexts[nf] = &frames[nf];
      }

#if 0
      for (file = the_proc->files; file; file = file->next) {
        if (file->tracer_module &&
            file->tracer_module->api_version >= 2 &&
            file->tracer_module->on_begin_thread_trace) {
          if (file->tracer_module->on_begin_thread_trace(&ana_api,
              file->objname, i, nframes, pcaddrs, contexts)
              == GIMLI_ANA_SUPPRESS) {
            suppress = 1;
            break;
          }
        }
      }
#endif

      if (!suppress) {
        printf("Thread %d (LWP %d)\n", i, thr->lwpid);
        for (nf = 0; nf < nframes; nf++) {
          suppress = 0;
#if 0
          for (file = the_proc->files; file; file = file->next) {
            if (file->tracer_module &&
                file->tracer_module->api_version >= 2 &&
                file->tracer_module->before_print_frame) {
              if (file->tracer_module->before_print_frame(&ana_api,
                  file->objname, i, nf, pcaddrs[nf], contexts[nf])
                  == GIMLI_ANA_SUPPRESS) {
                suppress = 1;
                break;
              }
            }
          }
#endif
          if (!suppress) {
            gimli_render_frame(i, nf, frames + nf);

#if 0
            for (file = the_proc->files; file; file = file->next) {
              if (file->tracer_module &&
                  file->tracer_module->api_version >= 2 &&
                  file->tracer_module->after_print_frame) {
                file->tracer_module->after_print_frame(&ana_api,
                      file->objname, i, nf, pcaddrs[nf], contexts[nf]);
              }
            }
#endif
          }
        }
#if 0
        for (file = the_proc->files; file; file = file->next) {
          if (file->tracer_module &&
              file->tracer_module->api_version >= 2 &&
              file->tracer_module->on_end_thread_trace) {
            file->tracer_module->on_end_thread_trace(&ana_api,
                file->objname, i, nframes, pcaddrs, contexts);
          }
        }
#endif
        printf("\n");
      }
    }

    printf("\n");

#if 0
    for (file = the_proc->files; file; file = file->next) {
      if (file->tracer_module == NULL) continue;

      if (file->tracer_module->perform_trace) {
        file->tracer_module->perform_trace(&ana_api, file->objname);
      }
    }
#endif

  }
out:
  ;
//  gimli_detach();
}

int main(int argc, char *argv[])
{
  int pid;
  int c;

  while (1) {
    c = getopt(argc, argv, "d");
    if (c == -1) {
      break;
    }
    switch (c) {
      /* -d option enables copious dwarf debugging */
      case 'd':
        debug = 1;
        break;
      default:
        fprintf(stderr, "invalid option %c\n", c);
        return 1;
    }
  }

  if (getenv("GIMLI_DWARF_DEBUG")) {
    debug = 1;
  }

  if (optind < argc) {
    pid = atoi(argv[optind]);
    trace_process(pid);
    return 0;
  }
  fprintf(stderr, "usage: %s <pid>\n", argv[0]);
  return 1;
}



/* vim:ts=2:sw=2:et:
 */

