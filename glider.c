/*
 * Copyright (c) 2007-2011 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

void trace_process(int pid)
{
  if (tracer_attach(pid)) {
    int i;
    struct gimli_object_file *file;
    struct gimli_unwind_cursor *frames;
    void **pcaddrs;
    void **contexts;

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

    for (file = gimli_files; file; file = file->next) {
      /* perform discovery of tracer module */
      struct gimli_symbol *sym;
      char *name = NULL;
      char buf[1024];
      char buf2[1024];
      void *h;

      sym = gimli_sym_lookup(file->objname, "gimli_tracer_module_name");
      if (sym) {
        name = gimli_read_string(sym->addr);
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

      gimli_process_dwarf(file);
      gimli_bake_symtab(file);
    }

    for (i = 0; i < gimli_nthreads; i++) {
      int nframes = gimli_stack_trace(i, frames, max_frames);
      int suppress = 0;
      int nf;

      for (nf = 0; nf < nframes; nf++) {
        pcaddrs[nf] = frames[nf].st.pc;
        contexts[nf] = &frames[nf];
      }

      for (file = gimli_files; file; file = file->next) {
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

      if (!suppress) {
        struct gimli_thread_state *thr = &gimli_threads[i];

        printf("Thread %d (LWP %d)\n", i, thr->lwpid);
        for (nf = 0; nf < nframes; nf++) {
          suppress = 0;
          for (file = gimli_files; file; file = file->next) {
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
          if (!suppress) {
            gimli_render_frame(i, nf, frames + nf);

            for (file = gimli_files; file; file = file->next) {
              if (file->tracer_module &&
                  file->tracer_module->api_version >= 2 &&
                  file->tracer_module->after_print_frame) {
                file->tracer_module->after_print_frame(&ana_api,
                      file->objname, i, nf, pcaddrs[nf], contexts[nf]);
              }
            }
          }
        }
        for (file = gimli_files; file; file = file->next) {
          if (file->tracer_module &&
              file->tracer_module->api_version >= 2 &&
              file->tracer_module->on_end_thread_trace) {
            file->tracer_module->on_end_thread_trace(&ana_api,
                file->objname, i, nframes, pcaddrs, contexts);
          }
        }
        printf("\n");
      }
    }

    printf("\n");

    for (file = gimli_files; file; file = file->next) {
      if (file->tracer_module == NULL) continue;

      if (file->tracer_module->perform_trace) {
        file->tracer_module->perform_trace(&ana_api, file->objname);
      }
    }

  }
out:
  gimli_detach();
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

