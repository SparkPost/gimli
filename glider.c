/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

/* perform discovery of tracer module */
static gimli_iter_status_t load_modules_for_file(const char *k, int klen,
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

  return GIMLI_ITER_CONT;
}

struct glider_args {
  int nthread;
  int nframe;
  void **pcaddrs;
  gimli_stack_frame_t *frames;
  gimli_proc_t proc;
  gimli_thread_t thread;
  gimli_stack_trace_t trace;
  int suppress;
};

static gimli_iter_status_t collect_frame(
      gimli_proc_t proc,
      gimli_thread_t thread,
      gimli_stack_frame_t frame,
      void *arg)
{
  struct glider_args *args = arg;
  int no = gimli_stack_frame_number(frame);

  args->pcaddrs[no] = (void*)(intptr_t)gimli_stack_frame_pcaddr(frame);
  args->frames[no] = frame;

  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t should_suppress_thread(
    const char *k, int klen, void *item, void *arg)
{
  gimli_mapped_object_t file = item;
  struct glider_args *args = arg;

  if (file->tracer_module &&
      file->tracer_module->api_version >= 2 &&
      file->tracer_module->on_begin_thread_trace) {

    if (file->tracer_module->on_begin_thread_trace(&ana_api,
        file->objname, args->nthread,
        gimli_stack_trace_num_frames(args->trace),
        args->pcaddrs, (void**)args->frames) == GIMLI_ANA_SUPPRESS) {
      args->suppress = 1;
      return GIMLI_ITER_STOP;
    }
  }

  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t should_suppress_frame(
    const char *k, int klen, void *item, void *arg)
{
  gimli_mapped_object_t file = item;
  struct glider_args *args = arg;

  if (file->tracer_module &&
      file->tracer_module->api_version >= 2 &&
      file->tracer_module->before_print_frame) {

    if (file->tracer_module->before_print_frame(&ana_api,
          file->objname, args->nthread, args->nframe,
          args->pcaddrs[args->nframe], args->frames[args->nframe])
        == GIMLI_ANA_SUPPRESS) {
      args->suppress = 1;
      return GIMLI_ITER_STOP;
    }
  }
  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t after_print_frame(
    const char *k, int klen, void *item, void *arg)
{
  gimli_mapped_object_t file = item;
  struct glider_args *args = arg;

  if (file->tracer_module &&
      file->tracer_module->api_version >= 2 &&
      file->tracer_module->after_print_frame) {

    file->tracer_module->after_print_frame(&ana_api,
        file->objname, args->nthread, args->nframe,
        args->pcaddrs[args->nframe], args->frames[args->nframe]);
  }

  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t after_print_thread(
    const char *k, int klen, void *item, void *arg)
{
  gimli_mapped_object_t file = item;
  struct glider_args *args = arg;

  if (file->tracer_module &&
      file->tracer_module->api_version >= 2 &&
      file->tracer_module->on_end_thread_trace) {

    file->tracer_module->on_end_thread_trace(&ana_api,
        file->objname, args->nthread,
        gimli_stack_trace_num_frames(args->trace),
        args->pcaddrs, (void**)args->frames);
  }

  return GIMLI_ITER_CONT;
}

static void render_thread(gimli_proc_t proc,
    gimli_thread_t thread,
    struct glider_args *args)
{
  int num_frames = gimli_stack_trace_num_frames(args->trace);

  args->suppress = 0;
  gimli_hash_iter(proc->files, should_suppress_thread, args);

  if (args->suppress) return;

  printf("Thread %d (LWP %d)\n", args->nthread, thread->lwpid);
  for (args->nframe = 0; args->nframe < num_frames; args->nframe++) {
    args->suppress = 0;
    gimli_hash_iter(proc->files, should_suppress_frame, args);
    if (args->suppress) continue;

    gimli_render_frame(args->nthread, args->nframe, args->frames[args->nframe]);

    gimli_hash_iter(proc->files, after_print_frame, args);
    gimli_hash_iter(proc->files, after_print_thread, args);
  }
  printf("\n");
}

static gimli_iter_status_t trace_thread(
    gimli_proc_t proc,
    gimli_thread_t thread,
    void *arg)
{
  struct glider_args *args = arg;

  args->trace = gimli_thread_stack_trace(thread, max_frames);

  if (args->trace) {
    struct glider_args *args = arg;

    args->thread = thread;
    gimli_stack_trace_visit(args->trace, collect_frame, args);

    render_thread(proc, thread, args);

    args->nthread++;

    gimli_stack_trace_delete(args->trace);
    args->trace = NULL;
  }

  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t run_trace_module(
    const char *k, int klen, void *item, void *arg)
{
  gimli_mapped_object_t file = item;

  if (file->tracer_module && file->tracer_module->perform_trace) {
    file->tracer_module->perform_trace(&ana_api, file->objname);
  }
  return GIMLI_ITER_CONT;
}

void trace_process(int pid)
{
  int i;
  struct glider_args args;

  if (!tracer_attach(pid)) {
    return;
  }

  args.proc = the_proc;
  args.frames = calloc(max_frames, sizeof(*args.frames));
  args.nthread = 0;
  if (!args.frames) {
    fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
    return;
  }
  args.pcaddrs = calloc(max_frames, sizeof(*args.pcaddrs));
  if (!args.pcaddrs) {
    fprintf(stderr, "Not enough memory to trace %d frames\n", max_frames);
    return;
  }
  gimli_hash_iter(the_proc->files, load_modules_for_file, NULL);

  gimli_proc_visit_threads(the_proc, trace_thread, &args);

  printf("\n");

  gimli_hash_iter(the_proc->files, run_trace_module, NULL);
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

