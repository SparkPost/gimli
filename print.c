/*
 * Copyright (c) 2007-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"

static gimli_hash_t derefd = NULL;
static int max_depth = 4;
static int max_arr = 16;

static char indentstr[] =
"                                                                      ";

struct print_data {
  gimli_proc_t proc;
  gimli_stack_frame_t frame;
  unsigned show_decl:1;
  unsigned is_param:1;
  unsigned terse:1;
  unsigned suppress:1;
  unsigned in_array;
  const char *prefix;
  const char *suffix;

  int depth;
  gimli_var_t var;
  gimli_addr_t addr;
  gimli_mem_ref_t mem;
  uint64_t offset;
  uint64_t size;
  char *ptr;
};

static int print_var(struct print_data *data, gimli_type_t t, const char *varname);

static void print_quoted_string(gimli_proc_t proc, gimli_addr_t addr)
{
  gimli_mem_ref_t ref;
  gimli_err_t err;
  char *buf, *end;
  int len, i;
#define STRING_AT_ONCE 1024

  err = gimli_proc_mem_ref(proc, addr, STRING_AT_ONCE, &ref);
  if (err != GIMLI_ERR_OK) {
    printf("<unable to read string>");
    return;
  }

  printf("\"");
  while (1) {
    buf = gimli_mem_ref_local(ref);
    len = gimli_mem_ref_size(ref);
    addr += len;
    end = buf + len;

    while (buf < end) {
      if (buf[0] == '\0') goto done;
      if (isprint(buf[0])) {
        printf("%c", buf[0]);
      } else if (buf[0] == '"') {
        printf("\\\"");
      } else if (buf[0] == '\\') {
        printf("\\\\");
      } else {
        printf("\\x%02x", ((int)buf[0]) & 0xff);
      }
      buf++;
    }

    gimli_mem_ref_delete(ref);
    err = gimli_proc_mem_ref(proc, addr, STRING_AT_ONCE, &ref);
    if (err != GIMLI_ERR_OK) {
      break;
    }
  }
done:
  printf("\"");
  if (err != GIMLI_ERR_OK) {
    printf(" <invalid read>");
  }

  gimli_mem_ref_delete(ref);
}



static gimli_iter_status_t print_member(const char *name,
    struct gimli_type_membinfo *info,
    void *arg)
{
  struct print_data *data = arg;

  data->offset = info->offset;
  data->size = info->size;
  print_var(data, info->type, name);

  return GIMLI_ITER_CONT;
}

static void print_float(gimli_proc_t proc,
    gimli_type_t t, gimli_addr_t addr,
    uint64_t offset, uint64_t bits)
{
  union {
    float f;
    double d;
    long double ld;
  } u;
  uint64_t bytes = bits / 8;
  struct gimli_type_encoding enc;

  gimli_type_encoding(t, &enc);

  addr += (offset / 8);

  if (gimli_read_mem(proc, addr, &u.f, bytes) != bytes) {
    printf("<unable to read %" PRIu64 " bytes @ " PTRFMT ">",
      bytes, addr);
    return;
  }

  switch (enc.format) {
    case GIMLI_FP_SINGLE:
      printf("%f", u.f);
      break;
    case GIMLI_FP_DOUBLE:
      printf("%f", u.d);
      break;
    case GIMLI_FP_LONG_DOUBLE:
      printf("%Lf", u.ld);
      break;
    default:
      printf("??? <unsupported FP format %" PRIu32 " %" PRIu64 " bits>",
          enc.format, bits);
  }
}

static void print_enum(gimli_proc_t proc,
    gimli_type_t t, gimli_addr_t addr,
    uint64_t offset, uint64_t bits)
{
  uint64_t bytes;
  union {
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    uint8_t  u8;
  } u;
  int val;
  const char *label;

  bytes = bits / 8;
  addr += (offset / 8);
  u.u64 = 0;

  if (gimli_read_mem(proc, addr, &u.u64, bytes) != bytes) {
    printf("<unable to read %" PRIu64 " bytes @ " PTRFMT ">",
        bytes, addr);
    return;
  }

  switch (bytes) {
    case 1:
      val = u.u8;
      break;
    case 2:
      val = u.u16;
      break;
    case 3:
      val = u.u32;
      break;
    case 4:
      val = u.u64;
      break;
  }

  label = gimli_type_enum_resolve(t, val);
  if (label) {
    printf("%s %u (0x%x)", label, val, val);
  } else {
    printf("<invalid enum value> %u (0x%x)", val, val);
  }
}

static void print_integer(struct print_data *data,
    gimli_proc_t proc,
    gimli_type_t t, gimli_addr_t addr,
    uint64_t offset, uint64_t bits)
{
  uint64_t bytes;
  union {
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    uint8_t  u8;
  } u;
  uint64_t val;
  const char *sformats[4] = {
    "%d (0x%x)", "%d (0x%x)", "%d (0x%x)", "%" PRId64 " (0x%" PRIx64 ")" };
  const char *uformats[4] = {
    "%u (0x%x)", "%u (0x%x)", "%u (0x%x)", "%" PRId64 " (0x%" PRIx64 ")" };
  const char *tsformats[4] = { "%d", "%d", "%d", "%" PRId64 };
  const char *tuformats[4] = { "0x%x", "0x%x", "0x%x", "0x%" PRIx64 };
  const char *fmt;
  struct gimli_type_encoding enc;
  int fmtidx;

  bytes = bits / 8;
  addr += (offset / 8);
  u.u64 = 0;

  if (bytes > 8 || (bits % 8 != 0) || (bytes & (bytes - 1)) != 0) {
    /* it's a bitfield */
    uint8_t bitoff = offset - (8*(offset/8));
    uint8_t shift =
#if WORDS_BIGENDIAN
        (sizeof(u.u64)*8) - (bitoff + bits);
#else
        bitoff - (bits - 1);
#endif
    uint64_t mask = (1ULL << bits) - 1;
    bytes = (bits + 7) / 8;

//printf("bitfield read from " PTRFMT " bits=%" PRIu64 " bytes=%" PRIu64 " offset=%" PRIu64 " bitoff=%d shift=%d mask=%" PRIx64 "\n", addr, bits, bytes, offset, bitoff, shift, mask);
    if (bytes > sizeof(u.u64)) {
      printf("??? <invalid bitfield size %" PRIu64 ">", bits);
      return;
    }
    if (gimli_read_mem(proc, addr, &u.u64, bytes) != bytes) {
      printf("<unable to read %" PRIu64 " bytes @ " PTRFMT ">",
        bytes, addr);
      return;
    }
//printf("READ: 0x%" PRIx64 "\n", u.u64);
    u.u64 >>= shift;
    u.u64 &= mask;
//printf("PROC: 0x%" PRIx64 "\n", u.u64);

    bytes = 8;

  } else if (gimli_read_mem(proc, addr, &u.u64, bytes) != bytes) {
    printf("<unable to read %" PRIu64 " bytes @ " PTRFMT ">",
        bytes, addr);
    return;
  }

#if 0
  printf("bytes = %" PRIu64 " bits = %" PRIu64 " offset=%" PRIu64 "\n",
      bytes, bits, offset);

  printf("RAW %p INT @ " PTRFMT " -> %" PRIu64 "\n", t, addr, u.u64);
#endif

  gimli_type_encoding(t, &enc);

  switch (bytes) {
    case 1:
      val = u.u8;
      fmtidx = 0;
      break;
    case 2:
      val = u.u16;
      fmtidx = 1;
      break;
    case 4:
      val = u.u32;
      fmtidx = 2;
      break;
    case 8:
      val = u.u64;
      fmtidx = 3;
      break;
    default:
      /* not possible due to bifield check above */
      abort();
  }

  if (data->terse) {
    fmt = (enc.format & GIMLI_INT_SIGNED) ? tsformats[fmtidx] : tuformats[fmtidx];
    printf(fmt, val);
  } else {
    fmt = (enc.format & GIMLI_INT_SIGNED) ? sformats[fmtidx] : uformats[fmtidx];
    printf(fmt, val, val);
  }
}

static void print_array(struct print_data *sdata, gimli_type_t t)
{
  struct gimli_type_encoding enc;
  struct gimli_type_arinfo arinfo;
  void *ptr;
  gimli_addr_t addr = sdata->addr + (sdata->offset / 8);
  uint64_t off = sdata->offset;
  int depth = sdata->depth;
  char addrkey[64];
  uint32_t i;
  struct print_data data = *sdata;
  int is_struct;
  gimli_type_t target;

  if (!gimli_type_arinfo(t, &arinfo)) {
    printf("not an array type in print_array!?\n");
    return;
  }

  target = gimli_type_resolve(arinfo.contents);
  gimli_type_encoding(target, &enc);
#if 0
  printf("array has %" PRIu64 " elements, kind=%" PRIu64 "\n",
      arinfo.nelems, gimli_type_kind(target));
  printf("enc.format = %" PRIx64 " size=%" PRIu64 "\n",
      enc.format, gimli_type_size(target));
#endif
  if (gimli_type_kind(target) == GIMLI_K_INTEGER &&
      enc.format & GIMLI_INT_CHAR) {
    /* Could be a string; try to read and print it as such */

    printf("[ ");
    print_quoted_string(data.proc, addr);
    printf(" ]");
    return;
  }
  if (depth + 1 > max_depth) {
    printf("[ ... ]");
    return;
  }

  is_struct = 0;
  switch (gimli_type_kind(target)) {
    case GIMLI_K_STRUCT:
    case GIMLI_K_UNION:
      is_struct = 1;
      break;
    case GIMLI_K_POINTER:
      switch (gimli_type_kind(gimli_type_resolve(
              gimli_type_follow_pointer(target)))) {
        case GIMLI_K_STRUCT:
        case GIMLI_K_UNION:
          is_struct = 1;
          break;
      }
      break;
  }

  printf("\n%.*s[",
      (data.depth + 1) * 4, indentstr);

  if (gimli_type_kind(target) == GIMLI_K_ARRAY) {
    printf("%.*s",
      (data.depth + 2) * 4, indentstr);
  } else {
    printf("\n%.*s",
      (data.depth + 2) * 4, indentstr);
  }
  data.offset = 0;
  data.size = gimli_type_size(target);
  data.show_decl = 0;
  data.prefix = "";
  data.suffix = is_struct ? "\n" : "";
  data.terse = 1;
  data.in_array++;

  for (i = 0; i < arinfo.nelems && i < max_arr; i++) {
    data.depth = depth + 1;
    data.addr = addr + (i * (data.size / 8));

    if (i) {
      if (is_struct) {
        printf("\n%.*s,\n%.*s",
            (depth + 2) * 4, indentstr,
            (depth + 2) * 4, indentstr);
      } else {
        printf(", ");
      }
    }
    print_var(&data, target, "");
  }
  if (arinfo.nelems > max_arr) {
    printf(" ...");
  }
  printf("\n%.*s]", (depth + 1) * 4, indentstr);
}

static void print_pointer(struct print_data *data, gimli_type_t t)
{
  void *dummy;
  gimli_type_t target = gimli_type_resolve(gimli_type_follow_pointer(t));
  struct gimli_type_encoding enc;
  void *tptr;
  gimli_addr_t ptr;
  gimli_addr_t addr = data->addr + (data->offset / 8);
  gimli_addr_t addrsave = data->addr;
  int depth = data->depth;
  char addrkey[64];
  char namebuf[1024];
  const char *symname;
  struct print_data savdata = *data;

  if (data->addr == 0) {
    printf("nil");
    return;
  }

  if (gimli_read_mem(data->proc, addr, &tptr,
        sizeof(tptr)) != sizeof(tptr)) {
    printf("<unable to read %lu bytes at " PTRFMT ">",
        sizeof(ptr), data->addr);
    return;
  }
  ptr = (gimli_addr_t)tptr;

  if (ptr == 0) {
    printf("nil");
    return;
  }

  gimli_type_encoding(target, &enc);

  symname = gimli_data_sym_name(data->proc, ptr, namebuf, sizeof(namebuf));
  if (symname && strlen(symname)) {
    if (gimli_type_kind(target) == GIMLI_K_FUNCTION) {
      printf("%s", symname);
      return;
    }
    printf("(%s) ", symname);
  }

  /* if we are a char*, render as a string */
  if (gimli_type_kind(target) == GIMLI_K_INTEGER &&
      (enc.format & GIMLI_INT_CHAR)) {

    printf(PTRFMT " ", ptr);
    print_quoted_string(data->proc, ptr);
    return;
  }

  /* don't deref function pointers */
  if (gimli_type_kind(target) == GIMLI_K_FUNCTION) {
    printf(PTRFMT, ptr);
    return;
  }

  /* don't deref void* */
  if (!strcmp(gimli_type_name(target), "void")) {
    printf(PTRFMT, ptr);
    return;
  }

  /* don't deref if the target is invalid memory */
  if (!gimli_read_mem(data->proc, ptr, &dummy, 1) ||
      !gimli_read_mem(data->proc, ptr + gimli_type_size(target), &dummy, 1)) {
    printf(PTRFMT " <invalid>", ptr);
    return;
  }

  if (data->depth + 1 > max_depth) {
    printf(PTRFMT, ptr);
    return;
  }

  snprintf(addrkey, sizeof(addrkey), "%p:%" PRIx64, target, data->addr);
  if (gimli_hash_find(derefd, addrkey, &dummy)) {
    printf(" " PTRFMT " [deref'd above]", ptr);
    return;
  }

  printf(PTRFMT " [deref'ing]\n", ptr);

  data->show_decl = 1;
  data->prefix = " = ";
  data->suffix = "\n";

  data->depth++;
  data->addr = (gimli_addr_t)ptr;
  data->offset = 0;
  data->size = gimli_type_size(target);

  print_var(data, target, NULL);

  *data = savdata;
}

static gimli_iter_status_t after_print_var(
    struct module_item *mod, void *arg)
{
  struct print_data *data = arg;
  const char *typename;
  uint64_t size;

  if (mod->api_version == 2 && mod->ptr.v2->after_print_frame_var) {
    if (data->var->type) {
      size = gimli_type_size(data->var->type);
      typename = gimli_type_declname(data->var->type);
    } else {
      size = 0;
      typename = "<optimized out>";
    }

    mod->ptr.v2->after_print_frame_var(&ana_api,
          mod->exename, data->frame->cur.tid,
          data->frame->cur.frameno, data->frame->cur.st.pc,
          data->frame,
          typename,
          data->var->varname,
          (void*)data->var->addr,
          size);
  }
  return GIMLI_ITER_CONT;
}

static int print_var(struct print_data *data, gimli_type_t t, const char *varname)
{
  int indent = 4 * (data->depth + 1);
  gimli_addr_t addr;
  char addrkey[64];
  void *dummy;

  if (data->frame) {

    if (gimli_module_call_var_printer(data->proc,
          data->frame, varname, t,
          data->addr, data->depth) == GIMLI_ITER_STOP) {
      return GIMLI_ITER_CONT;
    }
  }

  if (!t) {
    printf("%.*s%s <optimized out>%s",
        indent, indentstr, varname, data->suffix);
  } else {
    if (data->show_decl) {
      printf("%.*s%s",
          indent, indentstr,
          gimli_type_declname(t));
      if (varname) {
        printf(" %s", varname);
      }
    }

    if (data->addr == 0) {
      printf(" <optimized out>%s", data->suffix);
      goto after;
    }

    t = gimli_type_resolve(t);
    addr = data->addr + (data->offset / 8);

    switch (gimli_type_kind(t)) {
      case GIMLI_K_UNION:
      case GIMLI_K_STRUCT:
        snprintf(addrkey, sizeof(addrkey), "%p:%" PRIx64, t, addr);
        if (gimli_hash_find(derefd, addrkey, &dummy)) {
          printf(" " PTRFMT " [deref'd above]\n", addr);
          return;
        }
        if (!gimli_hash_insert(derefd, addrkey, NULL)) {
          printf(" " PTRFMT " <hash insert failed>\n", addr);
          return;
        }

        printf(" " PTRFMT " = {\n", addr);
        {
          struct print_data d = *data;
          d.depth++;
          d.addr = addr;
          d.offset = 0;
          gimli_type_member_visit(t, print_member, &d);
        }
        printf("%.*s}\n", indent, indentstr);
        break;
      case GIMLI_K_INTEGER:
        printf("%s", data->prefix);
        print_integer(data, data->proc, t, data->addr, data->offset, data->size);
        printf("%s", data->suffix);
        break;
      case GIMLI_K_FLOAT:
        printf("%s", data->prefix);
        print_float(data->proc, t, data->addr, data->offset, data->size);
        printf("%s", data->suffix);
        break;
      case GIMLI_K_POINTER:
        printf("%s", data->prefix);
        print_pointer(data, t);
        printf("%s", data->suffix);
        break;
      case GIMLI_K_ENUM:
        printf("%s", data->prefix);
        print_enum(data->proc, t, data->addr, data->offset, data->size);
        printf("%s", data->suffix);
        break;
      case GIMLI_K_ARRAY:
        printf("%s", data->prefix);
        print_array(data, t);
        printf("%s", data->suffix);
        break;
      default:
        printf(" <kind:%d offsetbits:%" PRIu64 " @" PTRFMT ">",
            gimli_type_kind(t),
            data->offset,
            data->addr + (data->offset / 8));
        printf("%s", data->suffix);
    }
  }

after:
  if (data->frame) {
    gimli_visit_modules(after_print_var, data);
  }

  return GIMLI_ITER_CONT;
}

static gimli_iter_status_t show_var(
    gimli_stack_frame_t frame,
    gimli_var_t var,
    void *arg)
{
  struct print_data *data = arg;

  data->var = var;
  data->is_param = var->is_param;
  data->addr = var->addr;
  data->offset = 0;
  data->size = var->type ? gimli_type_size(var->type) : 0;

  print_var(data, var->type, var->varname);

  return GIMLI_ITER_CONT;
}

static void tidy_deref(void)
{
  if (derefd) {
    gimli_hash_destroy(derefd);
    derefd = NULL;
  }
}

int gimli_print_addr_as_type(gimli_proc_t proc,
    gimli_stack_frame_t frame, const char *varname,
    gimli_type_t t, gimli_addr_t addr)
{
  struct print_data data;

  memset(&data, 0, sizeof(data));
  data.proc = proc;
  data.frame = frame;
  data.show_decl = 1;
  data.prefix = " = ";
  data.suffix = "\n";
  data.addr = addr;
  data.size = gimli_type_size(t);

  print_var(&data, t, varname);

  return 1;
}

void gimli_render_frame(int tid, int nframe, gimli_stack_frame_t frame)
{
  const char *name;
  char namebuf[1024];
  char filebuf[1024];
  uint64_t lineno;
  struct gimli_unwind_cursor cur = frame->cur;
  struct print_data data;

  if (gimli_is_signal_frame(&cur)) {
    if (cur.si.si_signo) {
      gimli_render_siginfo(cur.proc, &cur.si, namebuf, sizeof(namebuf));
      printf("#%-2d %s\n", nframe, namebuf);
    } else {
      printf("#%-2d signal handler\n", nframe);
    }
  } else {
    name = gimli_pc_sym_name(cur.proc, (gimli_addr_t)cur.st.pc,
        namebuf, sizeof(namebuf));
    printf("#%-2d " PTRFMT " %s", nframe, (PTRFMT_T)cur.st.pc, name);
    if (gimli_determine_source_line_number(cur.proc, (gimli_addr_t)cur.st.pc,
          filebuf, sizeof(filebuf), &lineno)) {
      printf(" (%s:%" PRId64 ")", filebuf, lineno);
    }
    printf("\n");

    memset(&data, 0, sizeof(data));
    data.proc = frame->cur.proc;
    data.frame = frame;
    data.show_decl = 1;
    data.prefix = " = ";
    data.suffix = "\n";

    if (!derefd) {
      derefd = gimli_hash_new(NULL);
      atexit(tidy_deref);
    }

    gimli_stack_frame_visit_vars(frame, GIMLI_WANT_ALL, show_var, &data);
  }
}

/* vim:ts=2:sw=2:et:
 */
