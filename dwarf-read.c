/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#include "impl.h"
#include "gimli_dwarf.h"

/* when rendering parameters, remember what we've already done */
static gimli_hash_t derefed_params = NULL;


static void local_hexdump(void *addr, int p, int n);

uint64_t dw_read_uleb128(const uint8_t **ptr, const uint8_t *end)
{
  uint64_t res = 0;
  int shift = 0;
  const uint8_t *cur = *ptr;
  while (cur < end) {
    uint8_t b = *(uint8_t*)cur;
    cur++;
    res |= (b & 0x7f) << shift;
    if ((b & 0x80) == 0) break;
    shift += 7;
  }
  *ptr = cur;
  return res;
}

int64_t dw_read_leb128(const uint8_t **ptr, const uint8_t *end)
{
  int64_t res = 0;
  int shift = 0;
  int sign;
  const uint8_t *cur = *ptr;
  while (cur < end) {
    uint8_t b = *(uint8_t*)cur;
    cur++;
    res |= (b & 0x7f) << shift;
    shift += 7;
    sign = (b & 0x40);
    if ((b & 0x80) == 0) break;
  }
  if ((shift < sizeof(res) * 8) && (sign)) {
    /* sign extend */
    res |= - (1 << shift);
  }
  *ptr = cur;
  return res;
}

int dw_read_encptr(uint8_t enc, const uint8_t **ptr, const uint8_t *end,
  uint64_t pc, uint64_t *output)
{
  const uint8_t *cur = *ptr;
  uint64_t res = 0;
  uint64_t base = 0;

  if ((enc & DW_EH_PE_indirect) == DW_EH_PE_indirect) {
    /* the issue here is that we need to adjust for the load address of
     * the target. */
    printf("DW_EH_PE_indirect is not supported correctly at this time\n");
    return 0;

    if (sizeof(void*) == 8) {
      if (gimli_read_mem((void*)(intptr_t)res, &res, sizeof(res))
          != sizeof(*output)) {
        return 0;
      }
    } else {
      uint32_t r;
      if (gimli_read_mem((void*)(intptr_t)res, &r, sizeof(r)) != sizeof(r)) {
        return 0;
      }
      res = r;
    }
  }

  switch (enc & DW_EH_PE_APPL_MASK) {
    case DW_EH_PE_absptr:
      base = 0;
      break;
    case DW_EH_PE_pcrel:
      base = (uint64_t)pc;
      break;
    case DW_EH_PE_datarel:
    default:
      fprintf(stderr, "DWARF: unhandled pointer application value: %02x at %p\n", enc & DW_EH_PE_APPL_MASK, pc);
      return 0;
  }

  if ((enc & 0x07) == 0x00) {
    if (sizeof(void*) == 4) {
      enc |= DW_EH_PE_udata4;
    } else {
      enc |= DW_EH_PE_udata8;
    }
  }

  switch (enc & 0x0f) {
    case DW_EH_PE_uleb128:
      res = base + dw_read_uleb128(ptr, end);
      break;
    case DW_EH_PE_udata2:
      {
        uint16_t d;
        memcpy(&d, cur, sizeof(d));
        *ptr = cur + sizeof(d);
        res = base + d;
      }
      break;
    case DW_EH_PE_udata4:
      {
        uint32_t d;
        memcpy(&d, cur, sizeof(d));
        *ptr = cur + sizeof(d);
        res = base + d;
      }
      break;
    case DW_EH_PE_udata8:
      {
        uint64_t d;
        memcpy(&d, cur, sizeof(d));
        *ptr = cur + sizeof(d);
        res = base + d;
      }
      break;
    case DW_EH_PE_sleb128:
      res = base + dw_read_leb128(ptr, end);
      break;
    case DW_EH_PE_sdata2:
      {
        int16_t d;
        memcpy(&d, cur, sizeof(d));
        *ptr = cur + sizeof(d);
        res = base + d;
      }
      break;
    case DW_EH_PE_sdata4:
      {
        int32_t d;
        memcpy(&d, cur, sizeof(d));
        *ptr = cur + sizeof(d);
        res = base + d;
      }
      break;
    case DW_EH_PE_sdata8:
      {
        int64_t d;
        memcpy(&d, cur, sizeof(d));
        *ptr = cur + sizeof(d);
        res = base + d;
      }
      break;
    default:
      fprintf(stderr, "DWARF: unhandled DW_EH_PE value: 0x%02x (masked to 0x%02x) at %p\n", enc, enc & 0x0f, pc);
      return 0;
  }

  *output = res;
  return 1;
}

static int sort_by_addr(const void *A, const void *B)
{
  struct gimli_line_info *a = *(struct gimli_line_info**)A;
  struct gimli_line_info *b = *(struct gimli_line_info**)B;

  return a->addr - b->addr;
}

/* read dwarf info to determine the source/line information for a given
 * address */
int dwarf_determine_source_line_number(void *pc, char *src, int srclen,
  uint64_t *lineno)
{
  struct gimli_object_mapping *m;
  int i, n, upper, lower;
  struct gimli_object_file *f;
  struct gimli_line_info *linfo;

  m = gimli_mapping_for_addr(pc);
  if (!m) return 0;
  f = m->objfile;

  if (!f->elf) {
    /* can happen if the original file has been removed from disk */
    return 0;
  }

  if (!gimli_object_is_executable(f->elf)) {
    pc -= (intptr_t)m->base;
  }

  n = f->linecount;
  lower = 0;
  upper = n - 1;

  while (lower <= upper) {
    i = lower + ((upper - lower)/2);
    linfo = f->larray[i];

    if (linfo->addr == pc) {
      goto found;
    }
    if (linfo->addr > pc) {
      /* too high */
      upper = i - 1;
    } else {
      /* in the right ballpark */
      lower = i + 1;
    }
  }
  if (lower < 0) lower = 0;
  if (upper < lower) upper = lower + 1;
  for (i = lower; i <= upper; i++) {
    if (i < 0 || i >= n) continue;
    linfo = f->larray[i];
    if (pc < linfo->addr) {
      if (i > 0) {
        linfo = f->larray[i-1];
found:
        snprintf(src, srclen, "%s", linfo->filename);
        *lineno = linfo->lineno;
        return 1;
      }
    }
  }
  return 0;
}


static int process_line_numbers(struct gimli_object_file *f)
{
  struct gimli_section_data *s = NULL;
  struct {
    char *address;
    uint64_t file;
    uint64_t line;
    uint64_t column;
    uint8_t is_stmt; /* recommended breakpoint location */
    uint8_t basic_block; /* is start of a basic block */
    uint8_t end_sequence;
    uint8_t prologue_end;
    uint8_t epilogue_begin;
    uint64_t isa;
  } regs;
  const uint8_t *data, *end;
  uint32_t initlen;
  uint64_t len;
  int is_64 = 0;
  uint16_t ver;
  struct {
    uint8_t min_insn_len;
    uint8_t def_is_stmt;
    int8_t line_base;
    uint8_t line_range;
    uint8_t opcode_base;
  } hdr_1;
  uint64_t *opcode_lengths = NULL;
  int i;
  const char *filenames[1024];
  uint8_t op;
  struct gimli_line_info *linfo;

  if (f->aux_elf) {
    s = gimli_get_section_by_name(f->aux_elf, ".debug_line");
    if (s) {
      data = s->data;
    }
  }
  if (!s) {
    s = gimli_get_section_by_name(f->elf, ".debug_line");
    if (s) {
      data = s->data;
    }
  }
  if (!s) {
    return 0;
  }
  if (debug) fprintf(stderr, "\nGot debug_line info\n");

  end = data + s->size;

  while (data < end) {
    const uint8_t *cuend;
    void *prior;

    memset(&regs, 0, sizeof(regs));
    regs.file = 1;
    regs.line = 1;
    prior = NULL;

    /* read the initial length, this tells us which dwarf version and format
     * we're dealing with */
    memcpy(&initlen, data, sizeof(initlen));
    data += sizeof(initlen);

    if (initlen == 0xffffffff) {
      /* this is a 64-bit dwarf */
      is_64 = 1;
      memcpy(&len, data, sizeof(len));
      data += sizeof(len);
    } else {
      len = initlen;
    }
    cuend = data + len;

    memcpy(&ver, data, sizeof(ver));
    data += sizeof(ver);

    if (debug) {
      fprintf(stderr, "initlen is %llx (%d bit) ver=%u\n", 
        len, is_64 ? 64 : 32, ver);
    }

    if (is_64) {
      memcpy(&len, data, sizeof(len));
      data += sizeof(len);
    } else {
      memcpy(&initlen, data, sizeof(initlen));
      data += sizeof(initlen);
      len = initlen;
    }
    memcpy(&hdr_1, data, sizeof(hdr_1));
    data += sizeof(hdr_1);
    regs.is_stmt = hdr_1.def_is_stmt;

    if (debug) {
      fprintf(stderr,
        "headerlen is %llu, min_insn_len=%u line_base=%d line_range=%u\n"
        "opcode_base=%u\n",
        len, hdr_1.min_insn_len, hdr_1.line_base, hdr_1.line_range,
        hdr_1.opcode_base);
    }
    if (opcode_lengths) free(opcode_lengths);
    opcode_lengths = calloc(hdr_1.opcode_base, sizeof(uint64_t));
    for (i = 1; i < hdr_1.opcode_base; i++) {
      opcode_lengths[i-1] = dw_read_uleb128(&data, cuend);
      if (debug) {
        fprintf(stderr, "op len [%d] = %llu\n", i, opcode_lengths[i-1]);
      }
    }
    /* include_directories */
    while (*data && data < cuend) {
      if (debug) fprintf(stderr, "inc_dir: %s\n", data);
      data += strlen((char*)data) + 1;
    }
    data++;

    /* files */
    i = 1;
    memset(filenames, 0, sizeof(filenames));
    while (*data && data < cuend) {
      if (i >= sizeof(filenames)/sizeof(filenames[0])) {
        fprintf(stderr, "DWARF: too many files for line number info reader\n");
        return 0;
      }
      if (debug) fprintf(stderr, "file[%d] = %s\n", i, data);
      filenames[i] = (char*)data;
      data += strlen((char*)data) + 1;
      /* ignore additional data about the file */
      dw_read_uleb128(&data, cuend);
      dw_read_uleb128(&data, cuend);
      dw_read_uleb128(&data, cuend);
      i++;
    }
    data++;

    /* opcodes */
    while (data < cuend) {
      memcpy(&op, data, sizeof(op));
      data += sizeof(op);

      prior = regs.address;

      if (op == 0) {
        /* extended */
        const uint8_t *next;
        initlen = dw_read_uleb128(&data, cuend);
        memcpy(&op, data, sizeof(op));
        next = data + initlen;
        data += sizeof(op);
        switch (op) {
          case DW_LNE_set_address:
            {
              void *addr;
              memcpy(&addr, data, sizeof(addr));
              if (debug) fprintf(stderr, "set_address %p\n", addr);
              regs.address = addr;
              break;
            }
          case DW_LNE_end_sequence:
            {
              if (debug) fprintf(stderr, "end_sequence\n");
              memset(&regs, 0, sizeof(regs));
              regs.file = 1;
              regs.line = 1;
              break;
            }
          case DW_LNE_define_file:
            {
              const char *fname = (char*)data;
              uint64_t fno;

              data += strlen(fname)+1;
              fno = dw_read_uleb128(&data, cuend);
              filenames[fno] = fname;
              if (debug) fprintf(stderr, "define_files[%d] = %s\n", fno, fname);
              break;
            }

          default:
            fprintf(stderr,
              "DWARF: line nos.: unhandled extended op=%02x, len=%llu\n",
              op, len);
            ;
        }
        data = next;
      } else if (op < hdr_1.opcode_base) {
        /* standard opcode */
        switch (op) {
          case DW_LNS_copy:
            if (debug) fprintf(stderr, "copy\n");
            regs.basic_block = 0;
            regs.prologue_end = 0;
            regs.epilogue_begin = 0;
            break;
          case DW_LNS_advance_line:
            {
              int64_t d = dw_read_leb128(&data, cuend);
              if (debug) {
                fprintf(stderr, "advance_line from %lld to %lld\n",
                  regs.line, regs.line + d);
              }
              regs.line += d;
              break;
            }

          case DW_LNS_advance_pc:
            {
              uint64_t u = dw_read_uleb128(&data, cuend);
              regs.address += u * hdr_1.min_insn_len;
              if (debug) {
                fprintf(stderr, "advance_pc: addr=%llx\n", regs.address);
              }
              break;
            }
          case DW_LNS_set_file:
          {
            uint64_t u = dw_read_uleb128(&data, cuend);
            regs.file = u;
            if (debug) fprintf(stderr, "set_file: %llu\n", regs.file);
            break;
          }
          case DW_LNS_set_column:
          {
            uint64_t u = dw_read_uleb128(&data, cuend);
            regs.column = u;
            if (debug) fprintf(stderr, "set_column: %llu\n", regs.column);
            break;
          }
          case DW_LNS_negate_stmt:
            if (debug) fprintf(stderr, "negate_stmt\n");
            regs.is_stmt = !regs.is_stmt;
            break;
          case DW_LNS_set_basic_block:
            if (debug) fprintf(stderr, "set_basic_block\n");
            regs.basic_block = 1;
            break;
          case DW_LNS_const_add_pc:
            regs.address += ((255 - hdr_1.opcode_base) /
                            hdr_1.line_range) * hdr_1.min_insn_len;
            if (debug) {
              fprintf(stderr, "const_add_pc: addr=%llx\n", regs.address);
            }
            break;
          case DW_LNS_fixed_advance_pc:
          {
            uint16_t u;
            memcpy(&u, data, sizeof(u));
            data += sizeof(u);
            regs.address += u;
            if (debug) {
              fprintf(stderr, "fixed_advance_pc: %llx\n", regs.address);
            }
            break;
          }
          case DW_LNS_set_prologue_end:
            if (debug) {
              fprintf(stderr, "set_prologue_end\n");
            }
            regs.prologue_end = 1;
            break;
          case DW_LNS_set_epilogue_begin:
            if (debug) {
              fprintf(stderr, "set_epilogue_begin\n");
            }
            regs.epilogue_begin = 1;
            break;
          case DW_LNS_set_isa:
            regs.isa = dw_read_uleb128(&data, cuend);
            if (debug) {
              fprintf(stderr, "set_isa: %llx\n", regs.isa);
            }
            break;
          default:
            fprintf(stderr, "DWARF: line nos: unhandled op: %02x\n", op);
            /* consume unknown/unhandled args */
            for (i = 0; i < opcode_lengths[i]; i++) {
              dw_read_uleb128(&data, cuend);
            }
        }
      } else {
        /* special opcode */
        op -= hdr_1.opcode_base;

        if (debug) {
          fprintf(stderr, "special before: addr = %p, line = %lld\n",
              regs.address, regs.line);
          fprintf(stderr, "line_base = %d, line_range = %d\n",
            hdr_1.line_base, hdr_1.line_range);
        }

        regs.address += (op / hdr_1.line_range) * hdr_1.min_insn_len;
        regs.line += hdr_1.line_base + (op % hdr_1.line_range);
        if (debug) {
          fprintf(stderr, "special: addr = %p, line = %lld\n",
            regs.address, regs.line);
        }
      }


      if (regs.address && filenames[regs.file]) {
        linfo = calloc(1, sizeof(*linfo));
        linfo->filename = (char*)filenames[regs.file];
        linfo->lineno = regs.line;
        linfo->addr = regs.address;
        linfo->next = f->lines;
        f->lines = linfo;
        f->linecount++;
      }
    }
  }

  f->larray = malloc(f->linecount * sizeof(linfo));
  for (i = 0, linfo = f->lines; linfo; linfo = linfo->next, i++) {
    f->larray[i] = linfo;
  }
  qsort(f->larray, f->linecount, sizeof(linfo), sort_by_addr);

  return 0;
}

int gimli_process_dwarf(struct gimli_object_file *f)
{
  /* pull out additional information from dwarf debugging information.
   * In particular, we can scan the .debug_info section to resolve
   * function names into symbols for the back trace code */

  if (f->elf) {
    process_line_numbers(f);
  }

  return 1;
}

static void local_hexdump(void *addr, int p, int n)
{
  uint32_t data[4];
  int i, j;
  int x;
  struct gimli_symbol *sym;
  char buf[16];

  addr = (char*)addr - (p * sizeof(data));

  for (i = 0; i < n; i++) {
    memcpy(data, addr, sizeof(data));
    printf("%p:   ", addr);
    for (j = 0; j < 4; j++) {
      printf("     %08x", data[j]);
    }
    printf("\n");

    addr += sizeof(data);
  }
}

static int get_sect_data(struct gimli_object_file *f, const char *name,
  const uint8_t **startptr, const uint8_t **endptr, gimli_object_file_t **elf)
{
  const uint8_t *data = NULL, *end = NULL;
  struct gimli_section_data *s;

  if (elf && *elf) {
    s = gimli_get_section_by_name(*elf, name);
  } else {
    s = gimli_get_section_by_name(f->elf, name);
    if (!s || s->size <= sizeof(void*)) {
      if (f->aux_elf) {
        s = gimli_get_section_by_name(f->aux_elf, name);
      } else {
        s = NULL;
      }
    }
  }
  if (s) {
    data = s->data;
    if (elf) *elf = s->container;
  } else {
    data = NULL;
    if (elf) *elf = NULL;
  }
  if (data == NULL) {
    return 0;
  }
  end = data + s->size;

  *startptr = data;
  *endptr = end;
  return 1;
}


/* given a location list offset, determine the location in question */
int dw_calc_location(struct gimli_unwind_cursor *cur,
  uint64_t compilation_unit_base_addr,
  struct gimli_object_mapping *m, uint64_t offset, uint64_t *res,
  gimli_object_file_t *elf, int *is_stack)
{
  const uint8_t *data, *end;
  void *rstart = NULL, *rend = NULL;
  uint16_t len;
  uint64_t off = compilation_unit_base_addr;

  if (!get_sect_data(m->objfile, ".debug_loc", &data, &end, &elf)) {
    printf("Couldn't find a .debug_loc\n");
    return 0;
  }

//  printf("Using offset %d into .debug_loc\n", offset);
  data += offset;
//  local_hexdump(data, 0, 20);

  while (data < end) {
//    printf("populating rstart with %d bytes\n", sizeof(rstart));
    memcpy(&rstart, data, sizeof(rstart));
    data += sizeof(rstart);
    memcpy(&rend, data, sizeof(rend));
    data += sizeof(rend);
    if (rstart == 0 && rend == 0) {
      /* end of list */
//      printf("rstart = %p, so ending list\n", rstart);
      break;
    }
    if (rstart == (void*)-1) {
      /* base selection */
      off = (uint64_t)(intptr_t)rend;
      printf("got base selection: %p\n", rend);
      continue;
    }

    rstart += off;
    rend += off;

    memcpy(&len, data, sizeof(len));
    data += sizeof(len);
//    printf("This section is %d bytes in length\n", len);

//    printf("%p - %p\n", rstart, rend);
    if (cur->st.pc >= rstart && cur->st.pc < rend) {
//      printf("Found the range I was looking for, data=%p, len=%d\n", data, len);

      return dw_eval_expr(cur, (uint8_t*)data, len, 0, res, NULL, is_stack);
    }
    data += len;
  }
  return 0;
}


static const uint8_t *find_abbr(const uint8_t *abbr, const uint8_t *end,
  uint64_t fcode)
{
  uint64_t code;
  uint64_t tag;

  while (abbr < end) {
    code = dw_read_uleb128(&abbr, end);
    if (code == 0) continue;
//    printf("find_abbr: %lld (looking for %lld)\n", code, fcode);
    if (fcode == code) return abbr;

    tag = dw_read_uleb128(&abbr, end);
    abbr += sizeof(uint8_t);


    while (abbr < end) {
      dw_read_uleb128(&abbr, end);
      code = dw_read_uleb128(&abbr, end);
      if (code == 0) {
        break;
      }
    }
  }
  return NULL;
}

static uint64_t get_value(uint64_t form, uint64_t addr_size, int is_64,
  const uint8_t **datap, const uint8_t *end,
  uint64_t *vptr, const uint8_t **byteptr,
  gimli_object_file_t *elf)
{
  uint64_t u64;
  int64_t s64;
  uint32_t u32;
  uint16_t u16;
  uint8_t u8;
  const uint8_t *data = *datap;
  const uint8_t *strp, *send;

  *byteptr = NULL;

  switch (form) {
    case DW_FORM_addr:
    case DW_FORM_ref_addr:
      switch (addr_size) {
        case 1:
          memcpy(&u8, data, sizeof(u8));
          *vptr = u8;
          break;
        case 2:
          memcpy(&u16, data, sizeof(u16));
          *vptr = u16;
          break;
        case 4:
          memcpy(&u32, data, sizeof(u32));
          *vptr = u32;
          break;
        case 8:
          memcpy(vptr, data, sizeof(u64));
          break;
      }
      data += addr_size;
      break;
    case DW_FORM_data1:
    case DW_FORM_ref1:
      memcpy(&u8, data, sizeof(u8));
      data += sizeof(u8);
      *vptr = u8;
      break;
    case DW_FORM_data2:
    case DW_FORM_ref2:
      memcpy(&u16, data, sizeof(u16));
      data += sizeof(u16);
      *vptr = u16;
      break;
    case DW_FORM_data4:
    case DW_FORM_ref4:
      memcpy(&u32, data, sizeof(u32));
      data += sizeof(u32);
      *vptr = u32;
      break;
    case DW_FORM_data8:
    case DW_FORM_ref8:
      memcpy(&u64, data, sizeof(u64));
      data += sizeof(u64);
      *vptr = u64;
      break;
    case DW_FORM_udata:
    case DW_FORM_ref_udata:
      *vptr = dw_read_uleb128(&data, end);
      break;
    case DW_FORM_sdata:
      s64 = dw_read_leb128(&data, end);
      *vptr = (uint64_t)s64;
      break;
    case DW_FORM_flag:
      memcpy(&u8, data, sizeof(u8));
      data += sizeof(u8);
      *vptr = u8;
      break;
    /* for blocks, store length in vptr and set byteptr to start of data */
    case DW_FORM_block1:
      memcpy(&u8, data, sizeof(u8));
      *vptr = u8;
      data += sizeof(u8);
      *byteptr = data;
      data += *vptr;
      break;
    case DW_FORM_block2:
      memcpy(&u16, data, sizeof(u16));
      *vptr = u16;
      data += sizeof(u16);
      *byteptr = data;
      data += *vptr;
      break;
    case DW_FORM_block4:
      memcpy(&u32, data, sizeof(u32));
      *vptr = u32;
      data += sizeof(u32);
      *byteptr = data;
      data += *vptr;
      break;
    case DW_FORM_block:
      *vptr = dw_read_uleb128(&data, end);
      *byteptr = data;
      data += *vptr;
      break;
    case DW_FORM_strp:
      if (is_64) {
        memcpy(vptr, data, sizeof(*vptr));
        data += sizeof(*vptr);
      } else {
        memcpy(&u32, data, sizeof(u32));
        data += sizeof(u32);
        *vptr = u32;
      }
      if (get_sect_data(NULL, ".debug_str", &strp, &send, &elf)) {
        const uint8_t *str = strp + *vptr;
        *vptr = strlen((char*)str);
        form = DW_FORM_string;
        *byteptr = str;
      }
      break;
    case DW_FORM_string:
      *byteptr = data;
      *vptr = strlen((char*)data);
      data += 1 + *vptr;
      break;
    
    case DW_FORM_indirect:
      form = dw_read_uleb128(datap, end);
      if (form == DW_FORM_indirect) {
        printf(
          "DWARF: can't have an indirect FORM reference an indirect FORM\n");
        return 0;
      }
      return get_value(form, addr_size, is_64, datap, end, vptr, byteptr, elf);

    default:
      printf("DWARF: unhandled FORM: 0x%llx\n", form);
      return 0;
  }

  *datap = data;

  /* normalize the form */
  switch (form) {
    case DW_FORM_string:
    case DW_FORM_flag:
    case DW_FORM_addr:
    case DW_FORM_udata:
    case DW_FORM_sdata:
    case DW_FORM_ref_addr:
      break;
    case DW_FORM_block:
    case DW_FORM_block1:
    case DW_FORM_block2:
    case DW_FORM_block4:
      form = DW_FORM_block;
      break;
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
      form = DW_FORM_data8;
      break;
    case DW_FORM_ref1:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_ref_udata:
      form = DW_FORM_ref_udata;
      break;
  }
  if (debug) {
  printf("value normalized to form 0x%llx val=0x%llx bytep=%p %s\n",
       form, *vptr, *byteptr, form == DW_FORM_string ? (char*)*byteptr : "");
  }


  return form;
}


static struct gimli_dwarf_die *process_die(
  uint64_t reloc, const uint8_t *datastart,
  const uint8_t *custart,
  const uint8_t **datap, const uint8_t *end,
  const uint8_t *abbrstart, const uint8_t *abbrend,
  int is_64, uint8_t addr_size,
  gimli_object_file_t *elf,
  gimli_hash_t diehash
)
{
  const uint8_t *data = *datap;
  uint64_t abbr_code;
  uint64_t tag;
  uint8_t has_children;
  uint64_t atype, aform;
  const uint8_t *abbr;
  struct gimli_dwarf_die *die = NULL, *kid = NULL;
  struct gimli_dwarf_attr *attr = NULL;
  uint64_t offset;
  char diename[64];

  offset = data - datastart;
  abbr_code = dw_read_uleb128(&data, end);
  if (abbr_code == 0) {
    // Skip over NUL entry
//    printf("found a NUL entry @ %llx\n", offset);
    *datap = data;
    return NULL;
  }
  abbr = find_abbr(abbrstart, abbrend, abbr_code);
  if (!abbr) {
    printf("Couldn't locate abbrev code %lld\n", abbr_code);
    *datap = data;
    return NULL;
  }

  /* what kind of entry is this? */
  tag = dw_read_uleb128(&abbr, abbrend);
  memcpy(&has_children, abbr, sizeof(has_children));
  abbr += sizeof(has_children);

  die = calloc(1, sizeof(*die));
  die->offset = offset;
  die->tag = tag;
  snprintf(diename, sizeof(diename)-1, "%llx", offset);
  gimli_hash_insert(diehash, diename, die);
//  printf("die @ %s tag=%llx\n", diename, die->tag);

  while (data < end && abbr < abbrend) {
    atype = dw_read_uleb128(&abbr, abbrend);
    aform = dw_read_uleb128(&abbr, abbrend);

    if (atype == 0) {
      break;
    }

    attr = calloc(1, sizeof(*attr));
    attr->attr = atype;

    attr->form = get_value(aform, addr_size, is_64, &data, end,
        &attr->code, &attr->ptr, elf);

    if (attr->form == 0) {
      printf("Failed to resolve value for attribute\n");
      break;
    }

    if (attr->form == DW_FORM_addr) {
      attr->code += reloc;
    } else if (attr->form == DW_FORM_ref_udata) {
      /* offset from start of its respective CU */
      attr->code += (int64_t)(custart - datastart);
      attr->form = DW_FORM_data8;
    }

    attr->next = die->attrs;
    die->attrs = attr;
    attr = NULL;
  }

  if (has_children) {
    /* go recursive and pull those in now.
     * The first child may be NULL and not indicate a terminator */
    while (1) {
      kid = process_die(reloc, datastart, custart, &data, end, abbrstart,
            abbrend, is_64, addr_size, elf, diehash);
      if (kid == NULL) {
        if (die->last_kid) {
          break;
        }
        continue;
      }
      if (!die->kids) {
        die->kids = kid;
      }
      if (die->last_kid) {
        die->last_kid->next = kid;
      }
      die->last_kid = kid;
      kid->parent = die;
    }
  }

  *datap = data;
  return die;
}

struct gimli_dwarf_die *gimli_dwarf_get_die(struct gimli_object_file *f,
  uint64_t offset)
{
  const uint8_t *data, *datastart, *end, *next;
  const uint8_t *abbr, *abbrstart, *abbrend;
  const uint8_t *cuend, *custart;
  gimli_object_file_t *elf = NULL;
  uint64_t initlen;
  uint32_t len32;
  uint16_t ver;
  uint64_t da_offset;
  int is_64 = 0;
  uint8_t addr_size, seg_size;
  uint64_t reloc = 0;
  struct gimli_dwarf_die *die = NULL;
  struct gimli_dwarf_die *last_die = NULL;
  char diename[64];

  if (!f->dies) {
    f->dies = gimli_hash_new(NULL);

    if (!get_sect_data(f, ".debug_info", &datastart, &end, &elf)) {
      printf("no debug info for %s\n", f->objname);
      return 0;
    }
    data = datastart;

    if (!gimli_object_is_executable(f->elf)) {
      struct gimli_object_mapping *m;

      for (m = gimli_mappings; m; m = m->next) {
        if (m->objfile == f) {
          reloc = (uint64_t)(intptr_t)m->base;
        }
      }
      //    printf("Using reloc adjustment for %s: 0x%llx\n", m->objfile->objname, reloc);
    }

    while (data < end) {
      custart = data;
      memcpy(&len32, data, sizeof(len32));
      data += sizeof(len32);
      if (len32 == 0xffffffff) {
        is_64 = 1;
        memcpy(&initlen, data, sizeof(initlen));
        data += sizeof(initlen);
      } else {
        is_64 = 0;
        initlen = len32;
      }
      cuend = data + initlen;

      memcpy(&ver, data, sizeof(ver));
      data += sizeof(ver);
      if (ver != 2) {
        printf("Encountered a compilation unit with dwarf version %d; ending processing\n", ver);

        break;
      }

      if (is_64) {
        memcpy(&da_offset, data, sizeof(da_offset));
        data += sizeof(da_offset);
      } else {
        memcpy(&len32, data, sizeof(len32));
        data += sizeof(len32);
        da_offset = len32;
      }

      memcpy(&addr_size, data, sizeof(addr_size));
      data += sizeof(addr_size);

      if (!get_sect_data(f, ".debug_abbrev",
            &abbrstart, &abbrend, &elf)) {
        printf("could not get abbrev data for %s\n", f->objname);
        return 0;
      }
      abbrstart += da_offset;

      /* now we have a series of Debugging Information Entries (DIE) */
      while (data < cuend) {
        die = process_die(reloc, datastart, custart, &data, cuend,
                abbrstart, abbrend, is_64, addr_size, elf, f->dies);
        if (!die) {
          continue;
        }
        if (last_die) {
          last_die->next = die;
        }
        if (!f->first_die) {
          f->first_die = die;
        }
        last_die = die;
      }
      data = cuend;
    }
  }

  snprintf(diename, sizeof(diename)-1, "%llx", offset);
  if (gimli_hash_find(f->dies, diename, (void**)&die)) {
    return die;
  }

  for (die = f->first_die; die; die = die->next) {
    if (die->offset >= offset) {
      return die;
    }
  }

//  printf("Didn't find die at offset %s\n", diename);
  return NULL;
}



struct gimli_dwarf_attr *gimli_dwarf_die_get_attr(
  struct gimli_dwarf_die *die, uint64_t attrcode)
{
  struct gimli_dwarf_attr *attr;

  for (attr = die->attrs; attr; attr = attr->next) {
    if (attr->attr == attrcode) {
      return attr;
    }
  }
  return NULL;
}

int gimli_dwarf_die_get_uint64_t_attr(
  struct gimli_dwarf_die *die, uint64_t attrcode, uint64_t *val)
{
  struct gimli_dwarf_attr *attr;

  attr = gimli_dwarf_die_get_attr(die, attrcode);
  if (attr) {
    *val = attr->code;
    return 1;
  }
  return 0;
}

struct gimli_dwarf_die *gimli_dwarf_get_die_for_pc(
  struct gimli_unwind_cursor *cur)
{
  struct gimli_section_data *s = NULL;
  const uint8_t *data, *end, *next;
  struct gimli_object_mapping *m;
  gimli_object_file_t *elf = NULL;
  uint64_t reloc = 0;
  uint32_t len32;
  int is_64 = 0;
  uint64_t initlen;
  uint16_t ver;
  uint64_t di_offset;
  uint8_t addr_size, seg_size;
  struct gimli_dwarf_die *die;

  m = gimli_mapping_for_addr(cur->st.pc);
  if (!m) {
    return 0;
  }
  if (!m->objfile->elf) {
    /* (deleted) */
    return 0;
  }
  if (!get_sect_data(m->objfile, ".debug_aranges", &data, &end, &elf)) {
    return 0;
  }

  if (!gimli_object_is_executable(m->objfile->elf)) {
    reloc = (uint64_t)(intptr_t)m->base;
//    printf("Using reloc adjustment for %s: 0x%llx\n", m->objfile->objname, reloc);
  }

  while (data < end) {
    uint64_t mask;

    /* read header */

    memcpy(&len32, data, sizeof(len32));
    data += sizeof(len32);
    if (len32 == 0xffffffff) {
      is_64 = 1;
      memcpy(&initlen, data, sizeof(initlen));
      data += sizeof(initlen);
    } else {
      is_64 = 0;
      initlen = len32;
    }
    next = data + initlen;

    memcpy(&ver, data, sizeof(ver));
    data += sizeof(ver);

    if (is_64) {
      memcpy(&di_offset, data, sizeof(di_offset));
      data += sizeof(di_offset);
    } else {
      memcpy(&len32, data, sizeof(len32));
      data += sizeof(len32);
      di_offset = len32;
    }

    memcpy(&addr_size, data, sizeof(addr_size));
    data += sizeof(addr_size);

    memcpy(&seg_size, data, sizeof(seg_size));
    data += sizeof(seg_size);

    /* align to double-addr-size boundary */
    mask = (2 * addr_size) - 1;
    data += mask;
    data = (void*)(intptr_t)((intptr_t)data & ~mask);

    while (data < next) {
      /* now we have a series of tuples */
      void *addr;
      uint64_t l;

      memcpy(&addr, data, sizeof(addr));
      data += sizeof(addr);
      if (data >= next) break;

      if (sizeof(void*) == 8) {
        memcpy(&l, data, sizeof(l));
        data += sizeof(l);
      } else {
        memcpy(&len32, data, sizeof(len32));
        data += sizeof(len32);
        l = len32;
      }

      if (addr == 0 && l == 0) {
        break;
      }

      addr += reloc;

      if (cur->st.pc >= addr && cur->st.pc <= addr + l) {
//        printf("found di offset: pc=%p addr=%p len=%llx\n",
//          cur->st.pc, addr, l);
//        printf("Looking for die @ %llx\n", di_offset);
        die = gimli_dwarf_get_die(m->objfile, di_offset);
//        printf("--> die %p @ %llx\n", die, die ? die->offset : 0);
        if (die && die->tag == DW_TAG_compile_unit) {
          /* this is the die for the compilation unit; we need to walk
           * through it and find the subprogram that matches */
          for (die = die->kids; die; die = die->next) {
            uint64_t lopc, hipc;
//            struct gimli_dwarf_attr *lopc, *hipc;

            if (die->tag != DW_TAG_subprogram) {
//              printf("skip die %p: tag=%llx\n", die, die->tag);
              continue;
            }

            if (!gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_low_pc, &lopc)) {
              lopc = (uint64_t)(intptr_t)addr;
              continue;
            }
            if (!gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_high_pc, &hipc)) {
              hipc = (uint64_t)(intptr_t)addr + l;
              continue;
            }

//            lopc = gimli_dwarf_die_get_attr(die, DW_AT_low_pc);
//            hipc = gimli_dwarf_die_get_attr(die, DW_AT_high_pc);

            if (cur->st.pc >= (void*)(intptr_t)lopc &&
                cur->st.pc <= (void*)(intptr_t)hipc) {
//printf("Have a subprogram lopc=%p hipc=%p die offset=%llx\n", lopc, hipc, die->offset);
              return die;
            }
          }
        }
      }
//      printf("arange: pc=%p addr=%p %llx\n", cur->st.pc, addr, l);
    }
    data = next;
  }

  /* no joy */
  return 0;
}

static const char *resolve_type_name(struct gimli_object_file *f,
  struct gimli_dwarf_attr *type)
{
  struct gimli_dwarf_die *td, *kid;
  struct gimli_dwarf_attr *name;
  int pointer_level = 0;
  char namebuf[1024];
  int i;
  int is_const = 0;
  const char *namestr;

#define STARS "*****************************"

  while (type) {
    td = gimli_dwarf_get_die(f, type->code);
    if (!td) return NULL;

    name = gimli_dwarf_die_get_attr(td, DW_AT_name);
    if (name) {
      namestr = (char*)name->ptr;
    } else {
      namestr = "<anon>";
    }

    switch (td->tag) {
      case DW_TAG_base_type:
      case DW_TAG_typedef:
        snprintf(namebuf, sizeof(namebuf)-1, "%s %.*s",
          namestr,
          pointer_level, STARS);
        return strdup(namebuf);

      case DW_TAG_enumeration_type:
        snprintf(namebuf, sizeof(namebuf)-1, "enum %s %.*s",
          namestr,
          pointer_level, STARS);
        return strdup(namebuf);

      case DW_TAG_structure_type:
        snprintf(namebuf, sizeof(namebuf)-1, "struct %s %.*s",
          namestr,
          pointer_level, STARS);
        return strdup(namebuf);

      case DW_TAG_union_type:
        snprintf(namebuf, sizeof(namebuf)-1, "union %s %.*s",
          namestr,
          pointer_level, STARS);
        return strdup(namebuf);

      case DW_TAG_pointer_type:
        pointer_level++;
        type = gimli_dwarf_die_get_attr(td, DW_AT_type);
        if (!type) {
          snprintf(namebuf, sizeof(namebuf)-1, "void %.*s",
            pointer_level, STARS);
          return strdup(namebuf);
        }
        continue;

      case DW_TAG_subroutine_type:
        snprintf(namebuf, sizeof(namebuf)-1, "(%.*s %s) ",
          pointer_level, STARS,
          namestr
          );
        return strdup(namebuf);



      case DW_TAG_const_type:
        is_const++;
        type = gimli_dwarf_die_get_attr(td, DW_AT_type);
        continue;

      case DW_TAG_array_type:
        type = gimli_dwarf_die_get_attr(td, DW_AT_type);
        namestr = resolve_type_name(f, type);
        snprintf(namebuf, sizeof(namebuf)-1, "%s", namestr);
        free((char*)namestr);
        namestr = namebuf + strlen(namebuf);
        for (kid = td->kids; kid; kid = kid->next) {
          uint64_t upper;
          if (kid->tag != DW_TAG_subrange_type) continue;
          if (gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_upper_bound, &upper))
          {
            sprintf((char*)namestr, "[%llu]", upper);
            namestr += strlen(namestr);
          } else {
            sprintf((char*)namestr, "[]");
            namestr += 2;
          }
        }
        return strdup(namebuf);

      default:
        printf("Unhandled tag %llx for type name (offset=<%llx>)\n", td->tag, td->offset);
        return NULL;
    }
  }
  return NULL;
}

static int read_value(void *addr, int is_stack, void *out, uint64_t size)
{
  uint32_t u32;
  uint16_t u16;
  uint8_t u8;
  uint64_t v;

  if (is_stack) {
    return gimli_read_mem(addr, out, size) == size;
  }
  /* otherwise, addr actually contains the value */
  v = (uint64_t)(intptr_t)addr;
  switch (size) {
    case 8:
      memcpy(out, &v, size);
      return 1;
    case 4:
      u32 = v;
      memcpy(out, &u32, size);
      return 1;
    case 2:
      u16 = v;
      memcpy(out, &u16, size);
      return 1;
    case 1:
      u8 = v;
      memcpy(out, &u8, size);
      return 1;
  }
  printf("Can't handle register stored values > 8 bytes in size\n");
  return 0;
}

static int do_before(
    struct gimli_unwind_cursor *cur,
//    int tid, int frameno, void *pcaddr, void *context,
    const char *datatype, const char *varname,
    void *varaddr, uint64_t varsize)
{
  struct gimli_object_file *file;

  for (file = gimli_files; file; file = file->next) {
    if (file->tracer_module &&
        file->tracer_module->api_version >= 2 &&
        file->tracer_module->before_print_frame_var) {
      if (file->tracer_module->before_print_frame_var(
            &ana_api, file->objname, cur->tid, cur->frameno,
            cur->st.pc, (void*)cur, datatype, varname, varaddr, varsize)
          == GIMLI_ANA_SUPPRESS) {
        return 1;
      }
    }
  }
  return 0;
}

static int do_after(
    struct gimli_unwind_cursor *cur,
//    int tid, int frameno, void *pcaddr, void *context,
    const char *datatype, const char *varname,
    void *varaddr, uint64_t varsize)
{
  struct gimli_object_file *file;

  for (file = gimli_files; file; file = file->next) {
    if (file->tracer_module &&
        file->tracer_module->api_version >= 2 &&
        file->tracer_module->after_print_frame_var) {
      file->tracer_module->after_print_frame_var(
          &ana_api, file->objname, cur->tid, cur->frameno,
          cur->st.pc, (void*)cur, datatype, varname, varaddr, varsize);
    }
  }
  return 0;
}

static int show_param(struct gimli_unwind_cursor *cur,
  struct gimli_object_file *f,
  struct gimli_dwarf_attr *type, void *addr, int is_stack,
  const char *name, const char *type_name,
  int indent, int mask, int shift)
{
  uint64_t ate, size = 0;
  uint64_t u64;
  int64_t s64;
  int32_t s32;
  uint32_t u32;
  int16_t s16;
  uint16_t u16;
  uint8_t u8;
  int8_t s8;
  struct gimli_dwarf_die *td, *kid;
  struct gimli_dwarf_attr *attr;
  char indentstr[1024];
  char namebuf[1024];
  const char *symname;
  int suppress;
  int do_hook = indent == 2; /* only call tracer_module for top-level params */

  if (derefed_params == NULL) {
    derefed_params = gimli_hash_new(NULL);
  }
  snprintf(indentstr, sizeof(indentstr)-1, "%.*s", indent,
    "                                                            ");

  if (type_name == NULL) {
    type_name = resolve_type_name(f, type);
  }
  td = gimli_dwarf_get_die(f, type->code);
//printf("show_param: offset=%llx tag=%llx\n", td->offset, td->tag);
  if (td) {
    switch (td->tag) {
      case DW_TAG_typedef:
      case DW_TAG_const_type:
        /* resolve to underlying type */
        type = gimli_dwarf_die_get_attr(td, DW_AT_type);
        return show_param(cur, f, type, addr, is_stack, 
                  name, type_name, indent,
          mask, shift);

      case DW_TAG_base_type:
        if (!gimli_dwarf_die_get_uint64_t_attr(td, DW_AT_encoding, &ate)) {
          ate = DW_ATE_signed;
        }
        gimli_dwarf_die_get_uint64_t_attr(td, DW_AT_byte_size, &size);

        if (do_hook && do_before(cur, type_name, name, addr, size)) {
          return 1;
        }

        printf("%s%s%s = ", indentstr, type_name, name);
        switch (ate) {
          case DW_ATE_unsigned:
          case DW_ATE_unsigned_char:
            switch (size) {
              case 8:
                read_value(addr, is_stack, &u64, size);
                if (mask) {
                  u64 >>= shift;
                  u64 &= mask;
                }
                printf("%llu (0x%llx)\n", u64, u64);
                break;
              case 4:
                read_value(addr, is_stack, &u32, size);
                if (mask) {
                  u32 >>= shift;
                  u32 &= mask;
                }
                printf("%u (0x%x)\n", u32, u32);
                break;
              case 2:
                read_value(addr, is_stack, &u16, size);
                if (mask) {
                  u16 >>= shift;
                  u16 &= mask;
                }
                printf("%u (0x%x)\n", u16, u16);
                break;
              case 1:
                read_value(addr, is_stack, &u8, size);
                if (mask) {
                  u8 >>= shift;
                  u8 &= mask;
                }
                printf("%u (0x%2x)\n", u8, u8);
                break;
              default:
                printf("unhandled byte size %lld\n", size);
                return 0;
            }
            break;
          case DW_ATE_signed:
          case DW_ATE_signed_char:
          default:
            switch (size) {
              case 8:
                read_value(addr, is_stack, &s64, size);
                if (mask) {
                  s64 >>= shift;
                  s64 &= mask;
                }
                printf("%lld (0x%llx)\n", s64, s64);
                break;
              case 4:
                read_value(addr, is_stack, &s32, size);
                if (mask) {
                  s32 >>= shift;
                  s32 &= mask;
                }
                printf("%d (0x%x)\n", s32, s32);
                break;
              case 2:
                read_value(addr, is_stack, &s16, size);
                if (mask) {
                  s16 >>= shift;
                  s16 &= mask;
                }
                printf("%d (0x%x)\n", s16, s16);
                break;
              case 1:
                read_value(addr, is_stack, &s8, size);
                if (mask) {
                  s8 >>= shift;
                  s8 &= mask;
                }
                printf("%d (0x%2x)\n", s8, s8);
                break;
              default:
                printf("unhandled byte size %lld\n", size);
                return 0;
            }
            break;
        }
        if (do_hook) do_after(cur, type_name, name, addr, size);
        return 1;

      case DW_TAG_enumeration_type:
        gimli_dwarf_die_get_uint64_t_attr(td, DW_AT_byte_size, &size);

        if (do_hook && do_before(cur, type_name, name, addr, size)) {
          return 1;
        }

        printf("%s%s%s = ", indentstr, type_name, name);
        switch (size) {
          case 8:
            read_value(addr, is_stack, &s64, size);
            break;
          case 4:
            read_value(addr, is_stack, &s32, size);
            s64 = s32;
            break;
          case 2:
            read_value(addr, is_stack, &s16, size);
            s64 = s16;
            break;
          case 1:
            read_value(addr, is_stack, &s8, size);
            s64 = s8;
            break;
        }
        for (kid = td->kids; kid; kid = kid->next) {
          if (kid->tag == DW_TAG_enumerator) {
            struct gimli_dwarf_attr *cv;
            
            cv = gimli_dwarf_die_get_attr(kid, DW_AT_const_value);
            if (cv && (int64_t)cv->code == s64) {
              cv = gimli_dwarf_die_get_attr(kid, DW_AT_name);
              if (cv) printf("%s ", cv->ptr);
              break;
            }
          }
        }
        printf("%lld (0x%llx)\n", s64, s64);
        if (do_hook) do_after(cur, type_name, name, addr, size);
        return 1;

      case DW_TAG_array_type:
        if (do_hook && do_before(cur, type_name, name, addr, size)) {
          return 1;
        }

        printf("%s%s %s = {...}\n", indentstr, type_name, name);
        if (do_hook) do_after(cur, type_name, name, addr, size);
        return 1;

      case DW_TAG_pointer_type:
        gimli_dwarf_die_get_uint64_t_attr(td, DW_AT_byte_size, &size);
        if (size == 4) {
          read_value(addr, is_stack, &u32, size);
          addr = (void*)(intptr_t)u32;
        } else {
          read_value(addr, is_stack, &u64, size);
          addr = (void*)(intptr_t)u64;
        }
        if (!type_name) {
          type_name = "void *";
        }
        if (do_hook && do_before(cur, type_name, name, addr, size)) {
          return 1;
        }

        printf("%s%s%s = %p", indentstr, type_name, name, addr);
        symname = gimli_pc_sym_name(addr, namebuf, sizeof(namebuf));
        if (symname && strlen(symname)) {
          printf(" (%s)", symname);
        }
        /* if it points to a structured type, de-ref */
        attr = gimli_dwarf_die_get_attr(td, DW_AT_type);
        if (attr && addr) {
          kid = gimli_dwarf_get_die(f, attr->code);
          if (kid && kid->tag == DW_TAG_const_type) {
            attr = gimli_dwarf_die_get_attr(kid, DW_AT_type);
            if (attr) {
              kid = gimli_dwarf_get_die(f, attr->code);
            }
          }
        }
        if (attr && addr) {
          if (kid && kid->tag == DW_TAG_base_type &&
              gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_byte_size, &size)
              && size == 1) {
            /* smells like a string */
            printf(" ");
            if (gimli_read_mem(addr, namebuf, 1)) {
              printf("\"");
              while (gimli_read_mem(addr, namebuf, 1)) {
                if (namebuf[0] == '\0') break;
                if (isprint(namebuf[0])) {
                  printf("%c", namebuf[0]);
                } else if (namebuf[0] == '"') {
                  printf("\\\"");
                } else if (namebuf[0] == '\\') {
                  printf("\\\\");
                } else {
                  printf("\\x%02x", ((int)namebuf[0]) & 0xff);
                }
                addr++;
              }
              printf("\"\n");
            } else {
              printf(" <invalid address>\n");
            }
          } else if (indent < 6) {
            snprintf(namebuf, sizeof(namebuf)-1, "%p", addr);
            if (!gimli_hash_find(derefed_params, namebuf, NULL)) {

              printf("%s[deref'ing %s]\n", indentstr, name);
              gimli_hash_insert(derefed_params, namebuf, addr);
              show_param(cur, f, attr, addr, 0, 
                      namebuf, NULL, indent + 2, 0, 0);
            } else {
              printf("%s[deref'ed above]\n", indentstr);
            }
          } else {
            printf("\n");
          }
        } else {
          printf("\n");
        }
        if (do_hook) do_after(cur, type_name, name, addr, size);
        return 1;
      case DW_TAG_structure_type:
      case DW_TAG_union_type:
        if (do_hook && do_before(cur, type_name, name, addr, size)) {
          return 1;
        }

        if (name[0] == '0') {
          printf("%s%s @ %s = {\n", indentstr, type_name, name);
        } else {
          printf("%s%s%s @ %p = {\n", indentstr, type_name, name, addr);
        }
        for (kid = td->kids; kid; kid = kid->next) {
          struct gimli_dwarf_attr *loc, *mtype, *mname;
          uint64_t root = (uint64_t)(intptr_t)addr;

          if (kid->tag != DW_TAG_member) continue;

          loc = gimli_dwarf_die_get_attr(kid, DW_AT_data_member_location);
          is_stack = 1;
          if (loc && loc->form == DW_FORM_block) {
            if (!dw_eval_expr(cur, (uint8_t*)loc->ptr, loc->code, 0,
                &root, &root, &is_stack)) {
              printf("unable to evaluate member location\n");
              root = 0;
            } else {
//              printf("calculated %p from %p (indirect=%d)\n",
//                (void*)root, addr, is_stack);
            }
          } else if (loc) {
            root = 0;
            printf("Unhandled location form %llx for struct member\n",
              loc->form);
          } else {
            /* an omitted member location implies that it occupies the
             * start of the element */
          }

          if (root) {
            mtype = gimli_dwarf_die_get_attr(kid, DW_AT_type);
            mname = gimli_dwarf_die_get_attr(kid, DW_AT_name);

            if (gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_bit_size, &u64)) {
              /* it's a bit field */
              uint64_t size = u64;
              uint64_t off;

              if (!gimli_dwarf_die_get_uint64_t_attr(kid,
                  DW_AT_bit_offset, &off)) {
                off = 1;
              }
              gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_byte_size, &u64);

              /* offset is number of bits from MSB for that storage type.
               * Let's flip that around so that it is the offset from the
               * LSB */
              off = ((u64 * 8) - 1) - off;
              mask = (1 << size) - 1;
              shift = off - (size - 1);

            } else {
              mask = 0;
              shift = 0;
            }
            show_param(cur, f, mtype, (void*)(intptr_t)root,
                is_stack,
                (char*)mname->ptr, NULL, indent + 2, mask, shift);
          }
        }
        printf("%s};\n", indentstr);
        if (do_hook) do_after(cur, type_name, name, addr, size);
        return 1;
      default:
        printf("Unhandled tag %llx in show_param\n", td->tag);
    }
  } else {
    printf("no type information\n");
  }
  return 0;
}

int gimli_show_param_info(struct gimli_unwind_cursor *cur)
{
  struct gimli_dwarf_die *die = gimli_dwarf_get_die_for_pc(cur);
  struct gimli_dwarf_die *td;
  uint64_t frame_base = 0;
  uint64_t res;
  uint64_t comp_unit_base = 0;
  struct gimli_dwarf_attr *location, *type;
  struct gimli_dwarf_attr *name, *frame_base_attr;
  struct gimli_object_mapping *m = gimli_mapping_for_addr(cur->st.pc);
  int had_params = 0;
  int is_stack = 0;

  if (!die) {
    return 0;
  }

  if (die->parent->tag == DW_TAG_compile_unit) {
    gimli_dwarf_die_get_uint64_t_attr(die->parent, 
      DW_AT_low_pc, &comp_unit_base);
  }

  frame_base_attr = gimli_dwarf_die_get_attr(die, DW_AT_frame_base);
  if (frame_base_attr) {
    switch (frame_base_attr->form) {
      case DW_FORM_block:
        dw_eval_expr(cur, (uint8_t*)frame_base_attr->ptr, frame_base_attr->code,
            0, &frame_base, NULL, &is_stack);
        break;
      case DW_FORM_data8:
        dw_calc_location(cur, comp_unit_base, m,
            frame_base_attr->code, &frame_base, NULL, &is_stack);
        break;
      default:
        printf("Unhandled frame base form %llx\n",
            frame_base_attr->form);
    }
  } 

  for (die = die->kids; die; die = die->next) {
    if (die->tag == DW_TAG_formal_parameter) {
      location = gimli_dwarf_die_get_attr(die, DW_AT_location);
      name = gimli_dwarf_die_get_attr(die, DW_AT_name);
      type = gimli_dwarf_die_get_attr(die, DW_AT_type);

      res = 0;
      is_stack = 1;
      if (location) {
        switch (location->form) {
          case DW_FORM_block:
//            printf("using block to eval param location\n");
            if (!dw_eval_expr(cur, (uint8_t*)location->ptr, location->code,
                frame_base, &res, NULL, &is_stack)) {
              res = 0;
            }
            break;
          case DW_FORM_data8:
//            printf("using loclist to eval param location\n");
//              printf("loc form=%llx code=%llx ptr=%p\n",
//                location->form, location->code, location->ptr);
            if (!dw_calc_location(cur, comp_unit_base, m,
                location->code, &res, NULL, &is_stack)) {
//              printf("failed to calc location\n");
              res = 0;
            }
//            printf("got %llx\n", res);
            break;
          default:
            printf("Unhandled location form %llx\n", location->form);
        }
      } else {
        printf("no location attribute for parameter %s die->offset=%llx %s\n",
          name ? (char*)name->ptr : "?", die->offset, m->objfile->objname);
      }
//printf("param: die offset %llx @ %p\n", die->offset, (void*)(intptr_t)res);
      if (res) {
        had_params++;
//        printf("type=%p %llx form %llx ind=%d\n", type, type->code, type->form, is_stack);
        if (!show_param(cur, m->objfile, type,
            (void*)(intptr_t)res, is_stack, (char*)name->ptr, NULL, 2, 0, 0)) {
          printf("    %s @ %llx (type data @ %llx)\n",
            name->ptr, res, type->code);
        }
      }
    }
  }

  if (had_params) {
    printf("\n");
  }

  return 0;
}

/* vim:ts=2:sw=2:et:
 */

