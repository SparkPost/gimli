/*
 * Copyright (c) 2009-2012 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"
#include "gimli_dwarf.h"

struct dw_die_arange {
  uint64_t addr;
  uint64_t len;
  uint64_t di_offset;
};

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

int dw_read_encptr(gimli_proc_t proc,
  uint8_t enc, const uint8_t **ptr, const uint8_t *end,
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
      if (gimli_read_mem(proc, res, &res, sizeof(res))
          != sizeof(*output)) {
        return 0;
      }
    } else {
      uint32_t r;
      if (gimli_read_mem(proc, res, &r, sizeof(r)) != sizeof(r)) {
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
      fprintf(stderr, "DWARF: unhandled pointer application value: %02x at %p\n", enc & DW_EH_PE_APPL_MASK, (void*)pc);
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
      fprintf(stderr, "DWARF: unhandled DW_EH_PE value: 0x%02x (masked to 0x%02x) at %p\n", enc, enc & 0x0f, (void*)pc);
      return 0;
  }

  *output = res;
  return 1;
}

static int sort_by_addr(const void *A, const void *B)
{
  struct gimli_line_info *a = (struct gimli_line_info*)A;
  struct gimli_line_info *b = (struct gimli_line_info*)B;

  return a->addr - b->addr;
}

static int search_compare_line(const void *addrp, const void *L)
{
  struct gimli_line_info *line = (struct gimli_line_info*)L;
  gimli_addr_t pc = *(gimli_addr_t*)addrp;

  if (pc < line->addr) {
    return -1;
  }
  if (pc < line->end) {
    return 0;
  }
  return 1;
}

static int process_line_numbers(gimli_mapped_object_t f);

/* read dwarf info to determine the source/line information for a given
 * address */
int gimli_determine_source_line_number(gimli_proc_t proc,
  gimli_addr_t pc, char *src, int srclen,
  uint64_t *lineno)
{
  struct gimli_object_mapping *m;
  gimli_mapped_object_t f;
  struct gimli_line_info *linfo;

  m = gimli_mapping_for_addr(proc, pc);
  if (!m) return 0;
  f = m->objfile;

  if (!f->elf) {
    /* can happen if the original file has been removed from disk */
    return 0;
  }
  if (!f->lines) {
    process_line_numbers(f);
    if (!f->lines) {
      return 0;
    }
  }

  if (!gimli_object_is_executable(f->elf)) {
    pc -= m->base;
  }

  linfo = bsearch(&pc, f->lines, f->linecount, sizeof(*linfo),
      search_compare_line);

  if (linfo) {
    snprintf(src, srclen, "%s", linfo->filename);
    *lineno = linfo->lineno;
    return 1;
  }
  return 0;
}


static int process_line_numbers(gimli_mapped_object_t f)
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
  int debugline = debug && 0;

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
  if (debugline) fprintf(stderr, "\nGot debug_line info\n");

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

    if (debugline) {
      fprintf(stderr, "initlen is 0x%" PRIx64 " (%d bit) ver=%u\n",
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

    if (debugline) {
      fprintf(stderr,
        "headerlen is %" PRIu64 ", min_insn_len=%u line_base=%d line_range=%u\n"
        "opcode_base=%u\n",
        len, hdr_1.min_insn_len, hdr_1.line_base, hdr_1.line_range,
        hdr_1.opcode_base);
    }
    if (opcode_lengths) free(opcode_lengths);
    opcode_lengths = calloc(hdr_1.opcode_base, sizeof(uint64_t));
    for (i = 1; i < hdr_1.opcode_base; i++) {
      opcode_lengths[i-1] = dw_read_uleb128(&data, cuend);
      if (debugline) {
        fprintf(stderr, "op len [%d] = %" PRIu64 "\n", i, opcode_lengths[i-1]);
      }
    }
    /* include_directories */
    while (*data && data < cuend) {
      if (debugline) fprintf(stderr, "inc_dir: %s\n", data);
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
      if (debugline) fprintf(stderr, "file[%d] = %s\n", i, data);
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
              if (debugline) fprintf(stderr, "set_address %p\n", addr);
              regs.address = addr;
              break;
            }
          case DW_LNE_end_sequence:
            {
              if (debugline) fprintf(stderr, "end_sequence\n");
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
              if (debugline) fprintf(stderr, "define_files[%" PRIu64 "] = %s\n", fno, fname);
              break;
            }

          default:
//            fprintf(stderr,
//              "DWARF: line nos.: unhandled extended op=%02x, len=%" PRIu32 "\n",
//              op, initlen);
            ;
        }
        data = next;
      } else if (op < hdr_1.opcode_base) {
        /* standard opcode */
        switch (op) {
          case DW_LNS_copy:
            if (debugline) fprintf(stderr, "copy\n");
            regs.basic_block = 0;
            regs.prologue_end = 0;
            regs.epilogue_begin = 0;
            break;
          case DW_LNS_advance_line:
            {
              int64_t d = dw_read_leb128(&data, cuend);
              if (debugline) {
                fprintf(stderr, "advance_line from %" PRId64 " to %" PRId64 "\n",
                  regs.line, regs.line + d);
              }
              regs.line += d;
              break;
            }

          case DW_LNS_advance_pc:
            {
              uint64_t u = dw_read_uleb128(&data, cuend);
              regs.address += u * hdr_1.min_insn_len;
              if (debugline) {
                fprintf(stderr, "advance_pc: addr=0x%" PRIx64 "\n", (uintptr_t)regs.address);
              }
              break;
            }
          case DW_LNS_set_file:
          {
            uint64_t u = dw_read_uleb128(&data, cuend);
            regs.file = u;
            if (debugline) fprintf(stderr, "set_file: %" PRIu64 "\n", regs.file);
            break;
          }
          case DW_LNS_set_column:
          {
            uint64_t u = dw_read_uleb128(&data, cuend);
            regs.column = u;
            if (debugline) fprintf(stderr, "set_column: %" PRIu64 "\n", regs.column);
            break;
          }
          case DW_LNS_negate_stmt:
            if (debugline) fprintf(stderr, "negate_stmt\n");
            regs.is_stmt = !regs.is_stmt;
            break;
          case DW_LNS_set_basic_block:
            if (debugline) fprintf(stderr, "set_basic_block\n");
            regs.basic_block = 1;
            break;
          case DW_LNS_const_add_pc:
            regs.address += ((255 - hdr_1.opcode_base) /
                            hdr_1.line_range) * hdr_1.min_insn_len;
            if (debugline) {
              fprintf(stderr, "const_add_pc: addr=0x%" PRIx64 "\n", (uintptr_t)regs.address);
            }
            break;
          case DW_LNS_fixed_advance_pc:
          {
            uint16_t u;
            memcpy(&u, data, sizeof(u));
            data += sizeof(u);
            regs.address += u;
            if (debugline) {
              fprintf(stderr, "fixed_advance_pc: 0x%" PRIx64 "\n", (uintptr_t)regs.address);
            }
            break;
          }
          case DW_LNS_set_prologue_end:
            if (debugline) {
              fprintf(stderr, "set_prologue_end\n");
            }
            regs.prologue_end = 1;
            break;
          case DW_LNS_set_epilogue_begin:
            if (debugline) {
              fprintf(stderr, "set_epilogue_begin\n");
            }
            regs.epilogue_begin = 1;
            break;
          case DW_LNS_set_isa:
            regs.isa = dw_read_uleb128(&data, cuend);
            if (debugline) {
              fprintf(stderr, "set_isa: 0x%" PRIx64 "\n", regs.isa);
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

        if (debugline) {
          fprintf(stderr, "special before: addr = %p, line = %" PRId64 "\n",
              regs.address, regs.line);
          fprintf(stderr, "line_base = %d, line_range = %d\n",
            hdr_1.line_base, hdr_1.line_range);
        }

        regs.address += (op / hdr_1.line_range) * hdr_1.min_insn_len;
        regs.line += hdr_1.line_base + (op % hdr_1.line_range);
        if (debugline) {
          fprintf(stderr, "special: addr = %p, line = %" PRId64 "\n",
            regs.address, regs.line);
        }
      }


      if (regs.address && filenames[regs.file]) {
        if (f->linecount + 1 >= f->linealloc) {
          f->linealloc = f->linealloc ? f->linealloc * 2 : 1024;
          f->lines = realloc(f->lines, f->linealloc * sizeof(*linfo));
        }
        linfo = &f->lines[f->linecount++];
        linfo->filename = filenames[regs.file];
        linfo->lineno = regs.line;
        linfo->addr = (gimli_addr_t)regs.address;
      }
    }
  }

  qsort(f->lines, f->linecount, sizeof(struct gimli_line_info), sort_by_addr);
//printf("sorting %d lines in %s\n", f->linecount, f->objname);

  free(opcode_lengths);

  /* make a pass to fill in the end member to make it easier to find
   * an approx match */
  if (f->linecount) {
    for (i = 0; i < f->linecount - 1; i++) {
      f->lines[i].end = f->lines[i+1].addr;
    }
  }

  return 0;
}

int gimli_process_dwarf(gimli_mapped_object_t f)
{
  /* pull out additional information from dwarf debugging information.
   * In particular, we can scan the .debug_info section to resolve
   * function names into symbols for the back trace code */

  if (f->elf) {
    //process_line_numbers(f);
  }

  return 1;
}

static int get_sect_data(gimli_mapped_object_t f, const char *name,
  const uint8_t **startptr, const uint8_t **endptr, gimli_object_file_t *elf)
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
  gimli_object_file_t elf, int *is_stack)
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


static const uint8_t *find_abbr(gimli_mapped_object_t file,
    uint64_t da_offset,
    uint64_t fcode)
{
  uint64_t code;
  uint64_t tag;
  uint64_t key;
  const uint8_t *abbr;
  int slow_mode = 0;

  if (!file->abbr.map) {
    if (!get_sect_data(file, ".debug_abbrev",
          &file->abbr.start, &file->abbr.end, &file->abbr.elf)) {
      printf("could not get abbrev data for %s\n", file->objname);
      return 0;
    }

    /* observed approx 11-13 per abbrev, err on the side of avoiding
     * rebuckets */
    file->abbr.map = gimli_hash_new_size(NULL, GIMLI_HASH_U64_KEYS,
        (file->abbr.end - file->abbr.start) / 10);
  }

  /* NOTE: even though DWARF allows for 64-bit offsets, we're making the assumption
   * that they are not practical or possible for the next few years.
   * Doing so allows us to cheaply record both the da_offset and code
   * into a u64 key.
   * I've observed approx 17% collisions with a max chain length of 7
   * in a collided bucket.  It's not perfect but it is effective.
   * */
  if (da_offset > UINT32_MAX || fcode > UINT32_MAX) {
    // Allow correct, albeit slow, operation when we overflow this assumption
    slow_mode = 1;
  }
  if (!slow_mode) {
    key = (da_offset << 32) | (fcode & 0xffffffff);
    if (gimli_hash_find_u64(file->abbr.map, key, (void**)&abbr)) {
      return abbr;
    }
  }

  abbr = file->abbr.start + da_offset;

  while (abbr < file->abbr.end) {
    code = dw_read_uleb128(&abbr, file->abbr.end);
    if (code == 0) continue;
//    printf("find_abbr: %lld (looking for %lld)\n", code, fcode);
    if (fcode == code) {

//printf("find_abbr: %" PRIx64 " -> %p\n", fcode, abbr);
      if (!slow_mode &&
          !gimli_hash_insert_u64(file->abbr.map, key, (void*)abbr)) {
        void *ptr = NULL;
        gimli_hash_find_u64(file->abbr.map, key, &ptr);
        if (ptr != abbr) {
          printf("find_abbr: %" PRIx64 " (key=%" PRIx64 ") collided with %p and %p\n",
              fcode, key, abbr, ptr);
        }
      }
      return abbr;
    }

    tag = dw_read_uleb128(&abbr, file->abbr.end);
    abbr += sizeof(uint8_t);


    while (abbr < file->abbr.end) {
      dw_read_uleb128(&abbr, file->abbr.end);
      code = dw_read_uleb128(&abbr, file->abbr.end);
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
  gimli_object_file_t elf)
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
      printf("DWARF: unhandled FORM: 0x%" PRIx64 "\n", form);
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
  if (debug && 0) {
    printf("value normalized to form 0x%" PRIx64 " val=0x%" PRIx64 " bytep=%p %s\n",
       form, *vptr, *byteptr, form == DW_FORM_string ? (char*)*byteptr : "");
  }


  return form;
}

static struct gimli_dwarf_die *process_die(
  gimli_mapped_object_t file,
  struct gimli_dwarf_cu *cu,
  const uint8_t *custart,
  const uint8_t **datap, const uint8_t *end,
  uint64_t da_offset,
  int is_64, uint8_t addr_size
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

  offset = data - file->debug_info.start;

  abbr_code = dw_read_uleb128(&data, end);
  if (abbr_code == 0) {
    // Skip over NUL entry
//    printf("found a NUL entry @ 0x%" PRIx64 "\n", offset);
    *datap = data;
    return NULL;
  }
  abbr = find_abbr(file, da_offset, abbr_code);
  if (!abbr) {
    printf("Couldn't locate abbrev code %" PRId64 "\n", abbr_code);
    *datap = data;
    return NULL;
  }

  /* what kind of entry is this? */
  tag = dw_read_uleb128(&abbr, file->abbr.end);
  memcpy(&has_children, abbr, sizeof(has_children));
  abbr += sizeof(has_children);
  if (has_children != 0 && has_children != 1) {
    printf("invalid value for has_children! %d\n", has_children);
    abort();
  }

  die = gimli_slab_alloc(&file->dieslab);
  memset(die, 0, sizeof(*die));
  die->offset = offset;
  die->tag = tag;
  STAILQ_INIT(&die->kids);

  while (data < end && abbr < file->abbr.end) {
    atype = dw_read_uleb128(&abbr, file->abbr.end);
    aform = dw_read_uleb128(&abbr, file->abbr.end);

    if (atype == 0) {
      break;
    }

    attr = gimli_slab_alloc(&file->attrslab);
    memset(attr, 0, sizeof(*attr));
    attr->attr = atype;

    attr->form = get_value(aform, addr_size, is_64, &data, end,
        &attr->code, &attr->ptr, file->debug_info.elf);

    if (attr->form == 0) {
      printf("Failed to resolve value for attribute\n");
      break;
    }

    if (attr->form == DW_FORM_addr) {
      attr->code += file->debug_info.reloc;
    } else if (attr->form == DW_FORM_ref_udata) {
      /* offset from start of its respective CU */
//      printf("ref CU, code is %" PRIx64, attr->code);
      attr->code += (int64_t)(custart - file->debug_info.start);
//      printf(" fixed up to %" PRIx64 "\n", attr->code);
      attr->ptr = (const uint8_t*)cu;
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
      kid = process_die(file, cu, custart, &data, end, da_offset,
            is_64, addr_size);
      if (kid == NULL) {
        if (STAILQ_FIRST(&die->kids)) {
          break;
        }
        continue;
      }
      STAILQ_INSERT_TAIL(&die->kids, kid, siblings);
      kid->parent = die;
    }
  }

#if 0
  printf("process_die stopping at offset %" PRIx64 "\n",
      data - file->debug_info.start);
#endif
  *datap = data;
  return die;
}

/* Calculate the relocation slide value; it only applies
 * to shared objects (not the main executable) and must
 * be the value of the lowest load address of all the
 * mappings for that object */
static gimli_addr_t calc_reloc(gimli_mapped_object_t f)
{
  int i;
  struct gimli_object_mapping *m;
  gimli_addr_t smallest = 0;

  if (gimli_object_is_executable(f->elf) || f->debug_info.reloc) {
    return f->debug_info.reloc;
  }

  for (i = 0; i < the_proc->nmaps; i++) {
    m = the_proc->mappings[i];

    if (m->objfile == f) {
      if (smallest) {
        if (m->base < smallest) {
          smallest = m->base;
        }
      } else {
        smallest = m->base;
      }
    }
    f->debug_info.reloc = smallest;
  }
#if 0
  printf("Using reloc adjustment for %s: 0x%" PRIx64 "\n",
      m->objfile->objname, f->debug_info.reloc);
#endif
  return f->debug_info.reloc;
}

static int init_debug_info(gimli_mapped_object_t f)
{
  if (f->debug_info.start) return 1;

  if (!get_sect_data(f, ".debug_info", &f->debug_info.start,
        &f->debug_info.end, &f->debug_info.elf)) {
    printf("no debug info for %s\n", f->objname);
    return 0;
  }

  calc_reloc(f);

  return 1;
}

/* insert CU into the appropriate portion of the binary search tree
 * pointed to by root */
static void insert_cu(struct gimli_dwarf_cu **rootp, struct gimli_dwarf_cu *cu)
{
  struct gimli_dwarf_cu *root = *rootp;

  if (!root) {
    *rootp = cu;
    return;
  }
  while (root) {
    if (cu->offset >= root->offset && cu->offset < root->end) {
      printf("CU list already contains %" PRIx64 "\n", cu->offset);
      abort();
    }
    if (cu->offset < root->offset) {
      if (root->left) {
        root = root->left;
        continue;
      }
      root->left = cu;
      return;
    }
    /* must be on the right */
    if (root->right) {
      root = root->right;
      continue;
    }
    root->right = cu;
    return;
  }
}

static struct gimli_dwarf_cu *load_cu(gimli_mapped_object_t f, uint64_t offset)
{
  const uint8_t *data, *next;
  const uint8_t *cuend, *custart;
  gimli_object_file_t elf = NULL;
  uint64_t initlen;
  uint32_t len32;
  uint16_t ver;
  uint64_t da_offset;
  int is_64 = 0;
  uint8_t addr_size, seg_size;
  struct gimli_dwarf_cu *cu, *cuptr;
  struct gimli_dwarf_die *die = NULL;

  if (!init_debug_info(f)) {
    return 0;
  }
  data = f->debug_info.start + offset;

#if 0
  printf("Loading CU @ offset %" PRIx64 " from data of size %" PRIu64 "\n",
      offset,
      f->debug_info.end - f->debug_info.start);
#endif

  if (data >= f->debug_info.end) {
    printf("CU offset %" PRIx64 " it out of bounds\n", offset);
    return 0;
  }

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
  if (ver < 2 || ver > 3) {
    printf("%s: CU @ offset 0x%" PRIx64 " with dwarf version %d; ending processing\n",
        f->objname, offset, ver);
    abort();
    return 0;
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

  cu = calloc(1, sizeof(*cu));
  cu->offset = offset;
  cu->end = cuend - f->debug_info.start;
  cu->da_offset = da_offset;
  STAILQ_INIT(&cu->dies);

  /* insert into the cu tree */
  insert_cu(&f->debug_info.cus, cu);
#if 0
  printf("Recording CU %" PRIx64 " - %" PRIx64 " @ %p\n",
      cu->offset, cu->end, cu);
#endif

  /* now we have a series of Debugging Information Entries (DIE) */
  while (data < cuend) {
    die = process_die(f, cu, custart, &data, cuend,
        da_offset, is_64, addr_size);
    if (!die) {
      continue;
    }
    STAILQ_INSERT_TAIL(&cu->dies, die, siblings);
  }

#if 0
  printf("abbr.map is %d in size, data size %" PRIu64 " approx %" PRIu64 " per entry\n",
      gimli_hash_size(f->abbr.map), f->abbr.end - f->abbr.start,
      (f->abbr.end - f->abbr.start) / gimli_hash_size(f->abbr.map));
  gimli_hash_diagnose(f->abbr.map);
#endif

  return cu;
}

/* searches the CU binary search tree for the requested offset */
static struct gimli_dwarf_cu *find_cu(
  gimli_mapped_object_t f,
  uint64_t offset)
{
  struct gimli_dwarf_die *die = NULL;
  struct gimli_dwarf_cu *cu;

  /* search binary tree */
  cu = f->debug_info.cus;
  while (cu) {
    if (offset >= cu->offset && offset < cu->end) {
      return cu;
    }
    if (offset < cu->offset) {
      cu = cu->left;
    } else {
      cu = cu->right;
    }
  }
  return NULL;
}

static struct gimli_dwarf_die *find_die_r(struct gimli_dwarf_die *die, uint64_t offset)
{
  struct gimli_dwarf_die *kid, *res;

  if (die->offset == offset) {
    return die;
  }
  STAILQ_FOREACH(kid, &die->kids, siblings) {
    if (kid->offset == offset) {
      return kid;
    }
  }
  STAILQ_FOREACH(kid, &die->kids, siblings) {
    res = find_die_r(kid, offset);
    if (res) {
      return res;
    }
  }
  return NULL;
}

struct gimli_dwarf_die *gimli_dwarf_get_die(
  gimli_mapped_object_t f,
  uint64_t offset)
{
  struct gimli_dwarf_die *die = NULL, *res;
  struct gimli_dwarf_cu *cu;

  cu = find_cu(f, offset);
  if (!cu) {
    /* not found; will need to go out to disk to read it */
    cu = load_cu(f, offset);
  }

  if (cu) {
    STAILQ_FOREACH(die, &cu->dies, siblings) {
      res = find_die_r(die, offset);
      if (res) {
        return res;
      }
    }
  }

  printf("get_die: %" PRIx64 " MISSING cu=%p %" PRIx64 "-%" PRIx64 "\n",
      offset, cu, cu->offset, cu->end);
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

static int gimli_dwarf_die_get_uint64_t_attr(
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

static int sort_compare_arange(const void *A, const void *B)
{
  struct dw_die_arange *a = (struct dw_die_arange*)A;
  struct dw_die_arange *b = (struct dw_die_arange*)B;

  return a->addr - b->addr;
}

/* Load the DIE location data from an object file */
static int load_arange(struct gimli_object_mapping *m)
{
  struct gimli_section_data *s = NULL;
  const uint8_t *data, *end, *next;
  gimli_object_file_t elf = NULL;
  uint64_t reloc = 0;
  uint32_t len32;
  int is_64 = 0;
  uint64_t initlen;
  uint16_t ver;
  uint64_t di_offset;
  uint8_t addr_size, seg_size;
  struct gimli_dwarf_die *die;

  if (!m->objfile->elf) {
    /* (deleted) */
    return 0;
  }
  if (!get_sect_data(m->objfile, ".debug_aranges", &data, &end, &elf)) {
    return 0;
  }

  reloc = calc_reloc(m->objfile);

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

    if (seg_size) {
      printf("DWARF: I don't support segmented debug_aranges data\n");
      return 0;
    }

//    printf("arange: ver %d addr_size %d seg %d\n", ver, addr_size, seg_size);

    /* align to double-addr-size boundary */
    mask = (2 * addr_size) - 1;
    data += mask;
    data = (void*)(intptr_t)((intptr_t)data & ~mask);

    while (data < next) {
      /* now we have a series of tuples */
      gimli_addr_t addr;
      uint64_t l;
      struct dw_die_arange *arange;

      if (addr_size == 8) {
        memcpy(&l, data, sizeof(l));
        data += sizeof(l);
        addr = l;
      } else {
        memcpy(&len32, data, sizeof(len32));
        data += sizeof(len32);
        addr = len32;
      }

      if (data >= next) break;

      if (addr_size == 8) {
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

      if (m->objfile->num_arange + 1 >= m->objfile->alloc_arange) {
        m->objfile->alloc_arange = m->objfile->alloc_arange ? m->objfile->alloc_arange * 2 : 1024;
        m->objfile->arange = realloc(m->objfile->arange, m->objfile->alloc_arange * sizeof(*arange));
      }
      arange = &m->objfile->arange[m->objfile->num_arange++];
      arange->addr = addr;
      arange->len = l;
      arange->di_offset = di_offset;

//      printf("arange: addr=" PTRFMT " 0x%" PRIx64 "\n", addr, l);
    }
    data = next;
  }

  /* ensure ascending order */
  qsort(m->objfile->arange, m->objfile->num_arange, sizeof(struct dw_die_arange),
      sort_compare_arange);
//printf("sorting %d arange in %s\n", m->objfile->num_arange, m->objfile->objname);

  return 1;
}

static int search_compare_arange(const void *K, const void *R)
{
  struct dw_die_arange *arange = (struct dw_die_arange*)R;
  gimli_addr_t pc = *(gimli_addr_t*)K;

  if (pc < arange->addr) {
    return -1;
  }

  if (pc < arange->addr + arange->len) {
    return 0;
  }

  return 1;
}

/* Given a CU, locate the DIE corresponding to the provided data address */
static struct gimli_dwarf_die *find_var_die_for_addr(gimli_proc_t proc,
    struct gimli_object_mapping *m,
    struct gimli_dwarf_cu *cu, gimli_addr_t addr)
{
  struct gimli_dwarf_die *die, *kid;
  struct gimli_unwind_cursor cur;
  uint64_t frame_base = 0;
  uint64_t comp_unit_base = 0;
  int is_stack = 0;
  struct gimli_dwarf_attr *frame_base_attr;

  memset(&cur, 0, sizeof(cur));
  cur.proc = proc;

  STAILQ_FOREACH(die, &cu->dies, siblings) {
    uint64_t lopc, hipc;

    if (die->tag != DW_TAG_compile_unit) {
      printf("DIE is not a compile unit!? tag=0x%" PRIx64 "\n", die->tag);
      continue;
    }

    gimli_dwarf_die_get_uint64_t_attr(die,
        DW_AT_low_pc, &comp_unit_base);

    frame_base_attr = gimli_dwarf_die_get_attr(die, DW_AT_frame_base);
    if (frame_base_attr) {
      switch (frame_base_attr->form) {
        case DW_FORM_block:
          dw_eval_expr(&cur, (uint8_t*)frame_base_attr->ptr, frame_base_attr->code,
              0, &frame_base, NULL, &is_stack);
          break;
        case DW_FORM_data8:
          dw_calc_location(&cur, comp_unit_base, m,
              frame_base_attr->code, &frame_base, NULL, &is_stack);
          break;
        default:
          printf("Unhandled frame base form 0x%" PRIx64 "\n",
              frame_base_attr->form);
          return 0;
      }
    }

    /* this is the die for the compilation unit; we need to walk
     * through it and find the data it contains */
    STAILQ_FOREACH(kid, &die->kids, siblings) {
      uint64_t res = 0;
      is_stack = 1;
      struct gimli_dwarf_attr *location, *type, *name;

      if (kid->tag != DW_TAG_variable && kid->tag != DW_TAG_constant) {
//        printf("skipping kid with tag 0x%" PRIx64 "\n", kid->tag);
        continue;
      }

      location = gimli_dwarf_die_get_attr(kid, DW_AT_location);
      if (!location) {
        continue;
      }

      switch (location->form) {
        case DW_FORM_block:
          if (!dw_eval_expr(&cur, (uint8_t*)location->ptr, location->code,
                frame_base, &res, NULL, &is_stack)) {
            res = 0;
          }
          break;
        case DW_FORM_data8:
          if (!dw_calc_location(&cur, comp_unit_base, m,
                location->code, &res, NULL, &is_stack)) {
            res = 0;
          }
          break;
        default:
          printf("Unhandled location form 0x%" PRIx64 "\n", location->form);
          res = 0;
      }

      if (res == addr) {
        return kid;
      }
    }
  }

  /* no joy */
  return NULL;
}

/* attempt to locate a DW_TAG_variable or DW_TAG_constant die
 * corresponding to the provided data address.
 * We make this attempt using the debug_aranges data, but it
 * may not be successful, as gcc doesn't appear to generate
 * it for the data segment, despite the DWARF standard indicating
 * that it can be used in that fashion.
 * In that case, we have to fall back to crawling the CU data.
 * */
static struct gimli_dwarf_die *gimli_dwarf_get_die_for_data(
    gimli_proc_t proc, gimli_addr_t pc)
{
  struct gimli_object_mapping *m;
  struct gimli_dwarf_cu *cu;
  struct dw_die_arange *arange;
  struct gimli_dwarf_die *die;
  gimli_mapped_object_t file;
  const uint8_t *cuptr;
  uint64_t off;

  m = gimli_mapping_for_addr(proc, pc);
  if (!m) {
    return NULL;
  }
  file = m->objfile;

  if (!file->elf) {
    return NULL;
  }

  if (!file->arange && !load_arange(m)) {
    return NULL;
  }

  arange = bsearch(&pc, file->arange, file->num_arange,
      sizeof(*arange), search_compare_arange);
  if (arange) {
    /* arange gives us a pointer to the CU */
    cu = find_cu(file, arange->di_offset);
    if (!cu) {
      cu = load_cu(file, arange->di_offset);
    }
    if (cu) {
      return find_var_die_for_addr(proc, m, cu, pc);
    }
  }

  cuptr = file->debug_info.start;
  while (cuptr < file->debug_info.end) {
    off = cuptr - file->debug_info.start;
    cu = find_cu(file, off);
    if (!cu) {
      cu = load_cu(file, off);
    }
    if (!cu) break;
    cuptr = file->debug_info.start + cu->end;

    die = find_var_die_for_addr(proc, m, cu, pc);
    if (die) return die;
  }

  return NULL;
}

struct gimli_dwarf_die *gimli_dwarf_get_die_for_pc(gimli_proc_t proc, gimli_addr_t pc)
{
  struct gimli_object_mapping *m;
  struct gimli_dwarf_die *die, *kid;
  struct gimli_dwarf_cu *cu;
  struct dw_die_arange *arange;

  m = gimli_mapping_for_addr(proc, pc);
  if (!m) {
    return NULL;
  }

  if (!m->objfile->elf) {
    return NULL;
  }

  if (!m->objfile->arange && !load_arange(m)) {
    return NULL;
  }

  arange = bsearch(&pc, m->objfile->arange, m->objfile->num_arange,
      sizeof(*arange), search_compare_arange);
  if (!arange) {
//    printf("no arange for pc " PTRFMT "\n", pc);
    return NULL;
  }
  /* arange gives us a pointer to the CU */
  cu = find_cu(m->objfile, arange->di_offset);
  if (!cu) {
    cu = load_cu(m->objfile, arange->di_offset);
  }
  if (!cu) {
//    printf("no CU for pc " PTRFMT " arange said off %" PRIx64 "\n", pc, arange->di_offset);
    return NULL;
  }

//  printf("got CU " PTRFMT " - " PTRFMT " arange said off %" PRIx64 "\n", cu->offset, cu->end, arange->di_offset);

  STAILQ_FOREACH(die, &cu->dies, siblings) {
    uint64_t lopc, hipc;

    if (die->tag != DW_TAG_compile_unit) {
      printf("DIE is not a compile unit!? tag=0x%" PRIx64 "\n", die->tag);
      continue;
    }

    /* this is the die for the compilation unit; we need to walk
     * through it and find the subprogram that matches */
    STAILQ_FOREACH(kid, &die->kids, siblings) {
      lopc = arange->addr;
      hipc = arange->len;

      if (kid->tag != DW_TAG_subprogram) {
        continue;
      }

      if (!gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_low_pc, &lopc)) {
        continue;
      }
      if (!gimli_dwarf_die_get_uint64_t_attr(kid, DW_AT_high_pc, &hipc)) {
        continue;
      }

      if (pc >= lopc && pc <= hipc) {
        return kid;
      }
    }
  }

  /* no joy */
  return NULL;
}

int gimli_dwarf_read_value(gimli_proc_t proc,
    gimli_addr_t addr, int is_stack, void *out, uint64_t size)
{
  uint32_t u32;
  uint16_t u16;
  uint8_t u8;
  uint64_t v;

  if (is_stack) {
    return gimli_read_mem(proc, addr, out, size) == size;
  }
  /* otherwise, addr actually contains the value */
  v = addr;
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


static gimli_type_t load_type(
    gimli_mapped_object_t file,
    struct gimli_dwarf_attr *type);

static void populate_struct_or_union(
    gimli_type_t t,
    gimli_mapped_object_t file,
    struct gimli_dwarf_die *die)
{
  struct gimli_dwarf_attr *loc, *type, *mname;
  uint64_t root = 0;
  struct gimli_unwind_cursor cur;
  int is_stack = 1;
  uint64_t size, offset;
  gimli_type_t memt;


  memset(&cur, 0, sizeof(cur));

  STAILQ_FOREACH(die, &die->kids, siblings) {
    if (die->tag != DW_TAG_member) continue;

    loc = gimli_dwarf_die_get_attr(die, DW_AT_data_member_location);
    is_stack = 1;
    /* assume start of struct */
    root = 0;
    if (loc && loc->form == DW_FORM_block) {
      if (!dw_eval_expr(&cur, (uint8_t*)loc->ptr, loc->code, 0,
            &root, &root, &is_stack)) {
        printf("unable to evaluate member location\n");
        root = 0;
      }
    } else if (loc) {
      printf("Unhandled location form 0x%" PRIx64 " for struct member\n",
          loc->form);
    }
    type = gimli_dwarf_die_get_attr(die, DW_AT_type);
    mname = gimli_dwarf_die_get_attr(die, DW_AT_name);

    memt = load_type(file, type);
    if (!memt) {
#if 0
      printf("failed to load type info for member %s %" PRIx64 "\n", mname->ptr,
          type->code);
#endif
      continue;
    }
    offset = 0;
    if (gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_bit_size, &size)) {
      uint64_t bytesize;

      if (!gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_bit_offset, &offset)) {
        offset = 1;
      }
      /* convert to bit offset from start of storage */
      /* FIXME: check this for big endian systems */
      if (!gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_byte_size, &bytesize)) {
        bytesize = gimli_type_size(memt)/8;
      }
      offset = ((bytesize * 8) - 1) - offset;

    } else {
      size = gimli_type_size(memt);
    }

    gimli_type_add_member(t, mname ? (char*)mname->ptr : NULL,
        memt, size, (root * 8) + offset);
  }
}

static gimli_type_t array_dim(gimli_mapped_object_t file,
    struct gimli_dwarf_die *die, gimli_type_t eletype)
{
  struct gimli_type_arinfo info;
  uint64_t uval;
  struct gimli_dwarf_attr *type;
  gimli_type_t t, target;

  memset(&info, 0, sizeof(info));

  if (STAILQ_NEXT(die, siblings)) {
    info.contents = array_dim(file, STAILQ_NEXT(die, siblings), eletype);
  } else {
    info.contents = eletype;
  }

  if (gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_upper_bound, &uval)) {
    info.nelems = uval + 1;
  } else {
    info.nelems = 0;
  }

  return gimli_type_new_array(file->types, &info);
}

static gimli_type_t populate_array(gimli_mapped_object_t file,
    struct gimli_dwarf_die *die)
{
  struct gimli_type_arinfo info;
  gimli_type_t t;
  struct gimli_dwarf_attr *type;

  if (!STAILQ_FIRST(&die->kids) || STAILQ_FIRST(&die->kids)->tag != DW_TAG_subrange_type) {
    printf("cannot determine array bounds!\n");
    return NULL;
  }

  /* find target type */
  type = gimli_dwarf_die_get_attr(die, DW_AT_type);
  t = load_type(file, type);
  if (!t) {
    return NULL;
  }

  t = array_dim(file, STAILQ_FIRST(&die->kids), t);
  return t;
}

static gimli_type_t load_void(gimli_mapped_object_t file)
{
  struct gimli_type_encoding enc;

  memset(&enc, 0, sizeof(enc));
  enc.bits = 8;
  return gimli_type_new_integer(file->types, "void", &enc);
}

static gimli_type_t populate_func(gimli_mapped_object_t file,
    const char *name,
    struct gimli_dwarf_die *die)
{
  struct gimli_dwarf_die *kid;
  struct gimli_dwarf_attr *type, *pname;
  gimli_type_t rettype = NULL, t;
  uint32_t flags = 0;

  type = gimli_dwarf_die_get_attr(die, DW_AT_type);
  if (type) {
    rettype = load_type(file, type);
  } else {
    rettype = load_void(file);
  }

  /* are we variadic? */
  STAILQ_FOREACH(kid, &die->kids, siblings) {
    if (kid->tag == DW_TAG_unspecified_parameters) {
      flags = GIMLI_FUNC_VARARG;
      break;
    }
  }

  t = gimli_type_new_function(file->types, name, flags, rettype);

  STAILQ_FOREACH(kid, &die->kids, siblings) {
    if (kid->tag == DW_TAG_unspecified_parameters) {
      continue;
    }
    if (kid->tag == DW_TAG_formal_parameter) {
      gimli_type_t ptype;
      pname = gimli_dwarf_die_get_attr(kid, DW_AT_name);

      type = gimli_dwarf_die_get_attr(kid, DW_AT_type);
      if (type) {
        ptype = load_type(file, type);
        gimli_type_function_add_parameter(t, pname ? pname->ptr : NULL, ptype);
      }
      continue;
    }
  }

  return t;
}

static int populate_enum(gimli_type_t t,
    gimli_mapped_object_t file,
    struct gimli_dwarf_die *parent)
{
  struct gimli_dwarf_die *die;
  struct gimli_dwarf_attr *name = NULL;

  STAILQ_FOREACH(die, &parent->kids, siblings) {
    struct gimli_dwarf_attr *cv;

    if (die->tag != DW_TAG_enumerator) {
      printf("unexpected tag 0x%" PRIx64 " in enumeration_type\n",
          die->tag);
      return 0;
    }
    name = gimli_dwarf_die_get_attr(die, DW_AT_name);
    if (!name) {
      printf("expected name for enumerator!\n");
      return 0;
    }

    cv = gimli_dwarf_die_get_attr(die, DW_AT_const_value);
    if (!cv) {
      printf("missing const_value for enumerator\n");
      return 0;
    }
    gimli_type_enum_add(t, (char*)name->ptr, (int)cv->code);
  }
  return 1;
}

static gimli_type_t load_type_die(
    gimli_mapped_object_t file,
    struct gimli_dwarf_die *die)
{
  gimli_type_t t = NULL, target = NULL;
  uint64_t ate, size = 0;
  struct gimli_type_encoding enc;
  const char *type_name = NULL;
  struct gimli_dwarf_attr *name = NULL;
  struct gimli_dwarf_attr *type = NULL;

  if (file->die_to_type) {
    if (gimli_hash_find_ptr(file->die_to_type, die, (void**)&t)) {
      return t;
    }
  }

  if (!file->types) {
    file->types = gimli_type_collection_new();
  }
  if (!file->die_to_type) {
    file->die_to_type = gimli_hash_new_size(NULL, GIMLI_HASH_PTR_KEYS, 0);
  }

  name = gimli_dwarf_die_get_attr(die, DW_AT_name);
  if (name) {
    type_name = (char*)name->ptr;
  } else {
    type_name = NULL;
  }

  switch (die->tag) {
    case DW_TAG_base_type:
      if (!gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_encoding, &ate)) {
        ate = DW_ATE_signed;
      }
      memset(&enc, 0, sizeof(enc));

      gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_byte_size, &size);
      enc.bits = size * 8;

      switch (ate) {
        case DW_ATE_unsigned_char:
          enc.format = GIMLI_INT_CHAR;
          t = gimli_type_new_integer(file->types, type_name, &enc);
          break;
        case DW_ATE_unsigned:
          t = gimli_type_new_integer(file->types, type_name, &enc);
          break;
        case DW_ATE_signed:
          enc.format = GIMLI_INT_SIGNED;
          t = gimli_type_new_integer(file->types, type_name, &enc);
          break;
        case DW_ATE_signed_char:
          enc.format = GIMLI_INT_SIGNED|GIMLI_INT_CHAR;
          t = gimli_type_new_integer(file->types, type_name, &enc);
          break;
        case DW_ATE_boolean:
          enc.format = GIMLI_INT_BOOL;
          t = gimli_type_new_integer(file->types, type_name, &enc);
          break;
        case DW_ATE_float:
          switch (size) {
            case sizeof(double):
              enc.format = GIMLI_FP_DOUBLE;
              break;
            case sizeof(float):
              enc.format = GIMLI_FP_SINGLE;
              break;
            case sizeof(long double):
              enc.format = GIMLI_FP_LONG_DOUBLE;
              break;
          }
          t = gimli_type_new_float(file->types, type_name, &enc);
          break;
        case DW_ATE_complex_float:
          enc.format = GIMLI_FP_COMPLEX;
          t = gimli_type_new_float(file->types, type_name, &enc);
          break;
        case DW_ATE_imaginary_float:
          enc.format = GIMLI_FP_IMAGINARY;
          t = gimli_type_new_float(file->types, type_name, &enc);
          break;
        default:
          printf("unhandled DW_AT_encoding for base_type: 0x%" PRIx64 "\n", ate);
      }
      break;

    case DW_TAG_pointer_type:
      type = gimli_dwarf_die_get_attr(die, DW_AT_type);
      if (type) {
        target = load_type(file, type);
      } else {
        target = load_void(file);
      }
      if (target) {
        t = gimli_type_new_pointer(file->types, target);
      }
      break;
    case DW_TAG_const_type:
      type = gimli_dwarf_die_get_attr(die, DW_AT_type);
      if (type) {
        target = load_type(file, type);
        if (target) {
          t = gimli_type_new_const(file->types, target);
        }
      }
      break;
    case DW_TAG_volatile_type:
      type = gimli_dwarf_die_get_attr(die, DW_AT_type);
      if (type) {
        target = load_type(file, type);
        if (target) {
          t = gimli_type_new_volatile(file->types, target);
        }
      }
      break;
    case DW_TAG_restrict_type:
      type = gimli_dwarf_die_get_attr(die, DW_AT_type);
      if (type) {
        target = load_type(file, type);
        if (target) {
          t = gimli_type_new_restrict(file->types, target);
        }
      }
      break;

    case DW_TAG_typedef:
      type = gimli_dwarf_die_get_attr(die, DW_AT_type);
      if (type) {
        target = load_type(file, type);
        if (target) {
          t = gimli_type_new_typedef(file->types, target, type_name);
        }
      }
      break;

    case DW_TAG_structure_type:
      t = gimli_type_new_struct(file->types, type_name);
      gimli_hash_insert_ptr(file->die_to_type, die, t);
      populate_struct_or_union(t, file, die);
      return t;

    case DW_TAG_union_type:
      t = gimli_type_new_union(file->types, type_name);
      gimli_hash_insert_ptr(file->die_to_type, die, t);
      populate_struct_or_union(t, file, die);
      return t;


    case DW_TAG_array_type:
      t = populate_array(file, die);
      break;

    case DW_TAG_enumeration_type:
      memset(&enc, 0, sizeof(enc));
      gimli_dwarf_die_get_uint64_t_attr(die, DW_AT_byte_size, &size);
      enc.bits = size * 8;

      t = gimli_type_new_enum(file->types, type_name, &enc);
      if (!populate_enum(t, file, die)) {
        return NULL;
      }
      break;

    case DW_TAG_subroutine_type:
      t = populate_func(file, type_name, die);
      break;

    default:
      printf("unhandled tag 0x%" PRIx64 " in load_type (%s)\n", die->tag, type_name);
      return NULL;
  }

  if (t) {
    gimli_hash_insert_ptr(file->die_to_type, die, t);
  }

  return t;
}

static gimli_type_t load_type(
    gimli_mapped_object_t file,
    struct gimli_dwarf_attr *type)
{
  struct gimli_dwarf_die *die;

  die = gimli_dwarf_get_die(file, type->code);
  if (!die) {
    return NULL;
  }

  return load_type_die(file, die);
}

static void load_types_in_die(gimli_mapped_object_t file,
    struct gimli_dwarf_die *die)
{
  struct gimli_dwarf_die *kid;

  switch (die->tag) {
    case DW_TAG_base_type:
    case DW_TAG_pointer_type:
    case DW_TAG_const_type:
    case DW_TAG_volatile_type:
    case DW_TAG_restrict_type:
    case DW_TAG_typedef:
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
    case DW_TAG_array_type:
    case DW_TAG_enumeration_type:
    case DW_TAG_subroutine_type:
      load_type_die(file, die);
      break;
  }

  STAILQ_FOREACH(kid, &die->kids, siblings) {
    load_types_in_die(file, kid);
  }
}

/* pull in all the CU's and register all the types we find;
 * this is relatively expensive but we only do it based
 * on user request; a module has to ask for a type by name
 * that we haven't already loaded */
void gimli_dwarf_load_all_types(gimli_mapped_object_t file)
{
  struct gimli_dwarf_cu *cu;
  struct gimli_dwarf_die *die;
  const uint8_t *cuptr;
  uint64_t off;

  if (!init_debug_info(file)) {
    return;
  }

  cuptr = file->debug_info.start;
  while (cuptr < file->debug_info.end) {
    off = cuptr - file->debug_info.start;
    cu = find_cu(file, off);
    if (!cu) {
      cu = load_cu(file, off);
    }
    if (!cu) break;
    cuptr = file->debug_info.start + cu->end;

    /* now walk the DIEs and map the types */
    STAILQ_FOREACH(die, &cu->dies, siblings) {
      load_types_in_die(file, die);
    }
  }
}

/* Locate the DIE for a data address and load its type
 * information */
gimli_type_t gimli_dwarf_load_type_for_data(gimli_proc_t proc,
    gimli_addr_t addr)
{
  struct gimli_dwarf_die *die;
  struct gimli_object_mapping *m;
  gimli_mapped_object_t file;
  struct gimli_dwarf_attr *type;

  die = gimli_dwarf_get_die_for_data(proc, addr);
  if (!die) {
    return NULL;
  }

  m = gimli_mapping_for_addr(proc, addr);
  file = m->objfile;

  type = gimli_dwarf_die_get_attr(die, DW_AT_type);
  if (!type) {
    return NULL;
  }

  return load_type(file, type);
}

static void load_var(
    gimli_stack_frame_t frame,
    struct gimli_dwarf_die *die,
    uint64_t frame_base, uint64_t comp_unit_base,
    struct gimli_object_mapping *m)
{
  uint64_t res = 0;
  int is_stack = 1;
  struct gimli_dwarf_attr *location, *type, *name;
  gimli_var_t var;

  type = gimli_dwarf_die_get_attr(die, DW_AT_type);
  if (!type) {
    return;
  }

  location = gimli_dwarf_die_get_attr(die, DW_AT_location);
  name = gimli_dwarf_die_get_attr(die, DW_AT_name);

  if (location) {
    switch (location->form) {
      case DW_FORM_block:
        if (!dw_eval_expr(&frame->cur, (uint8_t*)location->ptr, location->code,
              frame_base, &res, NULL, &is_stack)) {
          res = 0;
        }
        break;
      case DW_FORM_data8:
        if (!dw_calc_location(&frame->cur, comp_unit_base, m,
              location->code, &res, NULL, &is_stack)) {
          res = 0;
        }
        break;
      default:
        printf("Unhandled location form 0x%" PRIx64 "\n", location->form);
    }
  } else if (name) {
    /* no location defined, so assume the compiler optimized it away */
    res = 0; /* we treat NULL address as "optimized out" */
  } else {
    return;
  }

  var = calloc(1, sizeof(*var));
  var->varname = name ? name->ptr : NULL;
  var->addr = res;
  var->proc = frame->cur.proc;
  var->type = load_type(m->objfile, type);
  var->is_param = (die->tag == DW_TAG_formal_parameter) ?
    GIMLI_WANT_PARAMS : GIMLI_WANT_LOCALS;

  STAILQ_INSERT_TAIL(&frame->vars, var, vars);
}

/* load DWARF DIEs to collect information about variables */
int gimli_dwarf_load_frame_var_info(gimli_stack_frame_t frame)
{
  struct gimli_dwarf_die *die, *kid;
  uint64_t frame_base = 0;
  uint64_t comp_unit_base = 0;
  struct gimli_dwarf_attr *frame_base_attr;
  struct gimli_object_mapping *m;
  gimli_proc_t proc = frame->cur.proc;
  gimli_addr_t pc = (gimli_addr_t)frame->cur.st.pc;

  if (frame->loaded_vars) return 1;
  frame->loaded_vars = 1;

  die = gimli_dwarf_get_die_for_pc(proc, pc);
  if (!die) {
//    printf("no DIE for pc=" PTRFMT "\n", pc);
    return 0;
  }
  m = gimli_mapping_for_addr(proc, pc);

  if (die->parent->tag == DW_TAG_compile_unit) {
    gimli_dwarf_die_get_uint64_t_attr(die->parent,
      DW_AT_low_pc, &comp_unit_base);
  }

  frame_base_attr = gimli_dwarf_die_get_attr(die, DW_AT_frame_base);
  if (frame_base_attr) {
    int is_stack = 0;

    switch (frame_base_attr->form) {
      case DW_FORM_block:
        dw_eval_expr(&frame->cur, (uint8_t*)frame_base_attr->ptr, frame_base_attr->code,
            0, &frame_base, NULL, &is_stack);
        break;
      case DW_FORM_data8:
        dw_calc_location(&frame->cur, comp_unit_base, m,
            frame_base_attr->code, &frame_base, NULL, &is_stack);
        break;
      default:
        printf("Unhandled frame base form 0x%" PRIx64 "\n",
            frame_base_attr->form);
        return 0;
    }
  }

  STAILQ_FOREACH(kid, &die->kids, siblings) {
    if (kid->tag == DW_TAG_formal_parameter || kid->tag == DW_TAG_variable) {
      load_var(frame, kid, frame_base, comp_unit_base, m);
    }
  }

  return 1;
}

/* vim:ts=2:sw=2:et:
 */
