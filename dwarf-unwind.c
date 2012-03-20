/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"
#include "gimli_dwarf.h"

struct dw_rule_stack {
  struct gimli_dwarf_reg_column cols[GIMLI_MAX_DWARF_REGS];
  struct dw_rule_stack *next;
};

struct dw_cie {
  char key[32];
  uint64_t ptr;
  const uint8_t *aug, *init_insns, *insn_end;
  uint64_t code_align, ret_addr;
  int64_t data_align;
  uint64_t personality_routine;
  uint8_t code_enc;
  uint8_t lsda_enc;
  unsigned is_signal_frame:1;
  /* rules as set by the initial instructions */
  struct gimli_dwarf_reg_column init_cols[GIMLI_MAX_DWARF_REGS];
  struct dw_rule_stack *rule_stack;
};

struct dw_fde {
  uint64_t initial_loc;
  uint64_t addr_range;
  const uint8_t *insns, *insn_end;
  uint64_t lsda_ptr;
  struct dw_cie *cie;
};

/* Per Dwarf 3, section 6.4.3 Call Frame Instruction Usage:

To determine the virtual unwind rule set for a given location (L1), one
searches through the FDE headers looking at the initial_location and
address_range values to see if L1 is contained in the FDE. If so, then:

  1. Initialize a register set by reading the initial_instructions field of
     the associated CIE.

  2. Read and process the FDE’s instruction sequence until a
     DW_CFA_advance_loc, DW_CFA_set_loc, or the end of the instruction stream
     is encountered.

  3. If a DW_CFA_advance_loc or DW_CFA_set_loc instruction was encountered,
     then compute a new location value (L2). If L1 >= L2 then process the
     instruction and go back to step 2.

  4. The end of the instruction stream can be thought of as a DW_CFA_set_loc
     (initial_location + address_range) instruction.  Unless the FDE is
     ill-formed, L1 should be less than L2 at this point.

The rules in the register set now apply to location L1.  For an example, see
Appendix D.6.
*/

static void set_rule(struct gimli_unwind_cursor *cur,
  int colno, int rule, uint64_t val)
{
  if (debug) {
    fprintf(stderr,
        "   set_rule: colno=%d rule=%d %lld\n", colno, rule,
        (long long)val);
  }
  cur->dw.cols[colno].rule = rule;
  cur->dw.cols[colno].value = val;
}

static void set_expr(struct gimli_unwind_cursor *cur,
  int colno, int rule, const uint8_t *ops, uint64_t val)
{
  if (debug) {
    fprintf(stderr,
        "   set_rule: colno=%d rule=%d %lld\n", colno, rule,
        (long long)val);
  }
  cur->dw.cols[colno].rule = rule;
  cur->dw.cols[colno].value = val;
  cur->dw.cols[colno].ops = ops;
}

/* Here, pc is initially set to the program counter that corresponds
 * to the start of the dwarf instructions (the initial location).
 * As we process through the CFA rule table, we may advance the pc
 * forward (representing looking further down into the code for that
 * function).  There's no need to continue processing rules once we
 * pass the pc address of interest (cur->st.pc), so we break out of
 * the loop at that point */
static int process_dwarf_insns(struct gimli_unwind_cursor *cur,
    struct dw_cie *cie, struct dw_fde *fde, const uint8_t *insns,
    const uint8_t *insn_end, uint64_t pc)
{
  uint64_t regnum, arg;

  if (debug) {
    fprintf(stderr,
      "\nprocess insns: %p to %p, pc = %p\n", insns, insn_end, cur->st.pc);
  }

  while (pc <= (intptr_t)cur->st.pc && insns < insn_end) {
    uint8_t op = (uint8_t)*insns;
    uint8_t oprand;

    insns++;
    /* extract encoded operand */
    if (op & 0xc0) {
      oprand = op & 0x3f;
      op &= ~0x3f;
    } else {
      oprand = 0;
    }

    switch (op) {
      /* opcodes that affect our effective pc address */
      case DW_CFA_set_loc:
        if (!dw_read_encptr(cie->code_enc, &insns, insn_end, pc, &pc)) {
          return 0;
        }
        break;

      case DW_CFA_advance_loc:
        pc += oprand * cie->code_align;
        if (debug) {
          fprintf(stderr, "CFA_advance_loc: pc += (%d * %d) => %p\n", oprand, cie->code_align, pc);
        }
        break;
      case DW_CFA_advance_loc1:
      {
        uint8_t delta;
        memcpy(&delta, insns, sizeof(delta));
        insns += sizeof(delta);
        pc += delta * cie->code_align;
        if (debug) {
          fprintf(stderr, "CFA_advance_loc1: pc now %p\n", pc);
        }
        break;
      }
      case DW_CFA_advance_loc2:
      {
        uint16_t delta;
        memcpy(&delta, insns, sizeof(delta));
        insns += sizeof(delta);
        pc += delta * cie->code_align;
        if (debug) {
          fprintf(stderr, "CFA_advance_loc2: pc now %p\n", pc);
        }
        break;
      }
      case DW_CFA_advance_loc4:
      {
        uint32_t delta;
        memcpy(&delta, insns, sizeof(delta));
        insns += sizeof(delta);
        pc += delta * cie->code_align;
        if (debug) {
          fprintf(stderr, "CFA_advance_loc4: pc now %p\n", pc);
        }
        break;
      }
      /* opcodes that define rules for determining the CFA */
      case DW_CFA_def_cfa:
        regnum = dw_read_uleb128(&insns, insn_end);
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_def_cfa: regnum=%lld arg=%lld\n", regnum, arg);
        }
        set_rule(cur, GIMLI_DWARF_CFA_REG, DW_RULE_REG, regnum);
        set_rule(cur, GIMLI_DWARF_CFA_OFF, 0, arg);
        break;
      case DW_CFA_def_cfa_sf:
      {
        int64_t sarg;
        regnum = dw_read_uleb128(&insns, insn_end);
        arg = dw_read_leb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_def_cfa_sf: regnum=%lld arg=%lld\n",
            regnum, sarg);
        }
        set_rule(cur, GIMLI_DWARF_CFA_REG, DW_RULE_REG, regnum);
        set_rule(cur, GIMLI_DWARF_CFA_OFF, 0, sarg * cie->data_align);
        break;
      }
      case DW_CFA_def_cfa_offset:
        /* non-factored, no need for data_align */
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "DW_CFA_def_cfa_offset: arg=%llx\n", arg);
        }
        set_rule(cur, GIMLI_DWARF_CFA_OFF, 0, arg);
        break;
      case DW_CFA_def_cfa_register:
        regnum = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_def_cfa_register: regnum=%lld\n", regnum);
        }
        set_rule(cur, GIMLI_DWARF_CFA_REG, DW_RULE_REG, regnum);
        break;

      /* rules for calculating register values */
      case DW_CFA_offset:
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "DW_CFA_offset: arg=%llx align=%lld\n", arg, cie->data_align);
        }
        set_rule(cur, oprand, DW_RULE_OFFSET, arg * cie->data_align);
        break;
      case DW_CFA_offset_extended:
        regnum = dw_read_uleb128(&insns, insn_end);
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_offset_extended: regnum=%lld off=%lld\n",
            regnum, arg);
        }
        set_rule(cur, regnum, DW_RULE_OFFSET, arg * cie->data_align);
        break;
      case DW_CFA_offset_extended_sf:
      {
        int64_t sarg;
        regnum = dw_read_uleb128(&insns, insn_end);
        sarg = dw_read_leb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_offset_extended_sr: regnum=%lld off=%lld\n",
            regnum, arg);
        }
        set_rule(cur, regnum, DW_RULE_OFFSET, sarg * cie->data_align);
        break;
      }
      case DW_CFA_restore:
      {
        if (debug) {
          fprintf(stderr, "CFA_restore: regnum=%d\n", oprand);
        }
        memcpy(&cur->dw.cols[oprand], &cie->init_cols[oprand],
          sizeof(cur->dw.cols[oprand]));
        break;
      }
      case DW_CFA_restore_extended:
        regnum = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_restore_extended: regnum=%lld\n", regnum);
        }
        memcpy(&cur->dw.cols[regnum], &cie->init_cols[regnum],
          sizeof(cur->dw.cols[regnum]));
        break;
      case DW_CFA_undefined:
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "DW_CFA_undefined: arg=%llx\n", arg);
        }
        set_rule(cur, arg, DW_RULE_UNDEF, 0);
        break;
      case DW_CFA_same_value:
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "DW_CFA_same_value: arg=%llx\n", arg);
        }
        set_rule(cur, arg, DW_RULE_SAME, 0);
        break;
      case DW_CFA_register:
        regnum = dw_read_uleb128(&insns, insn_end);
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "DW_CFA_register: arg=%llx\n", arg);
        }
        set_rule(cur, regnum, DW_RULE_REG, arg);
        break;
      case DW_CFA_remember_state:
      {
        struct dw_rule_stack *s = calloc(1, sizeof(*s));
        memcpy(s->cols, cur->dw.cols, sizeof(s->cols));
        s->next = cie->rule_stack;
        cie->rule_stack = s;
        break;
      }
      case DW_CFA_restore_state:
      {
        struct dw_rule_stack *s = cie->rule_stack;
        cie->rule_stack = s->next;
        memcpy(cur->dw.cols, s->cols, sizeof(cur->dw.cols));
        free(s);
        break;
      }
      case DW_CFA_nop:
        if (debug) {
          fprintf(stderr, "nop\n");
        }
        break;
      /* GNU extensions */
      case DW_CFA_GNU_args_size:
        /* http://refspecs.freestandards.org/LSB_3.1.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
         * The DW_CFA_GNU_args_size instruction takes an unsigned LEB128
         * operand representing an argument size. This instruction specifies
         * the total of the size of the arguments which have been pushed onto
         * the stack.
         * We ignore this */
        dw_read_uleb128(&insns, insn_end);
        break;
      case DW_CFA_GNU_negative_offset_extended:
        regnum = dw_read_uleb128(&insns, insn_end);
        arg = dw_read_uleb128(&insns, insn_end);
        if (debug) {
          fprintf(stderr, "CFA_offset_extended_sr: regnum=%lld off=%lld\n",
            regnum, arg);
        }
        set_rule(cur, regnum, DW_RULE_OFFSET, -arg * cie->data_align);
        break;

      case DW_CFA_GNU_window_save:
        /* sparc special */
        for (regnum = 16; regnum < 32; regnum++) {
          set_rule(cur, regnum, DW_RULE_OFFSET,
            (regnum - 16) * sizeof(void*));
        }
        break;

      case DW_CFA_expression:
      {
        const uint8_t *exprop;
        void *res;

        regnum = dw_read_uleb128(&insns, insn_end);
        /* size of expression data */
        arg = dw_read_uleb128(&insns, insn_end);
        exprop = insns;
        insns += arg;

        if (debug) {
          fprintf(stderr, "DW_CFA_expression regnum=%d\n", regnum);
        }
        set_expr(cur, regnum, DW_RULE_EXPR, exprop, arg);
        break;
      }

      case DW_CFA_val_expression:
      {
        const uint8_t *exprop;
        void *res;

        regnum = dw_read_uleb128(&insns, insn_end);
        /* size of expression data */
        arg = dw_read_uleb128(&insns, insn_end);
        exprop = insns;
        insns += arg;

        if (debug) {
          fprintf(stderr, "DW_CFA_val_expression regnum=%d\n", regnum);
        }
        set_expr(cur, regnum, DW_RULE_VAL_EXPR, exprop, arg);
        break;
      }

      case DW_CFA_def_cfa_expression:
      {
        const uint8_t *exprop;
        void *res;

        /* size of expression data */
        arg = dw_read_uleb128(&insns, insn_end);
        exprop = insns;
        insns += arg;

        if (debug) {
          fprintf(stderr, "DW_CFA_def_cfa_expression\n");
        }
        set_expr(cur, GIMLI_DWARF_CFA_REG, DW_RULE_EXPR, exprop, arg);
        set_rule(cur, GIMLI_DWARF_CFA_OFF, 0, 0);
        break;
      }


      default:
        fprintf(stderr, "DWARF: unwind: unhandled insn %02x (%02x)\n",
          op, oprand);
        return 0;
    }
  }

  return 1;
}

static int eval_expr(int exprcol,
  uint64_t initval, uint64_t *retval,
  struct gimli_unwind_cursor *cur)
{
  const uint8_t *ops, *end;
  int is_stack = 1;

  ops = cur->dw.cols[exprcol].ops;
  end = ops + cur->dw.cols[exprcol].value;

  return dw_eval_expr(cur, ops, cur->dw.cols[exprcol].value,
    0, // frame_base,
    retval, &initval, &is_stack);
}

static int apply_regs(struct gimli_unwind_cursor *cur,
  struct dw_cie *cie)
{
  int i;
  void *pc = cur->st.pc;
  void *fp = cur->st.fp;
  void *regaddr;
  void *val;

  if (debug) {
    fprintf(stderr, "\napply_regs:\npc=%p fp=%p sp=%p\n",
      cur->st.pc, cur->st.fp, cur->st.sp);
  }

  /* compute the new CFA first, as expressions may depend on the
   * newly computed value */
  if (cur->dw.cols[GIMLI_DWARF_CFA_REG].rule == DW_RULE_REG) {
    i = cur->dw.cols[GIMLI_DWARF_CFA_REG].value;
    if (debug) {
      fprintf(stderr, "CFA is stored relative to register %d\n", i);
    }
    regaddr = gimli_reg_addr(cur, i);
    if (!regaddr) {
      fprintf(stderr, "DWARF: no address for reg %d\n", i);
      return 0;
    }
    regaddr = *(void**)regaddr;
    if (debug) {
      fprintf(stderr, "target addr: %p + %lld\n",
        regaddr, cur->dw.cols[GIMLI_DWARF_CFA_OFF].value);
    }
    regaddr += cur->dw.cols[GIMLI_DWARF_CFA_OFF].value;
    fp = regaddr;
    if (debug) {
      fprintf(stderr, "fp=%p\n", fp);
    }
  } else if (cur->dw.cols[GIMLI_DWARF_CFA_REG].rule == DW_RULE_EXPR) {
    uint64_t ret;
    if (!eval_expr(GIMLI_DWARF_CFA_REG, 0, &ret, cur)) {
      fprintf(stderr, "failed to evaluate DWARF expression\n");
      return 0;
    }
    fp = (void*)(intptr_t)ret;
  } else {
    fprintf(stderr, "DWARF: line %d: Unhandled rule %d for CFA\n",
      __LINE__, cur->dw.cols[GIMLI_DWARF_CFA_REG].rule);
    return 0;
  }
  if (debug) {
    fprintf(stderr, "New CFA is %p\n", fp);
  }

  for (i = 0; i < GIMLI_DWARF_CFA_REG; i++) {
    switch (cur->dw.cols[i].rule) {
      case DW_RULE_UNDEF:
        break;
      case DW_RULE_OFFSET:
        regaddr = fp + cur->dw.cols[i].value;
        if (debug) {
          fprintf(stderr, "col %d: CFA relative, reading %p + %lld = %p\n", i,
            fp, cur->dw.cols[i].value, regaddr);
        }
        if (gimli_read_mem(regaddr, &val, sizeof(val)) != sizeof(val)) {
          fprintf(stderr, "col %d: couldn't read value\n", i);
          return 0;
        }
        regaddr = gimli_reg_addr(cur, i);
        if (!regaddr) {
          printf("couldn't find address for column %d\n", i);
          return 0;
        }
        *(void**)regaddr = val;
        if (debug) {
          fprintf(stderr, "Setting col %d to %p\n", i, val);
        }
        break;
      case DW_RULE_REG:
        regaddr = gimli_reg_addr(cur, cur->dw.cols[i].value);
        if (!regaddr) {
          printf("Couldn't find address for register %d\n",
            cur->dw.cols[i].value);
          return 0;
        }
        val = *(void**)regaddr;
        regaddr = gimli_reg_addr(cur, i);
        if (!regaddr) {
          printf("couldn't find address for column %d\n", i);
          return 0;
        }
        *(void**)regaddr = val;
        if (debug) {
          fprintf(stderr, "Setting col %d to %p\n", i, val);
        }
        break;
      case DW_RULE_EXPR:
        {
          uint64_t ret;
          if (!eval_expr(i, (uint64_t)(intptr_t)fp, &ret, cur)) {
            fprintf(stderr, "failed to evaluate DWARF expression\n");
            return 0;
          }
          regaddr = gimli_reg_addr(cur, i);
          if (!regaddr) {
            printf("couldn't find address for column %d\n", i);
            return 0;
          }
          val = *(void**)(intptr_t)ret;
          *(void**)regaddr = val;
          if (debug) {
            fprintf(stderr, "Setting col %d to %p\n", i, val);
          }
          break;
        }

      case DW_RULE_VAL_EXPR:
        {
          uint64_t ret;
          if (!eval_expr(i, (uint64_t)(intptr_t)fp, &ret, cur)) {
            fprintf(stderr, "failed to evaluate DWARF expression\n");
            return 0;
          }
          regaddr = gimli_reg_addr(cur, i);
          if (!regaddr) {
            printf("couldn't find address for column %d\n", i);
            return 0;
          }
          *(void**)regaddr = (void*)(intptr_t)ret;
          if (debug) {
            fprintf(stderr, "Setting col %d to %p\n", i, ret);
          }
          break;
        }


      default:
        fprintf(stderr, "DWARF: line %d: Unhandled rule %d\n",
          __LINE__, cur->dw.cols[i].rule);
        return 0;
    }
  }
  if (debug) {
    fprintf(stderr, "retaddr is in col %d\n", cie->ret_addr);
  }

  regaddr = gimli_reg_addr(cur, cie->ret_addr);
  if (!regaddr) {
    fprintf(stderr, "DWARF: line %d: could not find address for return addr column %d\n",
      __LINE__, cie->ret_addr);
    return 0;
  }
  pc = *(void**)regaddr;
  if (debug) {
    fprintf(stderr, "new pc is %p\n", pc);
  }
  cur->st.pc = pc;
  cur->st.fp = fp;

  /* For architectures with constant-length instructions where the return
   * address immediately follows the call instruction, a simple solution is to
   * subtract the length of an instruction from the return address to obtain
   * the calling instruction. For architectures with variable-length
   * instructions (e.g.  x86), this is not possible. However, subtracting 1
   * from the return address, although not guaranteed to provide the exact
   * calling address, generally will produce an address within the same context
   * as the calling address, and that usually is sufficient.
   */
  if (cur->st.pc && !cie->is_signal_frame && !gimli_is_signal_frame(cur)) {
    cur->st.pc--;
  }
  return 1;
}

/* sorts fde's in ascending order */
static int sort_compare_fde(const void *A, const void *B)
{
  struct dw_fde *a = (struct dw_fde*)A;
  struct dw_fde *b = (struct dw_fde*)B;

  return a->initial_loc - b->initial_loc;
}

/* read the FDE data from an object file */
static int load_fde(struct gimli_object_mapping *m)
{
  struct gimli_section_data *s = NULL;
  const uint8_t *eh_start;
  const uint8_t *eh_frame;
  const uint8_t *end, *next;
  int is_eh_frame = 0;
  struct {
    char *name;
    int is_eh_frame;
  } sections_to_try[] = {
    { ".eh_frame", 1 },
    { ".debug_frame", 0 },
    { NULL, 0 }
  };
  int section_number;
  gimli_hash_t cie_tbl;

  if (!m->objfile->elf) {
    return 0;
  }

  cie_tbl = gimli_hash_new(NULL);

  for (section_number = 0; sections_to_try[section_number].name;
      section_number++) {

    is_eh_frame = sections_to_try[section_number].is_eh_frame;
    s = gimli_get_section_by_name(m->objfile->elf,
        sections_to_try[section_number].name);

    if (s) {
      /* on solaris, GCC can emit an eh_frame section, but it can
       * be effectively empty; we want to fall back on debug_frame */
      if (s->size <= sizeof(void*)) {
        s = NULL;
      }
    }

    if (!s && m->objfile->aux_elf) {
      s = gimli_get_section_by_name(m->objfile->aux_elf,
          sections_to_try[section_number].name);
    }

    if (!s) {
      continue;
    }

    eh_frame = s->data;
    if (!eh_frame) {
      continue;
    }
    if (debug) {
      fprintf(stderr, "Using %s for unwind data for %s, %x bytes offset %x\n",
          s->name, s->container->objname, s->size, s->offset);
    }

    eh_start = eh_frame;
    end = eh_frame + s->size;

    while (eh_frame && eh_frame < end) {
      uint32_t len;
      uint64_t cie_id;
      const uint8_t *aug;
      int is_64 = 0;
      uint64_t initlen;
      const uint8_t *next;
      const uint8_t *recstart = eh_frame;

      if (debug) fprintf(stderr, "\noffset: %p\n", eh_frame - eh_start);
      memcpy(&len, eh_frame, sizeof(len));
      if (len == 0 && is_eh_frame) {
        break;
      }
      eh_frame += sizeof(len);
      if (len == 0xffffffff) {
        is_64 = 1;
        memcpy(&initlen, eh_frame, sizeof(initlen));
        eh_frame += sizeof(initlen);
      } else {
        is_64 = 0;
        initlen = len;
      }
      next = eh_frame + initlen;
      if (is_64) {
        memcpy(&cie_id, eh_frame, sizeof(cie_id));
        eh_frame += sizeof(cie_id);
      } else {
        memcpy(&len, eh_frame, sizeof(len));
        eh_frame += sizeof(len);
        cie_id = len;
        if (cie_id == 0xffffffff) {
          cie_id = 0xffffffffffffffffULL;
        }
      }
      if (debug) {
        fprintf(stderr,
            "initlen: %lx (next = %lx) is64=%d cie_id=0x%llx (%d)\n",
            (long)initlen, (long)(next - eh_start), is_64,
            (long long)cie_id, (long long)cie_id);
      }
      if ((is_eh_frame && cie_id == 0) ||
          (!is_eh_frame && cie_id == 0xffffffffffffffffULL)) {
        uint8_t ver;
        struct dw_cie *cie;

        /* this is a cie */
        cie = calloc(1, sizeof(*cie));
        cie->ptr = (uint64_t)(recstart - eh_start);

        if (sizeof(void*) == 8) {
          cie->code_enc = DW_EH_PE_udata8;
        } else if (sizeof(void*) == 4) {
          cie->code_enc = DW_EH_PE_udata4;
        }
        cie->code_enc = DW_EH_PE_absptr;
        cie->lsda_enc = DW_EH_PE_omit;

        memcpy(&ver, eh_frame, sizeof(ver));
        eh_frame += sizeof(ver);
        cie->aug = eh_frame;
        eh_frame += strlen((char*)cie->aug) + 1;
        if (cie->aug[0] == 'e' && cie->aug[1] == 'h') {
          /* ignore GNU 'eh' augmentation data that immediately
           * follows the augmentation string */
          eh_frame += sizeof(void*);
        }
        cie->code_align = dw_read_uleb128(&eh_frame, end);
        cie->data_align = dw_read_leb128(&eh_frame, end);
        if (ver == 3) {
          cie->ret_addr = dw_read_uleb128(&eh_frame, end);
        } else {
          uint8_t r;
          memcpy(&r, eh_frame, sizeof(r));
          eh_frame += sizeof(r);
          cie->ret_addr = r;
        }
        cie->init_insns = eh_frame;
        cie->insn_end = next;

        aug = cie->aug;

        /* read in augmentation information */
        while (aug && *aug) {
          if (*aug == 'e' && *aug == 'h') {
            /* skip the 'eh' augmentation; already processed above */
            aug += 2;
          } else if (*aug == 'z') {
            /* augmentation section size */
            uint64_t o = dw_read_uleb128(&eh_frame, end);
            cie->init_insns = eh_frame + o;
          } else if (*aug == 'P') {
            uint8_t enc;

            memcpy(&enc, eh_frame, sizeof(enc));
            eh_frame += sizeof(enc);

            /* the personality routines tend to be indirectly encoded.
             * Since we don't need them in our use case, let's turn off
             * the override bit; we still need to consume the data, but
             * we don't want to attempt the indirection */
            enc &= ~ DW_EH_PE_indirect;

            if (!dw_read_encptr(enc, &eh_frame, end,
                  s->addr + eh_frame - eh_start,
                  &cie->personality_routine)) {
              fprintf(stderr, "Error reading personality routine, "
                  "enc=%02x offset: %lx\n", enc, eh_frame - eh_start);
              return 0;
            }
          } else if (*aug == 'R') {
            memcpy(&cie->code_enc, eh_frame, sizeof(cie->code_enc));
            eh_frame += sizeof(cie->code_enc);
          } else if (*aug == 'L') {
            /* A 'L' may be present at any position after the first character
             * of the string. This character may only be present if 'z' is the
             * first character of the string. If present, it indicates the
             * presence of one argument in the Augmentation Data of the CIE,
             * and a corresponding argument in the Augmentation Data of the
             * FDE. The argument in the Augmentation Data of the CIE is 1-byte
             * and represents the pointer encoding used for the argument in the
             * Augmentation Data of the FDE, which is the address of a
             * language-specific data area (LSDA). The size of the LSDA pointer
             * is specified by the pointer encoding used.
             */
            memcpy(&cie->lsda_enc, eh_frame, sizeof(cie->lsda_enc));
            eh_frame += sizeof(cie->lsda_enc);
          } else if (*aug == 'S') {
            /* 'S' indicates a signal frame; we should not do the PC decrement
             * operation on these frames (see big comment about architecture
             * in apply_regs */
            cie->is_signal_frame = 1;
          }
          aug++;
        }

        if (debug) {
          fprintf(stderr, "\n\nReading CIE, len is %ju, ver=%d aug=%s\n"
              "code_align=%jd data_align=%jd ret_addr=%ju init_insns=%p-%p\n",
              initlen, ver, cie->aug,
              cie->code_align, cie->data_align, cie->ret_addr,
              cie->init_insns, cie->insn_end);

        }

        snprintf(cie->key, sizeof(cie->key), "%jd", cie->ptr);
        gimli_hash_insert(cie_tbl, cie->key, cie);

      } else {
        /* this is an fde */
        struct dw_fde *fde;
        char cie_key[32];

        /* add to the fdes table */
        m->fdes = realloc(m->fdes, (m->num_fdes + 1) * sizeof(*fde));
        fde = &m->fdes[m->num_fdes++];
        memset(fde, 0, sizeof(*fde));

        /* locate our CIE; it may not be the last CIE preceeding this one */
        if (is_eh_frame) {
          cie_id = (uint64_t)(eh_frame - eh_start) - cie_id;
          cie_id -= is_64 ? 8 : 4;
        }
        snprintf(cie_key, sizeof(cie_key), "%jd", cie_id);
        if (!gimli_hash_find(cie_tbl, cie_key, (void**)&fde->cie)) {
          fprintf(stderr, "could not resolve CIE %s!\n", cie_key);
          return 0;
        }

        if (!dw_read_encptr(fde->cie->code_enc, &eh_frame, end,
              s->addr + eh_frame - eh_start, &fde->initial_loc)) {
          fprintf(stderr, "Error while reading initial loc\n");
          return 0;
        }

        if (!dw_read_encptr(fde->cie->code_enc & 0x0f, &eh_frame, end,
              s->addr + eh_frame - eh_start,
              &fde->addr_range)) {
          fprintf(stderr, "Error while reading addr_range\n");
          return 0;
        }
        if (debug) {
          fprintf(stderr, "FDE: addr_range raw=%p\ninit_loc=%p addr=%p\n",
              (void*)(intptr_t)fde->addr_range,
              (void*)(intptr_t)fde->initial_loc,
              s->addr);
        }
        fde->initial_loc += m->objfile->base_addr;
        if (debug) {
          char name[1024];
          const char *sym = gimli_pc_sym_name(
              (void*)(intptr_t)fde->initial_loc, name, sizeof(name));
          fprintf(stderr, "FDE: init=%p-%p %s aug=%s\n",
              (char*)(intptr_t)fde->initial_loc,
              (char*)(intptr_t)(fde->initial_loc + fde->addr_range),
              sym,
              fde->cie->aug);
        }

        fde->insns = eh_frame;
        fde->insn_end = next;

      }
      eh_frame = next;
    }
  }

  /* ensure that the fde data is sorted in ascending order so that
   * bsearch can be used correctly.  This should normally be the case,
   * but I don't trust the data to be that way in all situations */
  qsort(m->fdes, m->num_fdes, sizeof(struct dw_fde), sort_compare_fde);

  gimli_hash_destroy(cie_tbl);
  return 1;
}

static int search_compare_fde(const void *PC, const void *FDE)
{
  intptr_t pc = (intptr_t)*(void**)PC;
  struct dw_fde *fde = (struct dw_fde*)FDE;

  if (pc < fde->initial_loc) {
    return -1;
  }
  if (pc < fde->initial_loc + fde->addr_range) {
    return 0;
  }

  return 1;
}

/* find the FDE for the specified pc address */
static struct dw_fde *find_fde(void *pc)
{
  struct gimli_object_mapping *m;
  struct dw_fde *fde;

  m = gimli_mapping_for_addr(pc);
  if (!m) {
    return NULL;
  }

  if (!m->objfile->elf) {
    return NULL;
  }

  if (!m->fdes && !load_fde(m)) {
    return NULL;
  }

  fde = bsearch(&pc, m->fdes, m->num_fdes, sizeof(*fde), search_compare_fde);
  if (fde) {
    return fde;
  }

  return NULL;
}

int gimli_dwarf_unwind_next(struct gimli_unwind_cursor *cur)
{
  struct dw_fde *fde;

  /* can't unwind via dwarf if don't have a valid register set */
  if (cur->dwarffail) {
    return 0;
  }

  if (debug) {
    fprintf(stderr, "DWARF: unwind_next pc=%p fp=%p\n", cur->st.pc, cur->st.fp);
  }

  fde = find_fde(cur->st.pc);
  if (!fde) {
    cur->dwarffail = 1;
    return 0;
  }

  if (debug) {
    fprintf(stderr, "This is the FDE for the current PC\n");
    fprintf(stderr, "FDE: init=" PTRFMT "-" PTRFMT " pc=" PTRFMT "\n",
        (void*)(intptr_t)fde->initial_loc,
        (void*)(intptr_t)fde->addr_range,
        (void*)cur->st.pc);
  }

  /* run initial instructions */
  memset(&cur->dw, 0, sizeof(cur->dw));
  memset(&fde->cie->init_cols, 0, sizeof(fde->cie->init_cols));
  fde->cie->rule_stack = NULL;

  if (!process_dwarf_insns(cur, fde->cie, fde,
        fde->cie->init_insns, fde->cie->insn_end, fde->initial_loc)) {
    if (debug) {
      fprintf(stderr, "DWARF: unwind: failed to run init instructions\n");
    }
    return 0;
  }
  /* copy the current rules into the init rules; this
   * is to support the "restore" opcodes */
  memcpy(fde->cie->init_cols, cur->dw.cols, sizeof(fde->cie->init_cols));

  /* walk up the stack using the fde rules */
  if (!process_dwarf_insns(cur, fde->cie, fde, fde->insns, fde->insn_end,
        fde->initial_loc)) {
    if (debug) {
      fprintf(stderr,
          "DWARF: unwind: failed to run unwind instructions\n");
    }
    return 0;
  }
  /* map the regs back into the cursor */
  if (!apply_regs(cur, fde->cie)) {
    if (debug) {
      fprintf(stderr,
          "DWARF: unwind: failed to apply unwind rules\n");
    }
    return 0;
  }
  cur->dwarffail = 0;

  return 1;
}

/* vim:ts=2:sw=2:et:
 */

