/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://labs.omniti.com/gimli/trunk/LICENSE
 */
#include "impl.h"
#include "gimli_dwarf.h"

struct dw_rule_stack {
  struct gimli_dwarf_reg_column cols[GIMLI_MAX_DWARF_REGS];
  struct dw_rule_stack *next;
};

struct dw_cie {
  const char *aug, *init_insns, *insn_end;
  uint64_t code_align, ret_addr;
  int64_t data_align;
  uint64_t personality_routine;
  uint8_t code_enc;
  uint8_t lsda_enc;
  /* rules as set by the initial instructions */
  struct gimli_dwarf_reg_column init_cols[GIMLI_MAX_DWARF_REGS];
  struct dw_rule_stack *rule_stack;
};

struct dw_fde {
  uint64_t initial_loc;
  uint64_t addr_range;
  const char *insns, *insn_end;
  uint64_t lsda_ptr;
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

/* Here, pc is initially set to the program counter that corresponds
 * to the start of the dwarf instructions (the initial location).
 * As we process through the CFA rule table, we may advance the pc
 * forward (representing looking further down into the code for that
 * function).  There's no need to continue processing rules once we
 * pass the pc address of interest (cur->st.pc), so we break out of
 * the loop at that point */
static int process_dwarf_insns(struct gimli_unwind_cursor *cur,
    struct dw_cie *cie, struct dw_fde *fde, const char *insns,
    const char *insn_end, uint64_t pc)
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
          fprintf(stderr, "CFA_advance_loc: pc now %p\n", pc);
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

      default:
        fprintf(stderr, "DWARF: unwind: unhandled insn %02x (%02x)\n",
          op, oprand);
        return 0;
    }
  }

  return 1;
}

static int apply_regs(struct gimli_unwind_cursor *cur,
  struct dw_cie *cie)
{
  int i;
  void *pc = cur->st.pc;
  void *fp = cur->st.fp;
  void *regaddr;
  void *val;
//  uint64_t new_values[GIMLI_MAX_DWARF_REGS];

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
  } else {
    fprintf(stderr, "DWARF: line %d: Unhandled rule %d for CFA\n",
      __LINE__, cur->dw.cols[GIMLI_DWARF_CFA_REG].rule);
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

      default:
        fprintf(stderr, "DWARF: line %d: Unhandled rule %d\n",
          __LINE__, cur->dw.cols[i].rule);
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
  if (cur->st.pc && !gimli_is_signal_frame(cur)) {
    cur->st.pc--;
  }
  return 1;
}

int gimli_dwarf_unwind_next(struct gimli_unwind_cursor *cur)
{
  struct gimli_object_mapping *m;
  struct gimli_section_data *s = NULL;
  const char *eh_start;
  const char *eh_frame;
  const char *end, *next;
  int is_eh_frame = 0;
  int is_64 = 0;
  uint64_t initlen;
  struct {
    char *name;
    int is_eh_frame;
  } sections_to_try[] = {
    { ".eh_frame", 1 },
    { ".debug_frame", 0 },
    { NULL, 0 }
  };
  int section_number;

  m = gimli_mapping_for_addr(cur->st.pc);
  if (!m) {
    return 0;
  }
  if (!m->objfile->elf) {
    return 0;
  }

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
      printf("Using %s for unwind data for %s, %x bytes offset %x\n",
          s->name, s->container->objname, s->size, s->offset);
    }

    eh_start = eh_frame;
    end = eh_frame + s->size;

    while (eh_frame < end) {
      struct dw_cie cie;
      struct dw_fde fde;
      uint32_t len;
      uint64_t cie_id;
      const char *aug;

      //printf("offset: %p\n", eh_frame - eh_start);
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

      if ((is_eh_frame && cie_id == 0) ||
          (!is_eh_frame && cie_id == 0xffffffffffffffffULL)) {
        uint8_t ver;

        /* this is a cie */
        memset(&cie, 0, sizeof(cie));
        if (is_eh_frame || sizeof(void*) == 8) { // FIXME not dependent on eh_frame?
          cie.code_enc = DW_EH_PE_udata8;
        } else if (sizeof(void*) == 4) {
          cie.code_enc = DW_EH_PE_udata4;
        }
        cie.lsda_enc = DW_EH_PE_omit;

        memcpy(&ver, eh_frame, sizeof(ver));
        eh_frame += sizeof(ver);
        cie.aug = eh_frame;
        eh_frame += strlen(cie.aug) + 1;
        cie.code_align = dw_read_uleb128(&eh_frame, end);
        cie.data_align = dw_read_leb128(&eh_frame, end);
        if (ver == 3) {
          cie.ret_addr = dw_read_uleb128(&eh_frame, end);
        } else {
          uint8_t r;
          memcpy(&r, eh_frame, sizeof(r));
          eh_frame += sizeof(r);
          cie.ret_addr = r;
        }
        cie.init_insns = eh_frame;
        cie.insn_end = next;

        aug = cie.aug;

        /* read in augmentation information */
        while (aug && *aug) {
          if (*aug == 'z') {
            /* augmentation section size */
            uint64_t o = dw_read_uleb128(&eh_frame, end);
            cie.init_insns = eh_frame + o;
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
                  s->addr + eh_frame - eh_start, &cie.personality_routine)) {
              fprintf(stderr, "Error while reading personality routine, enc=%02x offset: %lx\n", enc, eh_frame - eh_start);
              return 0;
            }
          } else if (*aug == 'R') {
            memcpy(&cie.code_enc, eh_frame, sizeof(cie.code_enc));
            eh_frame += sizeof(cie.code_enc);
          } else if (*aug == 'L') {
            memcpy(&cie.lsda_enc, eh_frame, sizeof(cie.lsda_enc));
            eh_frame += sizeof(cie.lsda_enc);
          }
          aug++;
        }

        if (debug) {
          printf("\n\nReading CIE, len is %ju, ver=%d aug=%s\n"
              "code_align=%jd data_align=%jd ret_addr=%ju\n",
              initlen, ver, cie.aug,
              cie.code_align, cie.data_align, cie.ret_addr);
        }

      } else {
        /* this is an fde */
        memset(&fde, 0, sizeof(fde));

        /* cie_id is the offset to the CIE that preceeds this FDE,
         * but we already know what it is */
        if (!dw_read_encptr(cie.code_enc, &eh_frame, end,
              s->addr + eh_frame - eh_start, &fde.initial_loc)) {
          fprintf(stderr, "Error while reading initial loc\n");
          return 0;
        }

        /* it makes no sense to have a relative number here, so we
         * make the base address 0 */
        if (!dw_read_encptr(cie.code_enc, &eh_frame, end, 0, &fde.addr_range)) {
          fprintf(stderr, "Error while reading addr_range\n");
          return 0;
        }
        fde.initial_loc += m->objfile->base_addr;
        if (debug) {
          printf("FDE: init=%p-%p pc=%p aug=%s\n",
              (char*)(intptr_t)fde.initial_loc,
              (char*)(intptr_t)(fde.initial_loc + fde.addr_range),
              cur->st.pc, cie.aug);
        }
        if (cie.lsda_enc != DW_EH_PE_omit) {
          if (!dw_read_encptr(cie.lsda_enc, &eh_frame, end,
                s->addr + eh_frame - eh_start, &fde.lsda_ptr)) {
            fprintf(stderr, "Error while reading lsda pointer\n");
            return 0;
          }
        }

        fde.insns = eh_frame;
        fde.insn_end = next;

        if ((intptr_t)cur->st.pc >= (intptr_t)fde.initial_loc &&
            (intptr_t)cur->st.pc <= (intptr_t)(fde.initial_loc + fde.addr_range)) {
          if (debug) {
            fprintf(stderr, "This is the FDE for the current PC\n");
            fprintf(stderr, "FDE: init=" PTRFMT "-" PTRFMT " pc=" PTRFMT "\n",
                (intptr_t)fde.initial_loc, fde.addr_range,
                (void*)cur->st.pc);
          }

          /* run initial instructions */
          memset(&cur->dw, 0, sizeof(cur->dw));
          if (!process_dwarf_insns(cur, &cie, &fde,
                cie.init_insns, cie.insn_end, fde.initial_loc)) {
            if (debug) {
              fprintf(stderr, "DWARF: unwind: failed to run init instructions\n");
            }
            return 0;
          }
          /* copy the current rules into the init rules; this
           * is to support the "restore" opcodes */
          memcpy(cie.init_cols, cur->dw.cols, sizeof(cie.init_cols));

          /* walk up the stack using the fde rules */
          if (!process_dwarf_insns(cur, &cie, &fde, fde.insns, fde.insn_end,
                fde.initial_loc)) {
            if (debug) {
              fprintf(stderr,
                  "DWARF: unwind: failed to run unwind instructions\n");
            }
            return 0;
          }
          /* map the regs back into the cursor */
          if (!apply_regs(cur, &cie)) {
            if (debug) {
              fprintf(stderr,
                  "DWARF: unwind: failed to apply unwind rules\n");
            }
            return 0;
          }

          return 1;
        }
      }

      eh_frame = next;
    }
  }

  if (debug) {
    fprintf(stderr,
      "DWARF: unwind: no suitable rules found\n");
  }

  return 0;
}

/* vim:ts=2:sw=2:et:
 */

