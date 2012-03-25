/*
 * Copyright (c) 2009 Message Systems, Inc. All rights reserved
 * For licensing information, see:
 * https://bitbucket.org/wez/gimli/src/tip/LICENSE
 */
#include "impl.h"
#include "gimli_dwarf.h"
//#define debug 1

struct dw_stack_val {
  int is_signed;
  int is_stack;
  union {
    uint64_t u64;
    int64_t s64;
  } v;
};

struct dw_expr {
  int top;
  struct dw_stack_val stack[255];
  const uint8_t *ops, *end;
};

static int push(struct dw_expr *e, struct dw_stack_val *v)
{
  if (e->top > 0 && e->top >= sizeof(e->stack)/sizeof(e->stack[0])) {
    fprintf(stderr, "DWARF: expr: stack overflow (%d)\n", e->top);
    return 0;
  }
  e->stack[++e->top] = *v;
  if (debug) printf("push: sp=%d %llx\n", e->top, e->stack[e->top].v.u64);
  return 1;
}

static int pop(struct dw_expr *e, struct dw_stack_val *v)
{
  if (e->top < 0) {
    fprintf(stderr, "DWARF:expr: stack underflow\n");
    return 0;
  }
  *v = e->stack[e->top--];
  if (debug) printf("pop: sp=%d %llx\n", e->top, v->v.u64);
  return 1;
}

static int deref(gimli_proc_t proc, uint64_t addr, uint64_t *resp, uint8_t opsize)
{
  uint8_t u8;
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  int res;
  void *ptr = (void*)(intptr_t)addr;

  switch (opsize) {
    case 1:
      res = gimli_read_mem(proc, ptr, &u8, opsize);
      u64 = u8;
      break;
    case 2:
      res = gimli_read_mem(proc, ptr, &u16, opsize);
      u64 = u16;
      break;
    case 4:
      res = gimli_read_mem(proc, ptr, &u32, opsize);
      u64 = u32;
      break;
    case 8:
      res = gimli_read_mem(proc, ptr, &u64, opsize);
      break;
  }
  if (res != opsize) {
    fprintf(stderr, "DWARF: expr: unable to deref %d bytes from %p\n",
      opsize, ptr);
    return 0;
  }
  if (debug) printf("deref: addr=%p opsize=%d res=%llx\n", ptr, opsize, res);
  *resp = res;
  return 1;
}

static int get_reg(struct gimli_unwind_cursor *cur, int regno, uint64_t *val)
{
  void **addr = gimli_reg_addr(cur, regno);
  if (!addr) {
    fprintf(stderr, "DWARF: expr: no address for reg %d\n", regno);
    return 0;
  }
  *val = (uint64_t)(intptr_t)*addr;
  return 1;
}

int dw_eval_expr(struct gimli_unwind_cursor *cur, const uint8_t *ops,
  uint64_t oplen,
  uint64_t frame_base, uint64_t *result, uint64_t *prepopulate,
  int *is_stack)
{
  struct dw_expr e;
  uint32_t u32;
  int32_t s32;
  uint8_t u8;
  int8_t s8;
  uint16_t u16;
  int16_t s16;
  int64_t s64;
  uint64_t u64;
  struct dw_stack_val val, val2;
  int i;

  memset(&e, 0, sizeof(e));
  e.ops = ops;
  e.end = ops + oplen;
  e.top = -1;

  if (prepopulate) {
    val.is_signed = 0;
    val.is_stack = is_stack ? *is_stack : 0;
    val.v.u64 = *prepopulate;
    push(&e, &val);
  }

  memset(&val, 0, sizeof(val));
  memset(&val2, 0, sizeof(val2));

  while (e.ops < e.end) {
    uint8_t op = (uint8_t)*e.ops;

    if (debug) printf("OP: %02x\n", op);
    e.ops++;

    /* literal encodings: all these operations push a value onto the stack */
    if (op >= DW_OP_lit0 && op <= DW_OP_lit31) {
      val.is_signed = 0;
      val.is_stack = 0;
      val.v.u64 = op - DW_OP_lit0;
      if (debug) printf("OP_lit%d\n", op - DW_OP_lit0);
      if (!push(&e, &val)) return 0;
      continue;
    }
    if (op >= DW_OP_breg0 && op <= DW_OP_breg31) {
      s64 = dw_read_leb128(&e.ops, e.end);
      val.is_signed = 0;
      val.is_stack = 1;
      if (!get_reg(cur, op - DW_OP_breg0, &val.v.u64)) return 0;
      if (debug) printf("OP_breg%d val=%llx\n", op - DW_OP_breg0, val.v.u64);
      val.v.u64 += s64;
      if (!push(&e, &val)) return 0;
      continue;
    }
    if (op >= DW_OP_reg0 && op <= DW_OP_reg31) {
      val.is_signed = 0;
      val.is_stack = 0;
      if (!get_reg(cur, op - DW_OP_reg0, &val.v.u64)) return 0;
      if (debug) printf("OP_reg%d -> %llx\n", op - DW_OP_reg0, val.v.u64);
      if (!push(&e, &val)) return 0;
      continue;
    }

    switch (op) {
      case DW_OP_addr:
        val.is_signed = 0;
        val.is_stack = 1;
        if (sizeof(void*) == 4) {
          memcpy(&u32, e.ops, sizeof(u32));
          e.ops += sizeof(u32);
          val.v.u64 = u32;
        } else {
          memcpy(&val.v.u64, e.ops, sizeof(val.v.u64));
          e.ops += sizeof(val.v.u64);
        }
        if (debug) printf("OP_addr: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const1u:
        memcpy(&u8, e.ops, sizeof(u8));
        val.is_signed = 0;
        val.is_stack = 1;
        val.v.u64 = u8;
        if (debug) printf("OP_const1u: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const1s:
        memcpy(&s8, e.ops, sizeof(s8));
        val.is_signed = 1;
        val.is_stack = 1;
        val.v.s64 = s8;
        if (debug) printf("OP_const1s: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const2u:
        memcpy(&u16, e.ops, sizeof(u16));
        val.is_signed = 0;
        val.is_stack = 1;
        val.v.u64 = u16;
        if (debug) printf("OP_const2u: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const2s:
        memcpy(&s16, e.ops, sizeof(s16));
        val.is_signed = 1;
        val.is_stack = 1;
        val.v.s64 = s16;
        if (debug) printf("OP_const2s: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const4u:
        memcpy(&u32, e.ops, sizeof(u32));
        val.is_signed = 0;
        val.is_stack = 1;
        val.v.u64 = u32;
        if (debug) printf("OP_const4u: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const4s:
        memcpy(&s32, e.ops, sizeof(s32));
        val.is_signed = 1;
        val.is_stack = 1;
        val.v.s64 = s32;
        if (debug) printf("OP_const4s: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const8u:
        memcpy(&val.v.u64, e.ops, sizeof(val.v.u64));
        val.is_signed = 0;
        val.is_stack = 1;
        if (debug) printf("OP_const8u: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_const8s:
        memcpy(&val.v.s64, e.ops, sizeof(val.v.s64));
        val.is_signed = 1;
        val.is_stack = 1;
        if (debug) printf("OP_const8s: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_constu:
        val.v.u64 = dw_read_uleb128(&e.ops, e.end);
        val.is_signed = 0;
        val.is_stack = 1;
        if (debug) printf("OP_constu: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_consts:
        val.v.s64 = dw_read_leb128(&e.ops, e.end);
        val.is_signed = 1;
        val.is_stack = 1;
        if (debug) printf("OP_consts: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_fbreg:
        s64 = dw_read_leb128(&e.ops, e.end);
        val.is_signed = 0;
        val.is_stack = 1;
        val.v.u64 = frame_base + s64;
        if (debug) printf("OP_fbreg: %llx\n", val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_bregx:
        u64 = dw_read_uleb128(&e.ops, e.end);
        s64 = dw_read_leb128(&e.ops, e.end);
        val.is_signed = 0;
        val.is_stack = 1;
        if (!get_reg(cur, u64, &val.v.u64)) return 0;
        val.v.u64 += s64;
        if (debug) printf("OP_breg%d: %llx\n", u64, val.v.u64);
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_regx:
        u64 = dw_read_uleb128(&e.ops, e.end);
        val.is_signed = 0;
        val.is_stack = 0;
        if (!get_reg(cur, u64, &val.v.u64)) return 0;
        if (debug) printf("OP_reg%d\n", u64);
        if (!push(&e, &val)) return 0;
        continue;
       
      case DW_OP_dup:
        val = e.stack[e.top];
        if (debug) printf("OP_dup\n");
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_drop:
        if (!pop(&e, &val)) return 0;
        if (debug) printf("OP_drop\n");
        continue;

      case DW_OP_pick:
        memcpy(&u8, e.ops, sizeof(u8));
        e.ops += sizeof(u8);
        if (debug) printf("OP_pick %u\n", u8);
        if (e.top - u8 < 0) {
          fprintf(stderr, "DWARF:expr: DW_OP_pick(%d): stack underflow\n");
          return 0;
        }
        val = e.stack[e.top - u8];
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_over:
        if (e.top - 1 < 0) {
          fprintf(stderr, "DWARF:expr: DW_OP_over: stack underflow\n");
          return 0;
        }
        val = e.stack[e.top - 1];
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_swap:
        if (e.top < 1) {
          fprintf(stderr, "DWARF: expr: DW_OP_swap: stack underflow\n");
          return 0;
        }

        val = e.stack[e.top - 1];
        e.stack[e.top - 1] = e.stack[e.top];
        e.stack[e.top] = val;
        continue;

      case DW_OP_rot:
        if (e.top < 2) {
          fprintf(stderr, "DWARF: expr: DW_OP_rot: stack underflow\n");
          return 0;
        }

        val = e.stack[e.top];
        e.stack[e.top] = e.stack[e.top - 2];
        e.stack[e.top - 2] = e.stack[e.top - 1];
        e.stack[e.top - 1] = val;
        continue;

      case DW_OP_deref:
        if (!pop(&e, &val)) return 0;
        if (!deref(cur->proc, val.v.u64, &u64, sizeof(void*))) return 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_deref_size:
        memcpy(&u8, e.ops, sizeof(u8));
        if (!pop(&e, &val)) return 0;
        if (!deref(cur->proc, val.v.u64, &u64, u8)) return 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_call_frame_cfa:
        val.is_signed = 0;
        val.is_stack = 0;
        val.v.u64 = (uint64_t)(intptr_t)cur->st.fp;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_abs:
        if (!pop(&e, &val)) return 0;
        if (val.v.s64 < 0) {
          u64 = -val.v.s64;
        } else {
          u64 = val.v.s64;
        }
        val.v.u64 = u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_and:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 &= val2.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_div:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 / val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_minus:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 - val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_mod:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 % val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_mul:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 * val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_neg:
        if (!pop(&e, &val)) return 0;
        val.v.u64 = ~val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_not:
        if (!pop(&e, &val)) return 0;
        val.v.u64 = !val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_or:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 |= val2.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_plus:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 += val2.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_plus_uconst:
        if (!pop(&e, &val)) return 0;
        val.v.u64 += dw_read_uleb128(&e.ops, e.end);
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_shl:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 << val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_shr:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 >> val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_shra:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        if (val2.is_signed) {
          for (i = 0; i < val.v.u64; i++) {
            val2.v.s64 /= 2;
          }
        } else {
          val2.v.u64 = val2.v.u64 >> val.v.u64;
        }
        val2.is_stack = 1;
        if (!push(&e, &val2)) return 0;
        continue;

      case DW_OP_xor:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = val2.v.u64 ^ val.v.u64;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_le:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = (val2.v.s64 <= val.v.s64) ? 1 : 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_lt:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = (val2.v.s64 < val.v.s64) ? 1 : 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_ge:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = (val2.v.s64 >= val.v.s64) ? 1 : 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_gt:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = (val2.v.s64 > val.v.s64) ? 1 : 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_eq:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = (val2.v.s64 == val.v.s64) ? 1 : 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_ne:
        if (!pop(&e, &val)) return 0;
        if (!pop(&e, &val2)) return 0;
        val.v.u64 = (val2.v.s64 != val.v.s64) ? 1 : 0;
        val.is_signed = 0;
        val.is_stack = 1;
        if (!push(&e, &val)) return 0;
        continue;

      case DW_OP_skip:
        memcpy(&s16, e.ops, sizeof(s16));
        e.ops += sizeof(s16);
        e.ops += s16;
        continue;

      case DW_OP_bra:
        memcpy(&s16, e.ops, sizeof(s16));
        e.ops += sizeof(s16);
        if (!pop(&e, &val)) return 0;
        if (val.v.u64) {
          e.ops += s16;
        }
        continue;

      case DW_OP_nop:
        continue;

      default:
        fprintf(stderr, "DWARF: expr: unhandled op %02x\n", op);
        return 0;
    }
  }

  if (is_stack) *is_stack = e.stack[e.top].is_stack;
  *result = e.stack[e.top].v.u64;
  if (debug) printf("eval expr: result=%llx\n", *result);
  return 1;
}

/* vim:ts=2:sw=2:et:
 */
