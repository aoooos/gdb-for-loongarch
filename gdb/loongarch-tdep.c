/* Target-dependent code for the RISC-V architecture, for GDB.

   Copyright (C) 2018 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "frame.h"
#include "inferior.h"
#include "symtab.h"
#include "value.h"
#include "gdbcmd.h"
#include "language.h"
#include "gdbcore.h"
#include "symfile.h"
#include "objfiles.h"
#include "gdbtypes.h"
#include "target.h"
#include "arch-utils.h"
#include "regcache.h"
#include "osabi.h"
#include "block.h"
#include "reggroups.h"
#include "elf-bfd.h"
#include "symcat.h"
#include "dis-asm.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "infcall.h"
#include "floatformat.h"
#include "remote.h"
#include "target-descriptions.h"
#include "dwarf2-frame.h"
#include "user-regs.h"
#include "valprint.h"
#include "common-defs.h"
#include "cli/cli-decode.h"
#include "observable.h"
#include "loongarch-tdep.h"
#include "arch/loongarch.h"

static int
loongarch_rlen (struct gdbarch *gdbarch)
{
  switch (gdbarch_tdep (gdbarch)->ef_abi)
    {
    case EF_LARCH_ABI_LP64:
    case EF_LARCH_ABI_XLP32:
      return 64;
    case EF_LARCH_ABI_LP32:
      return 32;
    default:
      gdb_assert_not_reached ("unknown ABI");
    }
  return 0;
}

static insn_t
loongarch_fetch_instruction (CORE_ADDR addr, int *errp)
{
  /* 本意是传入足够的信息得到指令长度，目前不是变长指令，无所谓了 */
  size_t insnlen = loongarch_insn_length (0);
  gdb_byte buf[insnlen];
  int err;
  ULONGEST ret;

  err = target_read_memory (addr, buf, insnlen);
  if (errp != NULL)
    *errp = err;
  if (err != 0)
    {
      if (errp == NULL)
	memory_error (TARGET_XFER_E_IO, addr);
      return 0;
    }
  ret = extract_unsigned_integer (buf, insnlen, BFD_ENDIAN_LITTLE);
  return ret;
}

static int
loongarch_insn_is_branch_and_must_branch (insn_t insn)
{
  if ((insn & 0xfc000000) == 0x4c000000		/* jirl r0:5,r5:5,s10:16<<2 */
      || (insn & 0xfc000000) == 0x50000000	/* b sb0:10|10:16<<2 */
      || (insn & 0xfc000000) == 0x54000000	/* bl sb0:10|10:16<<2 */
      || (insn & 0xfc0003e0) == 0x48000200	/* jiscr0 s0:5|10:16<<2 */
      || (insn & 0xfc0003e0) == 0x48000300)	/* jiscr1 s0:5|10:16<<2 */
    return 1;
  return 0;
}

static int
loongarch_insn_is_branch (insn_t insn)
{
  if (loongarch_insn_is_branch_and_must_branch (insn)
      || (insn & 0xfc000000) == 0x40000000	/* beqz r5:5,sb0:5|10:16<<2 */
      || (insn & 0xfc000000) == 0x44000000	/* bnez r5:5,sb0:5|10:16<<2 */
      || (insn & 0xfc000300) == 0x48000000	/* bceqz c5:3,sb0:5|10:16<<2 */
      || (insn & 0xfc000300) == 0x48000100	/* bcnez c5:3,sb0:5|10:16<<2 */
      || (insn & 0xfc000000) == 0x58000000	/* beq r5:5,r0:5,sb10:16<<2 */
      || (insn & 0xfc000000) == 0x5c000000	/* bne r5:5,r0:5,sb10:16<<2 */
      || (insn & 0xfc000000) == 0x60000000	/* blt r5:5,r0:5,sb10:16<<2 */
      || (insn & 0xfc000000) == 0x64000000	/* bge r5:5,r0:5,sb10:16<<2 */
      || (insn & 0xfc000000) == 0x68000000	/* bltu r5:5,r0:5,sb10:16<<2 */
      || (insn & 0xfc000000) == 0x6c000000)	/* bgeu r5:5,r0:5,sb10:16<<2 */
    return 1;
  return 0;
}

static CORE_ADDR
loongarch_next_pc_if_branch (struct regcache *regcache, CORE_ADDR cur_pc, insn_t insn)
{
  struct gdbarch *gdbarch = regcache->arch ();
  auto regs = &gdbarch_tdep (gdbarch)->regs;
  CORE_ADDR next_pc;

  if ((insn & 0xfc000000) == 0x40000000		/* beqz r5:5,sb0:5|10:16<<2 */
      || (insn & 0xfc000000) == 0x44000000	/* bnez r5:5,sb0:5|10:16<<2 */
      || (insn & 0xfc000300) == 0x48000000	/* bceqz c5:3,sb0:5|10:16<<2 */
      || (insn & 0xfc000300) == 0x48000100)	/* bcnez c5:3,sb0:5|10:16<<2 */
    next_pc = cur_pc + loongarch_decode_imm ("0:5|10:16<<2", insn, 1);
  else if ((insn & 0xfc0003e0) == 0x48000200)	/* jiscr0 s0:5|10:16<<2 */
    {
      gdb_assert (0 <= regs->scr);
      next_pc = regcache_raw_get_signed (regcache, regs->scr)
	      + loongarch_decode_imm ("0:5|10:16<<2", insn, 1);
    }
  else if ((insn & 0xfc0003e0) == 0x48000300)	/* jiscr1 s0:5|10:16<<2 */
    {
      gdb_assert (0 <= regs->scr);
      next_pc = regcache_raw_get_signed (regcache, regs->scr + 1)
	      + loongarch_decode_imm ("0:5|10:16<<2", insn, 1);
    }
  else if ((insn & 0xfc000000) == 0x4c000000)	/* jirl r0:5,r5:5,s10:16<<2 */
    next_pc = regcache_raw_get_signed
	        (regcache, regs->r + loongarch_decode_imm ("5:5", insn, 0))
	    + loongarch_decode_imm ("10:16<<2", insn, 1);
  else if ((insn & 0xfc000000) == 0x50000000	/* b sb0:10|10:16<<2 */
	   || (insn & 0xfc000000) == 0x54000000)/* bl sb0:10|10:16<<2 */
    next_pc = cur_pc + loongarch_decode_imm ("0:10|10:16<<2", insn, 1);
  else if ((insn & 0xfc000000) == 0x58000000	/* beq r5:5,r0:5,sb10:16<<2 */
	   || (insn & 0xfc000000) == 0x5c000000	/* bne r5:5,r0:5,sb10:16<<2 */
	   || (insn & 0xfc000000) == 0x60000000	/* blt r5:5,r0:5,sb10:16<<2 */
	   || (insn & 0xfc000000) == 0x64000000	/* bge r5:5,r0:5,sb10:16<<2 */
	   || (insn & 0xfc000000) == 0x68000000	/* bltu r5:5,r0:5,sb10:16<<2 */
	   || (insn & 0xfc000000) == 0x6c000000)/* bgeu r5:5,r0:5,sb10:16<<2 */
    next_pc = cur_pc + loongarch_decode_imm ("10:16<<2", insn, 1);
  else
    gdb_assert_not_reached ("I don't know what branch is this");

  return next_pc;
}

/* Checks for an atomic sequence of instructions beginning with a LL/LLD
   instruction and ending with a SC/SCD instruction.  If such a sequence
   is found, attempt to step through it.  A breakpoint is placed at the end of
   the sequence.  */

static std::vector<CORE_ADDR>
loongarch_deal_with_atomic_sequence (struct regcache *regcache, CORE_ADDR pc)
{
  struct gdbarch *gdbarch = regcache->arch ();
  CORE_ADDR next_pc;
  std::vector<CORE_ADDR> next_pcs;
  insn_t insn = loongarch_fetch_instruction (pc, NULL);
  size_t insnlen = loongarch_insn_length (insn);
  int i, atomic_sequence_length, found_atomic_sequence_endpoint;

  /* 这个函数由loongarch_software_single_step调用，在single step时尝试找到原子
     指令序列的终点。返回的CORE_ADDR向量似乎意味着控制流的所有可能去处。
     如果 return {} 则意味着认为接下来的指令不属于原子操作。 */

  if ((insn & 0xff000000) != 0x20000000		/* ll.w */
      && (insn & 0xff000000) != 0x22000000)	/* ll.d */
    return {};

  if (loongarch_debug)
    fprintf_unfiltered (gdb_stdlog,
"Single step: PC: %s OK, I found ll\\.[wd] here. It's atomic sequence?\n",
      paddress (gdbarch, pc));

  atomic_sequence_length = 30; /* Magic. */
  found_atomic_sequence_endpoint = 0;
  for (pc += insnlen, i = 0; i < atomic_sequence_length; pc += insnlen, i++)
    {
      insn = loongarch_fetch_instruction (pc, NULL);
      insnlen = loongarch_insn_length (insn);

      if (loongarch_insn_is_branch_and_must_branch (insn))
	{
	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
	      "Single step: PC: %s Must branch here. Treat it normally.\n",
	      paddress (gdbarch, pc));
	  break;
	}
      else if (loongarch_insn_is_branch (insn))
	{
	  next_pc = loongarch_next_pc_if_branch (regcache, pc, insn);

	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"Single step: PC: %s May branch inside and target is %s. Breakpoint there.\n",
paddress (gdbarch, pc), paddress (gdbarch, next_pc));

	  next_pcs.push_back (next_pc);
	}
      else if ((insn & 0xff000000) == 0x21000000	/* sc.w */
	       || (insn & 0xff000000) == 0x23000000)	/* sc.d */
	{
	  found_atomic_sequence_endpoint = 1;
	  next_pc = pc + insnlen;

	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"Single step: PC: %s I found sc\\.[wd] and atomic sequence ends at here.\n"
"Breakpoint next pc: %s.\n",
paddress (gdbarch, pc), paddress (gdbarch, next_pc));

	  next_pcs.push_back (next_pc);
	  break;
	}
    }

  if (!found_atomic_sequence_endpoint)
    {
      if (loongarch_debug)
	fprintf_unfiltered (gdb_stdlog,
	  "Single step: PC: %s Not ends with sc\\.[wd] in %d insns?\n"
	  "Treat it as not atomic sequence.\n",
	  paddress (gdbarch, pc), atomic_sequence_length);

      return {};
    }

  return next_pcs;
}

/* mips_software_single_step() is called just before we want to resume
   the inferior, if we want to single-step it but there is no hardware
   or kernel single-step support (MIPS on GNU/Linux for example).  We find
   the target of the coming instruction and breakpoint it.  */

std::vector<CORE_ADDR>
loongarch_software_single_step (struct regcache *regcache)
{
  struct gdbarch *gdbarch = regcache->arch ();
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  CORE_ADDR pc = regcache_read_pc (regcache);
  std::vector<CORE_ADDR> next_pcs =
    loongarch_deal_with_atomic_sequence (regcache, pc);

  if (!next_pcs.empty ())
    return next_pcs;

  insn_t insn = loongarch_fetch_instruction (pc, NULL);
  size_t insnlen = loongarch_insn_length (insn);
  CORE_ADDR next = pc + insnlen;

  if ((insn & 0xffff8000) == 0x002b0000 && tdep->syscall_next_pc)
    {
      CORE_ADDR syscall_next = tdep->syscall_next_pc (get_current_frame ());
      if (syscall_next != -1)
	{
	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"PC: %s Syscall found. Next pc is %s.\n",
paddress (gdbarch, pc), paddress (gdbarch, syscall_next));
	  return {syscall_next};
	}
    }

  if (loongarch_insn_is_branch (insn))
    {
      CORE_ADDR branch_tgt = loongarch_next_pc_if_branch (regcache, pc, insn);
      if (loongarch_debug)
	fprintf_unfiltered (gdb_stdlog,
"PC: %s Next pc is %s if branch, %s for non-branch.\n",
paddress (gdbarch, pc), paddress (gdbarch, branch_tgt), paddress (gdbarch, next));
      return {next, branch_tgt};
    }
  else
    {
      if (loongarch_debug)
	fprintf_unfiltered (gdb_stdlog,
"PC: %s Next pc is %s.\n",
paddress (gdbarch, pc), paddress (gdbarch, next));
      return {next};
    }
}

/* Callback function for user_reg_add.  */

static struct value *
value_of_loongarch_user_reg (struct frame_info *frame, const void *baton)
{
  return value_of_register ((long long) baton, frame);
}

/* Implement the register_name gdbarch method.  */

static const char *
loongarch_register_name (struct gdbarch *gdbarch, int regnum)
{
  auto regs = &gdbarch_tdep (gdbarch)->regs;

  if (0 <= regs->r
	   && regs->r <= regnum
	   && regnum < regs->r + 32)
    switch (gdbarch_tdep (gdbarch)->ef_abi)
      {
      case EF_LARCH_ABI_LP64:
	return loongarch_r_lp64_name[regnum - regs->r] + 1;
      }
  else if (0 <= regs->f
	   && regs->f <= regnum
	   && regnum < regs->f + 32)
    switch (gdbarch_tdep (gdbarch)->ef_abi)
      {
      case EF_LARCH_ABI_LP64:
	return loongarch_f_lp64_name[regnum - regs->f] + 1;
      }
  return tdesc_register_name (gdbarch, regnum);
}

/* Analyze the function prologue from START_PC to LIMIT_PC.  Builds
   the associated FRAME_CACHE if not null.
   Return the address of the first instruction past the prologue.  */

static CORE_ADDR
loongarch_scan_prologue (struct gdbarch *gdbarch,
			 CORE_ADDR start_pc, CORE_ADDR limit_pc,
			 struct frame_info *this_frame,
			 struct trad_frame_cache *this_cache)
{
  /* 关键问题：我们分析callee的prologue而推断caller的保存寄存器被store在相对于
     callee的CFA的偏移量，但在函数执行中途我们不好拿到CFA的值，这是回溯的障碍。
     另外，黄沛给出了Power的ABI作参考，callee在维护调用栈时保持栈顶的两个地址
     恒为caller的返回地址和栈顶。在这里就不用analyze prologue了。但我们的指令集
     看起来还做不到这一点。

     在这里，我们约定
     a. CFA(canonical frame address from dwarf2)的值为caller调用callee那一瞬间
     $sp的值，即See MIPS run中的“$sp on entry”。这是因为分析prologue是按照控制
     流走向的，这样使得分析更加自然。
     b. 定义frame pointer为函数正文执行期间保持不变的，且存储有和CFA有常数
     偏移量的值的寄存器。lp64中的$fp便是这个用途，但考虑到二进制翻译会有寄存器
     映射，frame pointer还真不一定是$fp。对于栈帧不变的函数，$sp就是
     frame pointer。

     那么，
     a. 如果有一个$fp($r22)是$sp($r3)附加偏移量得到的。一旦$r22确定，在整个
     函数执行期间不会变化。对于栈帧可变的函数这很重要。由此，根据callee的$fp
     可以反推进入callee时$sp的值，由此就得到了CFA。
     b. 如果没有$fp被确定，那么我们认为在prologue中，$sp被调整后，其在函数执行
     期间不会变化，由此我们就知道了CFA。这是栈帧不变的函数。
     c. 上述约定尽量在-O0下生效，不过说到底也只是个启发式做法罢了。指令调度会
     使prologue没那么工整；shrink-wrapping会弱化prologue的概念；手写汇编更是可
     以自由发挥，这使得分析极其困难，我们也点到为止。

     那么prologue分析分为两部分，
     1. 求出callee的frame pointer，及frame pointer和CFA的偏移量以求出CFA。
     2. 求出来the offset based on CFA storing the register of caller  */

  auto regs = &gdbarch_tdep (gdbarch)->regs;
  int rlen_is_64b = (loongarch_rlen (gdbarch) == 64);

  CORE_ADDR cur_pc, prologue_end = 0;
  insn_t insn;
  size_t insnlen;

  int sp = regs->sp - regs->r;

  int fp = sp;/* frame pointer */
  long frame_offset = 0;
  int non_prologue_insns = 0;
  int cfa_unknown = 0;

  /* try to trace li */
  int64_t r_value[32] = {0};
  int r_value_known[32] = {1, 0};

  long r_cfa_offset[32] = {0};
  int r_cfa_offset_p[32] = {0};

  long f_cfa_offset[32] = {0};
  int f_cfa_offset_p[32] = {0};

  if (start_pc + 80 < limit_pc)
    limit_pc = start_pc + 80;

  for (cur_pc = start_pc; cur_pc < limit_pc; cur_pc += insnlen)
    {
      int rd, rj, rk;
      int64_t si12, si20, si14;

      insn = loongarch_fetch_instruction (cur_pc, NULL);
      insnlen = loongarch_insn_length (insn);

      rd = loongarch_decode_imm ("0:5", insn, 0);
      rj = loongarch_decode_imm ("5:5", insn, 0);
      rk = loongarch_decode_imm ("10:5", insn, 0);
      si12 = loongarch_decode_imm ("10:12", insn, 1);
      si20 = loongarch_decode_imm ("5:20", insn, 1);
      si14 = loongarch_decode_imm ("10:14<<2", insn, 1);

      if ((((insn & 0xffc00000) == 0x02800000		/* addi.w fp,fp,si12 */
	     && !rlen_is_64b)
	   || ((insn & 0xffc00000) == 0x02c00000	/* addi.d fp,fp,si12 */
	     && rlen_is_64b))
	  && rd == fp && rj == fp)
	{
	  if (si12 < 0)
            frame_offset -= si12;
	  else
	    /* Exit loop if a positive stack adjustment is found, which
	       usually means that the stack cleanup code in the function
	       epilogue is reached.  */
	    break;
	  prologue_end = cur_pc + insnlen;
	}
      else if ((((insn & 0xffc00000) == 0x29800000	/* st.w rd,fp,si12 */
		 && !rlen_is_64b)
	       || ((insn & 0xffc00000) == 0x29c00000	/* st.d rd,fp,si12 */
		 && rlen_is_64b))
	       && rj == fp)
	{
	  if (!r_cfa_offset_p[rd] && !r_value_known[rd])
	    r_cfa_offset[rd] = si12 - frame_offset, r_cfa_offset_p[rd] = 1;
	  prologue_end = cur_pc + insnlen;
	}
      else if ((((insn & 0xff000000) == 0x25000000	/* stptr.w rd,fp,si14 */
		 && !rlen_is_64b)
	       || ((insn & 0xff000000) == 0x27000000	/* stptr.d rd,fp,si14 */
		 && rlen_is_64b))
	       && rj == fp)
	{
	  if (!r_cfa_offset_p[rd] && !r_value_known[rd])
	    r_cfa_offset[rd] = si14 - frame_offset, r_cfa_offset_p[rd] = 1;
	  prologue_end = cur_pc + insnlen;
	}
      else if (((insn & 0xffc00000) == 0x2b400000	/* fst.s fd,fp,si12 */
		|| (insn & 0xffc00000) == 0x2bc00000)	/* fst.d fd,fp,si12 */
	       && rj == fp)
	{
	  if (!f_cfa_offset_p[rd])
	    f_cfa_offset[rd] = si12 - frame_offset, f_cfa_offset_p[rd] = 1;
	}
      else if ((((insn & 0xffff8000) == 0x00110000	/* sub.w fp,fp,rk */
		 && !rlen_is_64b)		
	       || ((insn & 0xffff8000) == 0x00118000	/* sub.d fp,fp,rk */
		 && rlen_is_64b))
	       && rd == fp && rj == fp)
	{
	  if (r_value_known[rk])
	    {
              frame_offset += r_value[rk];
	      prologue_end = cur_pc + insnlen;
	    }
	  else
	    cfa_unknown = 1;
	}
      else if ((insn & 0xffff8000) == 0x00150000	/* or rd,fp,$r0 */
	       && rj == fp && rk == 0)
	{
	  fp = rd;
	  prologue_end = cur_pc + insnlen;
	}
      else if ((insn & 0xffc00000) == 0x02800000)	/* addi.w rd,rj,si12 */
	{
	  if (r_value_known[rj] && rd != 0)
	    r_value[rd] = (int32_t) (r_value[rj] + si12), r_value_known[rd] = 1;
	}
      else if ((insn & 0xffc00000) == 0x03800000)	/* ori rd,rj,si12 */
	{
	  if (r_value_known[rj] && rd != 0)
	    r_value[rd] = r_value[rj] | (si12 & 0xfff) , r_value_known[rd] = 1;
	}
      else if ((insn & 0xfe000000) == 0x14000000)	/* lu12i.w rd,si20 */
	{
	  if (rd != 0)
	    r_value[rd] = si20 << 12, r_value_known[rd] = 1;
	}
      else if ((insn & 0xfe000000) == 0x16000000)	/* lu32i.d rd,si20 */
	{
	  if (r_value_known[rd] && rd != 0)
	    r_value[rd] = (r_value[rd] & 0xffffffff) | (si20 << 32)
	      , r_value_known[rd] = 1;
	}
      else if ((insn & 0xffc00000) == 0x03000000)	/* lu52i.d rd,rj,si12 */
	{
	  if (r_value_known[rj] && rd != 0)
	    r_value[rd] = (r_value[rj] & 0xfffffffffffff) | (si12 << 52)
	      , r_value_known[rd] = 1;
	}
      else if (loongarch_insn_is_branch (insn))
	break;/* shrink-wrap or end of prologue in a basic block */
      else
	non_prologue_insns++;

      if (5 < non_prologue_insns) /* 4 INSNs for 'la' and one for some other */
	break;
    }

  if (loongarch_debug)
    {
      const char *fun_name;
      find_pc_partial_function (start_pc, &fun_name, NULL, NULL);
      fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: -- Start -- Callee [%s] %s\n",
fun_name ? fun_name : "<unknown>", paddress (gdbarch, start_pc));
    }

  do
    {
      int i;
      CORE_ADDR cfa = -1, ret = -1;

      if (!(this_frame && this_cache))
	break;

      if (!cfa_unknown)
	{
	  TRY
	    {
	      cfa = get_frame_register_signed
		      (this_frame, regs->r + fp) + frame_offset;
	    }
	  CATCH (e, RETURN_MASK_ALL)
	    {
	      cfa_unknown = 1;
	    }
	  END_CATCH
	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: CFA is (frame pointer $%s + 0x%lx) = %s\n",
gdbarch_register_name (gdbarch, regs->r + fp),
(long)frame_offset, cfa_unknown ? "<unknown>" : paddress (gdbarch, cfa));
	}
      else
	if (loongarch_debug)
	  fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: Unknown stack frame size, so can't get known CFA\n");

      if (r_cfa_offset_p[1] && !cfa_unknown)
	{
	  CORE_ADDR ret_saved = cfa + r_cfa_offset[1];
	  trad_frame_set_reg_addr
	    (this_cache, gdbarch_pc_regnum (gdbarch), ret_saved);
	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: Return addr saved in (CFA - 0x%lx) = %s\n",
-r_cfa_offset[1], paddress (gdbarch, ret_saved));
	}
      else if (r_cfa_offset_p[1] /* && cfa_unknown */)
	{
	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: Return addr saved in (CFA - 0x%lx), but CFA is unknown\n",
-r_cfa_offset[1]);
	}
      else
	{
	  trad_frame_set_reg_realreg
	    (this_cache, gdbarch_pc_regnum (gdbarch), regs->r + 1);
	  if (loongarch_debug)
	    fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: No found $r1 pushed in stack. Return addr saved in $r1\n");
	}

      if (cfa_unknown)
	{
	  trad_frame_set_this_base (this_cache, -1);
	  break;
	}

      /* 在这里认为callee的CFA是caller的$sp的值。真实情况不一定如此。但在分析
	 caller的prologue时，
	 如果发现caller的frame pointer不为$sp，会unwind备份在callee frame中的
	 frame pointer，此时$sp的值也不重要了；
	 如果发现caller的frame pointer为$sp，那么$sp的值就是这个CFA */
      trad_frame_set_reg_value
	(this_cache, gdbarch_sp_regnum (gdbarch), (LONGEST) cfa);
      trad_frame_set_this_base (this_cache, cfa);

      if (loongarch_debug)
	fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: Where caller's registers saved as follow:\n");

      for (i = 0; i < 32; i++)
	if (r_cfa_offset_p[i] && i != 1)
	  {
	    trad_frame_set_reg_addr
	      (this_cache, regs->r + i, cfa + r_cfa_offset[i]);
	    if (loongarch_debug)
	      fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: $%s: saved in (CFA - 0x%lx) = %s\n",
gdbarch_register_name (gdbarch, regs->r + i), -r_cfa_offset[i],
paddress (gdbarch, cfa + r_cfa_offset[i]));
	  }

      if (regs->f <= 0)
	for (i = 0; i < 32; i++)
	  {
	    if (f_cfa_offset_p[i])
	      trad_frame_set_reg_addr
		(this_cache, regs->f + i, cfa + f_cfa_offset[i]);
	    if (loongarch_debug)
	      fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: $%s: saved in (CFA - 0x%lx) = %s\n",
gdbarch_register_name (gdbarch, regs->f + i), -f_cfa_offset[i],
paddress (gdbarch, cfa + f_cfa_offset[i]));
	  }
    }
  while (0);

  if (loongarch_debug)
    fprintf_unfiltered (gdb_stdlog,
"Prologue Analyze: -- End -- %s\n", paddress (gdbarch, cur_pc));

  return prologue_end ? prologue_end : cur_pc;
}


/* Implement the loongarch_skip_prologue gdbarch method.  */

/* To skip prologues, I use this predicate.  Returns either PC itself
   if the code at PC does not look like a function prologue; otherwise
   returns an address that (if we're lucky) follows the prologue.  If
   LENIENT, then we must skip everything which is involved in setting
   up the frame (it's OK to skip more, just so long as we don't skip
   anything which might clobber the registers which are being saved.
   We must skip more in the case where part of the prologue is in the
   delay slot of a non-prologue instruction).  */

static CORE_ADDR
loongarch_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR limit_pc;
  CORE_ADDR func_addr;

  /* See if we can determine the end of the prologue via the symbol table.
     If so, then return either PC, or the PC after the prologue, whichever
     is greater.  */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc
	= skip_prologue_using_sal (gdbarch, func_addr);
      if (post_prologue_pc != 0)
	return std::max (pc, post_prologue_pc);
    }

  /* Can't determine prologue from the symbol table, need to examine
     instructions.  */

  /* Find an upper limit on the function prologue using the debug
     information.  If the debug information could not be used to provide
     that bound, then use an arbitrary large number as the upper bound.  */
  limit_pc = skip_prologue_using_sal (gdbarch, pc);
  if (limit_pc == 0)
    limit_pc = pc + 100;          /* Magic.  */

  return loongarch_scan_prologue (gdbarch, pc, limit_pc, NULL, NULL);
}


/* Adjust the address downward (direction of stack growth) so that it
   is correctly aligned for a new stack frame.  */
static CORE_ADDR
loongarch_frame_align (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  return align_down (addr, 16);
}


/* Implement the unwind_pc gdbarch method.  */

static CORE_ADDR
loongarch_unwind_pc (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  return frame_unwind_register_signed
	   (next_frame, gdbarch_pc_regnum (gdbarch));
}


/* Implement the unwind_sp gdbarch method.  */

static CORE_ADDR
loongarch_unwind_sp (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  return frame_unwind_register_signed
	   (next_frame, gdbarch_sp_regnum (gdbarch));
}


/* Implement the dummy_id gdbarch method.  */

static struct frame_id
loongarch_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build
	   (get_frame_register_signed (this_frame,
				       gdbarch_sp_regnum (gdbarch)),
	    get_frame_pc (this_frame));
}

/* Generate, or return the cached frame cache for the RiscV frame
   unwinder.  */

static struct trad_frame_cache *
loongarch_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct trad_frame_cache *cache;
  CORE_ADDR pc, start_addr, stack_addr;

  if (*this_cache != NULL)
    return (struct trad_frame_cache *) *this_cache;
  cache = trad_frame_cache_zalloc (this_frame);
  *this_cache = cache;

  /* 这里的情况是，已知callee中各寄存器的值（包括PC），分析callee的prologue
     来推测caller中各寄存器备份在callee栈帧中的位置。  */

/* 我们先拿到callee的PC */
  pc = get_frame_address_in_block (this_frame);
  if (find_pc_partial_function (pc, NULL, &start_addr, NULL))
    {
/* find_pc_partial_function会从debug信息拿到函数开头，如果成功了，那啥也
   不说了，开始scan_prologue */
      loongarch_scan_prologue (gdbarch, start_addr, pc, this_frame, cache);
      stack_addr = trad_frame_get_this_base (cache);
      trad_frame_set_id (cache, stack_addr == -1 ?
			  frame_id_build_unavailable_stack (start_addr) :
			  frame_id_build (stack_addr, start_addr));
    }
  else
    {
/* 如果失败了，可能有三种情况
   1. PC在某个trampoline上。那应该有某个struct tramp_frame的sniffer的匹配
      优先级比这个通用的struct frame_unwind高。
   2. PC在某个函数中，可能在elf文件中但没debug信息；也可能是自修改代码。不考虑
   3. PC非法，反正要么已经发生段错误了；要么迟早发生段错误。不过这种的也要
      看情况，比如基本块没设计好，PC飞了，我们根本没任何线索搞backtrace。
   我们在这里考虑的情况唯一情况是进行了失败的绝对跳转的函数调用，这样的话
   caller的寄存器都在，而caller的地址就在ra中。 */
      auto regs = &gdbarch_tdep (gdbarch)->regs;
      /* 注意：我们认为caller的$ra是unknown的。原因是，下次unwind时的
	 find_pc_partial_function失效后（即callee的$ra不在某个带debug信息的
	 函数内），认为caller的caller的PC为caller的$ra。如果仍然认为caller的$ra
	 是callee的$ra，这个失效的PC值会让unwind无法停下来了。 */
      trad_frame_set_reg_realreg (cache, regs->ra, -2/* TF_REG_UNKNOWN */);
      trad_frame_set_reg_realreg
	(cache, gdbarch_pc_regnum (gdbarch), regs->ra);

      trad_frame_set_id (cache, frame_id_build_unavailable_stack (pc));
  }
  return cache;
}


/* Implement the this_id callback for RiscV frame unwinder.  */

static void
loongarch_frame_this_id (struct frame_info *this_frame,
			 void **prologue_cache,
			 struct frame_id *this_id)
{
  struct trad_frame_cache *info;

  info = loongarch_frame_cache (this_frame, prologue_cache);
  trad_frame_get_id (info, this_id);
}


/* Implement the prev_register callback for RiscV frame unwinder.  */

static struct value *
loongarch_frame_prev_register (struct frame_info *this_frame,
			       void **prologue_cache,
			       int regnum)
{
  struct trad_frame_cache *info;

  info = loongarch_frame_cache (this_frame, prologue_cache);
  return trad_frame_get_register (info, this_frame, regnum);
}


/* Structure defining the RiscV normal frame unwind functions.  Since we
   are the fallback unwinder (DWARF unwinder is used first), we use the
   default frame sniffer, which always accepts the frame.  */

static const struct frame_unwind loongarch_frame_unwind =
{
  /*.type          =*/ NORMAL_FRAME,
  /*.stop_reason   =*/ default_frame_unwind_stop_reason,
  /*.this_id       =*/ loongarch_frame_this_id,
  /*.prev_register =*/ loongarch_frame_prev_register,
  /*.unwind_data   =*/ NULL,
  /*.sniffer       =*/ default_frame_sniffer,
  /*.dealloc_cache =*/ NULL,
  /*.prev_arch     =*/ NULL,
};


/* 为了做mips的汇编级兼容，LP64和n64的传参方法是相同的 */
/* N32/N64 ABI stuff.  */

/* Implement the push dummy call gdbarch callback.  */

static CORE_ADDR
loongarch_xlp32lp64_push_dummy_call (struct gdbarch *gdbarch,
				     struct value *function,
				     struct regcache *regcache,
				     CORE_ADDR bp_addr,
				     int nargs, struct value **args,
				     CORE_ADDR sp,
				     int struct_return, CORE_ADDR struct_addr)
{
  const size_t rlen = loongarch_rlen (gdbarch) / 8;
  size_t i;

  /* 1. We find out the size of space to settle actual args */
  size_t Narg_slots = 0;
  if (struct_return)
    Narg_slots++;
  for (i = 0; i < nargs; i++)
    {
      struct value *arg = args[i];
      struct type *arg_type = check_typedef (value_type (arg));
      size_t len = TYPE_LENGTH (arg_type);
      size_t align = type_align (arg_type);
      enum type_code typecode = TYPE_CODE (arg_type);

      gdb_assert (0 < align);
      if (typecode == TYPE_CODE_COMPLEX && len == 8
	  && TYPE_CODE (check_typedef (TYPE_TARGET_TYPE (arg_type)))
	       == TYPE_CODE_FLT)
	/* For _Complex float, sometimes we need two float argument registers
	   to fit its real and img. */
	Narg_slots += 2;
      else
	{
	  Narg_slots = align_up (Narg_slots, (align + rlen - 1) / rlen);
	  Narg_slots += (len + rlen - 1) / rlen;
	}
    }

  /* 2. Set all actual arguments here */
  struct type *func_type = check_typedef (value_type (function));
  gdb_byte raw_args[Narg_slots * rlen];
  Narg_slots = 0;
  if (struct_return)
    store_signed_integer (raw_args + Narg_slots * rlen, rlen, BFD_ENDIAN_LITTLE, struct_addr)
      , Narg_slots++;

  for (i = 0; i < nargs; i++)
    {
      struct value *arg = args[i];
      struct type *arg_type = check_typedef (value_type (arg));
      size_t len = TYPE_LENGTH (arg_type);
      size_t align = type_align (arg_type);
      enum type_code typecode = TYPE_CODE (arg_type);
      const gdb_byte *val = value_contents (arg);
      Narg_slots = align_up (Narg_slots, (align + rlen - 1) / rlen);
      int is_var = TYPE_VARARGS (func_type) && TYPE_NFIELDS (func_type) <= i;

      if (((typecode == TYPE_CODE_INT && TYPE_UNSIGNED (arg_type))
	   || typecode == TYPE_CODE_ENUM) && len <= rlen)
	{
	  /* For unsigned scalar type in a register */
	  ULONGEST i = extract_unsigned_integer (val, len, BFD_ENDIAN_LITTLE);
	  store_unsigned_integer (raw_args + Narg_slots * rlen, rlen, BFD_ENDIAN_LITTLE, i);
	  Narg_slots++;
	}
      else if ((typecode == TYPE_CODE_INT || typecode == TYPE_CODE_PTR) && len <= rlen)
	{
	  /* For signed scalar type in a register */
	  LONGEST i = extract_signed_integer (val, len, BFD_ENDIAN_LITTLE);
	  store_signed_integer (raw_args + Narg_slots * rlen, rlen, BFD_ENDIAN_LITTLE, i);
	  Narg_slots++;
	}
      else if (!is_var && typecode == TYPE_CODE_COMPLEX && len == 8
	       && TYPE_CODE (check_typedef (TYPE_TARGET_TYPE (arg_type)))
		    == TYPE_CODE_FLT
	       && Narg_slots < 7)
	{
	  /* For '_Complex float', sometimes we need two float registers */
	  memcpy (raw_args + Narg_slots * rlen, val, 4);
	  memcpy (raw_args + (Narg_slots + 1) * rlen, val + 4, 4);
	  Narg_slots += 2;
	}
      else
	{
	  /* Otherwise for bigger actual args, such as structure
	     or '_Complex double long' etc, we memcpy. */
	  memcpy (raw_args + Narg_slots * rlen, val, len);
	  Narg_slots += (len + rlen - 1) / rlen;
	}
    }

  /* 3. Write in stack and argument registers */
  if (8 < Narg_slots)
    sp -= (Narg_slots - 8) * rlen;
  sp = align_down (sp, 16);

  if (8 < Narg_slots)
    write_memory (sp, raw_args + 8 * rlen, (Narg_slots - 8) * rlen);

  auto regs = &gdbarch_tdep (gdbarch)->regs;
  regcache_cooked_write_signed (regcache, regs->ra, bp_addr);
  regcache_cooked_write_signed (regcache, regs->sp, sp);
  for (i = 0; i < (8 < Narg_slots ? 8 : Narg_slots); i++)
    {
      ULONGEST data = extract_unsigned_integer (raw_args + i * rlen, rlen, BFD_ENDIAN_LITTLE);
      regcache_cooked_write_unsigned (regcache, regs->r + 4/* $a0 */ + i, data);
      if (0 <= regs->f)
	regcache_cooked_write_unsigned (regcache, regs->f/* $fa0 */ + i, data);
    }

  return sp;
}

static void
loongarch_xfer_reg_part (struct regcache *regcache, int reg_num,
			 int len, gdb_byte *readbuf, size_t readbuf_off,
			 const gdb_byte *writebuf, size_t writebuf_off)
{
  if (readbuf)
    regcache->cooked_read_part (reg_num, 0, len, readbuf + readbuf_off);
  if (writebuf)
    regcache->cooked_write_part (reg_num, 0, len, writebuf + writebuf_off);
}

static enum return_value_convention
loongarch_xlp32lp64_return_value (struct gdbarch *gdbarch,
				  struct value *function,
				  struct type *type, struct regcache *regcache,
				  gdb_byte *readbuf, const gdb_byte *writebuf)
{
  const size_t rlen = loongarch_rlen (gdbarch) / 8;
  auto regs = &gdbarch_tdep (gdbarch)->regs;
  size_t len = TYPE_LENGTH (type);
  enum type_code typecode = TYPE_CODE (type);
  int fpu_exist = 0 <= regs->f;
  int fv = fpu_exist ? regs->f : regs->r + 4;

  gdb_assert (8 <= sizeof (LONGEST));

  gdb_assert (!fpu_exist || register_size (gdbarch, regs->f) == rlen);

  if (2 * rlen < len)
    return RETURN_VALUE_STRUCT_CONVENTION;

  if ((typecode == TYPE_CODE_FLT
       || (typecode == TYPE_CODE_STRUCT && TYPE_NFIELDS (type) == 1
	   && TYPE_CODE (check_typedef (TYPE_FIELD_TYPE (type, 0)))
		== TYPE_CODE_FLT))
      && len <= rlen/* FIXME: May fpu32 on loongarch32 */)
    /* If $fv0 could fit in. */
    loongarch_xfer_reg_part (regcache, fv, len, readbuf, 0, writebuf, 0);
  else if ((typecode == TYPE_CODE_FLT
	    || (typecode == TYPE_CODE_STRUCT && TYPE_NFIELDS (type) == 1
		&& TYPE_CODE (check_typedef (TYPE_FIELD_TYPE (type, 0)))
		    == TYPE_CODE_FLT)) && rlen < len && len <= 2 * rlen)
    /* For 'long double' on fpu64 or 'double' on fpu32,
       '$fv0 | $fv1' is that.*/
    loongarch_xfer_reg_part (regcache, fv, rlen, readbuf, 0, writebuf, 0)
      , loongarch_xfer_reg_part
	  (regcache, fv + 1, len - rlen, readbuf, rlen, writebuf, rlen);
  else if (typecode == TYPE_CODE_STRUCT && TYPE_NFIELDS (type) == 2
	   && TYPE_CODE (check_typedef (TYPE_FIELD_TYPE (type, 0)))
		== TYPE_CODE_FLT
	   && TYPE_CODE (check_typedef (TYPE_FIELD_TYPE (type, 1)))
		== TYPE_CODE_FLT)
    {
      /* For structure with two float member,
	 $fv0 is the 1st member and $fv1 is the 2nd member */
      int off = FIELD_BITPOS (TYPE_FIELDS (type)[1]) / TARGET_CHAR_BIT;
      int len1 = TYPE_LENGTH (check_typedef (TYPE_FIELD_TYPE (type, 0)));
      int len2 = TYPE_LENGTH (check_typedef (TYPE_FIELD_TYPE (type, 1)));
      loongarch_xfer_reg_part (regcache, fv, len1, readbuf, 0, writebuf, 0);
      loongarch_xfer_reg_part
	(regcache, fv + 1, len2, readbuf, off, writebuf, off);
    }
  else if (typecode == TYPE_CODE_COMPLEX
	   && TYPE_CODE (check_typedef (TYPE_TARGET_TYPE (type)))
		== TYPE_CODE_FLT)
    /* For '_Complex', $fv0 is real and $fv1 is img.  */
    loongarch_xfer_reg_part (regcache, fv, len / 2, readbuf, 0, writebuf, 0)
      , loongarch_xfer_reg_part
	  (regcache, fv + 1, len / 2, readbuf, len / 2, writebuf, len / 2);
  else if (((typecode == TYPE_CODE_INT && TYPE_UNSIGNED (type))
	    || typecode == TYPE_CODE_ENUM)
	   && len <= rlen)
    /* For unsigned scalar type, we have zero-extended one in $v0. */
    if (writebuf)
      {
	gdb_byte buf[rlen];
	store_signed_integer (buf, rlen, BFD_ENDIAN_LITTLE,
	  extract_unsigned_integer (writebuf, len, BFD_ENDIAN_LITTLE));
	loongarch_xfer_reg_part
	  (regcache, regs->r + 4, rlen, NULL, 0, writebuf, 0);
      }
    else
      loongarch_xfer_reg_part
	(regcache, regs->r + 4, len, readbuf, 0, NULL, 0);
  else if (((typecode == TYPE_CODE_INT && !TYPE_UNSIGNED (type))
	    || typecode == TYPE_CODE_PTR)
	   && len <= rlen)
    /* For signed scalar type, we have sign-extended one in $v0. */
    if (writebuf)
      {
	gdb_byte buf[rlen];
	store_signed_integer (buf, rlen, BFD_ENDIAN_LITTLE,
	  extract_signed_integer (writebuf, len, BFD_ENDIAN_LITTLE));
	loongarch_xfer_reg_part
	  (regcache, regs->r + 4, rlen, NULL, 0, writebuf, 0);
      }
    else
      loongarch_xfer_reg_part
	(regcache, regs->r + 4, len, readbuf, 0, NULL, 0);
  else
    {
      /* For small structure or int64_t on loongarch32 */
      if (len <= rlen)
	loongarch_xfer_reg_part
	  (regcache, regs->r + 4, len, readbuf, 0, writebuf, 0);
      else
	loongarch_xfer_reg_part
	  (regcache, regs->r + 4, rlen, readbuf, 0, writebuf, 0)
	    , loongarch_xfer_reg_part (regcache, regs->r + 5, len - rlen,
				       readbuf, rlen, writebuf, rlen);
    }

  return RETURN_VALUE_REGISTER_CONVENTION;
}

static int
loongarch_dwarf2_reg_to_regnum (struct gdbarch *gdbarch, int num)
{
  auto regs = &gdbarch_tdep (gdbarch)->regs;
  if (0 <= num && num < 32)
    return regs->r + num;
  else if (32 <= num && num < 64 && 0 <= regs->f)
    return regs->f + num - 32;
  else if (64 <= num && num < 72 && 0 <= regs->fcc)
    return regs->fcc + num - 64;
  else
    return -1;
}

static char *
loongarch_gcc_target_options (struct gdbarch *gdbarch)
{
  return NULL;
}

static int
loongarch_register_reggroup_p (struct gdbarch *gdbarch, int regnum,
			       struct reggroup *group)
{
  auto regs = &gdbarch_tdep (gdbarch)->regs;

  if (gdbarch_register_name (gdbarch, regnum) == NULL
      || *gdbarch_register_name (gdbarch, regnum) == '\0')
    return 0;

  int raw_p = regnum < gdbarch_num_regs (gdbarch);

  if (group == save_reggroup || group == restore_reggroup)
    return raw_p;
  if (group == all_reggroup)
    return 1;

  /* 重载默认的reggroup_p函数主要是为了自定义info register的寄存器显示。
     默认的reggroup_p对float_reggroup的判断是“register_type是不是浮点”，
     我在feature中对浮点寄存器设定的类型是union {float f; double d;}，
     因此reggroup_p默认情况下不认为浮点寄存器属于float_reggroup，info float
     就不打印浮点寄存器；info vector也是类似。info register默认会打印LBT
     寄存器，因为它们属于general_reggroup，但实际上这些寄存器相当特殊。 */

  if (group == general_reggroup
      && (regs->pc == regnum
      || regs->badvaddr == regnum
	  || (regs->r <= regnum && regnum < regs->r + 32)))
    return 1;

  /* Only $rx and $pc in general_reggroup */
  if (group == general_reggroup)
    return 0;

  if (0 <= regs->f
      && (regs->fcsr == regnum
	  || (regs->f <= regnum && regnum < regs->f + 32)
	  || (regs->fcc <= regnum && regnum < regs->fcc +8)))
    return group == float_reggroup;

  /* Only $fx / $fccx / $fcsr in float_reggroup */
  if (group == float_reggroup)
    return 0;

  if (0 <= regs->vr && regs->vr <= regnum && regnum < regs->vr + 32)
    if (group == vector_reggroup)
      return 1;

  if (0 <= regs->xr && regs->xr <= regnum && regnum < regs->xr + 32)
    if (group == vector_reggroup)
      return 1;

  int ret = tdesc_register_in_reggroup_p (gdbarch, regnum, group);
  if (ret != -1)
    return ret;

  return default_register_reggroup_p (gdbarch, regnum, group);
}

static void
loongarch_print_all_r_registers (struct gdbarch *gdbarch, struct ui_file *file,
				 struct frame_info *frame)
{
  int i, col;
  int rlen = loongarch_rlen (gdbarch) / 8;
  int ncols = rlen == 4 ? 8 : 4;

  for (i = 0; i < 32; i += ncols)
    {
      fprintf_filtered (file, "     ");
      for (col = 0; col < ncols; col++)
	fprintf_filtered (file, rlen == 8 ? "%17s" : "%9s",
			  gdbarch_register_name (gdbarch, i + col));

      fprintf_filtered (file, "\nR%-4d", i);

      for (col = 0; col < ncols; col++)
	{
	  const gdb_byte *raw_buffer;
	  struct value *value = get_frame_register_value (frame, i + col);
	  int byte;
	  if (value_optimized_out (value) || !value_entirely_available (value))
	    fprintf_filtered
	      (file, "%*s", 2 * rlen, rlen == 4 ? "<unavl>" : "<unavailable>");
	  else
	    {
	      int byte;
	      const gdb_byte *raw_buffer = value_contents_all (value);
	      for (byte = rlen - 1; 0 <= byte; byte--)
		fprintf_filtered (file, "%02x", raw_buffer[byte]);
	    }
	  fprintf_filtered (file, " ");
	}
      fprintf_filtered (file, "\n");
    }
}

static void
loongarch_print_registers_info (struct gdbarch *gdbarch, struct ui_file *file,
				struct frame_info *frame, int regnum, int all)
{
  int i;
  auto regs = &gdbarch_tdep (gdbarch)->regs;
  const int numregs = gdbarch_num_regs (gdbarch)
		    + gdbarch_num_pseudo_regs (gdbarch);

  for (i = 0; i < numregs; i++)
    {
      if (regnum == -1)
	{
	  if (regs->r == i)
	    loongarch_print_all_r_registers (gdbarch, file, frame), i += 32;

	  if (all)
	    {
	      if (!gdbarch_register_reggroup_p (gdbarch, i, all_reggroup))
		continue;
	    }
	  else
	    {
	      if (!gdbarch_register_reggroup_p (gdbarch, i, general_reggroup))
		continue;
	    }
	}
      else if (i != regnum)
	continue;

      if (gdbarch_register_name (gdbarch, i) == NULL
	  || *(gdbarch_register_name (gdbarch, i)) == '\0')
	continue;

      default_print_registers_info (gdbarch, file, frame, i, 0);
    }
}

constexpr gdb_byte loongarch_default_breakpoint[] = {0x05, 0x00, 0x2a, 0x00};
typedef BP_MANIPULATION (loongarch_default_breakpoint) loongarch_breakpoint;

/* Initialize the current architecture based on INFO.  If possible,
   re-use an architecture from ARCHES, which is a list of
   architectures already created during this debugging session.

   Called e.g. at program startup, when reading a core file, and when
   reading a binary file.  */


/* This predicate tests whether we need to read lsx/lasx registers 
   (instead of fp registers with the same DWARF2 code 
   (thus the same internal code, though lasx/lsx/fp reg internal codes are different))
   according to the byte-size of requested type. */

static int
loongarch_fp_regnum_refers_to_lsx_lasx_p (struct gdbarch *gdbarch, int regnum, struct type *type)
{
    /* Conditions:
       1) regnum is in "disputed" zone (fp/lsx/lasx, translated from dwarf regnum)
       2) type is larger than 8 bytes 

      (if specified type is larger than 8 bytes, 
       then regnum refers to lsx / lasx register instead of fp register) 
    */
    return
        regnum >= gdbarch_tdep(gdbarch)->regs.f
        && regnum < gdbarch_tdep(gdbarch)->regs.f + 32
        && TYPE_LENGTH (type) > 8;
}


static int
loongarch_convert_register_p (struct gdbarch *gdbarch,
                              int regnum, struct type *type)
{
    return loongarch_fp_regnum_refers_to_lsx_lasx_p (gdbarch, regnum, type);
}

static int
loongarch_register_to_value (struct frame_info *frame, int regnum,
                             struct type *type, gdb_byte *to,
                             int *optimizedp, int *unavailablep)
{
    struct gdbarch *gdbarch = get_frame_arch (frame);   

    if (loongarch_fp_regnum_refers_to_lsx_lasx_p (gdbarch, regnum, type))
    {
        /* Add a displacement to regnum */
        switch (TYPE_LENGTH (type))
        {
            case 16:  /* 16-byte types, access vr */
            if (!get_frame_register_bytes (frame, regnum + gdbarch_tdep(gdbarch)->regs.vr - gdbarch_tdep(gdbarch)->regs.f, 
                                      0, 16, to, optimizedp, unavailablep))
                return 0;
            break;


            case 32:  /* 32-byte types, access xr */
            if (!get_frame_register_bytes (frame, regnum + gdbarch_tdep(gdbarch)->regs.xr - gdbarch_tdep(gdbarch)->regs.f, 
                                      0, 32, to, optimizedp, unavailablep))
                return 0;
            break;

            default:
            goto fail;
        }

        *optimizedp = *unavailablep = 0;
        return 1;  // 1 for success, 0 for fail
    }

    fail:
    internal_error (__FILE__, __LINE__,
                    _("loongarch_register_to_value: unrecognized case"));
}

static void
loongarch_value_to_register (struct frame_info *frame, int regnum,
                             struct type *type, const gdb_byte *from)
{
    struct gdbarch *gdbarch = get_frame_arch (frame);
    if (loongarch_fp_regnum_refers_to_lsx_lasx_p (gdbarch, regnum, type))
    {
        switch (TYPE_LENGTH (type))
        {
            case 16:  /* 16-byte types, access vr */
            put_frame_register (frame, 
                regnum + gdbarch_tdep(gdbarch)->regs.vr - gdbarch_tdep(gdbarch)->regs.f, from);
            return;

            case 32:  /* 32-byte types, access xr */
            put_frame_register (frame, 
                regnum + gdbarch_tdep(gdbarch)->regs.xr - gdbarch_tdep(gdbarch)->regs.f, from);
            return;
        }
    }

    internal_error (__FILE__, __LINE__,
                    _("loongarch_value_to_register: unrecognized case"));
}


static struct gdbarch *
loongarch_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch;
  struct gdbarch_tdep tdep_instant, *tdep;
  struct tdesc_arch_data *tdesc_data = NULL;
  const struct target_desc *tdesc = info.target_desc;
  int i;
  size_t regnum;

  tdep = &tdep_instant;
  memset (tdep, 0, sizeof (tdep));
  memset (&tdep->regs, -1, sizeof (tdep->regs));

  if (info.abfd != NULL
      && bfd_get_flavour (info.abfd) == bfd_target_elf_flavour)
    {
      unsigned char eclass = elf_elfheader (info.abfd)->e_ident[EI_CLASS];
      int e_flags = elf_elfheader (info.abfd)->e_flags;
      auto e_abi = e_flags & EF_LARCH_ABI;

      switch (e_abi)
	{
	case EF_LARCH_ABI_XLP32:
	case EF_LARCH_ABI_LP32:
	case EF_LARCH_ABI_LP64:
	  tdep->ef_abi = e_abi;
	  break;
	default:
	  tdep->ef_abi = EF_LARCH_ABI_LP64;
	}
    }
  else
    tdep->ef_abi = EF_LARCH_ABI_LP64;

  /* Check any target description for validity.  */
  if (!tdesc_has_registers (tdesc))
    tdesc = loongarch_get_base_target_description
	      (tdep->ef_abi == EF_LARCH_ABI_LP32 ? 32 : 64);

  int valid_p = 1;
  const struct tdesc_feature *feature;

  feature = tdesc_find_feature (tdesc, "org.gnu.gdb.loongarch.base");
  if (feature == NULL)
    return NULL;
  regnum = 0;
  tdesc_data = tdesc_data_alloc ();

  tdep->regs.r = regnum;
  for (i = 0; i < 32; i++)
    valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++,
					loongarch_r_normal_name[i] + 1);
  valid_p &= tdesc_numbered_register
	       (feature, tdesc_data, tdep->regs.pc = regnum++, "pc");
  valid_p &= tdesc_numbered_register
           (feature, tdesc_data, tdep->regs.badvaddr = regnum++, "badvaddr");

  if ((feature = tdesc_find_feature (tdesc, "org.gnu.gdb.loongarch.fpu")))
    {
      tdep->regs.f = regnum;
      for (i = 0; i < 32; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++,
					    loongarch_f_normal_name[i] + 1);
      tdep->regs.fcc = regnum;
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc0");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc1");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc2");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc3");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc4");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc5");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc6");
      valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++, "fcc7");
      valid_p &= tdesc_numbered_register
	(feature, tdesc_data, tdep->regs.fcsr = regnum++, "fcsr");
    }

  if ((feature = tdesc_find_feature (tdesc, "org.gnu.gdb.loongarch.lbt")))
    {
      tdep->regs.scr = regnum;
      for (i = 0; i < 4; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++,
					    loongarch_cr_normal_name[i] + 1);
      valid_p &= tdesc_numbered_register
	(feature, tdesc_data, tdep->regs.EFLAG = regnum++, "EFLAG");
      valid_p &= tdesc_numbered_register
	(feature, tdesc_data, tdep->regs.x86_top = regnum++, "x86_top");
    }

  if ((feature = tdesc_find_feature (tdesc, "org.gnu.gdb.loongarch.lsx")))
    {
      tdep->regs.vr = regnum;
      for (i = 0; i < 32; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++,
					    loongarch_v_normal_name[i] + 1);
    }

  if ((feature = tdesc_find_feature (tdesc, "org.gnu.gdb.loongarch.lasx")))
    {
      tdep->regs.xr = regnum;
      for (i = 0; i < 32; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data, regnum++,
					    loongarch_x_normal_name[i] + 1);
    }

  if (!valid_p)
    {
      tdesc_data_cleanup (tdesc_data);
      return NULL;
    }

  info.byte_order_for_code = BFD_ENDIAN_LITTLE;

  /* Find a candidate among the list of pre-declared architectures.  */
  for (arches = gdbarch_list_lookup_by_info (arches, &info);
       arches != NULL;
       arches = gdbarch_list_lookup_by_info (arches->next, &info))
    {
      if (gdbarch_tdep (arches->gdbarch)->ef_abi != tdep->ef_abi)
	continue;

      if (tdesc_data != NULL)
	tdesc_data_cleanup (tdesc_data);

      return arches->gdbarch;
    }

  /* None found, so create a new architecture from the information provided.  */
  tdep = (struct gdbarch_tdep *) xmalloc (sizeof (tdep_instant));
  memcpy (tdep, &tdep_instant, sizeof (tdep_instant));
  gdbarch = gdbarch_alloc (&info, tdep);

  /* Target data types.  */
  switch (tdep->ef_abi)
    {
    case EF_LARCH_ABI_XLP32:
      set_gdbarch_short_bit (gdbarch, 16);
      set_gdbarch_int_bit (gdbarch, 32);
      set_gdbarch_long_bit (gdbarch, 64);
      set_gdbarch_long_long_bit (gdbarch, 64);
      set_gdbarch_float_bit (gdbarch, 32);
      set_gdbarch_double_bit (gdbarch, 64);
      set_gdbarch_long_double_bit (gdbarch, 128);
      set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
      set_gdbarch_ptr_bit (gdbarch, 32);
      set_gdbarch_char_signed (gdbarch, 0);
      break;
    case EF_LARCH_ABI_LP32:
      set_gdbarch_short_bit (gdbarch, 16);
      set_gdbarch_int_bit (gdbarch, 32);
      set_gdbarch_long_bit (gdbarch, 32);
      set_gdbarch_long_long_bit (gdbarch, 32);
      set_gdbarch_float_bit (gdbarch, 32);
      set_gdbarch_double_bit (gdbarch, 64);
      set_gdbarch_long_double_bit (gdbarch, 128);
      set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
      set_gdbarch_ptr_bit (gdbarch, 32);
      set_gdbarch_char_signed (gdbarch, 0);
      break;
    case EF_LARCH_ABI_LP64:
      set_gdbarch_short_bit (gdbarch, 16);
      set_gdbarch_int_bit (gdbarch, 32);
      set_gdbarch_long_bit (gdbarch, 64);
      set_gdbarch_long_long_bit (gdbarch, 64);
      set_gdbarch_float_bit (gdbarch, 32);
      set_gdbarch_double_bit (gdbarch, 64);
      set_gdbarch_long_double_bit (gdbarch, 128);
      set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
      set_gdbarch_ptr_bit (gdbarch, 64);
      set_gdbarch_char_signed (gdbarch, 0);

      tdep->regs.ra = tdep->regs.r + 1;
      tdep->regs.sp = tdep->regs.r + 3;

      for (i = 0; i < ARRAY_SIZE (loongarch_r_normal_name); ++i)
	if (loongarch_r_normal_name[i][0] != '\0')
	  user_reg_add (gdbarch, loongarch_r_normal_name[i] + 1,
	    value_of_loongarch_user_reg, (void *) (size_t) (tdep->regs.r + i));

      for (i = 0; i < ARRAY_SIZE (loongarch_r_lp64_name); ++i)
	if (loongarch_r_lp64_name[i][0] != '\0')
	  user_reg_add (gdbarch, loongarch_r_lp64_name[i] + 1,
	    value_of_loongarch_user_reg, (void *) (size_t) (tdep->regs.r + i));

      for (i = 0; i < ARRAY_SIZE (loongarch_r_lp64_name1); ++i)
	if (loongarch_r_lp64_name[i][0] != '\0')
	  user_reg_add (gdbarch, loongarch_r_lp64_name1[i] + 1,
	    value_of_loongarch_user_reg, (void *) (size_t) (tdep->regs.r + i));

      /* Functions handling dummy frames.  */
      set_gdbarch_push_dummy_call
	(gdbarch, loongarch_xlp32lp64_push_dummy_call);
      set_gdbarch_return_value (gdbarch, loongarch_xlp32lp64_return_value);

      break;
    default:
      gdb_assert_not_reached ("unknown ABI");
    }

  /* Register architecture.  */
  set_gdbarch_num_regs (gdbarch, regnum);
  set_gdbarch_sp_regnum (gdbarch, tdep->regs.sp);
  set_gdbarch_pc_regnum (gdbarch, tdep->regs.pc);
//   set_gdbarch_ps_regnum (gdbarch, loongarch_FP_REGNUM);
//   set_gdbarch_deprecated_fp_regnum (gdbarch, loongarch_FP_REGNUM);

  tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  /* Functions to supply register information.  */
  set_gdbarch_register_name (gdbarch, loongarch_register_name);

  /* Handle overlapping dwarf2 register code for fp/lsx/lasx */
  set_gdbarch_convert_register_p (gdbarch, loongarch_convert_register_p);
  set_gdbarch_register_to_value (gdbarch, loongarch_register_to_value);
  set_gdbarch_value_to_register (gdbarch, loongarch_value_to_register);

  /* Functions to analyze frames.  */
  set_gdbarch_skip_prologue (gdbarch, loongarch_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
  set_gdbarch_frame_align (gdbarch, loongarch_frame_align);

  /* Functions to access frame data.  */
  set_gdbarch_unwind_pc (gdbarch, loongarch_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, loongarch_unwind_sp);

  set_gdbarch_dummy_id (gdbarch, loongarch_dummy_id);

  set_gdbarch_software_single_step (gdbarch, loongarch_software_single_step);

  set_gdbarch_breakpoint_kind_from_pc (gdbarch, loongarch_breakpoint::kind_from_pc);
  set_gdbarch_sw_breakpoint_from_kind (gdbarch, loongarch_breakpoint::bp_from_kind);

  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);

  /* Virtual tables.  */
  set_gdbarch_vbit_in_delta (gdbarch, 1);

  set_gdbarch_gcc_target_options (gdbarch, loongarch_gcc_target_options);

  /* Hook in OS ABI-specific overrides, if they have been registered.  */
  info.target_desc = tdesc;
  info.tdesc_data = tdesc_data;
  gdbarch_init_osabi (info, gdbarch);
  set_gdbarch_register_reggroup_p (gdbarch, loongarch_register_reggroup_p);
  set_gdbarch_register_name (gdbarch, loongarch_register_name);
  set_gdbarch_print_registers_info (gdbarch, loongarch_print_registers_info);

  /* Frame unwinders.  Use DWARF debug info if available, otherwise use our own
     unwinder.  */
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, loongarch_dwarf2_reg_to_regnum);
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &loongarch_frame_unwind);

  return gdbarch;
}


/* Allocate new loongarch_inferior_data object.  */

// static struct loongarch_inferior_data *
// loongarch_new_inferior_data (void)
// {
//   struct loongarch_inferior_data *inf_data
//     = new (struct loongarch_inferior_data);
//   inf_data->misa_read = false;
//   return inf_data;
// }

/* Free inferior data.  */

// static void
// loongarch_inferior_data_cleanup (struct inferior *inf, void *data)
// {
//   struct loongarch_inferior_data *inf_data =
//     static_cast <struct loongarch_inferior_data *> (data);
//   delete (inf_data);
// }

/* Return loongarch_inferior_data for the given INFERIOR.  If not yet created,
   construct it.  */

// struct loongarch_inferior_data *
// loongarch_inferior_data (struct inferior *const inf)
// {
//   struct loongarch_inferior_data *inf_data;

//   gdb_assert (inf != NULL);

//   inf_data
//     = (struct loongarch_inferior_data *) inferior_data (inf, loongarch_inferior_data_reg);
//   if (inf_data == NULL)
//     {
//       inf_data = loongarch_new_inferior_data ();
//       set_inferior_data (inf, loongarch_inferior_data_reg, inf_data);
//     }

//   return inf_data;
// }

/* Free the inferior data when an inferior exits.  */

// static void
// loongarch_invalidate_inferior_data (struct inferior *inf)
// {
//   struct loongarch_inferior_data *inf_data;

//   gdb_assert (inf != NULL);

//   /* Don't call loongarch_INFERIOR_DATA as we don't want to create the data if
//      we've not already created it by this point.  */
//   inf_data
//     = (struct loongarch_inferior_data *) inferior_data (inf, loongarch_inferior_data_reg);
//   if (inf_data != NULL)
//     {
//       delete (inf_data);
//       set_inferior_data (inf, loongarch_inferior_data_reg, NULL);
//     }
// }

static void
info_loongarch (const char *addr_exp, int from_tty)
{
  char *buf, *t;
  int set;
  char *item;
  unsigned long addr;
  unsigned long long value;

  if (addr_exp)
    {
      addr_exp = skip_spaces (addr_exp);
      buf = (char *) alloca (strlen (addr_exp) + 1);
      strcpy (buf, addr_exp);
      loongarch_eliminate_adjacent_repeat_char (buf, ' ');
    }
  else
    goto Empty;

  if (!(t = strtok (buf, " ")))
    goto Empty;
  if (strcmp (t, "set") == 0)
    {
      t = strtok (NULL, " ");
      set = 1;
    }
  else
    {
      if (strcmp (t, "get") == 0)
	t = strtok (NULL, " ");
      set = 0;
    }
  if (!(item = t))
    goto Empty;
  if (!(t = strtok (NULL, " ")))
    goto Empty;
  addr = strtoul (t, NULL, 0);
  if (set && (t = strtok (NULL, " ")) == NULL)
    goto Empty;
  value = strtoll (t, NULL, 0);

  if (set)
    if (strcmp (item, "cpucfg") == 0)
      {
	uint32_t t = value;
	ULONGEST xfered_len;
	target_xfer_partial (current_top_target (), TARGET_OBJECT_LARCH,
	                     "cpucfg", NULL, (const gdb_byte *) &t, addr * 4, sizeof (t),
	                     &xfered_len);
	if (0 < xfered_len)
	  fprintf_unfiltered (gdb_stdout, "ok\n");
	else
	  error ("Set failed");
      }
    else
      {
	uint64_t t = value;
	ULONGEST xfered_len;
	target_xfer_partial (current_top_target (), TARGET_OBJECT_LARCH,
			     item, NULL, (const gdb_byte *) &t, addr * 8, sizeof (t),
			     &xfered_len);
	if (0 < xfered_len)
	  fprintf_unfiltered (gdb_stdout, "ok\n");
	else
	  error ("Set failed");
      }
  else
    if (strcmp (item, "cpucfg") == 0)
      {
	uint32_t t;
	ULONGEST xfered_len;
	target_xfer_partial (current_top_target (), TARGET_OBJECT_LARCH,
			     "cpucfg", (gdb_byte *) &t, NULL, addr * 4, sizeof (t),
			     &xfered_len);
	if (0 < xfered_len)
	  fprintf_unfiltered (gdb_stdout, "return is %x\n", t);
	else
	  error ("Get failed");
      }
    else
      {
	uint64_t t;
	ULONGEST xfered_len;
	target_xfer_partial (current_top_target (), TARGET_OBJECT_LARCH,
			     item, (gdb_byte *) &t, NULL, addr * 8, sizeof (t),
			     &xfered_len);
	if (0 < xfered_len)
	  fprintf_unfiltered (gdb_stdout, "return is %llx\n", (long long) t);
	else
	  error ("Get failed");
      }

  return;
Empty:
  error ("Empty. Should be 'info loongarch ([get]|set) item addr [value]'");
}

void
_initialize_loongarch_tdep (void)
{
  gdbarch_register (bfd_arch_loongarch, loongarch_gdbarch_init, NULL);

  add_info ("loongarch", info_loongarch, _("Loongarch extra"));

  /* Debug this files internals.  */
  add_setshow_zuinteger_cmd ("loongarch", class_maintenance,
			     &loongarch_debug, _("\
Set loongarch debugging."), _("\
Show loongarch debugging."), _("\
When non-zero, loongarch specific debugging is enabled."),
			     NULL,
			     NULL,
			     &setdebuglist, &showdebuglist);
}
