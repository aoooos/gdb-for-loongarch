/* GNU/Linux/MIPS specific low level interface, for the remote server for GDB.
   Copyright (C) 1995-2018 Free Software Foundation, Inc.

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

#include "server.h"
#include "linux-low.h"

#include "nat/gdb_ptrace.h"

#include "gdb_proc_service.h"
#include "arch/loongarch.h"
#include "arch/loongarch-linux-nat.h"
#include "elf/common.h"
#include "tdesc.h"

static void
mips_arch_setup (void)
{
  int pid = lwpid_of (current_thread);
  struct target_desc *tdesc = loongarch_linux_read_description_runtime (pid);
  init_target_desc (tdesc, loongarch_expedite_regs);
  current_process ()->tdesc = tdesc;
}

/* Pseudo registers can not be read.  ptrace does not provide a way to
   read (or set) PS_REGNUM, and there's no point in reading or setting
   ZERO_REGNUM, it's always 0.  We also can not set BADVADDR, CAUSE,
   or FCRIR via ptrace().  */

static int
mips_cannot_fetch_register (int regno)
{
  const struct target_desc *tdesc;

  return 0;
}

static int
mips_cannot_store_register (int regno)
{
  const struct target_desc *tdesc;
//  /* On n32 we can't access 64-bit registers via PTRACE_POKEUSR.  */
//  if (register_size (tdesc, regno) > sizeof (PTRACE_XFER_TYPE))
//    return 1;

  return 0;
}

static int
mips_fetch_register (struct regcache *regcache, int regno)
{
  const struct target_desc *tdesc = current_process ()->tdesc;

  if (find_regno (tdesc, "r0") == regno)
    {
      supply_register_zeroed (regcache, regno);
      return 1;
    }

  return 0;
}

static CORE_ADDR
mips_get_pc (struct regcache *regcache)
{
  int regno = find_regno (regcache->tdesc, "pc");
  if (register_size (regcache->tdesc, regno) == 4)
    {
      int32_t pc;
      collect_register (regcache, regno, &pc);
      return pc;
    }
  else
    {
      int64_t pc;
      collect_register (regcache, regno, &pc);
      return pc;
    }
}

static void
mips_set_pc (struct regcache *regcache, CORE_ADDR pc)
{
  supply_register_by_name (regcache, "pc", &pc);
}

/* Correct in either endianness.  */
static const unsigned int mips_breakpoint = 0x002a0005;
#define mips_breakpoint_len 4

/* Implementation of linux_target_ops method "sw_breakpoint_from_kind".  */

static const gdb_byte *
mips_sw_breakpoint_from_kind (int kind, int *size)
{
  *size = mips_breakpoint_len;
  return (const gdb_byte *) &mips_breakpoint;
}

static int
mips_breakpoint_at (CORE_ADDR where)
{
  uint32_t insn;

  (*the_target->read_memory) (where, (unsigned char *) &insn, 4);
  if (insn == mips_breakpoint)
    return 1;

  /* If necessary, recognize more trap instructions here.  GDB only uses the
     one.  */
  return 0;
}

static void
mips_fill_gregset (struct regcache *regcache, void *buf)
{
  int i, r = find_regno (regcache->tdesc, "r0");

  for (i = 0; i < 32; i++)
    collect_register (regcache, r + i, (uint64_t *) buf + i);
  collect_register_by_name (regcache, "pc", (uint64_t *) buf + 32);
}

static void
mips_store_gregset (struct regcache *regcache, const void *buf)
{
  int i, r = find_regno (regcache->tdesc, "r0");

  supply_register_zeroed (regcache, r);
  for (i = 1; i < 32; i++)
    supply_register (regcache, r + i, (const uint64_t *) buf + i);
  supply_register_by_name (regcache, "pc", (const uint64_t *) buf + 32);
}

static void
mips_fill_fpregset (struct regcache *regcache, void *buf)
{
  int i, f, fcc;
  f = find_regno (regcache->tdesc, "f0");
  fcc = find_regno (regcache->tdesc, "fcc0");
  uint8_t *fccs = (uint8_t *) ((uint64_t *) buf + 32);

  for (i = 0; i < 32; i++)
    collect_register (regcache, f + i, (uint64_t *) buf + i);
  for (i = 0; i < 8; i++)
    collect_register (regcache, fcc + i, fccs + i);
  collect_register_by_name (regcache, "fcsr", (uint64_t *) buf + 33);
}

static void
mips_store_fpregset (struct regcache *regcache, const void *buf)
{
  int i, f, fcc;
  f = find_regno (regcache->tdesc, "f0");
  fcc = find_regno (regcache->tdesc, "fcc0");
  const uint8_t *fccs = (const uint8_t *) ((const uint64_t *) buf + 32);

  for (i = 0; i < 32; i++)
    supply_register (regcache, f + i, (const uint64_t *) buf + i);
  for (i = 0; i < 8; i++)
    supply_register (regcache, fcc + i, fccs + i);
  supply_register_by_name (regcache, "fcsr", (const uint64_t *) buf + 33);
}

static void
mips_fill_lbtregset (struct regcache *regcache, void *buf)
{
  int i, scr = find_regno (regcache->tdesc, "scr0");

  for (i = 0; i < 4; i++)
    collect_register (regcache, scr + i, (uint64_t *) buf + i);
  collect_register_by_name (regcache, "EFLAG", (uint64_t *) buf + 4);
  collect_register_by_name (regcache, "x86_top", (uint32_t *) buf + 9);
}

static void
mips_store_lbtregset (struct regcache *regcache, const void *buf)
{
  int i, scr = find_regno (regcache->tdesc, "scr0");

  for (i = 0; i < 4; i++)
    supply_register (regcache, scr + i, (const uint64_t *) buf + i);
  supply_register_by_name (regcache, "EFLAG", (const uint64_t *) buf + 4);
  supply_register_by_name (regcache, "x86_top", (const uint32_t *) buf + 9);
}

static void
mips_fill_lsxregset (struct regcache *regcache, void *buf)
{
  int i, vr = find_regno (regcache->tdesc, "vr0");

  for (i = 0; i < 32; i++)
    collect_register (regcache, vr + i, (uint64_t *) buf + 2 * i);
}

static void
mips_store_lsxregset (struct regcache *regcache, const void *buf)
{
  int i, vr = find_regno (regcache->tdesc, "vr0");

  for (i = 1; i < 32; i++)
    supply_register (regcache, vr + i, (const uint64_t *) buf + 2 * i);
}

static void
mips_fill_lasxregset (struct regcache *regcache, void *buf)
{
  int i, xr = find_regno (regcache->tdesc, "xr0");

  for (i = 0; i < 32; i++)
    collect_register (regcache, xr + i, (uint64_t *) buf + 4 * i);
}

static void
mips_store_lasxregset (struct regcache *regcache, const void *buf)
{
  int i, xr = find_regno (regcache->tdesc, "xr0");

  for (i = 1; i < 32; i++)
    supply_register (regcache, xr + i, (const uint64_t *) buf + 4 * i);
}

static struct regset_info mips_regsets[] = {
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS, 33 * 8, GENERAL_REGS,
    mips_fill_gregset, mips_store_gregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET, 34 * 8, FP_REGS,
    mips_fill_fpregset, mips_store_fpregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_LARCH_LBT, 5 * 8, EXTENDED_REGS,
    mips_fill_lbtregset, mips_store_lbtregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_LARCH_LSX, 32 * 16, EXTENDED_REGS,
    mips_fill_lsxregset, mips_store_lsxregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_LARCH_LASX, 32 * 32, EXTENDED_REGS,
    mips_fill_lasxregset, mips_store_lasxregset },
  NULL_REGSET
};

static struct regsets_info mips_regsets_info =
  {
    mips_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct regs_info regs_info =
  {
    NULL, /* regset_bitmap */
    NULL,
    &mips_regsets_info
  };

static const struct regs_info *
mips_regs_info (void)
{
  return &regs_info;
}

struct linux_target_ops the_low_target = {
  mips_arch_setup,
  mips_regs_info,
  mips_cannot_fetch_register,
  mips_cannot_store_register,
  mips_fetch_register,
  mips_get_pc,
  mips_set_pc,
  NULL, /* breakpoint_kind_from_pc */
  mips_sw_breakpoint_from_kind,
  NULL, /* get_next_pcs */
  0,
  mips_breakpoint_at,
  //mips_supports_z_point_type,
  //mips_insert_point,
  //mips_remove_point,
  //mips_stopped_by_watchpoint,
  //mips_stopped_data_address,
  //mips_collect_ptrace_register,
  //mips_supply_ptrace_register,
  //NULL, /* siginfo_fixup */
};

void
initialize_low_arch (void)
{
  initialize_regsets_info (&mips_regsets_info);
}
