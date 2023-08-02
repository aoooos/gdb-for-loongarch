#include "defs.h"
#include "inferior.h"
#include "gdbcore.h"
#include "target.h"
#include "solib-svr4.h"
#include "osabi.h"
#include "loongarch-tdep.h"
#include "frame.h"
#include "regcache.h"
#include "trad-frame.h"
#include "tramp-frame.h"
#include "gdbtypes.h"
#include "objfiles.h"
#include "solib.h"
#include "solist.h"
#include "symtab.h"
#include "target-descriptions.h"
#include "loongarch-linux-tdep.h"
#include "glibc-tdep.h"
#include "linux-tdep.h"
#include "xml-syscall.h"
#include "gdb_signals.h"

static void
loongarch_supply_elf_gregset (const struct regset *r,
			      struct regcache *regcache,
			      int regno, const void *gprs, size_t len)
{
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->r && sizeof (loongarch_elf_gregset_t) <= len);

  if (regno == -1)
    {
      size_t i;
      for (i = 0; i < 32; i++)
	loongarch_supply_elf_gregset (r, regcache, regs->r + i, gprs, len);
      loongarch_supply_elf_gregset (r, regcache, regs->pc, gprs, len);
      loongarch_supply_elf_gregset (r, regcache, regs->badvaddr, gprs, len);
    }
  else if (regs->r == regno)
    regcache->raw_supply_zeroed (regs->r);
  else if (regs->r < regno && regno < regs->r + 32)
    regcache->raw_supply (regno, (const uint64_t *) gprs + regno - regs->r);
  else if (regs->pc == regno)
    regcache->raw_supply (regno, (const uint64_t *) gprs + 32);
  else if (regs->badvaddr == regno)
    regcache->raw_supply (regno, (const uint64_t *) gprs + 33);
}

static void
loongarch_fill_elf_gregset (const struct regset *r,
			    const struct regcache *regcache, int regno,
			    void *gprs, size_t len)
{
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->r && sizeof (loongarch_elf_gregset_t) <= len);

  if (regno == -1)
    {
      size_t i;
      for (i = 0; i < 32; i++)
	loongarch_fill_elf_gregset (r, regcache, regs->r + i, gprs, len);
      loongarch_fill_elf_gregset (r, regcache, regs->pc, gprs, len);
    }
  else if (regs->r <= regno && regno < regs->r + 32)
    regcache->raw_collect (regno, (uint64_t *) gprs + regno - regs->r);
  else if (regs->pc == regno)
    regcache->raw_collect (regno, (uint64_t *) gprs + 32);
}

const struct regset loongarch_elf_gregset = {
  NULL, loongarch_supply_elf_gregset, loongarch_fill_elf_gregset,
};

static void
loongarch_supply_elf_fpregset (const struct regset *r,
			       struct regcache *regcache,
			       int regno, const void *fprs, size_t len)
{
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->f && sizeof (loongarch_elf_fpregset_t) <= len);

  if (regno == -1)
    {
      size_t i;
      for (i = 0; i < 32; i++)
	loongarch_supply_elf_fpregset (r, regcache, regs->f + i, fprs, len);
      for (i = 0; i < 8; i++)
	loongarch_supply_elf_fpregset (r, regcache, regs->fcc + i, fprs, len);
      loongarch_supply_elf_fpregset (r, regcache, regs->fcsr, fprs, len);
    }
  else if (regs->f <= regno && regno < regs->f + 32)
    regcache->raw_supply (regno, (const uint64_t *) fprs + regno - regs->f);
  else if (regs->fcc <= regno && regno < regs->fcc + 8)
    {
      const uint8_t *fcc = (const uint8_t *) ((const uint64_t *) fprs + 32);
      regcache->raw_supply_integer (regno, fcc + regno - regs->fcc, 1, false);
    }
  else if (regs->fcsr == regno)
    regcache->raw_supply_integer
      (regno, (const gdb_byte *) ((const uint64_t *) fprs + 33), 4, false);
}

static void
loongarch_fill_elf_fpregset (const struct regset *r,
			     const struct regcache *regcache, int regno,
			     void *fprs, size_t len)
{
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->f && sizeof (loongarch_elf_fpregset_t) <= len);

  if (regno == -1)
    {
      size_t i;
      for (i = 0; i < 32; i++)
        loongarch_fill_elf_fpregset (r, regcache, regs->f + i, fprs, len);
      for (i = 0; i < 8; i++)
	loongarch_fill_elf_fpregset (r, regcache, regs->fcc + i, fprs, len);
      loongarch_fill_elf_fpregset (r, regcache, regs->fcsr, fprs, len);
    }
  else if (regs->f <= regno && regno < regs->f + 32)
    regcache->raw_collect (regno, (uint64_t *) fprs + regno - regs->f);
  else if (regs->fcc <= regno && regno < regs->fcc + 8)
    {
      uint8_t *fcc = (uint8_t *) ((uint64_t *) fprs + 32);
      regcache->raw_collect (regno, fcc + regno - regs->fcc);
    }
  else if (regs->fcsr == regno)
    regcache->raw_collect_integer
      (regno, (gdb_byte *) ((uint64_t *) fprs + 33), 4, false);
}

const struct regset loongarch_elf_fpregset = {
  NULL, loongarch_supply_elf_fpregset, loongarch_fill_elf_fpregset,
};

static void
loongarch_supply_elf_cpucfgregset (const struct regset *r,
				   struct regcache *regcache,
				   int regno, const void *cpucfgs, size_t len)
{
}

static void
loongarch_fill_elf_cpucfgregset (const struct regset *r,
				 const struct regcache *regcache, int regno,
				 void *cpucfgs, size_t len)
{
  ULONGEST xfered_len;
  target_xfer_partial (current_top_target (), TARGET_OBJECT_LARCH, "cpucfg",
		       (gdb_byte *) cpucfgs, NULL, 0, len, &xfered_len);
  memset ((gdb_byte *) cpucfgs + xfered_len, 0, len - xfered_len);
}

const struct regset loongarch_elf_cpucfgregset = {
  NULL, loongarch_supply_elf_cpucfgregset, loongarch_fill_elf_cpucfgregset,
};

static void
loongarch_supply_elf_lbtregset (const struct regset *r,
				struct regcache *regcache,
				int regno, const void *lbtrs, size_t len)
{
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->scr && sizeof (loongarch_elf_lbtregset_t) <= len);

  if (regno == -1)
    {
      size_t i;
      for (i = 0; i < 4; i++)
	loongarch_supply_elf_lbtregset (r, regcache, regs->scr + i, lbtrs, len);
      loongarch_supply_elf_lbtregset (r, regcache, regs->EFLAG, lbtrs, len);
      loongarch_supply_elf_lbtregset (r, regcache, regs->x86_top, lbtrs, len);
    }
  else if (regs->scr <= regno && regno < regs->scr + 4)
    regcache->raw_supply (regno, (const uint64_t *) lbtrs + regno - regs->scr);
  else if (regs->EFLAG == regno)
    regcache->raw_supply (regno, (const uint64_t *) lbtrs + 4);
  else if (regs->x86_top == regno)
    regcache->raw_supply (regno, (const uint32_t *) lbtrs + 9);
}

static void
loongarch_fill_elf_lbtregset (const struct regset *r,
			      const struct regcache *regcache, int regno,
			      void *lbtrs, size_t len)
{
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->scr && sizeof (loongarch_elf_lbtregset_t) <= len);

  if (regno == -1)
    {
      size_t i;
      for (i = 0; i < 4; i++)
	loongarch_fill_elf_lbtregset (r, regcache, regs->scr + i, lbtrs, len);
      loongarch_fill_elf_lbtregset (r, regcache, regs->EFLAG, lbtrs, len);
      loongarch_fill_elf_lbtregset (r, regcache, regs->x86_top, lbtrs, len);
    }
  else if (regs->scr <= regno && regno < regs->scr + 4)
    regcache->raw_collect (regno, (uint64_t *) lbtrs + regno - regs->scr);
  else if (regs->EFLAG == regno)
    regcache->raw_collect (regno, (uint64_t *) lbtrs + 4);
  else if (regs->x86_top == regno)
    regcache->raw_collect (regno, (uint32_t *) lbtrs + 9);
}

const struct regset loongarch_elf_lbtregset = {
  NULL, loongarch_supply_elf_lbtregset, loongarch_fill_elf_lbtregset,
};

static void
loongarch_supply_elf_lsxregset (const struct regset *r,
				struct regcache *regcache,
				int regno, const void *lsxrs, size_t len)
{
  size_t i;
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->vr && sizeof (loongarch_elf_lsxregset_t) <= len);

  if (regno == -1)
    for (i = 0; i < 32; i++)
      loongarch_supply_elf_lsxregset (r, regcache, regs->vr + i, lsxrs, len);
  else if (regs->vr <= regno && regno < regs->vr + 32)
    regcache->raw_supply
      (regno, (const char *) lsxrs + (regno - regs->vr) * 16);
}

static void
loongarch_fill_elf_lsxregset (const struct regset *r,
			      const struct regcache *regcache, int regno,
			      void *lsxrs, size_t len)
{
  size_t i;
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->vr && sizeof (loongarch_elf_lsxregset_t) <= len);

  if (regno == -1)
    for (i = 0; i < 32; i++)
      loongarch_fill_elf_lsxregset (r, regcache, regs->vr + i, lsxrs, len);
  else if (regs->vr <= regno && regno < regs->vr + 32)
    regcache->raw_collect (regno, (char *) lsxrs + (regno - regs->vr) * 16);
}

const struct regset loongarch_elf_lsxregset = {
  NULL, loongarch_supply_elf_lsxregset, loongarch_fill_elf_lsxregset,
};

static void
loongarch_supply_elf_lasxregset (const struct regset *r,
				 struct regcache *regcache,
				 int regno, const void *lasxrs, size_t len)
{
  size_t i;
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->xr && sizeof (loongarch_elf_lasxregset_t) <= len);

  if (regno == -1)
    for (i = 0; i < 32; i++)
      loongarch_supply_elf_lasxregset (r, regcache, regs->xr + i, lasxrs, len);
  else if (regs->xr <= regno && regno < regs->xr + 32)
    regcache->raw_supply
      (regno, (const char *) lasxrs + (regno - regs->xr) * 32);
}

static void
loongarch_fill_elf_lasxregset (const struct regset *r,
			       const struct regcache *regcache, int regno,
			       void *lasxrs, size_t len)
{
  size_t i;
  auto regs = &gdbarch_tdep (regcache->arch ())->regs;
  gdb_assert (0 <= regs->xr && sizeof (loongarch_elf_lasxregset_t) <= len);

  if (regno == -1)
    for (i = 0; i < 32; i++)
      loongarch_fill_elf_lasxregset (r, regcache, regs->xr + i, lasxrs, len);
  else if (regs->xr <= regno && regno < regs->xr + 32)
    regcache->raw_collect (regno, (char *) lasxrs + (regno - regs->xr) * 32);
}

const struct regset loongarch_elf_lasxregset = {
  NULL, loongarch_supply_elf_lasxregset, loongarch_fill_elf_lasxregset,
};

static void
loongarch_linux_iterate_over_regset_sections (struct gdbarch *gdbarch,
					      iterate_over_regset_sections_cb *cb,
					      void *cb_data,
					      const struct regcache *regcache)
{
  auto regs = &gdbarch_tdep (gdbarch)->regs;
  if (0 <= regs->r)
    cb (".reg", sizeof (loongarch_elf_gregset_t),
	&loongarch_elf_gregset, NULL, cb_data);
  if (0 <= regs->f)
    cb (".reg2", sizeof (loongarch_elf_fpregset_t),
	&loongarch_elf_fpregset, NULL, cb_data);
  do
    {
      uint32_t t;
      ULONGEST xfered_len;
      if (target_xfer_partial (current_top_target (), TARGET_OBJECT_LARCH,
			       "cpucfg", (gdb_byte *) &t, NULL, 0, sizeof (t),
			       &xfered_len) != TARGET_XFER_OK)
	break;
      cb (".reg-loongarch-cpucfg", 64 * 4, &loongarch_elf_cpucfgregset,
	  "Loongarch CPU config", cb_data);
    }
  while (0);
  if (0 <= regs->scr)
    cb (".reg-loongarch-lbt", sizeof (loongarch_elf_lbtregset_t),
	&loongarch_elf_lbtregset, "Loongson Binary Translation", cb_data);
  if (0 <= regs->vr)
    cb (".reg-loongarch-lsx", sizeof (loongarch_elf_lsxregset_t),
	&loongarch_elf_lsxregset, "Loongson SIMD Extension", cb_data);
  if (0 <= regs->xr)
    cb (".reg-loongarch-lasx", sizeof (loongarch_elf_lasxregset_t),
	&loongarch_elf_lasxregset, "Loongson Advanced SIMD Extension", cb_data);
}

static const struct target_desc *
loongarch_linux_core_read_description (struct gdbarch *gdbarch,
				       struct target_ops *target, bfd *abfd)
{
  int rlen, fpu32, fpu64, lbt, lsx, lasx;

  /* 约定regset中的寄存器大小恒为64位，即使是在32位机器中，更高部分是低32位
     的符号扩展  */
  rlen = 64;
  fpu32 = 0;

  fpu64 = !!bfd_get_section_by_name (abfd, ".reg2");
  lbt = !!bfd_get_section_by_name (abfd, ".reg-loongarch-lbt");
  lsx = !!bfd_get_section_by_name (abfd, ".reg-loongarch-lsx");
  lasx = !!bfd_get_section_by_name (abfd, ".reg-loongarch-lasx");

  return
    loongarch_create_target_description (rlen, fpu32, fpu64, lbt, lsx, lasx);
}

//enum LARCH_BP_KIND
//{
//  LARCH_BP_GNU_LINUX_NORMAL,
//};
//
///* Implement the breakpoint_kind_from_pc gdbarch method.  */
//
//static int
//loongarch_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
//{
//  return LARCH_BP_GNU_LINUX_NORMAL;
//}
//
///* Implement the sw_breakpoint_from_kind gdbarch method.  */
//
//static const gdb_byte *
//loongarch_sw_breakpoint_from_kind (struct gdbarch *gdbarch, int kind, int *size)
//{
//  switch (kind)
//    {
//    case LARCH_BP_GNU_LINUX_NORMAL:
//      {
//	static const gdb_byte break_5[] =
//	  { 0x05, 0x00, 0x2a, 0x00 }; /* break BRK_SSTEPBP(5) */
//	*size = 4;
//	return break_5;
//      }
//    default:
//      gdb_assert_not_reached (_("unhandled breakpoint kind"));
//    }
//}

static void
loongarch_linux_lp64_sigframe_init (const struct tramp_frame *self,
				    struct frame_info *this_frame,
				    struct trad_frame_cache *this_cache,
				    CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  auto regs = &gdbarch_tdep (gdbarch)->regs;
  CORE_ADDR frame_sp = get_frame_sp (this_frame);

/*
  struct sigcontext {
    __u64   sc_pc;
    __u64   sc_regs[32];
    __u32   sc_flags;

    __u32   sc_fcsr;
    __u32   sc_vcsr;
    __u64   sc_fcc;
    union fpureg    sc_fpregs[32] FPU_ALIGN;

  #if defined(CONFIG_CPU_HAS_LBT)
    __u64   sc_scr[4];
  #endif
    __u32   sc_reserved;
  };

  typedef struct _sig_ucontext {
    unsigned long         uc_flags;
    struct _sig_ucontext  *uc_link;
    stack_t               uc_stack;
    struct sigcontext uc_mcontext;
    sigset_t      uc_sigmask;
  } _sig_ucontext_t;

  struct rt_sigframe {
    unsigned int ass[4];
    unsigned int trampoline[2];
    siginfo_t info;
    _sig_ucontext_t uc;
  };

  For returning from signal handler, '$sp' at VDSO sigreturn stub is
  a instance of 'struct rt_sigframe'. We want 'sc_pc' and 'sc_regs'.
  'sc_pc' is '$sp + 224'
  'sc_regs' is '$sp + 232'
  We just care the information to backtrace, others are ignored.
*/

  CORE_ADDR sigcontext_base = frame_sp + 224;
  int i;

  trad_frame_set_reg_addr (this_cache, regs->pc, sigcontext_base);
  for (i = 0; i < 32; i++)
    trad_frame_set_reg_addr (this_cache, regs->r + i,
			     sigcontext_base + 8 + i * 8);

  trad_frame_set_id (this_cache, frame_id_build (frame_sp, func));
}

static const struct tramp_frame loongarch_linux_lp64_rt_sigframe = {
  SIGTRAMP_FRAME,
  4,
  {
    /* from $kernel/arch/loongarch/vdso/sigreturn.S */
    { 0x03822c0b, 0xffffffff }, /* ori	$r11, $r0, 0x8b(__NR_rt_sigreturn) */
    { 0x002b0000, 0xffffffff }, /* syscall	0 */
    { TRAMP_SENTINEL_INSN, -1 }
  },
  loongarch_linux_lp64_sigframe_init,
  NULL
};

/* Return the current system call's number present in the
   a7 register.  When the function fails, it returns -1.  */

static LONGEST
loongarch_linux_get_syscall_number (struct gdbarch *gdbarch,
				    thread_info *thread)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  auto regs = &tdep->regs;
  struct regcache *regcache = get_thread_regcache (thread);
  LONGEST ret;

  switch (tdep->ef_abi)
    {
    case EF_LARCH_ABI_LP64:
      if (REG_VALID == regcache_cooked_read_signed
			 (regcache, regs->r + 11, &ret))
	return ret;
    }

  return -1;
}

static CORE_ADDR
loongarch_linux_syscall_next_pc (struct frame_info *frame)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  auto regs = &tdep->regs;
  CORE_ADDR pc = get_frame_pc (frame);
  ULONGEST a7 = get_frame_register_unsigned (frame, regs->r + 11);

  switch (tdep->ef_abi)
    {
    case EF_LARCH_ABI_LP64:
      /* If we are about to make a sigreturn syscall, use the unwinder to
	 decode the signal frame.  */
      if (a7 == 0x8b/* LP64: __NR_rt_sigreturn */)
	return frame_unwind_caller_pc (get_current_frame ());
    }

  return -1;
}

static void
loongarch_linux_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  const struct target_desc *tdesc = info.target_desc;
  struct tdesc_arch_data *tdesc_data = info.tdesc_data;
  const struct tdesc_feature *feature;
  int valid_p;

//   gdb_assert (tdesc_data);

  linux_init_abi (info, gdbarch);

  /* GNU/Linux uses ELF.  */
//   i386_elf_init_abi (info, gdbarch);

  /* Add the %orig_eax register used for syscall restarting.  */
//   set_gdbarch_write_pc (gdbarch, i386_linux_write_pc);

//   set_gdbarch_process_record (gdbarch, i386_process_record);
//   set_gdbarch_process_record_signal (gdbarch, i386_linux_record_signal);

  /* N_FUN symbols in shared libaries have 0 for their values and need
     to be relocated.  */
//   set_gdbarch_sofun_address_maybe_missing (gdbarch, 1);
  switch (tdep->ef_abi)
    {
    case EF_LARCH_ABI_LP32:
      set_solib_svr4_fetch_link_map_offsets
	(gdbarch, svr4_ilp32_fetch_link_map_offsets);
    break;
    case EF_LARCH_ABI_XLP32:
      set_solib_svr4_fetch_link_map_offsets
	(gdbarch, svr4_ilp32_fetch_link_map_offsets);
    break;
    case EF_LARCH_ABI_LP64:
      set_solib_svr4_fetch_link_map_offsets
	(gdbarch, svr4_lp64_fetch_link_map_offsets);
      tramp_frame_prepend_unwinder
	(gdbarch, &loongarch_linux_lp64_rt_sigframe);
      tdep->syscall_next_pc = loongarch_linux_syscall_next_pc;

      /* Functions for 'catch syscall'.  */
//   set_xml_syscall_file_name (gdbarch, XML_SYSCALL_FILENAME_I386);
      set_gdbarch_get_syscall_number
	(gdbarch, loongarch_linux_get_syscall_number);
    break;
    }
//   set_gdbarch_skip_trampoline_code (gdbarch, find_solib_trampoline_target);

  /* GNU/Linux uses the dynamic linker included in the GNU C Library.  */
  set_gdbarch_skip_solib_resolver (gdbarch, glibc_skip_solib_resolver);

//   dwarf2_frame_set_signal_frame_p (gdbarch, i386_linux_dwarf_signal_frame_p);

  /* Enable TLS support.  */
  set_gdbarch_fetch_tls_load_module_address
    (gdbarch, svr4_fetch_objfile_link_map);

  /* Information about the target architecture.  */
  //set_gdbarch_breakpoint_kind_from_pc (gdbarch, loongarch_breakpoint_kind_from_pc);
  //set_gdbarch_sw_breakpoint_from_kind (gdbarch, loongarch_sw_breakpoint_from_kind);
  set_gdbarch_call_dummy_location (gdbarch, AT_ENTRY_POINT);

  /* Core file support.  */
  set_gdbarch_iterate_over_regset_sections
    (gdbarch, loongarch_linux_iterate_over_regset_sections);
  set_gdbarch_core_read_description
    (gdbarch, loongarch_linux_core_read_description);
}

void
_initialize_loongarch_linux_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_loongarch, bfd_mach_loongarch32 /* GDB may not care what arch variant is this.
     So we specify DEFAULT_BFD_ARCH */,
			  GDB_OSABI_LINUX, loongarch_linux_init_abi);
}
