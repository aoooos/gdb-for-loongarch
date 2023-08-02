#include "common-defs.h"
#include "common-regcache.h"
#include "arch/loongarch.h"

const char *loongarch_expedite_regs[] = {"r3", "pc", NULL};

unsigned int loongarch_debug = 0;

#include <../features/loongarch/base32.c>
#include <../features/loongarch/base64.c>
#include <../features/loongarch/fpu32.c>
#include <../features/loongarch/fpu64.c>
#include <../features/loongarch/lbt32.c>
#include <../features/loongarch/lbt64.c>
#include <../features/loongarch/lsx.c>
#include <../features/loongarch/lasx.c>

struct target_desc *
loongarch_create_target_description (int rlen, int fpu32, int fpu64, int lbt,
				     int lsx, int lasx)
{
  gdb_assert (rlen == 32 || rlen == 64);

  struct target_desc *tdesc = allocate_target_description ();

  set_tdesc_architecture (tdesc, rlen == 64 ? "loongarch64" : "loongarch32");

  int regnum = 0;

  if (rlen == 64)
    regnum = create_feature_loongarch_base64 (tdesc, regnum);
  else if (rlen == 32)
    regnum = create_feature_loongarch_base32 (tdesc, regnum);
  else
    gdb_assert_not_reached ("rlen unknown");

  if (fpu32)
    regnum = create_feature_loongarch_fpu32 (tdesc, regnum);
  else if (fpu64)
    regnum = create_feature_loongarch_fpu64 (tdesc, regnum);

  if (lbt && rlen == 32)
    regnum = create_feature_loongarch_lbt32 (tdesc, regnum);
  else if (lbt && rlen == 64)
    regnum = create_feature_loongarch_lbt64 (tdesc, regnum);

  if (lsx)
    regnum = create_feature_loongarch_lsx (tdesc, regnum);

  if (lasx)
    regnum = create_feature_loongarch_lasx (tdesc, regnum);

  return tdesc;
}

struct target_desc *
loongarch_get_base_target_description (int rlen)
{
  if (rlen == 64)
    return loongarch_create_target_description (64, 0, 0, 0, 0, 0);
  else if (rlen == 32)
    return loongarch_create_target_description (32, 0, 0, 0, 0, 0);
  else
    gdb_assert_not_reached ("rlen unknown");
  return NULL;
}
