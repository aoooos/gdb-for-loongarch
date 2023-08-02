#ifndef GDB_LOONGARCH_ARCH_H
#define GDB_LOONGARCH_ARCH_H

#include "elf/loongarch.h"
#include "opcode/loongarch.h"

extern unsigned int loongarch_debug;

struct target_desc;

extern const char *loongarch_expedite_regs[];

extern struct target_desc *
loongarch_get_base_target_description (int rlen);

extern struct target_desc *
loongarch_create_target_description (int rlen,
				     int fpu32,
				     int fpu64,
				     int lbt,
				     int lsx,
				     int lasx);

#endif
