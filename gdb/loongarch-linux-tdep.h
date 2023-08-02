#ifndef LOONGARCH_LINUX_TDEP_H
#define LOONGARCH_LINUX_TDEP_H

#include <regset.h>
#include <sys/procfs.h>

typedef uint64_t loongarch_elf_gregset_t[ELF_NGREG];
extern const struct regset loongarch_elf_gregset;

#define ELF_NFPREG 32
typedef uint64_t loongarch_elf_fpregset_t[ELF_NFPREG];
extern const struct regset loongarch_elf_fpregset;

/* regset variable size */
extern const struct regset loongarch_elf_cpucfg;

/* 4 SCRs + 4-byte EFLAG + 1-byte x86_top */
typedef uint64_t loongarch_elf_lbtregset_t[5];
extern const struct regset loongarch_elf_lbtregset;

typedef uint64_t loongarch_elf_lsxregset_t[32 * 2];
extern const struct regset loongarch_elf_lsxregset;

typedef uint64_t loongarch_elf_lasxregset_t[32 * 4];
extern const struct regset loongarch_elf_lasxregset;

#endif
