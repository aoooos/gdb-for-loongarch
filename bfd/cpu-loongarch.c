#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

static const bfd_arch_info_type bfd_loongarch32_arch =
{
  32,				/* 32 bits in a word.  */
  32,				/* 64 bits in an address.  */
  8,				/* 8 bits in a byte.  */
  bfd_arch_loongarch,		/* Architecture.  */
  bfd_mach_loongarch32,				/* Machine number - 0 for now.  */
  "loongarch32",			/* Architecture name.  */
  "Loongarch32",			/* Printable name.  */
  3,				/* Section align power.  */
  FALSE,			/* This is the default architecture.  */
  bfd_default_compatible,	/* Architecture comparison function.  */
  bfd_default_scan,		/* String to architecture conversion.  */
  bfd_arch_default_fill,	/* Default fill.  */
  NULL,				/* Next in list.  */
};

const bfd_arch_info_type bfd_loongarch_arch =
{
  32,                           /* 32 bits in a word.  */
  64,                           /* 64 bits in an address.  */
  8,                            /* 8 bits in a byte.  */
  bfd_arch_loongarch,            /* Architecture.  */
  bfd_mach_loongarch64,                          /* Machine number of loongarch64 is larger so that loongarch64 is compatible to loongarch32  */
  "loongarch64",                   /* Architecture name.  */
  "Loongarch64",                 /* Printable name.  */
  3,                            /* Section align power.  */
  TRUE,                 /* This is the default architecture.  */
  bfd_default_compatible,       /* Architecture comparison function.  */
  bfd_default_scan,             /* String to architecture conversion.  */
  bfd_arch_default_fill,        /* Default fill.  */
  &bfd_loongarch32_arch,                          /* Next in list.  */
};

