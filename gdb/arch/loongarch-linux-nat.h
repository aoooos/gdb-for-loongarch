#ifndef LOONGARCH_LINUX_NAT_H
#define LOONGARCH_LINUX_NAT_H
#include <stdint.h>

static inline uint32_t
loongarch_cpucfg (uint64_t rj)
{
  uint32_t ret;
  asm ("cpucfg %0,%1":"=r"(ret):"r"(rj));
  return ret;
}

struct target_desc;

extern struct target_desc *
loongarch_linux_read_description_runtime (int tid);

#endif
