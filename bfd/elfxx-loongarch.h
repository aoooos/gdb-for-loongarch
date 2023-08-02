#include "elf/common.h"
#include "elf/internal.h"

extern reloc_howto_type *
loongarch_elf_rtype_to_howto (unsigned int r_type);

extern reloc_howto_type *
loongarch_reloc_type_lookup (bfd *abfd, bfd_reloc_code_real_type code);

extern reloc_howto_type *
loongarch_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name);
