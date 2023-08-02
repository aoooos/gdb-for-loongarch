/* GDB target debugging macros

   Copyright (C) 2014-2018 Free Software Foundation, Inc.

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

#ifndef TARGET_DEBUG_H
#define TARGET_DEBUG_H

/* Printers for the debug target.  Each prints an object of a given
   type to a string that needn't be freed.  Most printers are macros,
   for brevity, but a few are static functions where more complicated
   behavior is needed.

   References to these printers are automatically generated by
   make-target-delegates.  See the generated file target-delegates.c.

   In a couple cases, a special printing function is defined and then
   used via the TARGET_DEBUG_PRINTER macro.  See target.h.

   A few methods still have some explicit targetdebug code in
   target.c.  In most cases this is because target delegation hasn't
   been done for the method; but individual cases vary.  For instance,
   target_store_registers does some special register printing that is
   more simply done there, and target_xfer_partial additionally
   bypasses the debug target.  */


/* Helper macro.  */

#define target_debug_do_print(E)			\
  fputs_unfiltered ((E), gdb_stdlog);

#define target_debug_print_struct_target_ops_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_enum_target_object(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_CORE_ADDR(X)		\
  target_debug_do_print (core_addr_to_string (X))
#define target_debug_print_const_char_p(X)	\
  target_debug_do_print (((X) ? (X) : "(null)"))
#define target_debug_print_char_p(X)		\
  target_debug_do_print (((X) ? (X) : "(null)"))
#define target_debug_print_int(X)		\
  target_debug_do_print (plongest (X))
#define target_debug_print_bool(X)		\
  target_debug_do_print ((X) ? "true" : "false")
#define target_debug_print_long(X)		\
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_target_xfer_status(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_exec_direction_kind(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_trace_find_type(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_btrace_read_type(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_btrace_error(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_ptid_t(X)		\
  target_debug_do_print (plongest (ptid_get_pid (X)))
#define target_debug_print_struct_gdbarch_p(X)	\
  target_debug_do_print (gdbarch_bfd_arch_info (X)->printable_name)
#define target_debug_print_const_gdb_byte_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_gdb_byte_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_gdb_byte_pp(X)	\
  target_debug_do_print (host_address_to_string (*(X)))
#define target_debug_print_enum_gdb_signal(X)	\
  target_debug_do_print (gdb_signal_to_name (X))
#define target_debug_print_ULONGEST(X)		\
  target_debug_do_print (hex_string (X))
#define target_debug_print_ULONGEST_p(X)	\
  target_debug_do_print (hex_string (*(X)))
#define target_debug_print_LONGEST(X)		\
  target_debug_do_print (phex (X, 0))
#define target_debug_print_LONGEST_p(X)		\
  target_debug_do_print (phex (*(X), 0))
#define target_debug_print_struct_address_space_p(X)	\
  target_debug_do_print (plongest (address_space_num (X)))
#define target_debug_print_struct_bp_target_info_p(X)	\
  target_debug_do_print (core_addr_to_string ((X)->placed_address))
#define target_debug_print_struct_expression_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_CORE_ADDR_p(X)	\
  target_debug_do_print (core_addr_to_string (*(X)))
#define target_debug_print_int_p(X)		\
  target_debug_do_print (plongest (*(X)))
#define target_debug_print_struct_regcache_p(X) \
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_thread_info_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_ui_file_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_target_section_table_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_async_callback_ftype_p(X) \
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_void_p(X) \
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_find_memory_region_ftype(X) \
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_bfd_p(X) \
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_std_vector_mem_region(X) \
  target_debug_do_print (host_address_to_string (X.data ()))
#define target_debug_print_std_vector_static_tracepoint_marker(X)	\
  target_debug_do_print (host_address_to_string (X.data ()))
#define target_debug_print_const_struct_target_desc_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_bp_location_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_trace_state_variable_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_const_trace_state_variable_r(X)	\
  target_debug_do_print (host_address_to_string (&X))
#define target_debug_print_struct_trace_status_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_breakpoint_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_uploaded_tp_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_uploaded_tp_pp(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_uploaded_tsv_pp(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_static_tracepoint_marker_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_traceframe_info_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_btrace_target_info_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_VEC__btrace_block_s__pp(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_const_struct_frame_unwind_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_struct_btrace_data_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_enum_btrace_format(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_record_method(X)	\
  target_debug_do_print (plongest (X))
#define target_debug_print_const_struct_btrace_config_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_const_struct_btrace_target_info_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_enum_target_hw_bp_type(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_bptype(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_struct_inferior_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_enum_remove_bp_reason(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_gdb_disassembly_flags(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_traceframe_info_up(X) \
  target_debug_do_print (host_address_to_string (X.get ()))
#define target_debug_print_gdb_array_view_const_int(X)	\
  target_debug_do_print (host_address_to_string (X.data ()))
#define target_debug_print_inferior_p(inf) \
  target_debug_do_print (host_address_to_string (inf))
#define target_debug_print_record_print_flags(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_enum_info_proc_what(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_thread_control_capabilities(X) \
  target_debug_do_print (plongest (X))
#define target_debug_print_thread_info_p(X)	\
  target_debug_do_print (host_address_to_string (X))
#define target_debug_print_thread_info_pp(X)		\
  target_debug_do_print (host_address_to_string (X))

static void
target_debug_print_struct_target_waitstatus_p (struct target_waitstatus *status)
{
  std::string str = target_waitstatus_to_string (status);

  fputs_unfiltered (str.c_str (), gdb_stdlog);
}



/* Macros or functions that are used via TARGET_DEBUG_PRINTER.  */

#define target_debug_print_step(X) \
  target_debug_do_print ((X) ? "step" : "continue")

static void
target_debug_print_options (int options)
{
  char *str = target_options_to_string (options);

  fputs_unfiltered (str, gdb_stdlog);
  xfree (str);
}

static void
target_debug_print_signals (unsigned char *sigs)
{
  fputs_unfiltered ("{", gdb_stdlog);
  if (sigs != NULL)
    {
      int i;

      for (i = 0; i < GDB_SIGNAL_LAST; i++)
	if (sigs[i])
	  {
	    fprintf_unfiltered (gdb_stdlog, " %s",
				gdb_signal_to_name ((enum gdb_signal) i));
	  }
    }
  fputs_unfiltered (" }", gdb_stdlog);
}

#endif /* TARGET_DEBUG_H */