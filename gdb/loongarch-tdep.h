/* Target-dependent header for the RISC-V architecture, for GDB, the GNU Debugger.

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

#ifndef LOONGARCH_TDEP_H
#define LOONGARCH_TDEP_H

#include "arch/loongarch.h"

struct gdbarch_tdep
{
  /* 思来想去，我不太希望考虑CPU型号、体系结构变种之间的种种差别。LARCH指令集被
     强调为增量的，可执行文件的关键就是那个EM_MACHINE和ABI，动态连接器不会因为
     诸如CPU型号，指令集之类的差别拒绝执行可执行程序。至于同一个函数的不同实现
     （比如向量的memcpy），交给IFUNC来搞。考虑到LARCH的发展，可能其中个别指令
     的意义真的因为个别CPU发生改变；或者同一个指令编码的实际指令不同，这就意味
     着反汇编器状态有差别，那么ELF包含体系结构信息是必要的，否则无法分析文件。
     这延伸出来几个问题：
     1、如何将体系结构信息存入ELF文件？
	MIPS带来的问题是指令集充分发展使得FLAG域中的名字空间不够。这里初步设想
	使用段的存在来标记指令集信息。比如ELF文件中有LASX指令，那么有一个名为
	LARCH.ISA.LASX的空段。类似的，我们将反汇编器的状态都记录在ELF文件中，
	这样就可以分析一个可执行文件了。
     2、当GDB拿到可执行文件时，什么对GDB来说是至关重要的？
	机器之间的差别是客观的，可执行文件之间内容的差别也是客观的；但可执行
	文件本身的地位是平等的。但总是需要配置GDB，让GDB可以或不可以调试某些
	可执行程序。如果GDB不能调试一个可执行文件，那可能是什么原因？我想来想
	去，还是因为数据模型——如果我们认为long int类型的位宽不同，我们进行
	源码级调试的视角就不同，除此之外都无所谓。
	如果一个程序使用了向量指令而另一个程序没有，那我们认为世界上所有程序都
	使用了向量指令——如果操作系统无法访问向量寄存器，GDB将自己的register
	cache全填上1。如果一个程序是32位的而另一个程序是64位的，那我们认为世界
	上所有程序都是64位的，对于真正的32位程序，GDB内部认为高32位是低32位的
	符号扩展。总之，GDB内部表示总是拥有LARCH最强的能力，如果这个能力和操作
	系统有差别，那么多出来的部分被填上特殊值。
	在LARCH中，数据模型信息包含在ABI中，因此我们认为ABI是gdbarch_tdep的主键
     3、GDB如何对外显示？以及GDB内部某些实现策略
	对于双精度浮点寄存器、128b和256b的向量寄存器有重合的关系，如果我们将
  */
  int ef_abi; /* EF_LARCH_ABI */

  struct
  {
    int r;
    int ra;
    int sp;
    int pc;
    int badvaddr;

    int f;
    int fcc;
    int fcsr;
    int vr;
    int xr;

    int scr;
    int EFLAG;
    int x86_top;

  } regs;

  /* Return the expected next PC if FRAME is stopped at a syscall
     instruction.  */
  CORE_ADDR (*syscall_next_pc) (struct frame_info *frame);
};


#endif /* LOONGARCH_TDEP_H */
