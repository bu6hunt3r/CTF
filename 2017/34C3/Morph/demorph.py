#!/usr/bin/env python
#-*- coding: utf-8 -*-

import r2pipe
import re 

flag_begin="34C3_"
flag=flag_begin+'A'*(23-len(flag_begin))

r2=r2pipe.open("/home/cr0c0/Downloads/morph", flags=['-2'])
r2.cmd("ood %s" % flag)
r2.cmd("aa")
source_main=r2.cmd("pdf @ sym.main")
bp_lines=[line for line in source_main.split('\n') if "call rax" in line]
bps=[re.search(r"0x[0-9a-f]+", bp).group(0) for bp in bp_lines]

print bp_lines
