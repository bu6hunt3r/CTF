#!/usr/bin/python

import angr
import simuvex

p = angr.Project('rev')
#p.hook(0x400520,hooked_ptrace)
pg = p.factory.path_group()
pg.explore(find=0x08048679)
s = pg.found[0].state
f = open("found.bin","wb")
f.write(s.posix.dumps(0))
f.close()
print "ok"
