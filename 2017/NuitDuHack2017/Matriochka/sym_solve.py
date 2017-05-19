#!/usr/bin/env python

from manticore import Manticore

m=Manticore("./step2.bin")
m.verbosity=3
intermed_addy=0x6335b0

@m.hook(None)
def hook(state):
   print("Reached hook addy")
   cpu=state.cpu
   stat
   m.terminate() 

m.run
