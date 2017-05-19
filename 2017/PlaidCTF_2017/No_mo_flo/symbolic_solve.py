#!/usr/bin/env python

from manticore import Manticore

m=Manticore("./no_flo")

buffer=""

@m.hook(0x004027c9)
def hook(state):
    inp_adr=state.cpu.read_int()
    buffer=state.new_Symbolic_buffer(0x43)
    state.constrain(buffer[0]=ord("P"))
    state.constrain(buffer[1]=ord("C"))
    state.constrain(buffer[2]=ord("T"))
    state.constrain(buffer[3]=ord("F"))
    state.constrain(buffer[4]=ord("{"))
    state.cpu.write_bytes(input_adr, buffer)





