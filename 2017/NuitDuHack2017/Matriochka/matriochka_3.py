from manticore import Manticore
from termcolor import cprint, colored
import sys, time

print_red=lambda x: cprint(x,'red',attr=['bold'])

m=Manticore("./step2.bin")
intermed_addy=0x6335b0
# Entry point
@m.hook(None)
def hook(state):
    pc = state.cpu.PC
    if not (pc >= 0x400000 and pc <= 0x434000):
        buffer=state.new_symbolic_buffer(0x21)
        state.cpu.write_bytes(intermed_addy, buffer)
        state.cpu.R12=intermed_addy
        state.cpu.PC=0x4008db
    
        @m.hook(0x4009bc)
        def avoid_try_again(state):
            state.abandon()

        @m.hook(0x400906)
        def win(state):
            bs = state.cpu.read_bytes(intermed_addy,33)
            s = ''
            for b in bs:
                s += chr(state.solve_one(b))
            print "\033[1;31m{}\033[0m".format(get_arg('W'+s[1:])) 
            m.terminate()
        
def get_arg(out):
    result="W"
    for x in xrange(1,len(out)):
        c=out[x-1]
        d=out[x]
        flag=ord(c)&1
        if flag==1:
            result+=chr((ord(d)+ord(c))%256)
        else:
            result+=chr((ord(d)-ord(c))%256)
	
    return result

m.run()
    


