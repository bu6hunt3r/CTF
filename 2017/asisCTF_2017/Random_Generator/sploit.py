#!/usr/bin/env python2

from pwn import *

host="69.90.132.40"
port=4000

r=remote(host,port)

def menu():
	r.recvuntil("What random value do you want to get?")

def main():
	menu()
	r.sendline("8")
	print r.recvlines(2)

if __name__=="__main__":
	main()