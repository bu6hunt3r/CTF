#!/usr/bin/env python

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

