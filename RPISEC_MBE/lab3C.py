#!/usr/bin/env python

from pwn import *

context(os="linux", arch="i386", bits=32, log_level="INFO")

s=ssh(user="lab3C", password="lab03start", host="192.168.13.101")
s.close()