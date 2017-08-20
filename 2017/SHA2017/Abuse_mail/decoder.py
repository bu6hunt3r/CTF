#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Random import random
import sys
import base64
import time

BS=16

unpad=lambda s: s[0:-ord(s[-1])]
magic="SHA2017"

class AESCipher:
    
    def __init__(self, key):
        self.key=key

    def decrypt(self, enc):
        enc=base64.b64decode(enc)
        iv=enc[:16]
        cipher=AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

data=open("./icmps.txt",'r').read()
cmds=map(lambda x: x.decode("hex"),data.split('\n')[:-1])
cipher=AESCipher('K8djhaIU8H2d1jNb')
for cmd in cmds:
    cmd = cmd.split(magic + ':')[1]
    data = cipher.decrypt(cmd)
    print data
