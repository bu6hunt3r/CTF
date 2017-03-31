#!/usr/bin/env python

from termcolor import colored, cprint
from time import sleep
import binascii
import sys

print_red = lambda x: cprint(x,'red')
print_green = lambda x: cprint(x,'green')

def str_to_hex(str):
        return ''.join('|{:02x}'.format(ord(c)) for c in str)

def decrypt(enc):
    imd=""
    for i in range(len(imd),16):
        print( "---------------------")
        print( "--------i: %d--------" % i)
        print( "---------------------")
        iv=""
        for im in imd:
            print_green("\nIM: " + str_to_hex(im))
            iv+=chr((i+1)^ord(im))
            #sys.stdout.write("\r%s" % iv)
            sleep(0.5)
            sys.stdout.write("\rIV: " + str_to_hex(iv))
            #print_red("IV: " + str_to_hex(iv))
        iv=iv[::-1]
        for j in range(256):
            print( "\n---------------------")
            print( "--------j: %d--------" % i)
            print( "---------------------")
            ivt=chr(j)+iv
            print_green("\nOrig IVT (j^iv): " + str_to_hex(ivt))
            ivt = "\00"*16 + "\00"*(16-len(ivt)) + ivt
            print_red("Upd IVT: " + str_to_hex(ivt))
            if True:
                imd += chr(j^(i+1))
                res = "\x00"*(16 - len(imd)) + imd[::-1]
                break

decrypt("ABCDEFGHIJKLMNOP")

