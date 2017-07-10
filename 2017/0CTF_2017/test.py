#!/usr/local/bin/sage -python

from sage.all import *

def num2poly(num):
    poly=R(0)
    for i,v in enumerate(bin(num)[2:][::-1]):
        if (int(v)):
            poly+=x**i
    return poly

def poly2num(poly):
    bin=''.join([str(i) for i in poly.list()])
    return int(bin[::-1],2)

def gf2num(ele):
    return ele.polynomial().change_ring(ZZ)(2)

P = 0x10000000000000000000000000000000000000000000000000000000000000425L

fake_secret1 = "I_am_not_a_secret_so_you_know_me"
fake_secret2 = "feeddeadbeefcafefeeddeadbeefcafe"
secret = str2num(urandom(32))

R = PolynomialRing(GF(2), 'x')
x = R.gen()
GF2f = GF(2**256, name='a', modulus=num2poly(P))
 
f = open('ciphertext', 'r')
A = GF2f(num2poly(int(f.readline(), 16)))
B = GF2f(num2poly(int(f.readline(), 16)))
C = GF2f(num2poly(int(f.readline(), 16)))
 
b = GF2f(num2poly(str2num(fake_secret1)))
c = GF2f(num2poly(str2num(fake_secret2)))
 
# Retrieve partial key stream using known plaintexts
Y = B + b
Z = C + c
 
Q = (Z + Y**2)
K = (Y + Q).sqrt()
 
print 'flag{%s}' % hex(gf2num(A + K)).decode('hex')