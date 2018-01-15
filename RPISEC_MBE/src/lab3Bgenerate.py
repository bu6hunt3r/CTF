import string
import binascii

f = open("/tmp/payload","rw+")
f.truncate()

for i in string.printable[10:14]:
    f.write("xor e%sx, e%sx\n" % (i,i))


f.close()
