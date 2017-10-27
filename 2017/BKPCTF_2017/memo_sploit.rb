#!/usr/bin/env ruby
#coding: utf-8

require 'pwn'

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

=begin
Do you wanna set password? (y/n) y
Password must be set to 32 digits or less.
Password: ABCD
Done! have a good day efkay

1. Leave message on memo
2. Edit message last memo
3. View memo
4. Delete memo
5. Change password
6. Quit.
>> 
=end
z=MyTube.new("localhost",54321) 
z.recvuntil "What's user name: "
z.sendline "efkay"
z.recvuntil "Do you wanna set password? (y/n) "
z.sendline "y"
z.recvuntil "Password: "
z.sendline "AAAA"
z.recvuntil "Done! have a good day efkay"



puts "Data: #{data}"
