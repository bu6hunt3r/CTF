# !/usr/bin/env ruby
# https://blog.skullsecurity.org/2015/gits-2015-huffy-huffman-encoded-shellcode

class Huffman_code
	@@table={
	"0000"=>0x0, "0001"=>0x1, "0011"=>0x2, "0010"=>0x3,
	"0110"=>0x4, "0111"=>0x5, "0101"=>0x6, "0100"=>0x7,
	"1100"=>0x8, "1101"=>0x9, "1111"=>0xa, "1110"=>0xb,
	"1010"=>0xc, "1011"=>0xd, "1001"=>0xe, "1000"=>0xf,
	}    

	def self.encode_nibble(b)
		binary=b.to_s(2).rjust(4,"0")
		puts("Looking up %s... => %x" % [binary,@@table[binary]])
		return @@table[binary]
	end

	@@hist=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ]

	shellcode="hello, world"

	shellcode.each_byte do |b|
		n1=b >> 4
		n2=b & 0x0f

		puts("n1=%x" % n1)
		puts("n2=%x" % n2)

		@@hist[n1]+=1
		@@hist[n2]+=1

		out+=((self.encode_nibble(n1) << 4) | (self.encode_nibble(n2) & 0x0f)).chr
		puts out
	end
end

h=huffman_code.new
