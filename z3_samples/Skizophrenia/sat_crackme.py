#!/usr/bin/env python

from z3 import *
import r2pipe
import subprocess as sp

def get_operand():
        r2=r2pipe.open("crackme2_lin")
        r2.cmd("aaa")
        disas=r2.cmd("p8 8 @ 0x8049707")
        print "[+] Operand is {}".format(disas)
	return disas

def check(key):
        p=pwn.process("./crackme2_lin")
	print p.recvline()

def crack():
	solver=Solver()
	
	# define vars for serial
	s0, s1, s2, s3, s4, s5, s6, s7, s8=BitVecs('s0, s1, s2, s3, s4, s5, s6, s7, s8',8)

	# all serial values must be ascii-values between 0x30 and 0x7e
	solver.add(s0 >= 0x30); solver.add(s0 <= 0x7e)
	solver.add(s1 >= 0x30); solver.add(s1 <= 0x7e)
	solver.add(s2 >= 0x30); solver.add(s2 <= 0x7e)
	solver.add(s3 >= 0x30); solver.add(s3 <= 0x7e)
	solver.add(s4 >= 0x30); solver.add(s4 <= 0x7e)
	solver.add(s5 >= 0x30); solver.add(s5 <= 0x7e)
	solver.add(s6 >= 0x30); solver.add(s6 <= 0x7e)
	solver.add(s7 >= 0x30); solver.add(s7 <= 0x7e)
	solver.add((s8 - 0x61) <= 0x19); solver.add(s8 > 0x0)


	solver.add(s8==((s0^BitVecVal(0x45,8))+(s1^BitVecVal(0x36,8))+(s2^BitVecVal(0xab,8))+(s3^BitVecVal(0xc8,8))+(s4^BitVecVal(0xcc,8))+(s5^BitVecVal(0x11,8))+(s6^BitVecVal(0xe3,8))+(s7^BitVecVal(0x7a,8))))


	print("[+] solving...")
	print("[+] Conditions are {}".format(solver.check()))
	sol = [0 for i in range(9)]
	m = solver.model()

	#print m	
	for i in range(0,9):
		sol[i] = eval("chr(m.evaluate(s%d).as_long())" % i)

	print "[+] Found solution \033[1;31m", ''.join(sol), "\033[0m"
	sol=''.join(sol)
	return sol

def main():
	magic=get_operand()
	solution=crack()
	p=sp.Popen("./crackme2_lin",stdout=sp.PIPE, stdin=sp.PIPE, stderr=sp.PIPE)
	result=p.communicate(input=solution+"\n")[0]
	print "\033[1;31m", result, "\033[0m"
		

if __name__=="__main__":
	main()
