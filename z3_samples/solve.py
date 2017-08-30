
from z3 import *
import r2pipe
import subprocess as sp
import sys

def get_operand(path):
	''' 
	Just for fun getting comparison operand out of bin file 
	'''	
	r2=r2pipe.open(path)
	r2.cmd("aaa")
	disas=r2.cmd("ps @ 0x00400808")
	print("\033[1;31m[+] Operand is:\033[0m \t\t{}".format(disas)) 
	return disas

def check(path, passcode):
	p=sp.Popen([path,passcode])
	


def main():
	if len(sys.argv) != 2:
		print "Usage: {0} <path to binary>".format(sys.argv[0])
		exit(-1);
	else:
		path=sys.argv[1]
		print path 
	
	s=Solver()
	a=bytearray("g9f.F\x03Qv\x01\x1b\x03;,") 		# Hard-coded bytearray in binary file

	for i in xrange(0,8):
		exec("s_%d = Int('s%d')" % (i,i)) 		# Initializing symbolic vars for z3
		exec("s.add(s_%d == a[%d]^(%d*10))" % (i,i,i))	# Adding constraints

	if s.check() == sat:
		x=s.model()
	
	else:
		raise Exception('Unsat!')

	sol=""

	for i in range(8):
		exec("sol+=chr(x.evaluate(s_%d).as_long())" % (i))

	comp=get_operand(path)
	print("\033[1;31m[+] Solution should be:\033[0m \t{}".format(sol)) 
	check(path, sol)
if __name__=="__main__":
	main()

### Traditional (i guess far more easier way) way ;)
'''
i=0

while i != 8:
	s.append(a[i]^(i*10))
	i=i+1

print s
'''
