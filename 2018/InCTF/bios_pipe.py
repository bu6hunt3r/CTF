import r2pipe, sys, os

r2 = r2pipe.open('#!pipe')

# just the hdd params stolen from bochsrc
cylinders=20
heads=16
spt=63
bps=512

# function to read a key from stdin
def wait_key():
	result = None
	if os.name == 'nt':
		import msvcrt
		result = msvcrt.getch()
	else:
		import termios
		fd = sys.stdin.fileno()
		oldterm = termios.tcgetattr(fd)
		newattr = termios.tcgetattr(fd)
		newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
		termios.tcsetattr(fd, termios.TCSANOW, newattr)
		try:
			result = sys.stdin.read(1)
		except:
			pass
		finally:
			termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
		return result


# this handles the interrupts
def handle_intr(intNum):
	regs = r2.cmdj('arj')

	# helper funcs to read/write hi and low parts of regs
	def xh(regName, setValue = None):
		val = regs[regName]
		if setValue == None:
			return (val & 0xff00)>>8
		else:
			val = (val & 0xff) | ((setValue & 0xff) << 8)
			r2.cmd('ar ' + regName + '=' + hex(val))
			return val

	def xl(regName, setValue = None):
		val = regs[regName]
		if setValue == None:
			return val & 0xff
		else:
			val = (val & 0xff00) | (setValue & 0xff)
			r2.cmd('ar ' + regName + '=' + hex(val))
			return val

	# command is in ah
	command = xh('ax') 

	# read/write disk
	if intNum == 0x13: 
		# read from disk to memory
		if command == 2:
			# al, number of sectors to read
			nSectors = xl('ax')
			
			# ch, cylinder
			cylinder = xh('cx')
			
			# cl, sector
			firstSector = xl('cx')
			
			# dh, head
			head = xh('dx') 
			
			# bx, buffer in memory
			destination = regs['bx'] & 0xffff

			# hdd math
			source = (firstSector - 1 + (head + cylinder * heads) * spt ) * bps
			length = nSectors * bps

			# do the actual writing in r2
			r2.cmd('e io.cache=true')
			r2.cmd('wd ' + hex(source) + ' ' + hex(length) + ' @ ' + hex(destination))
			
			# success -> carry flag = 0
			r2.cmd('ar cf=0')
		
		# geometry query
		elif command == 8: 
			# dl drive number
			driveNum = xl('dx')
			
			if driveNum != 0x80:
				# if not first drive, error -> carry flag = 1
				r2.cmd('ar cf=1')
			else:
				# success, return geometry
				r2.cmd('ar cf=0')
				r2.cmd('ar ax=0')
				r2.cmd('ar dx=' + hex(((heads-1) << 8) | 1))
				r2.cmd('ar cx=' + hex(spt | (cylinders << 8)))

	# keyboard i/o
	elif intNum == 0x16: 
		# read extended key
		if command == 0x10:
			result = ord(wait_key())
			high = 0
			if result == 10:
				high = 0x1c
			elif result == 127:
				high = 0xe
			r2.cmd('ar ax=' + hex(result | (high << 8)))

	# screen output
	elif intNum == 0x10:
		# print char
		if command == 0xe:
			char = chr(xl('ax'))
			sys.stdout.write(char)
			sys.stdout.flush()

# call it, with parameter coming from r2
handle_intr(int(sys.argv[1], 0))

