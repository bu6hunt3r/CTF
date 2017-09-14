# TWCTF 2017 - rev_rev_rev
## Reversing - 25 pts

### Recon

It's more or less a classical crackme challenge, which means, that 
the binary is scrambling our input in some manner and doing a strcmp at the end to decide whether input was correct or not.

```
$ file rev
ELF 32-bit LSB  executable, 
Intel 80386, version 1 (SYSV), 
dynamically linked (uses shared libs)
[...Shortened for brevity...]

$ ldd rev
	linux-gate.so.1 =>  (0xf774b000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7586000)
        /lib/ld-linux.so.2 (0xf774d000)
```

Ok, it's dynamically linked against libc, so lets get some info about imported function from libc shared object:

```
rabin2 -ii rev
[Imports]
ordinal=001 plt=0x08048410 bind=GLOBAL type=FUNC name=strcmp
ordinal=002 plt=0x08048420 bind=GLOBAL type=FUNC name=printf
ordinal=003 plt=0x08048430 bind=GLOBAL type=FUNC name=fgets
ordinal=004 plt=0x08048440 bind=GLOBAL type=FUNC name=__stack_chk_fail
ordinal=005 plt=0x08048450 bind=GLOBAL type=FUNC name=puts
ordinal=006 plt=0x00000000 bind=WEAK type=NOTYPE name=__gmon_start__
ordinal=007 plt=0x08048460 bind=GLOBAL type=FUNC name=exit
ordinal=008 plt=0x08048470 bind=GLOBAL type=FUNC name=strchr
ordinal=009 plt=0x08048480 bind=GLOBAL type=FUNC name=strlen
ordinal=010 plt=0x08048490 bind=GLOBAL type=FUNC name=__libc_start_main

```

Not that much. Let's get a first insight into machinery with strace...Maybe there's something interesting?

```
execve("/usr/bin/rev", ["rev"], [/* 25 vars */]) = 0
brk(0)                                  = 0x1b65000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f22655f0000
[...]
read(0, 
[...]
```
So it's reading some number of characters from stdin into a buffer, where we still don't know it's location at the moment. It's disassembly time...

### Disassembly

```
$ r2 -A rev
[0x080484b0]> afl
0x080483d4    3 35           fcn.080483d4
0x08048410    1 6            sym.imp.strcmp
0x08048420    1 6            sym.imp.printf
0x08048430    1 6            sym.imp.fgets
0x08048440    1 6            sym.imp.__stack_chk_fail
0x08048450    1 6            sym.imp.puts
0x08048460    1 6            sym.imp.exit
0x08048470    1 6            sym.imp.strchr
0x08048480    1 6            sym.imp.strlen
0x08048490    1 6            sym.imp.__libc_start_main
0x080484a0    1 6            sub.__gmon_start___252_4a0
0x080484b0    1 33           entry0
0x080484e0    1 4            fcn.080484e0
0x080484f0    4 43           fcn.080484f0
0x080485ab    8 270          main
0x080486b9    1 34           sub.strchr_6b9
0x080486db    4 93           sub.strlen_6db
0x08048738    4 122          fcn.08048738
0x080487b2    4 52           fcn.080487b2
[0x080484b0]> afl | wc -l
19
```

So radare already recognized 19 functions in binary. Four of them are not imported. How many bytes do we need exactly to pass the challenge?

```
0x080485f8      6a21           push 0x21                   
0x080485fa      8d45d3         lea eax, [local_2dh]                               
0x080485fd      50             push eax                                           
0x080485fe      e82dfeffff     call sym.imp.fgets
```
fgets will read 33 bytes to a buffer stored locally (on stack) in main function.

During challenge my team-mate and me grabbed functionality out of two of them but struggled at the one that gets called in 2nd position.

Briefly said, functions 1, 2 and 4 are doing the following:

- Reversing input string (input[::-1])
- ?
- Flipping each bit (0xFF ^ c)

But there are symbolic exexution engines like angr for god's sake. There we have the possibility to define that path we want to go ant these we want to avoid. I used [r4ge](https://github.com/gast04/r4ge) plugin in radare2 for that.

 [![asciicast](https://asciinema.org/a/xRHwboc6hvxdsD7DZOMwwTu0v.png)](https://asciinema.org/a/xRHwboc6hvxdsD7DZOMwwTu0v) 
