# Writeups for MBE

## Lab 1C

### Recon

```
$ ./lab1C
-----------------------------
--- RPISEC - CrackMe v1.0 ---
-----------------------------

Password:
```

It's a crackme, so lets grab out some info about imports from external libraries to get a clue what functionality it provides by using syscalls i.e.:

```
$ rabin2 -ii lab1C
[Imports]
ordinal=001 plt=0xffffffff bind=UNKNOWN type=NOTYPE name=_ITM_deregisterTMCloneTable
ordinal=002 plt=0x08048550 bind=GLOBAL type=FUNC name=printf
ordinal=003 plt=0x08048560 bind=GLOBAL type=FUNC name=puts
ordinal=004 plt=0x08048570 bind=GLOBAL type=FUNC name=system
ordinal=005 plt=0x08048580 bind=UNKNOWN type=NOTYPE name=__gmon_start__
ordinal=006 plt=0x08048590 bind=GLOBAL type=FUNC name=__libc_start_main
ordinal=007 plt=0xffffffff bind=UNKNOWN type=NOTYPE name=_Jv_RegisterClasses
ordinal=008 plt=0x080485a0 bind=GLOBAL type=FUNC name=__isoc99_scanf
ordinal=009 plt=0xffffffff bind=UNKNOWN type=NOTYPE name=_ITM_registerTMCloneTable
```

Nothing super-spectacular, besides the use of ```system``` provided by libc. It's just a first guess, but I think the shot could be to provide lucky password, step onto the right path on "badboy" routine and spawning shell after all.

```
rafind2 -X -s "Password" ./lab1C
0x80d
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0000080d  5061 7373 776f 7264 3a20 0025 6400 0a41  Password: .%d..A
0x0000081d  7574 6865 6e74 6963 6174 6564 2100 2f62  uthenticated!./b
0x0000082d  696e 2f73 6800 0a49 6e76 616c 6964 2050  in/sh..Invalid P
0x0000083d  6173 7377 6f72 6421 2121 0001 1b03 3b28  assword!!!....;(
0x0000084d  0000 0004 0000 00f8 fcff ff44 0000       ...........D..
0x83c
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0000083c, 5061 7373 776f 7264 2121 2100 011b 033b  Password!!!....;
0x0000084c, 2800 0000 0400 0000 f8fc ffff 4400 0000  (...........D...
0x0000085c, 65fe ffff 6800 0000 f8fe ffff 8800 0000  e...h...........
0x0000086c, 68ff ffff c400 0000 1400 0000 0000 0000  h...............
0x0000087c, 017a 5200 017c 0801 1b0c 0404 8801       .zR..|........
```

By the way, the string "Password:" and the other shots above are all hard-wired in elf-binaries .rodata section. You can easily check that by using:

```
$ readelf -S ./lab1C
[...]
[15] .rodata           PROGBITS        080487c8 0007c8 000080 00   A  0   0  4
[...]
```

Let's use some radare cmds to find the location where we are faced with "Password:" prompt:

```
[0x080485b0]> iz~Password
vaddr=0x0804880c paddr=0x0000080c ordinal=002 sz=12 len=11 section=.rodata type=a string=\nPassword:
vaddr=0x08048833 paddr=0x00000833 ordinal=005 sz=21 len=20 section=.rodata type=a string=\nInvalid Password!!!
[0x080485b0]> axt @ 0x0804880c
d 0x80486da mov dword [esp], str._nPassword:
[0x080485b0]> pd 1@ 0x0804880c
   ; DATA XREF from 0x080486da (sym.main)
   ;-- str._nPassword::
   0x0804880c     .string "\\nPassword: " ; len=12
```

So in ```main``` there's the prompt. So let's seek to that:

```

│          0x080486ea    89442404       mov dword [esp + 4], eax        ; [0x4:4]=0x10101 
│          0x080486ee    c70424188804.  mov dword [esp], 0x8048818      ; [0x8048818:4]=0xa006425  ; "%d" @ 0x8048818
│          0x080486f5    e8a6feffff     call sym.imp.__isoc99_scanf    ;[3] ;sym.imp.__isoc99_scanf()
```

So at 0x080486f5 there's a call to ```scanf()``` which stores our input in a locally stored variable at esp+0x1C. What's the format specifier at 0x8048818?

```
:> ps @ 0x8048818
%d
``` 

It treats our input as integer, which is then compared to another int at 0x080486fe:

```
0x080486fe    3d9a140000     cmp eax, 0x149a 
```

Our input just has to be 0x149a and we will be faced with a shell afterwars. Fort lazy people lik me there's a radare built-in functionality to compare numbers:

```
:> ? 0x149a
5274 0x149a 012232 5.2K 0000:049a 5274 10011010 5274.0 0.000000f 0.000000
```

You could also use the tool ```rax2``` provided by radare framework to complete that task:

```
:> !!rax2 0x149a
5274
```

[![asciicast](https://asciinema.org/a/xIvKfysNoDOXShVBcp9mVCncU.png)](https://asciinema.org/a/xIvKfysNoDOXShVBcp9mVCncU)

### Pass Lab1B
```
n0_str1ngs_n0_pr0bl3m
```

## Lab1B

### Recon

```
$ ./lab1B
.---------------------------.
|-- RPISEC - CrackMe v2.0 --|
'---------------------------'

Password:
```

This time We have to enter an integer too.
It'll be stored at esp+0x4 by calling ```scanf```. Afterwars there's a call to ```test()```, which gets provided by two arguments on the stack:

- Our input integer and
- A hard wired integer with 0x1337d00d as value

In  ```test``` these values get copied to eax and edx registers. Both values (0x1337d00d and our input) will be subtracted from each other. There's a check afterwards if some condition is met:

```
 ;-- sym.test:                                                                                                                                                                                   
0x08048a74	  push ebp    
0x08048a75	  mov ebp, esp
0x08048a77	  sub esp, 0x28
0x08048a7a	  mov eax, dword [ebp + 8]       ; [0x8:4]=0
0x08048a7d	  mov edx, dword [ebp + 0xc]     ; [0xc:4]=0
0x08048a80	  sub edx, eax
0x08048a82	  mov eax, edx
0x08048a84	  mov dword [ebp-local_3], eax
0x08048a87	  cmp dword [ebp-local_3], 0x15  ; [0x15:4]=0x50000000 
0x08048a8b	  ja 0x8048bd5                  ;[1]
```

So difference of the two operands has to be less equal 0x15, otherwise we'll be rdeirected to functions epilogue and not to ```decrypt``` routine where we want to step into.

If we look closely at the imported functions list, we struggle over a call to ```system()``` with ```decrypt``` as caller. Strategy seems to be to here to input a number passing the check in main and afterwards the one in decryption routine.

Our input will then be xored with a special bytearray loaded by instructions between 0x080489c8 and 0x080489dd

```
0x080489c8    c745e3517d7c.  mov dword [ebp-local_7_1], 0x757c7d51  ; [0x757c7d51:4]=-1   
0x080489cf    c745e7607366.  mov dword [ebp - 0x19], 0x67667360  ; [0x67667360:4]=-1      
0x080489d6    c745eb7e7366.  mov dword [ebp - 0x15], 0x7b66737e  ; [0x7b66737e:4]=-1      
0x080489dd    c745ef7d7c61.  mov dword [ebp - 0x11], 0x33617c7d  ; [0x33617c7d:4]=-1      
```

After that result will be compared against string "Congratulations_".

```
0x08048a28    8b45d8         mov eax, dword [ebp-local_10]                                
0x08048a2b    3b45dc         cmp eax, dword [ebp-local_9]                                 
0x08048a2e    72d8           jb 0x8048a08                  ;[4]
0x08048a30    c7442404038d.  mov dword [esp + 4], str.Congratulations_  ; [0x8048d03:4]=0x676e6f43  ; "Congratulations!" @ 0x8048d03
│           0x08048a38    8d45e3         lea eax, [ebp-local_7_1]                                                                                                                                           
0x08048a3b    890424         mov dword [esp], eax                                         
0x08048a3e    e82dfdffff     call sym.imp.strcmp            ; sub.strcmp_12_76c+0x4 ;[5] ;sub.strcmp_12_76c() ; sym.imp.strcmp
```

I set a breakpoint at 0x080489e8 and printed out the bytearray located on the stack:

```
:> p8 17 @ ebp-0x19
517d7c75607366677e73667b7d7c613300
:> ps @ ebp-0x1d
Q}|u`sfg~sf{}|a3
```

input - 0x1337d00d <= 0x15
input <= 322424866

So summarized there are now the following two conditions:



- diff = Input - 0x1337d00d <= 0x15
- diff ^ b"bQ}|u`sfg~sf{}|a3" = b"Congratulations_"

To solve these equations I used one of my favourite toolset: z3. The script is provided in "lab1B.py"
[![asciicast](https://asciinema.org/a/Z4sFerJotqJG03pw48Vq86gqd.png)](https://asciinema.org/a/Z4sFerJotqJG03pw48Vq86gqd)

### Pass Lab1Bwq
```
1337_3nCRyptI0n_br0
```
