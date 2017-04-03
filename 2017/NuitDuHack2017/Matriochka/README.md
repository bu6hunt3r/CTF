# Matriochka Step 1
### Reversing - 35 pts


> **Description**
> _____
> *Can you reverse it ? Analyze it ? Calculate it ? Keygen it ? Modify it ? Enjoy yourself :)
> This challenge is separated in four steps with four separate flags to guide you.*

That challenge is named after the russian ...  and also the challenge's guides us to the assumption that we would have to peal some onions...

The interesting functions in that 64-bit ELF executable are:
```
0x00400666    4 74           sym.main
0x004006b0    1 29           sym.mmm
0x004006cd    1 29           sym.you
0x004006ea    1 29           sym.touch
0x00400707   11 276          sym.my
```
After some analysis we explore that mmm, you and touch are simple wrappers for a call to another fonction. So we got the chain ```you --> touch --> my```.
```
                                                            ┌──────────────────────────────────────────────────────────┐
                                                            │  0x400707 ;[c]                                           │
                                                            │ (fcn) sym.my 276                                         │
                                                            │   sym.my ();                                             │
                                                            │ ; var int input @ rbp-0x28                               │
                                                            │ ; var int result_buf @ rbp-0x19                          │
                                                            │ ; var int len_input @ rbp-0x18                           │
                                                            │ ; var int inter_input @ rbp-0x10                         │
                                                            │ ; var int term_zero @ rbp-0x8                            │
                                                            │ ; CALL XREF from 0x004006fd (sym.touch)                  │
                                                            │ push rbp                                                 │
                                                            │ mov rbp, rsp                                             │
                                                            │ sub rsp, 0x30 ; '0'                                      │
                                                            │ mov qword [rbp - input], rdi                             │
                                                            │ mov rax, qword [rbp - input]                             │
                                                            │ mov rdi, rax                                             │
                                                            │ call sym.imp.strlen ;[a]; size_t strlen(const char *s);  │
                                                            │ mov qword [rbp - len_input], rax                         │
                                                            │ cmp qword [rbp - len_input], 1                           │
                                                            │  ; [0x1:8]=0x10102464c45                                 │
                                                            │ jbe 0x400794 ;[b]                                        │
                                                            └──────────────────────────────────────────────────────────┘
                                                                    f t
                                                                  ┌─┘ └────────────────────────────────┐
                                                                  │                                    │
                                                                  │                                    │
                                                          ┌─────────────────────────────────────┐      │
                                                          │  0x40072a ;[e]                      │      │
                                                          │ mov qword [rbp - term_zero], 0      │      │
                                                          │ mov rax, qword [rbp - len_input]    │      │
                                                          │ sub rax, 1                          │      │
                                                          │ mov qword [rbp - inter_input], rax  │      │
                                                          │ jmp 0x400787 ;[d]                   │      │
                                                          └─────────────────────────────────────┘      │

```
 At first ```my``` calculates the length of user supplied argument from stdin stored in ```argv[1]```. The really intersting part starts at 0x400787 which reverts or input byte by byte with more or less the following algorithm:

```C
void reverse(char s[]) {
        int length = strlen(s);
        int c,i,j;

        for(i=0, j=length-1; i < j; i++, j--) {
                c=s[i];
                s[i]=s[j];
                s[j]=c;
        }
}
```
After reverting our input, it makes a call to libc's ```strcmp``` with the mutated variant of our input and the string "Tr4laLa!!!" as args.

```
                                                          ┌──────────┘ └────────────────┐ ┌────────────┘
                                                  │       │                             │ │
                                                  │       │                             │ │
                                                  │ ┌────────────┐              ┌─────────────────────────────────┐
                                                  │ │  0x400740 ;│f]            │  0x400794 ;[b]                  │
                                                  │ └────────────┘              │ 0x00400798 str.Tr4laLa___       │
                                                  └─────┘                       │ 0x004346b2 "Tr4laLa!!!"         │
                                                                                │ 0x004007a0 call sym.imp.strcmp  │
                                                                                └─────────────────────────────────┘

```
So if we supply "\!\!\!slaLal4rT" (note backslashes before ! cause bash otherwise will meh it up) we should reveal flag!
But wait... At the end of ```my``` there is a call to ```fputc``` within a loop with stderr as file descriptor and some raw binary bytes as output.
If we just supply the aforementioned string we would lead our shell to mordor. It would be better to redirect stderr to a file. So one binary dumps another...Nice

```
$ ./step1.bin \!\!\!aLal4rT 2> flag2.bin
Well done :)

```