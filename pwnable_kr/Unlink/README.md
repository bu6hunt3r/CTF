# pwnable.kr - unlink

- The goal of this challenge is to gain RCE via a variant of unlink macro used by libc.
- In simplified terms this program will release an node out of a double linked list that we fully control.

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
The following code snippet shows the routine that will be called by main in executable:

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