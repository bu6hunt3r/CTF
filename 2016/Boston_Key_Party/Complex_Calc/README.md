# Complex Calc writeup
## BKPCTF 2016
--------------------------------

The binary has almost the same attributes as Simple complex_calc

### Basic recon
```
$ file complex_calc
complex_calc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea,
not stripped

$ checksec --file ./complex_calc
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```
### The difference
The only difference is represented by just a few bytes...
```
$ radiff2 simple_calc complex_calc
0x000156e0 4885ff0f84af00 => 0f1f00660f1f44 0x000156e0

```
Let's look at ```0x000156e0 + 0x00400000 = 0x004156e0```:

```
│           0x004156e0      0f1f00         nop dword [rax]
│           0x004156e3      660f1f440000   nop word [rax + rax]
```
The code is located in the ```free``` function. These two NOPs have replaced a test assembly instruction in the unpatched version of the challenge:
```
│           0x004156e0      4885ff         test rdi, rdi
│           0x004156e3      0f84af000000   je 0x415798
```
The code tests if ```rdi``` is zero. Its the one and only argument to ```free```.
So a pointer to memory which has to be free'd is the argument passed to ```free``` in the unpatched binary.

If we try to execute the same payload that grilled the 'simple_calc', ```free``` will end up dereferencing an unallocated area of memory and segfault:
```
│           0x004156e9      488b47f8       mov rax, qword [rdi - 8]
```
The ROP chain we already constructed for 'simple_calc' should do it's job the same way (gadgets are the same, located at same addresses).  ```free``` must be tricked into believing that a valid chunk has been passed to it. So we need a memory region that won't be affected by ASLR and that we control...

## Memory region of interest
Each operation done by the calculator saves both operands and the operand in global variables:
```
pwndbg> set disassembdisassemble subs                                                                  
Dump of assembler code for function subs:
  0x0000000000401137 <+0>:     push   rbp
  0x0000000000401138 <+1>:     mov    rbp,rsp
  0x000000000040113b <+4>:     mov    edi,0x494208
  0x0000000000401140 <+9>:     mov    eax,0x0
  0x0000000000401145 <+14>:    call   0x408390 <printf>
  0x000000000040114a <+19>:    mov    esi,0x6c4ab0
  0x000000000040114f <+24>:    mov    edi,0x494214
  0x0000000000401154 <+29>:    mov    eax,0x0
  0x0000000000401159 <+34>:    call   0x4084c0 <__isoc99_scanf>
[snip]
  0x0000000000401177 <+64>:    mov    esi,0x6c4ab4
  0x000000000040117c <+69>:    mov    edi,0x494214
  0x0000000000401181 <+74>:    mov    eax,0x0
  0x0000000000401186 <+79>:    call   0x4084c0 <__isoc99_scanf>
[snip]
  0x00000000004011bf <+136>:   mov    edx,DWORD PTR [rip+0x2c38eb]        # 0x6c4ab0 <sub>
  0x00000000004011c5 <+142>:   mov    eax,DWORD PTR [rip+0x2c38e9]        # 0x6c4ab4 <sub+4>
  0x00000000004011cb <+148>:   sub    edx,eax
  0x00000000004011cd <+150>:   mov    eax,edx
  0x00000000004011cf <+152>:   mov    DWORD PTR [rip+0x2c38e3],eax        # 0x6c4ab8 <sub+8>
  0x00000000004011d5 <+158>:   mov    eax,DWORD PTR [rip+0x2c38dd]        # 0x6c4ab8 <sub+8>
  0x00000000004011db <+164>:   mov    esi,eax
  0x00000000004011dd <+166>:   mov    edi,0x49428e
  0x00000000004011e2 <+171>:   mov    eax,0x0
  0x00000000004011e7 <+176>:   call   0x408390 <printf>
  0x00000000004011ec <+181>:   pop    rbp
  0x00000000004011ed <+182>:   ret

```
- ```0x6c4ab0``` holds first operand, say ```sub_x```
- ```0x6c4ab0``` holds second operand, say ```sub_y```
- ```0x6c4ab0``` holds the result , say ```sub_r```

They all hold DWORDs, so we have an controllable area of 12 bytes. For our particular interest in tricking ```free``` we just need one chunk and not other adjacent areas.

## Analyzing
That free is part of [GNU libc](https://www.gnu.org/software/libc/) (source code already avalibale).

```C
if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* see if the dynamic brk/mmap threshold needs adjusting */
      if (!mp_.no_dyn_threshold
          && p->size > mp_.mmap_threshold
          && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
      return;
    }

```
```mem2chunk``` takes a pointer to memory area and returns the pointer to the start of the chunk.
```chunk_is_mapped``` is a macro that only checks if the second bit (from right) in the size header is set:

```C
/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)

```
The second ```if ``` is not that important, so let's skip over to call to ```munmap_chunk```:
```C
static void
internal_function
munmap_chunk (mchunkptr p)
{
  INTERNAL_SIZE_T size = chunksize (p);

  assert (chunk_is_mmapped (p));

  uintptr_t block = (uintptr_t) p - p->prev_size;
  size_t total_size = p->prev_size + size;
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
    {
      malloc_printerr (check_action, "munmap_chunk(): invalid pointer",
                       chunk2mem (p));
      return;
    }

  atomic_decrement (&mp_.n_mmaps);
  atomic_add (&mp_.mmapped_mem, -total_size);

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);
}
```
The macro ```chunksize``` removes the low bits from the ```size``` field in the chunk headers. Therefore second bit that has to be set will not be present in the variable ```size``` in the above code.

The only way to hit the return is to pass that ```if```-statement:

```C
if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
```
Therefore ```block``` bitwise OR'ed with ```total_size``` must have all its lowest significant bit not set (i.e. equal to zero), which means that none of ```block``` and ```total_size``` can have lower bits set.

- ```dl_pagesize = 0x1000``` 4k pages
- ```block = p - p->prev_size``` the address of the header of the chunk minus size of previous chunk
- ```total_size = p->prev_size + size``` the size of previous chunk plus size of chunk

This results in: ```((p - prev_size) | (p - prev_size + size)) & 0xfff == 0```

## Creating a fake chunk

We can control 3 DWORDS in memory area of interest with subtraction operation, but no trouble cause none of higher bits are checked. Memory layout looks as follows:
```
.bss:
          +---------------+
0x6c4ab0  | sub_x | sub_y |
          +---------------+
0x6c4ab8  | sub_x |  ???  |
          +---------------+
0x6c4ac0  |      ???      |

```
If we use above condition:

- ```block = p - p->prev_size = 0x6c4ab0 - p->prev_size```: ```block``` must end with ```0x000``` => ```prev_size``` ends with ```0xab0```
- ```total_size = p->prev_size + size```: ```total_size``` must end with ```0x000``` => ```size``` must end with ```0x1000 - 0xab0 = 0x550```
