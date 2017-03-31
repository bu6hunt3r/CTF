## Simple Calc pwnable

Seems to be a calculator

```
|#------------------------------------#|
|         Something Calculator         |
|#------------------------------------#|

Expected number of calculations: 4
Options Menu:
[1] Addition.
[2] Subtraction.
[3] Multiplication.
[4] Division.
[5] Save and Exit.
=> 1
Integer x: 1234
Integer y: 4321
Result for x + y is 5555.
```
```
   0x0040152e      8b45ec         mov eax, dword [rbp - no_of_calcs]
   0x00401531      c1e002         shl eax, 2
   0x00401534      4863d0         movsxd rdx, eax
   0x00401537      488b4df0       mov rcx, qword [rbp - heap_results]
   0x0040153b      488d45c0       lea rax, qword [rbp - stack_results]
   0x0040153f      4889ce         mov rsi, rcx
   0x00401542      4889c7         mov rdi, rax
   0x00401545      e886130200     call sym.memcpy            ; void *memcpy(void *s1, const void *s2, size_t n);
   0x0040154a      488b45f0       mov rax, qword [rbp - heap_results]
   0x0040154e      4889c7         mov rdi, rax
   0x00401551      e87a410100     call sym.__cfree           ; void free(void *ptr);

```
