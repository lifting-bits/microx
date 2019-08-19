; Build via nasm -f elf32 -o simple.elf simple.asm
BITS 32
SECTION .text

global main

main:
push   ebp
mov    ebp,esp
push   ecx
mov    eax, dword [ebp+0x8]
mov    cl, byte [eax]
mov    byte [ebp-0x1], cl
mov    esp,ebp
pop    ebp
ret    0x0

