.text
.globl main
.intel_syntax noprefix

main:
push   ebp
mov    ebp,esp
push   ecx
mov    eax, dword ptr [ebp+0x8]
mov    cl, byte ptr [eax]
mov    byte ptr [ebp-0x1], cl
mov    esp,ebp
pop    ebp
ret    0x0

