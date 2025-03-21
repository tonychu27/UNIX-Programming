; nc up.zoolab.org 2502

; bubble: bubble sort for 10 integers
; ======
; * BASEADDR rsi = 0x517000, DATAADDR = BASEADDR + 0x200000
;       a[0] @ 0x717000-717004
;       a[1] @ 0x717004-717008
;       a[2] @ 0x717008-71700c
;       a[3] @ 0x71700c-717010
;       a[4] @ 0x717010-717014
;       a[5] @ 0x717014-717018
;       a[6] @ 0x717018-71701c
;       a[7] @ 0x71701c-717020
;       a[8] @ 0x717020-717024
;       a[9] @ 0x717024-717028
; ======

mov ecx, 10
mov rdx, 0x200000
add rdx, rsi

outer_loop:
    dec ecx
    jz end_sort

    mov edi, 9
    mov rsi, rdx
inner_loop:
    mov eax, [rsi]
    mov ebx, [rsi + 4]
    cmp eax, ebx
    jle no_swap

    mov [rsi], ebx
    mov [rsi + 4], eax
no_swap:
    add rsi, 4
    dec edi
    jnz inner_loop

    jmp outer_loop

end_sort:

done: