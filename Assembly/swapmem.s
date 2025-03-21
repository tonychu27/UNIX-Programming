@ swapmem: swap the values in val1 and val2
@ ======
@ * BASEADDR rsi = 0x51e000, DATAADDR = BASEADDR + 0x200000
@       val1 @ 0x71e000-71e008
@       val2 @ 0x71e008-71e010
@ ======

add rsi, 0x200000
mov eax, [rsi]
mov ebx, [rsi + 0x000008]
mov [rsi], ebx
mov [rsi + 0x000008], eax

done:
