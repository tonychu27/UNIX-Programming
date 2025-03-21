@ mulbyshift: multiply val1 by 26 and store the result in val2
@ ======
@ * BASEADDR rsi = 0x44f000, DATAADDR = BASEADDR + 0x200000
@       val1 @ 0x64f000-64f004
@       val2 @ 0x64f004-64f008
@ ======

add rsi, 0x200000
mov eax, [rsi]
imul eax, 26
mov [rsi + 0x000004], eax

done: