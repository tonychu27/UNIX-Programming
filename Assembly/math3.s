@ math3: 32-bit unsigned arithmetic
@ 	var4 = (var1 * 5) / (var2 - 3)
@ 	note: overflowed part should be truncated
@ ======
@ * BASEADDR rsi = 0x540000, DATAADDR = BASEADDR + 0x200000
@       var1 @ 0x740000-740004
@       var2 @ 0x740004-740008
@       var4 @ 0x740008-74000c
@ ======

add rsi, 0x200000

mov eax, [rsi]
mov ebx, [rsi + 0x000004]

imul eax, eax, 5
sub ebx, 3
div ebx

mov [rsi + 0x000008], eax

done: