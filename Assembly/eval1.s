@ eval1:
@ 	Rval = -Xval + (Yval – Zval)
@ ======
@ * BASEADDR rsi = 0x57c000, DATAADDR = BASEADDR + 0x200000
@       Xval @ 0x77c000-77c004
@       Yval @ 0x77c004-77c008
@       Zval @ 0x77c008-77c00c
@       Rval @ 0x77c00c-77c010
@ ======

mov eax, [rsi + 0x200000]
neg eax
mov ebx, [rsi + 0x200004]
sub ebx, [rsi + 0x200008]
add eax, ebx
mov [rsi + 0x20000c], eax

done: