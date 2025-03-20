@ addsub1:
@ 	eax = 0xb62555a4
@ 	eax = eax + 0x5c4d5e9d 
@ 	eax = eax - 0x68c34d30
@ ======
@ * BASEADDR rsi = 0x531000, DATAADDR = BASEADDR + 0x200000
@ ======

mov eax, 0xb62555a4
add eax, 0x5c4d5e9d
sub eax, 0x68c34d30