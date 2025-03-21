@ leax:
@ 	eax = edi * 2
@ 	ebx = edi * 3
@ 	ecx = edi * 5
@ 	edx = edi * 9
@ ======
@ * BASEADDR rsi = 0x53f000, DATAADDR = BASEADDR + 0x200000
@ ======

lea eax, [edi + edi]
lea ebx, [edi + edi * 2]
lea ecx, [edi + edi * 4]
lea edx, [edi + edi * 8]

done: