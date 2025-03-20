@ clear17: clear bit-17 in eax (zero-based index)
@ ======
@ * BASEADDR rsi = 0x408000, DATAADDR = BASEADDR + 0x200000
@ ======

and eax, 0xfffdffff