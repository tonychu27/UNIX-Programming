; nc up.zoolab.org 2522

; ul+lu: convert the alphabet in CH from upper to lower or from lower to upper
; ======
; * BASEADDR rsi = 0x51f000, DATAADDR = BASEADDR + 0x200000
; ======

add ch, 0x20
done: